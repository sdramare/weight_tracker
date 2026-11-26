use std::ffi::c_void;
use std::io;
use std::ptr::{NonNull, null, null_mut};
use std::time::Duration;

use url::Url;
use windows::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_NAME_NOT_RESOLVED, ERROR_WINHTTP_TIMEOUT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_DISABLE_COOKIES, WINHTTP_FLAG_SECURE,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_QUERY_STATUS_CODE, WinHttpAddRequestHeaders,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts,
};
use windows::core::{Error, HRESULT, HSTRING, PCWSTR, w};

pub(super) struct Session(Handle);

pub(super) struct Response {
    pub(super) status: u32,
    pub(super) body: Vec<u8>,
    pub(super) service_token: Option<String>,
}

const MAX_RESPONSE: usize = 64 * 1024;
const CONNECT_TIMEOUT_MS: i32 = 5_000;

impl Session {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: All strings are valid WinHTTP parameters. This is a synchronous session.
        let handle = Handle::new(unsafe {
            WinHttpOpen(
                w!("blt_unlock"),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            )
        })?;
        // SAFETY: The handle is valid and the option expects a DWORD byte slice.
        unsafe {
            WinHttpSetOption(
                Some(handle.raw()),
                WINHTTP_OPTION_REDIRECT_POLICY,
                Some(&WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes()),
            )
        }
        .map_err(to_io)?;
        Ok(Self(handle))
    }

    pub(super) fn get(&self, url: &Url, timeout: Duration) -> io::Result<Response> {
        self.request(url, w!("GET"), None, None, timeout)
    }

    pub(super) fn post_form(
        &self,
        url: &Url,
        headers: &str,
        body: &str,
        timeout: Duration,
    ) -> io::Result<Response> {
        let headers = HSTRING::from(headers);
        self.request(
            url,
            w!("POST"),
            Some(&headers),
            Some(body.as_bytes()),
            timeout,
        )
    }

    fn request(
        &self,
        url: &Url,
        method: PCWSTR,
        headers: Option<&[u16]>,
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<Response> {
        let host = HSTRING::from(url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "the request URL has no host")
        })?);
        let path = HSTRING::from(&url[url::Position::BeforePath..url::Position::AfterQuery]);
        // SAFETY: The UTF-16 strings are live during the calls. The session
        // outlives both handles and the connection outlives its request.
        let connection = Handle::new(unsafe { WinHttpConnect(self.0.raw(), &host, 443, 0) })?;
        let request = Handle::new(unsafe {
            WinHttpOpenRequest(
                connection.raw(),
                method,
                &path,
                PCWSTR::null(),
                PCWSTR::null(),
                null(),
                WINHTTP_FLAG_SECURE,
            )
        })?;
        let receive_timeout = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let body_length = u32::try_from(body.map_or(0, <[u8]>::len)).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Xiaomi request is too large")
        })?;
        // SAFETY: The request is synchronous. The payload and headers outlive the call.
        unsafe {
            if let Some(headers) = headers {
                WinHttpSetOption(
                    Some(request.raw()),
                    WINHTTP_OPTION_DISABLE_FEATURE,
                    Some(&WINHTTP_DISABLE_COOKIES.to_ne_bytes()),
                )
                .map_err(to_io)?;
                WinHttpAddRequestHeaders(request.raw(), headers, WINHTTP_ADDREQ_FLAG_ADD)
                    .map_err(to_io)?;
            }
            WinHttpSetTimeouts(
                request.raw(),
                CONNECT_TIMEOUT_MS,
                CONNECT_TIMEOUT_MS,
                CONNECT_TIMEOUT_MS,
                receive_timeout,
            )
            .map_err(to_io)?;
            WinHttpSendRequest(
                request.raw(),
                None,
                body.map(|bytes| bytes.as_ptr().cast()),
                body_length,
                body_length,
                0,
            )
            .map_err(to_io)?;
            WinHttpReceiveResponse(request.raw(), null_mut()).map_err(to_io)?;
        }
        let status = status_code(&request)?;
        let service_token =
            if (200..400).contains(&status) && url.host_str() == Some("sts.api.io.mi.com") {
                service_token(&read_headers(&request)?).map(str::to_owned)
            } else {
                None
            };
        let body = read_body(&request)?;
        Ok(Response {
            status,
            body,
            service_token,
        })
    }
}

impl Response {
    pub(super) fn require_ok(&self, stage: &str) -> io::Result<()> {
        if self.status == 200 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Xiaomi's {stage} returned HTTP {}",
                self.status
            )))
        }
    }
}

fn status_code(request: &Handle) -> io::Result<u32> {
    let mut status = 0_u32;
    let mut bytes = size_of::<u32>() as u32;
    // SAFETY: NUMBER queries write a DWORD to the provided output address.
    unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some((&raw mut status).cast()),
            &mut bytes,
            null_mut(),
        )
    }
    .map_err(to_io)?;
    Ok(status)
}

fn read_headers(request: &Handle) -> io::Result<String> {
    let mut headers = vec![0_u16; MAX_RESPONSE / size_of::<u16>()];
    let mut bytes = MAX_RESPONSE as u32;
    // SAFETY: The allocated UTF-16 buffer is writable for the declared byte count.
    unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            PCWSTR::null(),
            Some(headers.as_mut_ptr().cast()),
            &mut bytes,
            null_mut(),
        )
    }
    .map_err(to_io)?;
    headers.truncate(bytes as usize / size_of::<u16>());
    Ok(String::from_utf16_lossy(&headers))
}

fn service_token(headers: &str) -> Option<&str> {
    headers.lines().find_map(|line| {
        let (name, content) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        let cookie = content.split(';').next()?.trim();
        let value = cookie.strip_prefix("serviceToken=")?;
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        // Accept only RFC 6265 cookie-octets because this value is reused in an HTTP header.
        let valid = !value.is_empty()
            && value.bytes().all(
                |byte| matches!(byte, b'!' | b'#'..=b'+' | b'-'..=b':' | b'<'..=b'[' | b']'..=b'~'),
            );
        valid.then_some(value)
    })
}

fn read_body(request: &Handle) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let mut count = 0_u32;
        // SAFETY: The buffer and count are writable and the handle is live.
        unsafe {
            WinHttpReadData(
                request.raw(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut count,
            )
        }
        .map_err(to_io)?;
        if count == 0 {
            return Ok(body);
        }
        if body.len() + count as usize > MAX_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Xiaomi's sign-in response is too large",
            ));
        }
        body.extend_from_slice(&buffer[..count as usize]);
    }
}

struct Handle(NonNull<c_void>);

impl Handle {
    fn new(raw: *mut c_void) -> io::Result<Self> {
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| to_io(Error::from_thread()))
    }

    fn raw(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: This guard owns the handle and releases it once.
        let _ = unsafe { WinHttpCloseHandle(self.raw()) };
    }
}

fn to_io(error: Error) -> io::Error {
    if error.code() == HRESULT::from_win32(ERROR_WINHTTP_TIMEOUT) {
        io::Error::new(io::ErrorKind::TimedOut, error)
    } else if error.code() == HRESULT::from_win32(ERROR_WINHTTP_NAME_NOT_RESOLVED) {
        io::Error::other("Windows could not resolve the Xiaomi server name")
    } else {
        io::Error::other(error)
    }
}

#[cfg(test)]
mod tests {
    use super::service_token;

    #[test]
    fn only_reads_a_valid_nonempty_service_token_cookie() {
        assert_eq!(
            service_token("Set-Cookie: serviceToken=\"test\"; Secure; HttpOnly\r\n"),
            Some("test")
        );
        assert!(service_token("Set-Cookie: serviceToken=; Secure\r\n").is_none());
        assert!(service_token("Set-Cookie: other=serviceToken=test; Secure\r\n").is_none());
        assert!(service_token("Set-Cookie: serviceToken=test cookie; Secure\r\n").is_none());
    }
}
