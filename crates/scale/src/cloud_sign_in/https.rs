use std::io::{self, Read};
use std::time::Duration;

use reqwest::blocking::{Client, Response as HttpResponse};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderMap, SET_COOKIE};
use reqwest::redirect::Policy;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: u64 = 64 * 1024;

pub(super) struct Session {
    client: Client,
    login_cookies: Jar,
}

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
    pub(super) service_token: Option<String>,
}

impl Session {
    pub(super) fn new() -> io::Result<Self> {
        let client = Client::builder()
            .user_agent("blt_unlock")
            .tls_backend_native()
            .https_only(true)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(to_io)?;
        Ok(Self {
            client,
            login_cookies: Jar::default(),
        })
    }

    pub(super) fn get(&self, url: &Url, timeout: Duration) -> io::Result<Response> {
        let mut request = self.client.get(url.clone()).timeout(timeout);
        // Only the sign-in GETs share a cookie jar. Signed POSTs send their own Cookie header.
        if let Some(mut cookie) = self.login_cookies.cookies(url) {
            cookie.set_sensitive(true);
            request = request.header(COOKIE, cookie);
        }
        let response = request.send().map_err(to_io)?;
        let mut cookies = response.headers().get_all(SET_COOKIE).iter();
        self.login_cookies.set_cookies(&mut cookies, response.url());
        Response::read(response)
    }

    pub(super) fn post_form(
        &self,
        url: &Url,
        headers: HeaderMap,
        body: &str,
        timeout: Duration,
    ) -> io::Result<Response> {
        let response = self
            .client
            .post(url.clone())
            .headers(headers)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.to_owned())
            .timeout(timeout)
            .send()
            .map_err(to_io)?;
        Response::read(response)
    }
}

impl Response {
    fn read(response: HttpResponse) -> io::Result<Self> {
        let status = response.status();
        let service_token = if (status.is_success() || status.is_redirection())
            && response.url().host_str() == Some("sts.api.io.mi.com")
        {
            service_token(response.headers()).map(str::to_owned)
        } else {
            None
        };
        let body = read_body(response)?;
        Ok(Self {
            status: status.as_u16(),
            body,
            service_token,
        })
    }

    pub(super) fn require_ok(&self, stage: &str) -> io::Result<()> {
        if self.status == 200 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Xiaomi's {stage} returned HTTP {}",
                self.status,
            )))
        }
    }
}

fn service_token(headers: &HeaderMap) -> Option<&str> {
    headers.get_all(SET_COOKIE).iter().find_map(|header| {
        let cookie = header.to_str().ok()?.split(';').next()?.trim();
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

fn read_body(body: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    body.take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            let timed_out = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<reqwest::Error>())
                .is_some_and(reqwest::Error::is_timeout);
            let kind = if timed_out {
                io::ErrorKind::TimedOut
            } else {
                error.kind()
            };
            io::Error::new(kind, "could not read Xiaomi's HTTP response")
        })?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Xiaomi's sign-in response is too large",
        ));
    }
    Ok(bytes)
}

fn to_io(error: reqwest::Error) -> io::Error {
    let kind = if error.is_timeout() {
        io::ErrorKind::TimedOut
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, error.without_url())
}

#[cfg(test)]
mod tests {
    use std::io;

    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};

    use super::{MAX_RESPONSE, read_body, service_token};

    #[test]
    fn only_reads_a_valid_nonempty_service_token_cookie() {
        let mut headers = HeaderMap::new();
        for invalid in [
            "serviceToken=; Secure",
            "other=serviceToken=test; Secure",
            "serviceToken=test cookie; Secure",
        ] {
            headers.append(SET_COOKIE, HeaderValue::from_static(invalid));
        }
        assert!(service_token(&headers).is_none());
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("serviceToken=\"test\"; Secure; HttpOnly"),
        );
        assert_eq!(service_token(&headers), Some("test"));
    }

    #[test]
    fn bounds_response_body_reads() {
        let body = vec![b'a'; MAX_RESPONSE as usize];
        assert_eq!(read_body(body.as_slice()).unwrap(), body);
        let error = read_body(io::repeat(b'a')).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
