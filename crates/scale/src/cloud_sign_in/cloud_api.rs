use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use reqwest::header::{ACCEPT_ENCODING, COOKIE, HeaderMap, HeaderValue};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use url::form_urlencoded;
use windows::Data::Json::{JsonObject, JsonValue};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCRYPT_RC4_ALG_HANDLE, BCryptDestroyKey, BCryptEncrypt,
    BCryptGenerateSymmetricKey,
};
use windows::core::HSTRING;

use super::{CloudAccount, REQUEST_TIMEOUT, https, secure_url, xiaomi_json};

const EUROPE_API: &str = "https://de.api.io.mi.com/app";
const DEVICE_COUNT_PATH: &str = "/v2/user/get_device_cnt";
const DEVICE_COUNT_QUERY: &str = r#"{"fetch_own":true,"fetch_share":false}"#;

pub(super) fn verify_device_count(
    client: &dyn https::RequestSession,
    account: &CloudAccount,
) -> io::Result<()> {
    signed_request(client, account, DEVICE_COUNT_PATH, DEVICE_COUNT_QUERY).map(|_| ())
}

pub(super) fn signed_request(
    client: &dyn https::RequestSession,
    account: &CloudAccount,
    path: &str,
    data: &str,
) -> io::Result<JsonValue> {
    let user_id = account
        .user_id
        .as_deref()
        .ok_or_else(|| io::Error::other("Xiaomi's sign-in response is missing the account ID"))?;
    let url = secure_url(&format!("{EUROPE_API}{path}"))?;
    let request = SignedRequest::new(path, data, &account.security, request_nonce()?)?;
    let token = &account.service_token;
    let mut cookie = HeaderValue::from_str(&format!(
        "userId={user_id}; serviceToken={token}; yetAnotherServiceToken={token}; locale=en_GB"
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Xiaomi session cookie"))?;
    cookie.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, cookie);
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(
        "x-xiaomi-protocal-flag-cli",
        HeaderValue::from_static("PROTOCAL-HTTP2"),
    );
    headers.insert(
        "miot-encrypt-algorithm",
        HeaderValue::from_static("ENCRYPT-RC4"),
    );
    let response = client
        .post_form(&url, headers, &request.form, REQUEST_TIMEOUT)
        .map_err(|error| super::request_error("reach Xiaomi's Europe API", error))?;
    response.require_ok("Europe cloud API")?;
    request.result(&response.body)
}

struct SignedRequest {
    form: String,
    key: [u8; 32],
}

impl SignedRequest {
    fn new(path: &str, data: &str, security: &str, nonce: [u8; 12]) -> io::Result<Self> {
        let decoded = decode_base64(security, "Xiaomi returned invalid session material")?;
        let mut digest = Sha256::new();
        digest.update(decoded);
        digest.update(nonce);
        let key: [u8; 32] = digest.finalize().into();
        let signed_nonce = Base64::encode_string(&key);
        let hash = signature(path, &[("data", data)], &signed_nonce);
        let data = Base64::encode_string(&rc4_drop(&key, data.as_bytes())?);
        let hash = Base64::encode_string(&rc4_drop(&key, hash.as_bytes())?);
        let signature = signature(
            path,
            &[("data", &data), ("rc4_hash__", &hash)],
            &signed_nonce,
        );
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("data", &data)
            .append_pair("rc4_hash__", &hash)
            .append_pair("signature", &signature)
            .append_pair("ssecurity", security)
            .append_pair("_nonce", &Base64::encode_string(&nonce))
            .finish();
        Ok(Self { form, key })
    }

    fn result(&self, body: &[u8]) -> io::Result<JsonValue> {
        let message = "Xiaomi's Europe API returned an unexpected response";
        let json = match xiaomi_json(body) {
            Ok(json) => json,
            Err(_) => {
                let text = std::str::from_utf8(body).map_err(|_| io::Error::other(message))?;
                let encrypted = decode_base64(text.trim(), message)?;
                let decrypted = rc4_drop(&self.key, &encrypted)?;
                xiaomi_json(&decrypted).map_err(|_| io::Error::other(message))?
            }
        };
        match cloud_code(&json) {
            Some(0) => json
                .GetNamedValue(&HSTRING::from("result"))
                .map_err(|_| io::Error::other(message)),
            Some(code) => Err(cloud_rejection(&json, code)),
            _ => Err(io::Error::other(message)),
        }
    }
}

fn cloud_code(json: &JsonObject) -> Option<i32> {
    json.GetNamedValue(&HSTRING::from("code"))
        .and_then(|value| value.Stringify())
        .ok()?
        .to_string_lossy()
        .parse()
        .ok()
}

fn cloud_rejection(json: &JsonObject, code: i32) -> io::Error {
    let message = format!("Xiaomi's Europe API rejected the request (code {code})");
    let detail = ["message", "description"]
        .into_iter()
        .filter_map(|field| json.GetNamedString(&HSTRING::from(field)).ok())
        .map(|value| value.to_string_lossy())
        .find(|value| {
            !value.trim().is_empty()
                && value.chars().count() <= 160
                && !value.chars().any(char::is_control)
        });
    io::Error::other(match detail {
        Some(detail) => format!("{message}. Xiaomi reported “{}”.", detail.trim()),
        None => message,
    })
}

fn decode_base64(value: &str, message: &'static str) -> io::Result<Vec<u8>> {
    Base64::decode_vec(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, message))
}

fn request_nonce() -> io::Result<[u8; 12]> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("the PC clock is earlier than the Unix epoch"))?;
    let minutes = u32::try_from(time.as_secs() / 60)
        .map_err(|_| io::Error::other("the PC clock is outside Xiaomi's nonce range"))?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce[..8])
        .map_err(|_| io::Error::other("could not generate a Xiaomi request nonce"))?;
    nonce[8..].copy_from_slice(&minutes.to_be_bytes());
    Ok(nonce)
}

fn signature(path: &str, fields: &[(&str, &str)], signed_nonce: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(b"POST&");
    digest.update(path);
    for (name, value) in fields {
        digest.update(b"&");
        digest.update(name);
        digest.update(b"=");
        digest.update(value);
    }
    digest.update(b"&");
    digest.update(signed_nonce);
    Base64::encode_string(&digest.finalize())
}

// Xiaomi's legacy wire format discards the first 1024 bytes of each RC4 stream.
fn rc4_drop(key: &[u8; 32], data: &[u8]) -> io::Result<Vec<u8>> {
    const DISCARD: usize = 1024;
    let mut handle = BCRYPT_KEY_HANDLE::default();
    // SAFETY: The algorithm pseudo-handle is from CNG. CNG owns the key object's allocation.
    check_cipher(unsafe {
        BCryptGenerateSymmetricKey(BCRYPT_RC4_ALG_HANDLE, &mut handle, None, key, 0)
    })?;
    let key = Rc4Key(handle);
    let mut input = vec![0; DISCARD];
    input.extend_from_slice(data);
    let mut output = vec![0; input.len()];
    let mut written = 0;
    // SAFETY: The key is live. The buffers are disjoint and writable only as specified.
    check_cipher(unsafe {
        BCryptEncrypt(
            key.0,
            Some(&input),
            None,
            None,
            Some(&mut output),
            &mut written,
            BCRYPT_FLAGS(0),
        )
    })?;
    if written as usize != output.len() {
        return Err(io::Error::other(
            "Windows returned an incomplete Xiaomi API cipher result",
        ));
    }
    output.drain(..DISCARD);
    Ok(output)
}

fn check_cipher(status: NTSTATUS) -> io::Result<()> {
    if status.0 >= 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Windows could not apply Xiaomi's API cipher ({:#010x})",
            status.0 as u32
        )))
    }
}

struct Rc4Key(BCRYPT_KEY_HANDLE);

impl Drop for Rc4Key {
    fn drop(&mut self) {
        // SAFETY: This guard owns the CNG key handle and releases it once.
        let _ = unsafe { BCryptDestroyKey(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use url::form_urlencoded;

    use super::{DEVICE_COUNT_PATH, DEVICE_COUNT_QUERY, SignedRequest};
    use crate::Apartment;

    #[test]
    fn signs_the_device_count_request_and_checks_the_encrypted_reply() {
        let _apartment = Apartment::initialize().unwrap();
        let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let request = SignedRequest::new(
            DEVICE_COUNT_PATH,
            DEVICE_COUNT_QUERY,
            "EBESExQVFhcYGRobHB0eHw==",
            nonce,
        )
        .unwrap();
        let fields: Vec<_> = form_urlencoded::parse(request.form.as_bytes()).collect();
        let expected = [
            (
                "data",
                "FcmKVQOYKh4aLIWfuS+KOj8aQtB3RazVks1hK6yJtelvd65QEY4=",
            ),
            ("rc4_hash__", "DLOaRjbOICgfYrjW9WKzCj1fE9UlWb/MvNhYdw=="),
            ("signature", "im7TdiowS2eNWL6b6QDX4WJzniA="),
            ("ssecurity", "EBESExQVFhcYGRobHB0eHw=="),
            ("_nonce", "AAECAwQFBgcICQoL"),
        ];
        assert_eq!(fields.len(), expected.len());
        for ((name, value), (expected_name, expected_value)) in fields.iter().zip(expected) {
            assert_eq!(name, expected_name);
            assert_eq!(value, expected_value);
        }
        assert!(
            request
                .result(b"FcmPXxOeYHtFd8nP5iiNIy4UWs0wUqDIo8orcO6R6g==")
                .is_ok()
        );
        let rejected = request
            .result(br#"{"code":-6,"message":"Example cloud rejection"}"#)
            .unwrap_err();
        assert!(rejected.to_string().contains("code -6"));
        assert!(rejected.to_string().contains("Example cloud rejection"));
        let multiline = request
            .result(br#"{"code":3,"message":"bad\nmessage"}"#)
            .unwrap_err();
        assert!(!multiline.to_string().contains('\n'));
    }
}
