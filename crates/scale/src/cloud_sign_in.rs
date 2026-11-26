use std::fmt;
use std::io;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use url::Url;
use windows::Data::Json::JsonObject;
use windows::core::HSTRING;

use super::Apartment;

mod cloud_api;
mod https;

const ACCOUNT_BOOTSTRAP: &str = "https://account.xiaomi.com/longPolling/loginUrl";
const SESSION_CALLBACK: &str = "https://sts.api.io.mi.com/sts";
const ACCOUNT_SERVICE: &str = "xiaomiio";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SIGN_IN_WINDOW: Duration = Duration::from_secs(300);

/// A short-lived sign-in link on Xiaomi's account service.
pub struct XiaomiSignInLink(Url);

impl fmt::Display for XiaomiSignInLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Tests browser sign-in to Xiaomi's smart-home account service.
///
/// The caller presents the login link. The function waits for Xiaomi to finish
/// authorization, then verifies that its callback issued a service session.
pub fn verify_xiaomi_sign_in(present: impl FnOnce(&XiaomiSignInLink)) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let client = https::Session::new()?;
    sign_in(&client, present).map(|_| ())
}

/// Uses browser sign-in to check the account's access to Xiaomi's Europe API.
/// The check reads the account's device count and discards it.
pub fn verify_xiaomi_cloud_europe(present: impl FnOnce(&XiaomiSignInLink)) -> io::Result<()> {
    check_xiaomi_cloud_europe(present, || {})
}

pub(super) fn check_xiaomi_cloud_europe(
    present: impl FnOnce(&XiaomiSignInLink),
    on_signed_in: impl FnOnce(),
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let client = https::Session::new()?;
    let account = sign_in(&client, present)?;
    on_signed_in();
    cloud_api::verify_device_count(&client, &account)
}

struct CloudAccount {
    user_id: Option<String>,
    security: String,
    service_token: String,
}

struct Authorization {
    callback: Url,
    user_id: Option<String>,
    security: String,
}

fn sign_in(
    client: &https::Session,
    present: impl FnOnce(&XiaomiSignInLink),
) -> io::Result<CloudAccount> {
    let bootstrap = client
        .get(&bootstrap_url()?, REQUEST_TIMEOUT)
        .map_err(|error| request_error("start Xiaomi sign-in", error))?;
    bootstrap.require_ok("sign-in request")?;
    let challenge = Challenge::parse(&bootstrap.body)?;
    let deadline = Instant::now() + challenge.valid_for;
    present(&challenge.link);

    let authorization = wait_for_authorization(client, &challenge.poll, deadline)?;
    let session = client
        .get(&authorization.callback, REQUEST_TIMEOUT)
        .map_err(|error| request_error("complete Xiaomi sign-in", error))?;
    let service_token = session.service_token.ok_or_else(|| {
        io::Error::other("Xiaomi's sign-in callback did not issue a smart-home service session")
    })?;
    Ok(CloudAccount {
        user_id: authorization.user_id,
        security: authorization.security,
        service_token,
    })
}

struct Challenge {
    link: XiaomiSignInLink,
    poll: Url,
    valid_for: Duration,
}

impl Challenge {
    fn parse(body: &[u8]) -> io::Result<Self> {
        let json = xiaomi_json(body)?;
        let browser = json
            .GetNamedString(&HSTRING::from("loginUrl"))
            .map_err(|_| {
                invalid_response("Xiaomi's response did not include a browser sign-in link")
            })?;
        let poll = json.GetNamedString(&HSTRING::from("lp")).map_err(|_| {
            invalid_response("Xiaomi's response did not include a sign-in polling link")
        })?;
        let seconds = json
            .GetNamedNumber(&HSTRING::from("timeout"))
            .map_err(|_| {
                invalid_response("Xiaomi's response did not include a sign-in lifetime")
            })?;
        if !seconds.is_finite() || seconds < 1.0 {
            return Err(invalid_response(
                "Xiaomi returned an invalid sign-in lifetime",
            ));
        }
        let valid_for = Duration::from_secs_f64(seconds.min(MAX_SIGN_IN_WINDOW.as_secs_f64()));
        Ok(Self {
            link: XiaomiSignInLink(account_url(&browser.to_string_lossy())?),
            poll: account_url(&poll.to_string_lossy())?,
            valid_for,
        })
    }
}

fn wait_for_authorization(
    client: &https::Session,
    poll: &Url,
    deadline: Instant,
) -> io::Result<Authorization> {
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match client.get(poll, remaining.min(REQUEST_TIMEOUT)) {
            Ok(response) if response.status == 200 => {
                return authorized_callback(&response.body);
            }
            Ok(response) if matches!(response.status, 202 | 204 | 408 | 504) => {}
            Ok(response) => {
                return Err(io::Error::other(format!(
                    "Xiaomi's sign-in check returned HTTP {}",
                    response.status,
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => return Err(request_error("check Xiaomi sign-in", error)),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(400)));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the Xiaomi sign-in link expired",
    ))
}

fn authorized_callback(body: &[u8]) -> io::Result<Authorization> {
    let json = xiaomi_json(body)?;
    let security = json
        .GetNamedString(&HSTRING::from("ssecurity"))
        .map_err(|_| invalid_response("Xiaomi did not grant the requested smart-home session"))?;
    if security.is_empty() {
        return Err(invalid_response("Xiaomi returned empty session material"));
    }
    let value = json
        .GetNamedString(&HSTRING::from("location"))
        .map_err(|_| invalid_response("Xiaomi did not provide the session callback"))?;
    let url = secure_url(&value.to_string_lossy())?;
    if url.host_str() != Some("sts.api.io.mi.com") || url.path() != "/sts" {
        return Err(invalid_response(
            "Xiaomi returned an unexpected session callback",
        ));
    }
    let user_id_key = HSTRING::from("userId");
    let user_id = json
        .GetNamedString(&user_id_key)
        .or_else(|_| json.GetNamedValue(&user_id_key)?.Stringify())
        .ok()
        .map(|value| value.to_string_lossy())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    Ok(Authorization {
        callback: url,
        user_id,
        security: security.to_string_lossy(),
    })
}

fn xiaomi_json(body: &[u8]) -> io::Result<JsonObject> {
    let text = std::str::from_utf8(body)
        .map_err(|_| invalid_response("Xiaomi returned a response with invalid text encoding"))?;
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let text = text.strip_prefix("&&&START&&&").unwrap_or(text).trim();
    JsonObject::Parse(&HSTRING::from(text))
        .map_err(|_| invalid_response("Xiaomi returned an unexpected sign-in response"))
}

fn bootstrap_url() -> io::Result<Url> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("the PC clock is earlier than the Unix epoch"))?
        .as_millis()
        .to_string();
    let mut url = secure_url(ACCOUNT_BOOTSTRAP)?;
    url.query_pairs_mut().extend_pairs([
        ("_qrsize", "480"),
        ("qs", "%3Fsid%3Dxiaomiio%26_json%3Dtrue"),
        ("callback", SESSION_CALLBACK),
        ("_hasLogo", "false"),
        ("sid", ACCOUNT_SERVICE),
        ("serviceParam", ""),
        ("_locale", "en_GB"),
        ("_dc", &milliseconds),
    ]);
    Ok(url)
}

fn account_url(value: &str) -> io::Result<Url> {
    let url = secure_url(value)?;
    let trusted = url.host_str().is_some_and(|host| {
        ["account.xiaomi.com", "account.mi.com"].iter().any(|root| {
            host == *root
                || host
                    .strip_suffix(root)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    });
    if !trusted {
        return Err(invalid_response(
            "Xiaomi returned a sign-in link outside its account service",
        ));
    }
    Ok(url)
}

fn secure_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid_response("Xiaomi returned an invalid URL"))?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid_response(
            "Xiaomi returned an unexpected sign-in URL",
        ));
    }
    Ok(url)
}

fn invalid_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn request_error(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("could not {stage}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{Apartment, Challenge, account_url, authorized_callback};

    #[test]
    fn parses_xiaomi_browser_challenge() {
        let _apartment = Apartment::initialize().unwrap();
        let challenge = Challenge::parse(
            br#"&&&START&&&{
            "loginUrl":"https://ak.account.xiaomi.com/longPolling/login?ticket=test",
            "lp":"https://lp.account.xiaomi.com/longPolling/login?ticket=test",
            "timeout":60
        }"#,
        )
        .unwrap();
        assert_eq!(challenge.valid_for.as_secs(), 60);
        assert_eq!(challenge.poll.host_str(), Some("lp.account.xiaomi.com"));
    }

    #[test]
    fn validates_the_destinations_of_sign_in_and_session_urls() {
        let _apartment = Apartment::initialize().unwrap();
        assert!(account_url("https://untrusted.test/account.xiaomi.com").is_err());
        assert!(account_url("http://account.xiaomi.com/").is_err());
        assert!(
            authorized_callback(br#"{"ssecurity":"test","location":"https://untrusted.test/sts"}"#)
                .is_err()
        );
        assert!(
            authorized_callback(
                br#"{"ssecurity":"test","location":"https://sts.api.io.mi.com/sts?ticket=test"}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn reads_an_account_id_as_a_string_or_number() {
        let _apartment = Apartment::initialize().unwrap();
        for user_id in ["1234567890", r#""1234567890""#] {
            let response = format!(
                r#"{{"ssecurity":"test","userId":{user_id},"location":"https://sts.api.io.mi.com/sts"}}"#
            );
            let authorization = authorized_callback(response.as_bytes()).unwrap();
            assert_eq!(authorization.user_id.as_deref(), Some("1234567890"));
        }
    }
}
