use std::fmt;
use std::io;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use url::Url;
use windows::Data::Json::{JsonObject, JsonValue};
use windows::core::HSTRING;

use super::{Apartment, check_cancellation};

mod cloud_api;
mod https;
mod registration_api;

pub(crate) use registration_api::{CloudAuthorization, CloudDeviceId};

const ACCOUNT_BOOTSTRAP: &str = "https://account.xiaomi.com/longPolling/loginUrl";
const SESSION_CALLBACK: &str = "https://sts.api.io.mi.com/sts";
const ACCOUNT_SERVICE: &str = "xiaomiio";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SIGN_IN_WINDOW: Duration = Duration::from_secs(300);

/// A short-lived sign-in link on Xiaomi's account service.
pub struct XiaomiSignInLink(Url);

/// Presents Xiaomi's browser link and tracks cancellation during scale setup.
pub trait ScaleSetupInteraction {
    fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink);

    fn setup_cancelled(&mut self) -> bool {
        false
    }
}

impl fmt::Display for XiaomiSignInLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Tests browser sign-in to Xiaomi's smart-home account service.
///
/// The caller presents the login link. The function waits for Xiaomi to finish
/// authorization, then verifies that its callback issued a service session.
pub fn verify_xiaomi_sign_in(interaction: &mut dyn ScaleSetupInteraction) -> io::Result<()> {
    EuropeSession::sign_in(interaction).map(|_| ())
}

/// Uses browser sign-in to check the account's access to Xiaomi's Europe API.
/// The check reads the account's device count and discards it.
pub fn verify_xiaomi_cloud_europe(interaction: &mut dyn ScaleSetupInteraction) -> io::Result<()> {
    EuropeSession::sign_in(interaction)?.verify_device_count()
}

pub(crate) struct EuropeSession {
    client: Box<dyn https::RequestSession>,
    account: CloudAccount,
    _apartment: Apartment,
}

impl EuropeSession {
    pub(crate) fn sign_in(interaction: &mut dyn ScaleSetupInteraction) -> io::Result<Self> {
        check_cancellation(interaction)?;
        let apartment = Apartment::initialize()?;
        let client = Box::new(https::Session::new()?);
        Self::authorize(client, interaction, apartment)
    }

    fn authorize(
        client: Box<dyn https::RequestSession>,
        interaction: &mut dyn ScaleSetupInteraction,
        apartment: Apartment,
    ) -> io::Result<Self> {
        let account = sign_in(client.as_ref(), interaction)?;
        Ok(Self {
            client,
            account,
            _apartment: apartment,
        })
    }

    pub(crate) fn verify_device_count(&self) -> io::Result<()> {
        cloud_api::verify_device_count(self.client.as_ref(), &self.account)
    }

    fn request(&self, path: &str, data: &str) -> io::Result<JsonValue> {
        cloud_api::signed_request(self.client.as_ref(), &self.account, path, data)
    }
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
    client: &dyn https::RequestSession,
    interaction: &mut dyn ScaleSetupInteraction,
) -> io::Result<CloudAccount> {
    let bootstrap = client
        .get(&bootstrap_url()?, REQUEST_TIMEOUT)
        .map_err(|error| request_error("start Xiaomi sign-in", error))?;
    bootstrap.require_ok("sign-in request")?;
    let challenge = Challenge::parse(&bootstrap.body)?;
    let deadline = Instant::now() + challenge.valid_for;
    check_cancellation(interaction)?;
    interaction.present_xiaomi_sign_in(&challenge.link);

    let authorization = wait_for_authorization(client, &challenge.poll, deadline, interaction)?;
    check_cancellation(interaction)?;
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
    client: &dyn https::RequestSession,
    poll: &Url,
    deadline: Instant,
    interaction: &mut dyn ScaleSetupInteraction,
) -> io::Result<Authorization> {
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        check_cancellation(interaction)?;
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
    check_cancellation(interaction)?;
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

#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
pub fn fixture_sign_in_link() -> Result<XiaomiSignInLink, url::ParseError> {
    Url::parse("https://account.xiaomi.com/longPolling/login?ticket=fixture").map(XiaomiSignInLink)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use reqwest::header::{COOKIE, HeaderMap};

    use super::*;
    use crate::BluetoothAddress;

    const CHALLENGE: &[u8] = br#"&&&START&&&{
        "loginUrl":"https://ak.account.xiaomi.com/longPolling/login?ticket=test",
        "lp":"https://lp.account.xiaomi.com/longPolling/login?ticket=test",
        "timeout":60
    }"#;
    const AUTHORIZED: &[u8] = br#"{"ssecurity":"dGVzdA==","userId":1234,
        "location":"https://sts.api.io.mi.com/sts?ticket=test"}"#;

    struct Exchange(&'static str, io::Result<https::Response>);
    struct Script(RefCell<VecDeque<Exchange>>);

    impl Script {
        fn new(exchanges: impl IntoIterator<Item = Exchange>) -> Self {
            Self(RefCell::new(exchanges.into_iter().collect()))
        }

        fn take(&self, url: &Url) -> io::Result<https::Response> {
            let Exchange(path, result) = self.0.borrow_mut().pop_front().unwrap();
            assert_eq!(url.path(), path);
            result
        }
    }

    impl https::RequestSession for Script {
        fn get(&self, url: &Url, timeout: Duration) -> io::Result<https::Response> {
            assert!(!timeout.is_zero() && timeout <= REQUEST_TIMEOUT);
            if url.path() == "/longPolling/loginUrl" {
                assert_eq!(url.host_str(), Some("account.xiaomi.com"));
                assert!(
                    url.query_pairs()
                        .any(|(key, val)| key == "sid" && val == "xiaomiio")
                );
            }
            self.take(url)
        }

        fn post_form(
            &self,
            url: &Url,
            headers: HeaderMap,
            body: &str,
            timeout: Duration,
        ) -> io::Result<https::Response> {
            assert_eq!(url.host_str(), Some("de.api.io.mi.com"));
            assert_eq!(timeout, REQUEST_TIMEOUT);
            assert!(headers[COOKIE].is_sensitive());
            assert_eq!(
                headers[COOKIE],
                "userId=1234; serviceToken=session-fixture; yetAnotherServiceToken=session-fixture; locale=en_GB"
            );
            assert!(
                url::form_urlencoded::parse(body.as_bytes()).any(|(key, _)| key == "signature")
            );
            self.take(url)
        }
    }

    #[derive(Default)]
    struct Browser {
        links: Vec<String>,
        cancel_after_link: bool,
    }

    impl ScaleSetupInteraction for Browser {
        fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink) {
            self.links.push(link.to_string());
        }

        fn setup_cancelled(&mut self) -> bool {
            self.cancel_after_link && !self.links.is_empty()
        }
    }

    fn reply(path: &'static str, status: u16, body: &[u8]) -> Exchange {
        Exchange(
            path,
            Ok(https::Response {
                status,
                body: body.to_vec(),
                service_token: None,
            }),
        )
    }

    pub(crate) fn fixture_session(replies: &[(&'static str, u16, &[u8])]) -> EuropeSession {
        EuropeSession {
            client: Box::new(Script::new(
                replies
                    .iter()
                    .map(|(path, status, body)| reply(path, *status, body)),
            )),
            account: CloudAccount {
                user_id: Some("1234".into()),
                security: "dGVzdA==".into(),
                service_token: "session-fixture".into(),
            },
            _apartment: Apartment::initialize().unwrap(),
        }
    }

    #[test]
    fn reuses_the_browser_session_for_multiple_signed_cloud_requests() {
        let mut browser = Browser::default();
        let authorization = format!(
            r#"{{"code":0,"result":{{"success":true,"cloud_cert":"MA","cloud_sign":"{}","utc":1234}}}}"#,
            <base64ct::Base64 as base64ct::Encoding>::encode_string(&[3; 64]),
        );
        let script = Script::new([
            reply("/longPolling/loginUrl", 200, CHALLENGE),
            reply("/longPolling/login", 202, b""),
            reply("/longPolling/login", 200, AUTHORIZED),
            Exchange(
                "/sts",
                Ok(https::Response {
                    status: 302,
                    body: Vec::new(),
                    service_token: Some("session-fixture".into()),
                }),
            ),
            reply(
                "/app/v2/user/get_device_cnt",
                200,
                br#"{"code":0,"result":1}"#,
            ),
            reply(
                "/app/device/bltapplydid",
                200,
                br#"{"code":0,"result":{"did":"blt.1.fixture"}}"#,
            ),
            reply(
                "/app/v2/device/ble_standard_bind",
                200,
                authorization.as_bytes(),
            ),
            reply(
                "/app/v2/home/device_list_page",
                200,
                br#"{"code":0,"result":{"list":[{"did":"blt.1.fixture"}]}}"#,
            ),
        ]);
        let session = EuropeSession::authorize(
            Box::new(script),
            &mut browser,
            Apartment::initialize().unwrap(),
        )
        .unwrap();
        assert_eq!(
            browser.links,
            ["https://ak.account.xiaomi.com/longPolling/login?ticket=test"]
        );
        session.verify_device_count().unwrap();
        let id = session
            .allocate_device_id(BluetoothAddress(1), "token-fixture", None)
            .unwrap();
        assert_eq!(id.as_str(), "blt.1.fixture");
        let authorization = session
            .authorize_standard_registration(&id, "token-fixture", "key-fixture")
            .unwrap();
        assert_eq!(authorization.certificate, [0x30]);
        assert_eq!(authorization.signature, [3; 64]);
        assert!(session.lists_device(&id).unwrap());
    }

    #[test]
    fn distinguishes_bootstrap_polling_callback_and_cancellation_errors() {
        let _apartment = Apartment::initialize().unwrap();
        for (mut browser, exchanges, kind, expected) in [
            (
                Browser::default(),
                vec![reply("/longPolling/loginUrl", 503, b"")],
                io::ErrorKind::Other,
                "HTTP 503",
            ),
            (
                Browser::default(),
                vec![
                    reply("/longPolling/loginUrl", 200, CHALLENGE),
                    reply("/longPolling/login", 403, b""),
                ],
                io::ErrorKind::Other,
                "HTTP 403",
            ),
            (
                Browser::default(),
                vec![
                    reply("/longPolling/loginUrl", 200, CHALLENGE),
                    reply("/longPolling/login", 200, AUTHORIZED),
                    reply("/sts", 200, b""),
                ],
                io::ErrorKind::Other,
                "did not issue",
            ),
            (
                Browser {
                    cancel_after_link: true,
                    ..Browser::default()
                },
                vec![reply("/longPolling/loginUrl", 200, CHALLENGE)],
                io::ErrorKind::Interrupted,
                "interrupted",
            ),
        ] {
            let script = Script::new(exchanges);
            let error = sign_in(&script, &mut browser).err().unwrap();
            assert_eq!(error.kind(), kind);
            assert!(error.to_string().contains(expected), "{error}");
            assert!(script.0.borrow().is_empty());
        }
        let url = account_url("https://account.xiaomi.com/poll").unwrap();
        let error = wait_for_authorization(
            &Script::new([]),
            &url,
            Instant::now() - Duration::from_millis(1),
            &mut Browser::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn parses_xiaomi_browser_challenge() {
        let _apartment = Apartment::initialize().unwrap();
        let challenge = Challenge::parse(CHALLENGE).unwrap();
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
