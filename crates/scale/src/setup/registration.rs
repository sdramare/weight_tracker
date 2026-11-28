use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::certificate_transfer::{
    RegistrationAuthorizer, RegistrationProof, SetupCertificateReply, finish_credentials,
    register_with,
};
use super::find_registration_scale_with;
use super::registration_crypto::Registration;
use crate::cloud_sign_in::{CloudDeviceId, EuropeSession};
use crate::{BluetoothAddress, Scale, ScaleSetupInteraction, check_cancellation};

/// A stage of cloud-backed S200 registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationStep {
    BrowserSignIn,
    EuropeApi,
    ScaleDiscovery,
    BluetoothKeyExchange,
    AllocateDeviceId,
    RequestCertificate,
    FinishSetup,
}

impl fmt::Display for RegistrationStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BrowserSignIn => "Xiaomi browser sign-in",
            Self::EuropeApi => "Xiaomi Europe API",
            Self::ScaleDiscovery => "Find the S200 over Bluetooth",
            Self::BluetoothKeyExchange => "Standard Auth Bluetooth key exchange",
            Self::AllocateDeviceId => "Apply for the Xiaomi BLE device ID",
            Self::RequestCertificate => "Request Xiaomi's signed Bluetooth authorization",
            Self::FinishSetup => "Send the Xiaomi certificate and wait for the scale to confirm",
        })
    }
}

/// Progress emitted by a single registration attempt.
#[derive(Clone, Copy, Debug)]
pub enum RegistrationEvent<'a> {
    Started(RegistrationStep),
    Passed(RegistrationStep),
    CredentialsSaved(&'a Path),
}

/// Receives registration progress and handles interaction during setup.
pub trait RegistrationObserver: ScaleSetupInteraction {
    fn report_registration(&mut self, event: RegistrationEvent<'_>);
}

/// An S200 that confirmed registration over Bluetooth.
pub struct RegisteredScale {
    address: BluetoothAddress,
    credentials: PathBuf,
}

impl RegisteredScale {
    pub fn address(&self) -> BluetoothAddress {
        self.address
    }

    pub fn credentials_file(&self) -> &Path {
        &self.credentials
    }
}

/// Registers the first awake, unregistered S200 ms113 using Xiaomi's Europe API.
/// The browser session is reused throughout the attempt. The device keys are
/// saved locally before binding so they survive an uncertain Bluetooth result.
///
/// Cancellation is checked through Bluetooth key exchange. Once cloud requests
/// begin for the selected scale, registration runs to completion.
pub fn register_scale_europe(
    scan_time: Duration,
    credentials_directory: &Path,
    observer: &mut dyn RegistrationObserver,
) -> io::Result<RegisteredScale> {
    run_registration(
        scan_time,
        credentials_directory,
        observer,
        &SystemRegistration,
    )
}

trait RegistrationServices {
    fn sign_in(&self, observer: &mut dyn RegistrationObserver) -> io::Result<EuropeSession>;
    fn find_scale(
        &self,
        scan_time: Duration,
        observer: &mut dyn RegistrationObserver,
    ) -> io::Result<Scale>;
    fn transfer(
        &self,
        scale: &Scale,
        authorizer: XiaomiRegistrationAuthorizer<'_>,
    ) -> io::Result<(SetupCertificateReply, PathBuf)>;
}

struct SystemRegistration;

impl RegistrationServices for SystemRegistration {
    fn sign_in(&self, observer: &mut dyn RegistrationObserver) -> io::Result<EuropeSession> {
        EuropeSession::sign_in(observer)
    }

    fn find_scale(
        &self,
        scan_time: Duration,
        observer: &mut dyn RegistrationObserver,
    ) -> io::Result<Scale> {
        find_registration_scale_with(scan_time, Some(observer))
    }

    fn transfer(
        &self,
        scale: &Scale,
        authorizer: XiaomiRegistrationAuthorizer<'_>,
    ) -> io::Result<(SetupCertificateReply, PathBuf)> {
        register_with(scale, authorizer)
    }
}

fn run_registration(
    scan_time: Duration,
    credentials_directory: &Path,
    observer: &mut dyn RegistrationObserver,
    services: &dyn RegistrationServices,
) -> io::Result<RegisteredScale> {
    use RegistrationEvent::{Passed, Started};
    use RegistrationStep::{
        BluetoothKeyExchange, BrowserSignIn, EuropeApi, FinishSetup, ScaleDiscovery,
    };

    observer.report_registration(Started(BrowserSignIn));
    let session = services.sign_in(observer);
    let session = complete_step(observer, BrowserSignIn, session)?;
    check_cancellation(observer)?;
    observer.report_registration(Started(EuropeApi));
    complete_step(observer, EuropeApi, session.verify_device_count())?;
    observer.report_registration(Started(ScaleDiscovery));
    let scale = services.find_scale(scan_time, observer)?;
    observer.report_registration(Passed(ScaleDiscovery));
    let address = scale.address();

    observer.report_registration(Started(BluetoothKeyExchange));
    check_cancellation(observer)?;
    let mut previous_device = None;
    let authorizer = XiaomiRegistrationAuthorizer {
        session: &session,
        address,
        credentials_directory,
        observer,
        previous_device: &mut previous_device,
    };
    let (reply, credentials) = services.transfer(&scale, authorizer)?;

    let credentials = finish_credentials(credentials, reply)?;
    match reply {
        SetupCertificateReply::RegistrationSucceeded => {}
        SetupCertificateReply::RegistrationFailed => {
            let mut message = String::from(
                "Xiaomi issued the setup authorization, but the scale rejected it (Bluetooth code 0x12). The scale gave no reason. The app marked this attempt’s keys as rejected.",
            );
            if let Some((device_id, different_id)) = previous_device {
                if different_id {
                    message.push_str(
                        " Xiaomi allocated a different device ID from the one the scale reported.",
                    );
                }
                let detail = match session.lists_device(&device_id) {
                    Ok(true) => {
                        " Xiaomi’s device list still shows the scale’s previous ID on this account."
                    }
                    Ok(false) => " Xiaomi’s device list did not return the ID the scale reported.",
                    Err(_) => {
                        " The app could not check the ID the scale reported in Xiaomi’s device list."
                    }
                };
                message.push_str(detail);
            }
            return Err(io::Error::other(message));
        }
        SetupCertificateReply::AlreadyRegistered => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The scale reports it is already paired (Bluetooth code 0xE1). Use its existing setup, or factory-reset it if you intend to pair it again.",
            ));
        }
        SetupCertificateReply::ReceivedWithoutRegistrationResult => {
            return Err(io::Error::other(format!(
                "The scale acknowledged the certificate transfer but did not confirm pairing. Candidate keys are saved in {}.",
                credentials.display()
            )));
        }
    }
    observer.report_registration(Passed(FinishSetup));
    Ok(RegisteredScale {
        address,
        credentials,
    })
}

struct XiaomiRegistrationAuthorizer<'a> {
    session: &'a EuropeSession,
    address: BluetoothAddress,
    credentials_directory: &'a Path,
    observer: &'a mut dyn RegistrationObserver,
    previous_device: &'a mut Option<(CloudDeviceId, bool)>,
}

impl RegistrationAuthorizer for XiaomiRegistrationAuthorizer<'_> {
    fn authorize_registration(
        self,
        registration: &Registration,
        stored_device_id: Option<CloudDeviceId>,
    ) -> io::Result<(RegistrationProof, PathBuf)> {
        use RegistrationEvent::{CredentialsSaved, Passed, Started};
        use RegistrationStep::{
            AllocateDeviceId, BluetoothKeyExchange, FinishSetup, RequestCertificate,
        };

        let Self {
            session,
            address,
            credentials_directory,
            observer,
            previous_device,
        } = self;
        check_cancellation(observer)?;
        observer.report_registration(Passed(BluetoothKeyExchange));
        let token = registration.login_token_hex();
        let bind_key = registration.bind_key_hex();
        observer.report_registration(Started(AllocateDeviceId));
        let device_id = complete_step(
            observer,
            AllocateDeviceId,
            session.allocate_device_id(address, &token, stored_device_id.as_ref()),
        )?;
        *previous_device = stored_device_id.map(|previous| {
            let different_id = previous.as_str() != device_id.as_str();
            (previous, different_id)
        });
        observer.report_registration(Started(RequestCertificate));
        let authorization = complete_step(
            observer,
            RequestCertificate,
            session.authorize_standard_registration(&device_id, &token, &bind_key),
        )?;
        let encrypted_id = registration.encrypted_cloud_identity(&device_id, &authorization)?;
        let credentials = registration
            .save_cloud_credentials(credentials_directory, &device_id, address)
            .map_err(|error| io::Error::new(error.kind(), format!("save S200 keys: {error}")))?;
        observer.report_registration(CredentialsSaved(&credentials));
        let proof = RegistrationProof {
            encrypted_id,
            certificate: authorization.certificate,
        };
        observer.report_registration(Started(FinishSetup));
        Ok((proof, credentials))
    }
}

fn complete_step<T>(
    observer: &mut dyn RegistrationObserver,
    step: RegistrationStep,
    result: io::Result<T>,
) -> io::Result<T> {
    let result =
        result.map_err(|error| io::Error::new(error.kind(), format!("{step}: {error}")))?;
    observer.report_registration(RegistrationEvent::Passed(step));
    Ok(result)
}

#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
pub fn fixture_registration(address: BluetoothAddress, credentials: PathBuf) -> RegisteredScale {
    RegisteredScale {
        address,
        credentials,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64ct::{Base64, Encoding};

    use super::*;
    use crate::cloud_sign_in::tests::fixture_session;
    use crate::setup::registration_crypto::RegistrationKeys;
    use crate::{ScaleSetupInfo, SignalStrength, XiaomiSignInLink};

    #[derive(Default)]
    struct Progress {
        started: Vec<RegistrationStep>,
        passed: Vec<RegistrationStep>,
        pending: Option<PathBuf>,
    }

    impl ScaleSetupInteraction for Progress {
        fn present_xiaomi_sign_in(&mut self, _: &XiaomiSignInLink) {}
    }

    impl RegistrationObserver for Progress {
        fn report_registration(&mut self, event: RegistrationEvent<'_>) {
            match event {
                RegistrationEvent::Started(step) => self.started.push(step),
                RegistrationEvent::Passed(step) => self.passed.push(step),
                RegistrationEvent::CredentialsSaved(path) => self.pending = Some(path.into()),
            }
        }
    }

    struct Fixture(SetupCertificateReply);

    impl RegistrationServices for Fixture {
        fn sign_in(&self, _: &mut dyn RegistrationObserver) -> io::Result<EuropeSession> {
            let certificate = format!(
                r#"{{"code":0,"result":{{"success":true,"cloud_cert":"MA","cloud_sign":"{}","utc":1234}}}}"#,
                Base64::encode_string(&[3; 64]),
            );
            Ok(fixture_session(&[
                (
                    "/app/v2/user/get_device_cnt",
                    200,
                    br#"{"code":0,"result":0}"#,
                ),
                (
                    "/app/device/bltapplydid",
                    200,
                    br#"{"code":0,"result":"blt.fixture-new"}"#,
                ),
                (
                    "/app/v2/device/ble_standard_bind",
                    200,
                    certificate.as_bytes(),
                ),
                (
                    "/app/v2/home/device_list_page",
                    200,
                    br#"{"code":0,"result":{"list":[{"did":"blt.fixture-old"}]}}"#,
                ),
            ]))
        }

        fn find_scale(
            &self,
            scan_time: Duration,
            _: &mut dyn RegistrationObserver,
        ) -> io::Result<Scale> {
            assert_eq!(scan_time, Duration::from_secs(5));
            Ok(Scale {
                address: BluetoothAddress(7),
                address_type: None,
                name: None,
                signal_strength: SignalStrength(-60),
                connectable: true,
                weight: None,
                setup_info: ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x58, 0xcb, 0x4d]),
            })
        }

        fn transfer(
            &self,
            scale: &Scale,
            authorizer: XiaomiRegistrationAuthorizer<'_>,
        ) -> io::Result<(SetupCertificateReply, PathBuf)> {
            assert_eq!(scale.address(), BluetoothAddress(7));
            let peer = RegistrationKeys::generate()?;
            let registration = RegistrationKeys::generate()?.finish(peer.public_key())?;
            let (proof, path) = authorizer.authorize_registration(
                &registration,
                CloudDeviceId::from_scale_field(b"blt.fixture-old")?,
            )?;
            assert_eq!(proof.certificate, [0x30]);
            assert_eq!(proof.encrypted_id.len(), 92);
            assert!(path.is_file());
            Ok((self.0, path))
        }
    }

    #[test]
    fn reports_each_stage_and_keeps_credentials_in_the_state_confirmed_by_the_scale() {
        use RegistrationStep::*;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "s200-registration-fixture-{}-{nonce}",
            std::process::id()
        ));
        let stages = [
            BrowserSignIn,
            EuropeApi,
            ScaleDiscovery,
            BluetoothKeyExchange,
            AllocateDeviceId,
            RequestCertificate,
            FinishSetup,
        ];
        for (index, (reply, suffix, message)) in [
            (
                SetupCertificateReply::RegistrationSucceeded,
                ".confirmed.keys",
                None,
            ),
            (
                SetupCertificateReply::RegistrationFailed,
                ".rejected.keys",
                Some("device list still shows"),
            ),
            (
                SetupCertificateReply::AlreadyRegistered,
                ".rejected.keys",
                Some("already paired"),
            ),
            (
                SetupCertificateReply::ReceivedWithoutRegistrationResult,
                ".pending.keys",
                Some("did not confirm"),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = root.join(index.to_string());
            let mut observer = Progress::default();
            let result = run_registration(
                Duration::from_secs(5),
                &directory,
                &mut observer,
                &Fixture(reply),
            );
            assert_eq!(observer.started, stages);
            assert!(
                observer
                    .pending
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".pending.keys")
            );
            let entry = fs::read_dir(&directory).unwrap().next().unwrap().unwrap();
            assert!(entry.file_name().to_string_lossy().ends_with(suffix));
            assert!(
                fs::read_to_string(entry.path())
                    .unwrap()
                    .contains("bluetooth_address=00:00:00:00:00:07")
            );
            if let Some(message) = message {
                let error = result.err().unwrap().to_string();
                assert!(error.contains(message), "{error}");
                assert_eq!(observer.passed, stages[..6]);
                if reply == SetupCertificateReply::RegistrationFailed {
                    assert!(error.contains("different device ID"));
                }
            } else {
                let registered = result.unwrap();
                assert_eq!(registered.address(), BluetoothAddress(7));
                assert_eq!(registered.credentials_file(), entry.path());
                assert_eq!(observer.passed, stages);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancels_queued_setup_before_requesting_a_browser_link() {
        #[derive(Default)]
        struct CancelledSetup {
            sign_in_presented: bool,
            stages: Vec<RegistrationStep>,
        }

        impl ScaleSetupInteraction for CancelledSetup {
            fn present_xiaomi_sign_in(&mut self, _: &XiaomiSignInLink) {
                self.sign_in_presented = true;
            }

            fn setup_cancelled(&mut self) -> bool {
                true
            }
        }

        impl RegistrationObserver for CancelledSetup {
            fn report_registration(&mut self, event: RegistrationEvent<'_>) {
                if let RegistrationEvent::Started(step) = event {
                    self.stages.push(step);
                }
            }
        }

        let mut observer = CancelledSetup::default();
        let result =
            register_scale_europe(Duration::from_secs(30), Path::new("unused"), &mut observer);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
        assert!(!observer.sign_in_presented);
        assert_eq!(observer.stages, [RegistrationStep::BrowserSignIn]);
    }
}
