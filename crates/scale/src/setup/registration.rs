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
use crate::{BluetoothAddress, ScaleSetupInteraction, check_cancellation};

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
    use RegistrationEvent::{Passed, Started};
    use RegistrationStep::{
        BluetoothKeyExchange, BrowserSignIn, EuropeApi, FinishSetup, ScaleDiscovery,
    };

    observer.report_registration(Started(BrowserSignIn));
    let session = EuropeSession::sign_in(observer);
    let session = complete_step(observer, BrowserSignIn, session)?;
    check_cancellation(observer)?;
    observer.report_registration(Started(EuropeApi));
    complete_step(observer, EuropeApi, session.verify_device_count())?;
    observer.report_registration(Started(ScaleDiscovery));
    let scale = find_registration_scale_with(scan_time, Some(observer))?;
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
    let (reply, credentials) = register_with(&scale, authorizer)?;

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

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use super::{RegistrationEvent, RegistrationObserver, RegistrationStep, register_scale_europe};
    use crate::{ScaleSetupInteraction, XiaomiSignInLink};

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
