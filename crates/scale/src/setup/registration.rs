use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::certificate_transfer::{
    RegistrationProof, SetupCertificateReply, finish_credentials, register_with,
};
use super::find_registration_scale_while;
use crate::cloud_sign_in::EuropeSession;
use crate::{BluetoothAddress, XiaomiSignInLink, check_cancellation};

/// A stage of cloud-backed S200 registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationStep {
    BrowserSignIn,
    EuropeApi,
    ScaleDiscovery,
    BluetoothKeyExchange,
    ReuseDeviceId,
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
            Self::ReuseDeviceId => "Use the Xiaomi device ID reported by the scale",
            Self::AllocateDeviceId => "Allocate the Xiaomi BLE device ID",
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
pub fn register_scale_europe(
    scan_time: Duration,
    credentials_directory: &Path,
    present_sign_in_link: impl FnOnce(&XiaomiSignInLink),
    report: impl FnMut(RegistrationEvent<'_>),
) -> io::Result<RegisteredScale> {
    register_scale_europe_while(
        scan_time,
        credentials_directory,
        || true,
        present_sign_in_link,
        report,
    )
}

/// Registers a scale, checking for cancellation through sign-in and discovery.
///
/// Once authorization is requested for the selected scale, finish the registration to
/// preserve the device's result and corresponding local credentials.
pub fn register_scale_europe_while(
    scan_time: Duration,
    credentials_directory: &Path,
    keep_going: impl Fn() -> bool,
    present_sign_in_link: impl FnOnce(&XiaomiSignInLink),
    mut report: impl FnMut(RegistrationEvent<'_>),
) -> io::Result<RegisteredScale> {
    use RegistrationEvent::{CredentialsSaved, Passed, Started};
    use RegistrationStep::{
        AllocateDeviceId, BluetoothKeyExchange, BrowserSignIn, EuropeApi, FinishSetup,
        RequestCertificate, ReuseDeviceId, ScaleDiscovery,
    };

    let session = run_step(&mut report, BrowserSignIn, || {
        EuropeSession::sign_in_while(&keep_going, present_sign_in_link)
    })?;
    check_cancellation(&keep_going)?;
    run_step(&mut report, EuropeApi, || session.verify_device_count())?;
    report(Started(ScaleDiscovery));
    let scale = find_registration_scale_while(scan_time, &keep_going)?;
    report(Passed(ScaleDiscovery));
    let address = scale.address();

    report(Started(BluetoothKeyExchange));
    check_cancellation(&keep_going)?;
    let (reply, credentials) = register_with(&scale, |registration, stored_device_id| {
        check_cancellation(&keep_going)?;
        report(Passed(BluetoothKeyExchange));
        let token = registration.login_token_hex();
        let bind_key = registration.bind_key_hex();
        let id_step = if stored_device_id.is_some() {
            ReuseDeviceId
        } else {
            AllocateDeviceId
        };
        let device_id = run_step(&mut report, id_step, || {
            stored_device_id.map_or_else(|| session.allocate_device_id(address, &token), Ok)
        })?;
        let authorization = run_step(&mut report, RequestCertificate, || {
            session.authorize_standard_registration(&device_id, &token, &bind_key)
        })?;
        let encrypted_id = registration.encrypted_cloud_identity(&device_id, &authorization)?;
        let credentials = registration
            .save_cloud_credentials(credentials_directory, &device_id, address)
            .map_err(|error| io::Error::new(error.kind(), format!("save S200 keys: {error}")))?;
        report(CredentialsSaved(&credentials));
        let proof = RegistrationProof {
            encrypted_id,
            certificate: authorization.certificate,
        };
        report(Started(FinishSetup));
        Ok((proof, credentials))
    })?;

    let credentials = finish_credentials(credentials, reply)?;
    match reply {
        SetupCertificateReply::RegistrationSucceeded => {}
        SetupCertificateReply::RegistrationFailed => {
            return Err(io::Error::other(
                "Xiaomi issued the setup authorization, but the scale rejected it (Bluetooth code 0x12). The scale gave no reason. The app marked this attempt’s keys as rejected.",
            ));
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
    report(Passed(FinishSetup));
    Ok(RegisteredScale {
        address,
        credentials,
    })
}

fn run_step<T>(
    report: &mut impl FnMut(RegistrationEvent<'_>),
    step: RegistrationStep,
    action: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    report(RegistrationEvent::Started(step));
    let result =
        action().map_err(|error| io::Error::new(error.kind(), format!("{step}: {error}")))?;
    report(RegistrationEvent::Passed(step));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use super::{RegistrationEvent, RegistrationStep, register_scale_europe_while};

    #[test]
    fn cancels_queued_setup_before_requesting_a_browser_link() {
        let mut sign_in_presented = false;
        let mut stages = Vec::new();
        let result = register_scale_europe_while(
            Duration::from_secs(30),
            Path::new("unused"),
            || false,
            |_| sign_in_presented = true,
            |event| {
                if let RegistrationEvent::Started(step) = event {
                    stages.push(step);
                }
            },
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
        assert!(!sign_in_presented);
        assert_eq!(stages, [RegistrationStep::BrowserSignIn]);
    }
}
