use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::certificate_transfer::{
    RegistrationProof, SetupCertificateReply, finish_credentials, register_with,
};
use super::find_registration_scale;
use crate::cloud_sign_in::EuropeSession;
use crate::{BluetoothAddress, XiaomiSignInLink};

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
            Self::ScaleDiscovery => "Find an unregistered S200 ms113",
            Self::BluetoothKeyExchange => "Standard Auth Bluetooth key exchange",
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
    mut report: impl FnMut(RegistrationEvent<'_>),
) -> io::Result<RegisteredScale> {
    use RegistrationEvent::{CredentialsSaved, Passed, Started};
    use RegistrationStep::{
        AllocateDeviceId, BluetoothKeyExchange, BrowserSignIn, EuropeApi, FinishSetup,
        RequestCertificate, ScaleDiscovery,
    };

    let session = run_step(&mut report, BrowserSignIn, || {
        EuropeSession::sign_in(present_sign_in_link)
    })?;
    run_step(&mut report, EuropeApi, || session.verify_device_count())?;
    let scale = run_step(&mut report, ScaleDiscovery, || {
        find_registration_scale(scan_time)
    })?;
    let address = scale.address();

    report(Started(BluetoothKeyExchange));
    let (reply, credentials) = register_with(&scale, |registration| {
        report(Passed(BluetoothKeyExchange));
        let token = registration.login_token_hex();
        let bind_key = registration.bind_key_hex();
        let device_id = run_step(&mut report, AllocateDeviceId, || {
            session.allocate_device_id(address, &token)
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
    if reply != SetupCertificateReply::RegistrationSucceeded {
        return Err(io::Error::other(format!(
            "{reply}. Candidate keys are saved in {}",
            credentials.display()
        )));
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
