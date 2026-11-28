use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use xiaomi_s200::{
    GattServiceUuid, RegisteredScale, RegistrationObserver, SavedScaleLogins, Scale, ScaleBindKey,
    ScaleLoginToken, ScaleScanObserver, ScaleSetupInteraction, SetupCertificateReply,
    SetupCheckObserver, SetupProfile, WeightSessionObserver,
};

pub(super) enum AccountCheck {
    SignIn,
    EuropeApi,
}

pub(super) enum ScaleSelection {
    Connectable,
    Unregistered,
}

pub(super) trait ScaleOperations {
    fn find_scale(&self, duration: Duration, selection: ScaleSelection) -> io::Result<Scale>;
    fn services(&self, scale: &Scale) -> io::Result<Vec<GattServiceUuid>>;
    fn logins(&self) -> io::Result<SavedScaleLogins>;
    fn bind_key(&self) -> io::Result<Option<ScaleBindKey>>;
    fn scan(
        &self,
        duration: Duration,
        key: Option<&ScaleBindKey>,
        observer: &mut dyn ScaleScanObserver,
    ) -> io::Result<()>;
    fn read_weight(
        &self,
        scale: &Scale,
        token: &ScaleLoginToken,
        duration: Duration,
        observer: &mut dyn WeightSessionObserver,
    ) -> io::Result<()>;
    fn check_setup(&self, duration: Duration, observer: &mut dyn SetupCheckObserver);
    fn sign_in(
        &self,
        interaction: &mut dyn ScaleSetupInteraction,
        check: AccountCheck,
    ) -> io::Result<()>;
    fn credentials_directory(&self) -> io::Result<PathBuf>;
    fn profile(&self, scale: &Scale) -> io::Result<SetupProfile>;
    fn register(
        &self,
        duration: Duration,
        directory: &Path,
        observer: &mut dyn RegistrationObserver,
    ) -> io::Result<RegisteredScale>;
    fn test_certificate(
        &self,
        scale: &Scale,
        directory: &Path,
    ) -> io::Result<SetupCertificateReply>;
}

#[cfg(windows)]
pub(super) struct WindowsScale;

#[cfg(windows)]
impl ScaleOperations for WindowsScale {
    fn find_scale(&self, duration: Duration, selection: ScaleSelection) -> io::Result<Scale> {
        match selection {
            ScaleSelection::Connectable => xiaomi_s200::find_connectable_scale(duration),
            ScaleSelection::Unregistered => xiaomi_s200::find_registration_scale(duration),
        }
    }

    fn services(&self, scale: &Scale) -> io::Result<Vec<GattServiceUuid>> {
        xiaomi_s200::read_services(scale)
    }

    fn logins(&self) -> io::Result<SavedScaleLogins> {
        SavedScaleLogins::load_default()
    }

    fn bind_key(&self) -> io::Result<Option<ScaleBindKey>> {
        ScaleBindKey::from_environment()
    }

    fn scan(
        &self,
        duration: Duration,
        key: Option<&ScaleBindKey>,
        observer: &mut dyn ScaleScanObserver,
    ) -> io::Result<()> {
        match key {
            Some(key) => xiaomi_s200::discover_scales_with_weight(duration, key, observer),
            None => xiaomi_s200::discover_scales(duration, observer),
        }
    }

    fn read_weight(
        &self,
        scale: &Scale,
        token: &ScaleLoginToken,
        duration: Duration,
        observer: &mut dyn WeightSessionObserver,
    ) -> io::Result<()> {
        xiaomi_s200::listen_for_connected_weight(scale, token, duration, observer)
    }

    fn check_setup(&self, duration: Duration, observer: &mut dyn SetupCheckObserver) {
        xiaomi_s200::check_scale_setup(duration, observer);
    }

    fn sign_in(
        &self,
        interaction: &mut dyn ScaleSetupInteraction,
        check: AccountCheck,
    ) -> io::Result<()> {
        match check {
            AccountCheck::SignIn => xiaomi_s200::verify_xiaomi_sign_in(interaction),
            AccountCheck::EuropeApi => xiaomi_s200::verify_xiaomi_cloud_europe(interaction),
        }
    }

    fn credentials_directory(&self) -> io::Result<PathBuf> {
        xiaomi_s200::default_registration_directory()
    }

    fn profile(&self, scale: &Scale) -> io::Result<SetupProfile> {
        xiaomi_s200::probe_setup_profile(scale)
    }

    fn register(
        &self,
        duration: Duration,
        directory: &Path,
        observer: &mut dyn RegistrationObserver,
    ) -> io::Result<RegisteredScale> {
        xiaomi_s200::register_scale_europe(duration, directory, observer)
    }

    fn test_certificate(
        &self,
        scale: &Scale,
        directory: &Path,
    ) -> io::Result<SetupCertificateReply> {
        xiaomi_s200::send_setup_test_certificate(scale, directory)
    }
}
