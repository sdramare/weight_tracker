use std::{
    cell::Cell,
    io,
    path::{Path, PathBuf},
};

use xiaomi_s200::{
    GattServiceUuid, RegisteredScale, ScaleBindKey, ScaleLoginToken, SetupCertificateReply,
    SetupProfile,
    test_fixtures::{
        fixture_logins, fixture_profile, fixture_registration, fixture_sign_in_link, scale,
        with_weight,
    },
};

use super::*;

struct SimulatedScale {
    keys: bool,
    broadcast: bool,
    receives_packets: bool,
    certificate_reply: SetupCertificateReply,
    diagnose_error: bool,
    read_connected: Cell<bool>,
}

impl Default for SimulatedScale {
    fn default() -> Self {
        Self {
            keys: true,
            broadcast: false,
            receives_packets: true,
            certificate_reply: SetupCertificateReply::RegistrationSucceeded,
            diagnose_error: false,
            read_connected: Cell::default(),
        }
    }
}

impl ScaleOperations for SimulatedScale {
    fn find_scale(&self, duration: Duration, selection: ScaleSelection) -> io::Result<Scale> {
        assert_eq!(duration, Duration::from_secs(5));
        Ok(scale(
            1,
            true,
            matches!(selection, ScaleSelection::Connectable),
        ))
    }

    fn services(&self, scale: &Scale) -> io::Result<Vec<GattServiceUuid>> {
        assert!(scale.is_connectable());
        Ok(Vec::new())
    }

    fn logins(&self) -> io::Result<SavedScaleLogins> {
        if self.keys {
            Ok(fixture_logins(&scale(1, true, true)))
        } else {
            Err(io::Error::other("keys unavailable"))
        }
    }

    fn bind_key(&self) -> io::Result<Option<ScaleBindKey>> {
        if self.broadcast {
            "00112233445566778899aabbccddeeff".parse().map(Some)
        } else {
            Ok(None)
        }
    }

    fn scan(
        &self,
        duration: Duration,
        key: Option<&ScaleBindKey>,
        observer: &mut dyn ScaleScanObserver,
    ) -> io::Result<()> {
        assert_eq!(duration, Duration::from_secs(5));
        assert_eq!(key.is_some(), self.broadcast);
        if self.receives_packets {
            let scale = scale(1, !self.broadcast, true);
            let scale = if self.broadcast {
                with_weight(scale, Weight::from_hundredths_of_kg(7300))
            } else {
                scale
            };
            let _ = observer.scale_discovered(&scale, scale.weight());
        }
        Ok(())
    }

    fn read_weight(
        &self,
        scale: &Scale,
        _: &ScaleLoginToken,
        duration: Duration,
        observer: &mut dyn WeightSessionObserver,
    ) -> io::Result<()> {
        assert_eq!(duration, Duration::from_secs(5));
        assert!(scale.is_connectable());
        self.read_connected.set(true);
        let weight = Weight::from_hundredths_of_kg(7300);
        for event in [
            ConnectedWeightEvent::Ready,
            ConnectedWeightEvent::Reading(WeightReading::Live(weight)),
            ConnectedWeightEvent::Reading(WeightReading::Settled(weight)),
        ] {
            assert!(observer.on_weight_event(event).is_continue());
        }
        Ok(())
    }

    fn check_setup(&self, _: Duration, observer: &mut dyn SetupCheckObserver) {
        observer.report_setup_check(SetupCheck::ScaleDiscovery, SetupCheckStatus::Started);
        if self.diagnose_error {
            observer.report_setup_check(
                SetupCheck::ScaleDiscovery,
                SetupCheckStatus::Failed(&io::Error::other("no scale")),
            );
            observer.report_setup_check(
                SetupCheck::RegistrationReadiness,
                SetupCheckStatus::Skipped(SetupCheck::ScaleDiscovery),
            );
        } else {
            observer.report_setup_check(SetupCheck::ScaleDiscovery, SetupCheckStatus::Passed);
        }
        observer
            .present_xiaomi_sign_in(&fixture_sign_in_link().expect("valid fixture sign-in link"));
    }

    fn sign_in(
        &self,
        interaction: &mut dyn ScaleSetupInteraction,
        _: AccountCheck,
    ) -> io::Result<()> {
        interaction.present_xiaomi_sign_in(&fixture_sign_in_link().map_err(io::Error::other)?);
        Ok(())
    }

    fn credentials_directory(&self) -> io::Result<PathBuf> {
        Ok(PathBuf::from("fixture"))
    }

    fn profile(&self, _: &Scale) -> io::Result<SetupProfile> {
        Ok(fixture_profile(vec![2, 0, 0, 0]))
    }

    fn register(
        &self,
        duration: Duration,
        directory: &Path,
        observer: &mut dyn RegistrationObserver,
    ) -> io::Result<RegisteredScale> {
        assert_eq!(duration, Duration::from_secs(5));
        assert_eq!(directory, Path::new("fixture"));
        observer.present_xiaomi_sign_in(&fixture_sign_in_link().map_err(io::Error::other)?);
        observer.report_registration(RegistrationEvent::Started(RegistrationStep::ScaleDiscovery));
        observer.report_registration(RegistrationEvent::Passed(RegistrationStep::ScaleDiscovery));
        let path = directory.join("s200-fixture.confirmed.keys");
        observer.report_registration(RegistrationEvent::CredentialsSaved(&path));
        Ok(fixture_registration(scale(1, true, false).address(), path))
    }

    fn test_certificate(&self, scale: &Scale, _: &Path) -> io::Result<SetupCertificateReply> {
        assert!(scale.setup_info().is_some());
        Ok(self.certificate_reply)
    }
}

#[test]
fn runs_each_command_with_a_simulated_scale_and_account() {
    let fixture = SimulatedScale::default();
    for command in [
        Command::Services,
        Command::Weight,
        Command::SetupInfo,
        Command::SetupProfile,
        Command::SetupTestCertificate,
        Command::SetupCheck,
        Command::RegisterScale,
        Command::XiaomiSignIn,
        Command::XiaomiCloudCheck,
    ] {
        assert_eq!(run_with(5, command, &fixture), ExitCode::SUCCESS);
    }
    assert!(fixture.read_connected.get());
}

#[test]
fn honors_broadcast_only_weight_and_reports_missing_devices_or_credentials() {
    let broadcast = SimulatedScale {
        keys: false,
        broadcast: true,
        ..SimulatedScale::default()
    };
    assert_eq!(run_with(5, Command::Weight, &broadcast), ExitCode::SUCCESS);
    assert!(!broadcast.read_connected.get());
    let silent = SimulatedScale {
        receives_packets: false,
        diagnose_error: true,
        ..SimulatedScale::default()
    };
    for command in [Command::Weight, Command::SetupInfo, Command::SetupCheck] {
        assert_eq!(run_with(5, command, &silent), ExitCode::FAILURE);
    }
    let unconfigured = SimulatedScale {
        keys: false,
        ..SimulatedScale::default()
    };
    assert_eq!(
        show_weight(Duration::from_secs(5), &unconfigured)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn distinguishes_pending_and_rejected_test_certificate_results() {
    for (certificate_reply, expected) in [
        (
            SetupCertificateReply::ReceivedWithoutRegistrationResult,
            ExitCode::SUCCESS,
        ),
        (SetupCertificateReply::RegistrationFailed, ExitCode::FAILURE),
        (SetupCertificateReply::AlreadyRegistered, ExitCode::FAILURE),
    ] {
        let fixture = SimulatedScale {
            certificate_reply,
            ..SimulatedScale::default()
        };
        assert_eq!(
            run_with(5, Command::SetupTestCertificate, &fixture),
            expected
        );
    }
}
