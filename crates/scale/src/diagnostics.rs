use std::fmt;
use std::io;
use std::ops::ControlFlow;
use std::time::Duration;

use super::cloud_sign_in::EuropeSession;
use super::setup::{advertised_registration_status, registration_ready};
use super::{
    Scale, ScaleScanObserver, ScaleSetupInteraction, Weight, discover_scales, probe_setup_service,
};

/// A read-only check of the prerequisites for S200 registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupCheck {
    ScaleDiscovery,
    RegistrationReadiness,
    StandardAuthGatt,
    BrowserSignIn,
    EuropeApi,
}

impl fmt::Display for SetupCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScaleDiscovery => "Bluetooth S200 discovery",
            Self::RegistrationReadiness => "S200 registration readiness",
            Self::StandardAuthGatt => "Standard Auth over Bluetooth (FE95/0019)",
            Self::BrowserSignIn => "Xiaomi browser sign-in",
            Self::EuropeApi => "Xiaomi Europe API",
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SetupCheckStatus<'a> {
    Started,
    Passed,
    Failed(&'a io::Error),
    Skipped(SetupCheck),
}

/// Receives the results of the setup diagnostics as they finish.
pub trait SetupCheckObserver: ScaleSetupInteraction {
    fn report_setup_check(&mut self, check: SetupCheck, status: SetupCheckStatus<'_>);
}

/// Checks the scale and account in one run, reporting each stage as it completes.
/// Bluetooth and account checks run independently. The Europe API reuses the
/// browser session from this run.
pub fn check_scale_setup(scan_time: Duration, observer: &mut dyn SetupCheckObserver) {
    run_setup_checks(scan_time, observer, &SystemDiagnostics);
}

trait DiagnosticServices {
    fn scan(&self, scan_time: Duration, observer: &mut dyn ScaleScanObserver) -> io::Result<()>;
    fn probe_auth(&self, scale: &Scale) -> io::Result<()>;
    fn sign_in(&self, interaction: &mut dyn ScaleSetupInteraction) -> io::Result<EuropeSession>;
}

struct SystemDiagnostics;

impl DiagnosticServices for SystemDiagnostics {
    fn scan(&self, scan_time: Duration, observer: &mut dyn ScaleScanObserver) -> io::Result<()> {
        discover_scales(scan_time, observer)
    }

    fn probe_auth(&self, scale: &Scale) -> io::Result<()> {
        probe_setup_service(scale)
    }

    fn sign_in(&self, interaction: &mut dyn ScaleSetupInteraction) -> io::Result<EuropeSession> {
        EuropeSession::sign_in(interaction)
    }
}

fn run_setup_checks(
    scan_time: Duration,
    observer: &mut dyn SetupCheckObserver,
    services: &dyn DiagnosticServices,
) {
    check_bluetooth(scan_time, observer, services);
    observer.report_setup_check(SetupCheck::BrowserSignIn, SetupCheckStatus::Started);
    let session = match services.sign_in(observer) {
        Ok(session) => session,
        Err(error) => {
            observer
                .report_setup_check(SetupCheck::BrowserSignIn, SetupCheckStatus::Failed(&error));
            observer.report_setup_check(
                SetupCheck::EuropeApi,
                SetupCheckStatus::Skipped(SetupCheck::BrowserSignIn),
            );
            return;
        }
    };
    observer.report_setup_check(SetupCheck::BrowserSignIn, SetupCheckStatus::Passed);
    observer.report_setup_check(SetupCheck::EuropeApi, SetupCheckStatus::Started);
    observer.report_setup_check(
        SetupCheck::EuropeApi,
        result_status(&session.verify_device_count()),
    );
}

fn check_bluetooth(
    scan_time: Duration,
    observer: &mut dyn SetupCheckObserver,
    services: &dyn DiagnosticServices,
) {
    observer.report_setup_check(SetupCheck::ScaleDiscovery, SetupCheckStatus::Started);
    let scale = match scan_scale(scan_time, services) {
        Ok(scale) => {
            observer.report_setup_check(SetupCheck::ScaleDiscovery, SetupCheckStatus::Passed);
            scale
        }
        Err(error) => {
            let prerequisite = SetupCheck::ScaleDiscovery;
            observer.report_setup_check(prerequisite, SetupCheckStatus::Failed(&error));
            observer.report_setup_check(
                SetupCheck::RegistrationReadiness,
                SetupCheckStatus::Skipped(prerequisite),
            );
            observer.report_setup_check(
                SetupCheck::StandardAuthGatt,
                SetupCheckStatus::Skipped(prerequisite),
            );
            return;
        }
    };

    let readiness = advertised_registration_status(&scale)
        .map_err(|blocker| io::Error::other(blocker.message()));
    observer.report_setup_check(SetupCheck::RegistrationReadiness, result_status(&readiness));

    observer.report_setup_check(SetupCheck::StandardAuthGatt, SetupCheckStatus::Started);
    let gatt = if scale.is_connectable() {
        services.probe_auth(&scale)
    } else {
        Err(io::Error::other(
            "the scale did not advertise a Bluetooth connection",
        ))
    };
    observer.report_setup_check(SetupCheck::StandardAuthGatt, result_status(&gatt));
}

fn scan_scale(scan_time: Duration, services: &dyn DiagnosticServices) -> io::Result<Scale> {
    let mut scan = SetupDiagnosticScan::default();
    services.scan(scan_time, &mut scan)?;
    scan.candidate.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no S200 broadcast was detected during the scan",
        )
    })
}

#[derive(Default)]
struct SetupDiagnosticScan {
    candidate: Option<Scale>,
}

impl ScaleScanObserver for SetupDiagnosticScan {
    fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
        if registration_ready(scale) {
            self.candidate = Some(scale.clone());
            return ControlFlow::Break(());
        }
        if self
            .candidate
            .as_ref()
            .is_none_or(|previous| scale_rank(scale) >= scale_rank(previous))
        {
            self.candidate = Some(scale.clone());
        }
        ControlFlow::Continue(())
    }
}

fn scale_rank(scale: &Scale) -> (bool, bool) {
    (scale.is_connectable(), scale.setup_info().is_some())
}

fn result_status(result: &io::Result<()>) -> SetupCheckStatus<'_> {
    match result {
        Ok(()) => SetupCheckStatus::Passed,
        Err(error) => SetupCheckStatus::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::cloud_sign_in::tests::fixture_session;
    use crate::{BluetoothAddress, ScaleSetupInfo, SignalStrength, XiaomiSignInLink};

    #[derive(Default)]
    struct CheckLog(Vec<(SetupCheck, &'static str)>);

    impl ScaleSetupInteraction for CheckLog {
        fn present_xiaomi_sign_in(&mut self, _: &XiaomiSignInLink) {}
    }

    impl SetupCheckObserver for CheckLog {
        fn report_setup_check(&mut self, check: SetupCheck, status: SetupCheckStatus<'_>) {
            let status = match status {
                SetupCheckStatus::Started => "started",
                SetupCheckStatus::Passed => "passed",
                SetupCheckStatus::Failed(error) => {
                    assert!(!error.to_string().is_empty());
                    "failed"
                }
                SetupCheckStatus::Skipped(_) => "skipped",
            };
            self.0.push((check, status));
        }
    }

    struct Fixture {
        scale: Option<Scale>,
        sign_in_ok: bool,
        probe_calls: Cell<u32>,
    }

    impl DiagnosticServices for Fixture {
        fn scan(&self, duration: Duration, observer: &mut dyn ScaleScanObserver) -> io::Result<()> {
            assert_eq!(duration, Duration::from_secs(5));
            if let Some(scale) = &self.scale {
                let _ = observer.scale_discovered(scale, None);
            }
            Ok(())
        }

        fn probe_auth(&self, _: &Scale) -> io::Result<()> {
            self.probe_calls.set(self.probe_calls.get() + 1);
            Ok(())
        }

        fn sign_in(&self, _: &mut dyn ScaleSetupInteraction) -> io::Result<EuropeSession> {
            if !self.sign_in_ok {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(fixture_session(&[(
                "/app/v2/user/get_device_cnt",
                200,
                br#"{"code":0,"result":0}"#,
            )]))
        }
    }

    #[test]
    fn checks_xiaomi_even_when_bluetooth_finds_no_scale() {
        use SetupCheck::*;
        let mut log = CheckLog::default();
        let services = Fixture {
            scale: None,
            sign_in_ok: true,
            probe_calls: Cell::new(0),
        };
        run_setup_checks(Duration::from_secs(5), &mut log, &services);
        assert_eq!(
            log.0,
            [
                (ScaleDiscovery, "started"),
                (ScaleDiscovery, "failed"),
                (RegistrationReadiness, "skipped"),
                (StandardAuthGatt, "skipped"),
                (BrowserSignIn, "started"),
                (BrowserSignIn, "passed"),
                (EuropeApi, "started"),
                (EuropeApi, "passed"),
            ]
        );
        assert_eq!(services.probe_calls.get(), 0);
    }

    #[test]
    fn probes_only_connectable_scales_and_skips_the_api_after_failed_sign_in() {
        use SetupCheck::*;
        for connectable in [true, false] {
            let services = Fixture {
                scale: Some(Scale {
                    address: BluetoothAddress(3),
                    address_type: None,
                    name: None,
                    signal_strength: SignalStrength(-50),
                    connectable,
                    weight: None,
                    setup_info: ScaleSetupInfo::from_mibeacon(&[
                        0x95, 0xfe, 0x10, 0x58, 0xcb, 0x4d,
                    ]),
                }),
                sign_in_ok: false,
                probe_calls: Cell::new(0),
            };
            let mut log = CheckLog::default();
            run_setup_checks(Duration::from_secs(5), &mut log, &services);
            assert!(log.0.contains(&(RegistrationReadiness, "passed")));
            assert!(log.0.contains(&(
                StandardAuthGatt,
                if connectable { "passed" } else { "failed" }
            )));
            assert_eq!(
                &log.0[log.0.len() - 2..],
                &[(BrowserSignIn, "failed"), (EuropeApi, "skipped")]
            );
            assert_eq!(services.probe_calls.get(), u32::from(connectable));
        }
    }

    #[test]
    fn waits_for_a_scale_that_is_ready_to_register() {
        let advertised = |address, control| Scale {
            address: BluetoothAddress(address),
            address_type: None,
            name: None,
            signal_strength: SignalStrength(-60),
            connectable: true,
            weight: None,
            setup_info: ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, control, 0xcb, 0x4d]),
        };
        let registered = advertised(1, 0x5b);
        let ready = advertised(2, 0x5a);
        let mut scan = SetupDiagnosticScan::default();
        assert_eq!(
            scan.scale_discovered(&registered, None),
            ControlFlow::Continue(())
        );
        assert_eq!(scan.candidate.as_ref(), Some(&registered));
        assert_eq!(scan.scale_discovered(&ready, None), ControlFlow::Break(()));
        assert_eq!(scan.candidate, Some(ready));
    }
}
