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
    check_bluetooth(scan_time, observer);

    observer.report_setup_check(SetupCheck::BrowserSignIn, SetupCheckStatus::Started);
    let session = match EuropeSession::sign_in(observer) {
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

fn check_bluetooth(scan_time: Duration, observer: &mut dyn SetupCheckObserver) {
    observer.report_setup_check(SetupCheck::ScaleDiscovery, SetupCheckStatus::Started);
    let scale = match scan_scale(scan_time) {
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
        probe_setup_service(&scale)
    } else {
        Err(io::Error::other(
            "the scale did not advertise a Bluetooth connection",
        ))
    };
    observer.report_setup_check(SetupCheck::StandardAuthGatt, result_status(&gatt));
}

fn scan_scale(scan_time: Duration) -> io::Result<Scale> {
    let mut scan = SetupDiagnosticScan::default();
    discover_scales(scan_time, &mut scan)?;
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
    use std::ops::ControlFlow;

    use super::SetupDiagnosticScan;
    use crate::{BluetoothAddress, Scale, ScaleScanObserver, ScaleSetupInfo, SignalStrength};

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
