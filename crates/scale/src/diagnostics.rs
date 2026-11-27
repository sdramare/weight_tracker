use std::fmt;
use std::io;
use std::ops::ControlFlow;
use std::time::Duration;

use super::cloud_sign_in::check_xiaomi_cloud_europe;
use super::setup::registration_ready;
use super::{Scale, XiaomiSignInLink, discover_scales, probe_setup_service};

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

/// Checks the scale and account in one run, reporting each stage as it completes.
/// Bluetooth and account checks run independently. The Europe API reuses the
/// browser session from this run.
pub fn check_scale_setup(
    scan_time: Duration,
    present_sign_in_link: impl FnOnce(&XiaomiSignInLink),
    mut report: impl FnMut(SetupCheck, SetupCheckStatus<'_>),
) {
    check_bluetooth(scan_time, &mut report);

    report(SetupCheck::BrowserSignIn, SetupCheckStatus::Started);
    let mut sign_in_completed = false;
    let cloud_result = check_xiaomi_cloud_europe(present_sign_in_link, || {
        sign_in_completed = true;
        report(SetupCheck::BrowserSignIn, SetupCheckStatus::Passed);
        report(SetupCheck::EuropeApi, SetupCheckStatus::Started);
    });
    if sign_in_completed {
        report(SetupCheck::EuropeApi, result_status(&cloud_result));
    } else {
        report(SetupCheck::BrowserSignIn, result_status(&cloud_result));
        report(
            SetupCheck::EuropeApi,
            SetupCheckStatus::Skipped(SetupCheck::BrowserSignIn),
        );
    }
}

fn check_bluetooth(scan_time: Duration, report: &mut impl FnMut(SetupCheck, SetupCheckStatus<'_>)) {
    report(SetupCheck::ScaleDiscovery, SetupCheckStatus::Started);
    let scale = match scan_scale(scan_time) {
        Ok(scale) => {
            report(SetupCheck::ScaleDiscovery, SetupCheckStatus::Passed);
            scale
        }
        Err(error) => {
            let prerequisite = SetupCheck::ScaleDiscovery;
            report(prerequisite, SetupCheckStatus::Failed(&error));
            report(
                SetupCheck::RegistrationReadiness,
                SetupCheckStatus::Skipped(prerequisite),
            );
            report(
                SetupCheck::StandardAuthGatt,
                SetupCheckStatus::Skipped(prerequisite),
            );
            return;
        }
    };

    let readiness = match scale.setup_info() {
        Some(info) if info.requests_certificate_test() => Ok(()),
        Some(info) => Err(io::Error::other(format!(
            "the scale is not requesting supported setup ({info})"
        ))),
        None => Err(io::Error::other(
            "the scale did not advertise MiBeacon setup information",
        )),
    };
    report(SetupCheck::RegistrationReadiness, result_status(&readiness));

    report(SetupCheck::StandardAuthGatt, SetupCheckStatus::Started);
    let gatt = if scale.is_connectable() {
        probe_setup_service(&scale)
    } else {
        Err(io::Error::other(
            "the scale did not advertise a Bluetooth connection",
        ))
    };
    report(SetupCheck::StandardAuthGatt, result_status(&gatt));
}

fn scan_scale(scan_time: Duration) -> io::Result<Scale> {
    let mut candidate: Option<Scale> = None;
    discover_scales(scan_time, |scale| consider_scale(&mut candidate, scale))?;
    candidate.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no S200 broadcast was detected during the scan",
        )
    })
}

fn consider_scale(candidate: &mut Option<Scale>, scale: &Scale) -> ControlFlow<()> {
    if registration_ready(scale) {
        *candidate = Some(scale.clone());
        return ControlFlow::Break(());
    }
    if candidate
        .as_ref()
        .is_none_or(|previous| scale_rank(scale) >= scale_rank(previous))
    {
        *candidate = Some(scale.clone());
    }
    ControlFlow::Continue(())
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

    use super::consider_scale;
    use crate::{BluetoothAddress, Scale, ScaleSetupInfo, SignalStrength};

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
        let mut candidate = None;
        assert_eq!(
            consider_scale(&mut candidate, &registered),
            ControlFlow::Continue(())
        );
        assert_eq!(candidate.as_ref(), Some(&registered));
        assert_eq!(
            consider_scale(&mut candidate, &ready),
            ControlFlow::Break(())
        );
        assert_eq!(candidate, Some(ready));
    }
}
