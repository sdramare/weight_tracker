mod certificate_transfer;
mod connected_weight;
mod registration;
mod registration_crypto;

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::time::Duration;
use std::{fmt, io};

use windows::Devices::Bluetooth::GenericAttributeProfile::{GattCharacteristic, GattDeviceService};
use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothLEDevice, BluetoothUuidHelper};

use super::{
    Apartment, Scale, ScaleScanObserver, ScaleSetupInteraction, Weight, check_service_status,
    discover_scales, open_scale_device,
};

pub use certificate_transfer::{
    SetupCertificateReply, SetupProfile, probe_setup_profile, send_setup_test_certificate,
};
pub use connected_weight::{
    ConnectedWeightEvent, WeightSessionObserver, listen_for_connected_weight,
    watch_connected_weights,
};
pub use registration::{
    RegisteredScale, RegistrationEvent, RegistrationObserver, RegistrationStep,
    register_scale_europe,
};

#[cfg(feature = "test-fixtures")]
pub use registration::fixture_registration;

#[cfg(feature = "test-fixtures")]
pub use certificate_transfer::fixture_profile;

/// Finds the first connectable S200 ms113 that advertises unregistered Standard Auth.
pub fn find_registration_scale(duration: Duration) -> io::Result<Scale> {
    find_registration_scale_with(duration, None)
}

fn find_registration_scale_with(
    duration: Duration,
    interaction: Option<&mut dyn ScaleSetupInteraction>,
) -> io::Result<Scale> {
    let mut scan = RegistrationScaleSearch {
        interaction,
        candidate: None,
        blockers: HashMap::new(),
    };
    if !scan.should_scan() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    discover_scales(duration, &mut scan)?;
    if !scan.should_scan() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    scan.finish()
}

struct RegistrationScaleSearch<'a> {
    interaction: Option<&'a mut dyn ScaleSetupInteraction>,
    candidate: Option<Scale>,
    blockers: HashMap<super::BluetoothAddress, SetupBlocker>,
}

impl RegistrationScaleSearch<'_> {
    fn finish(self) -> io::Result<Scale> {
        self.candidate.ok_or_else(|| {
            self.blockers.into_values().max().map_or_else(
                || io::Error::new(
                    io::ErrorKind::NotFound,
                    "Windows did not see an S200 during this scan. Keep the scale near this PC and step on it when setup starts scanning.",
                ),
                |blocker| io::Error::new(io::ErrorKind::NotFound, blocker.message()),
            )
        })
    }
}

impl ScaleScanObserver for RegistrationScaleSearch<'_> {
    fn should_scan(&mut self) -> bool {
        self.interaction
            .as_mut()
            .is_none_or(|interaction| !interaction.setup_cancelled())
    }

    fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
        match registration_status(scale) {
            Ok(()) => {
                self.candidate = Some(scale.clone());
                ControlFlow::Break(())
            }
            Err(blocker) => {
                self.blockers.insert(scale.address(), blocker);
                ControlFlow::Continue(())
            }
        }
    }
}

pub(super) fn registration_ready(scale: &Scale) -> bool {
    registration_status(scale).is_ok()
}

fn registration_status(scale: &Scale) -> Result<(), SetupBlocker> {
    advertised_registration_status(scale)?;
    if !scale.is_connectable() {
        return Err(SetupBlocker::NotConnectable);
    }
    Ok(())
}

pub(super) fn advertised_registration_status(scale: &Scale) -> Result<(), SetupBlocker> {
    scale
        .setup_info()
        .ok_or(SetupBlocker::MissingSetupInfo)?
        .registration_status()
}

/// In a scan with several scales, prefer evidence from a supported ms113.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SetupBlocker {
    MissingSetupInfo,
    OtherModel,
    UnknownSetupState,
    OtherAuthentication,
    AlreadyRegistered,
    NotConnectable,
}

impl SetupBlocker {
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::MissingSetupInfo => {
                "Windows saw the S200's name but did not receive its setup information. Bring it closer to this PC and wake it again while setup scans."
            }
            Self::OtherModel => {
                "Windows saw an S200 variant that this app cannot set up. This setup flow supports the ms113 Bluetooth variant."
            }
            Self::UnknownSetupState => {
                "Windows saw an S200 ms113 but its broadcast did not include a supported setup status."
            }
            Self::OtherAuthentication => {
                "Windows saw an S200 ms113 using a Bluetooth authentication mode this app does not support for setup."
            }
            Self::AlreadyRegistered => {
                "The S200 still reports an existing pairing. If you intend to reset it, hold Reset under the battery cover for 7 seconds. Wait for all LEDs to light and the display to return to 0.0, then retry setup."
            }
            Self::NotConnectable => {
                "Windows saw an unpaired S200 but did not receive a Bluetooth connection offer. Close any app connected to the scale and wake it again near this PC while setup scans."
            }
        }
    }
}

/// Connects to the scale and checks for the Xiaomi Standard Auth characteristic.
pub fn probe_setup_service(scale: &Scale) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let device = open_scale_device(scale)?;
    let service = setup_service(&device)?;
    setup_characteristic(&service, 0x0019)?;
    Ok(())
}

fn setup_service(device: &BluetoothLEDevice) -> io::Result<GattDeviceService> {
    let service_uuid = BluetoothUuidHelper::FromShortId(0xfe95)?;
    let result = device
        .GetGattServicesForUuidWithCacheModeAsync(service_uuid, BluetoothCacheMode::Uncached)?
        .join()?;
    check_service_status(result.Status()?)?;
    let services = result.Services()?;
    if services.Size()? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the scale did not expose the Xiaomi setup service (FE95)",
        ));
    }
    Ok(services.GetAt(0)?)
}

fn setup_characteristic(
    service: &GattDeviceService,
    short_uuid: u32,
) -> io::Result<GattCharacteristic> {
    let uuid = BluetoothUuidHelper::FromShortId(short_uuid)?;
    let result = service
        .GetCharacteristicsForUuidWithCacheModeAsync(uuid, BluetoothCacheMode::Uncached)?
        .join()?;
    check_service_status(result.Status()?)?;
    let characteristics = result.Characteristics()?;
    if characteristics.Size()? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("the scale did not expose setup characteristic {short_uuid:04X}"),
        ));
    }
    Ok(characteristics.GetAt(0)?)
}

/// Product and setup information advertised by a Xiaomi Smart Scale S200.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleSetupInfo {
    product_id: u16,
    version: u16,
    flags: Option<SetupFlags>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SetupFlags {
    authentication: Authentication,
    registered: bool,
    solicited: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Authentication {
    Legacy,
    Secure,
    Standard,
    Reserved,
}

impl ScaleSetupInfo {
    pub(crate) fn is_ms113(&self) -> bool {
        self.product_id == 0x4dcb
    }

    pub(crate) fn registered(&self) -> Option<bool> {
        self.flags.map(|flags| flags.registered)
    }

    /// Whether this supported, unregistered variant actively requests setup in its broadcast.
    pub fn requests_certificate_test(&self) -> bool {
        self.registration_status().is_ok() && self.flags.is_some_and(|flags| flags.solicited)
    }

    fn registration_status(&self) -> Result<(), SetupBlocker> {
        if !self.is_ms113() {
            return Err(SetupBlocker::OtherModel);
        }
        let flags = self.flags.ok_or(SetupBlocker::UnknownSetupState)?;
        if flags.registered {
            return Err(SetupBlocker::AlreadyRegistered);
        }
        if flags.authentication != Authentication::Standard {
            return Err(SetupBlocker::OtherAuthentication);
        }
        // The solicitation flag controls whether the scale initiates a pairing prompt.
        // Setup started by the user can proceed to the device's GATT capability check.
        Ok(())
    }

    pub(super) fn from_mibeacon(data: &[u8]) -> Option<Self> {
        let [0x95, 0xfe, frame @ ..] = data else {
            return None;
        };
        Self::from_mibeacon_frame(frame)
    }

    pub(super) fn from_mibeacon_frame(frame: &[u8]) -> Option<Self> {
        let [control_low, control_high, product_low, product_high, ..] = frame else {
            return None;
        };
        let product_id = u16::from_le_bytes([*product_low, *product_high]);
        if !matches!(product_id, 0x45c9 | 0x4c04 | 0x4dcb) {
            return None;
        }

        let control = u16::from_le_bytes([*control_low, *control_high]);
        let version = control >> 12;
        let flags = (version == 5).then_some(SetupFlags::from_v5_control(control));
        Some(Self {
            product_id,
            version,
            flags,
        })
    }
}

impl SetupFlags {
    fn from_v5_control(control: u16) -> Self {
        let authentication = match (control >> 10) & 0x03 {
            0 => Authentication::Legacy,
            1 => Authentication::Secure,
            2 => Authentication::Standard,
            _ => Authentication::Reserved,
        };
        Self {
            authentication,
            registered: control & 0x0100 != 0,
            solicited: control & 0x0200 != 0,
        }
    }
}

impl fmt::Display for ScaleSetupInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Product 0x{:04X}, MiBeacon v{}",
            self.product_id, self.version
        )?;
        let Some(flags) = self.flags else {
            return formatter.write_str(", setup flags unavailable");
        };
        let authentication = match flags.authentication {
            Authentication::Legacy => "legacy authentication",
            Authentication::Secure => "secure authentication",
            Authentication::Standard => "standard authentication",
            Authentication::Reserved => "reserved authentication mode",
        };
        let binding = if flags.registered {
            "registered"
        } else {
            "unregistered"
        };
        let solicitation = if flags.solicited {
            "setup requested"
        } else {
            "no setup request"
        };
        write!(formatter, ", {authentication}, {binding}, {solicitation}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BluetoothAddress, Scale, SignalStrength};

    #[test]
    fn recognizes_s200_mibeacon_headers() {
        for product_id in [0x45c9u16, 0x4c04, 0x4dcb] {
            let [low, high] = product_id.to_le_bytes();
            let setup =
                ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x5b, low, high]).unwrap();
            assert_eq!(setup.product_id, product_id);
        }
        assert!(ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x5b, 0xd5, 0x3b]).is_none());
        assert!(ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x5b, 0xcb]).is_none());
        assert!(ScaleSetupInfo::from_mibeacon(&[0x16, 0x18, 0x10, 0x5b, 0xcb, 0x4d]).is_none());
    }

    #[test]
    fn reports_only_the_documented_v5_setup_flags() {
        let setup = ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x5b, 0xcb, 0x4d]).unwrap();
        assert_eq!(
            setup.flags,
            Some(SetupFlags {
                authentication: Authentication::Standard,
                registered: true,
                solicited: true,
            })
        );
        assert_eq!(
            setup.to_string(),
            "Product 0x4DCB, MiBeacon v5, standard authentication, registered, setup requested"
        );
        assert_eq!(
            ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x4b, 0xcb, 0x4d])
                .unwrap()
                .flags,
            None
        );
    }

    #[test]
    fn reads_the_same_setup_flags_from_xiaomi_manufacturer_and_service_data() {
        let manufacturer_frame = [0x10, 0x59, 0xcb, 0x4d];
        let setup = ScaleSetupInfo::from_mibeacon_frame(&manufacturer_frame).unwrap();
        assert_eq!(
            Some(setup),
            ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, 0x59, 0xcb, 0x4d])
        );
        assert_eq!(setup.registered(), Some(true));
        assert!(ScaleSetupInfo::from_mibeacon_frame(&manufacturer_frame[..3]).is_none());
    }

    #[test]
    fn manual_setup_accepts_an_unpaired_ms113_with_or_without_solicitation() {
        for (control, connectable, expected) in [
            (0x58, true, Ok(())),
            (0x5a, true, Ok(())),
            (0x59, true, Err(SetupBlocker::AlreadyRegistered)),
            (0x5b, true, Err(SetupBlocker::AlreadyRegistered)),
            (0x58, false, Err(SetupBlocker::NotConnectable)),
            (0x48, true, Err(SetupBlocker::UnknownSetupState)),
            (0x54, true, Err(SetupBlocker::OtherAuthentication)),
        ] {
            let scale = Scale {
                address: BluetoothAddress(1),
                address_type: None,
                name: None,
                signal_strength: SignalStrength(-60),
                connectable,
                weight: None,
                setup_info: ScaleSetupInfo::from_mibeacon_frame(&[0x10, control, 0xcb, 0x4d]),
            };
            assert_eq!(registration_status(&scale), expected, "0x{control:02X}");
        }
    }

    fn candidate(control: u8, product: [u8; 2], connectable: bool) -> Scale {
        Scale {
            address: BluetoothAddress(1),
            address_type: None,
            name: None,
            signal_strength: SignalStrength(-59),
            connectable,
            weight: None,
            setup_info: ScaleSetupInfo::from_mibeacon_frame(&[
                0x10, control, product[0], product[1],
            ]),
        }
    }

    #[test]
    fn distinguishes_missing_broadcasts_and_reports_the_latest_blocker_for_a_scale() {
        let search = || RegistrationScaleSearch {
            interaction: None,
            candidate: None,
            blockers: HashMap::new(),
        };
        assert!(
            search()
                .finish()
                .unwrap_err()
                .to_string()
                .contains("did not see an S200")
        );

        for (control, model, message, display) in [
            (0x58, [0, 0], "did not receive its setup information", ""),
            (
                0x58,
                [0x04, 0x4c],
                "cannot set up",
                "standard authentication",
            ),
            (
                0x48,
                [0xcb, 0x4d],
                "supported setup status",
                "setup flags unavailable",
            ),
            (
                0x50,
                [0xcb, 0x4d],
                "does not support for setup",
                "legacy authentication",
            ),
            (
                0x54,
                [0xcb, 0x4d],
                "does not support for setup",
                "secure authentication",
            ),
            (
                0x5c,
                [0xcb, 0x4d],
                "does not support for setup",
                "reserved authentication",
            ),
            (0x59, [0xcb, 0x4d], "existing pairing", "registered"),
            (0x58, [0xcb, 0x4d], "connection offer", "unregistered"),
        ] {
            let mut scan = search();
            let scale = candidate(control, model, false);
            assert!(scan.should_scan());
            assert!(scan.scale_discovered(&scale, None).is_continue());
            assert!(scan.finish().unwrap_err().to_string().contains(message));
            if let Some(info) = scale.setup_info() {
                assert!(info.to_string().contains(display));
            }
        }
        let mut scan = search();
        assert!(
            scan.scale_discovered(&candidate(0x59, [0xcb, 0x4d], true), None)
                .is_continue()
        );
        let eligible = candidate(0x58, [0xcb, 0x4d], true);
        assert!(scan.scale_discovered(&eligible, None).is_break());
        assert_eq!(scan.finish().unwrap(), eligible);
    }
}
