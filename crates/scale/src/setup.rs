mod certificate_transfer;
mod connected_weight;
mod registration;
mod registration_crypto;

use std::ops::ControlFlow;
use std::time::Duration;
use std::{fmt, io};

use windows::Devices::Bluetooth::GenericAttributeProfile::{GattCharacteristic, GattDeviceService};
use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothLEDevice, BluetoothUuidHelper};

use super::{Apartment, Scale, check_service_status, discover_scales, open_scale_device};

pub use certificate_transfer::{SetupCertificateReply, send_setup_test_certificate};
pub use connected_weight::{ConnectedWeightEvent, listen_for_connected_weight};
pub use registration::{
    RegisteredScale, RegistrationEvent, RegistrationStep, register_scale_europe,
};

/// Finds the first connectable S200 ms113 that requests Standard Auth registration.
pub fn find_registration_scale(duration: Duration) -> io::Result<Scale> {
    let mut candidate = None;
    discover_scales(duration, |scale| {
        if scale.is_connectable()
            && scale
                .setup_info()
                .is_some_and(|info| info.requests_certificate_test())
        {
            candidate = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })?;
    candidate.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no connectable, unregistered S200 ms113 requested setup",
        )
    })
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

    /// The supported variant is unregistered and currently requesting Standard Auth setup.
    pub fn requests_certificate_test(&self) -> bool {
        self.is_ms113()
            && matches!(
                self.flags,
                Some(SetupFlags {
                    authentication: Authentication::Standard,
                    registered: false,
                    solicited: true,
                })
            )
    }

    pub(super) fn from_mibeacon(data: &[u8]) -> Option<Self> {
        let [
            0x95,
            0xfe,
            control_low,
            control_high,
            product_low,
            product_high,
            ..,
        ] = data
        else {
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
    use super::{Authentication, ScaleSetupInfo, SetupFlags};

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
}
