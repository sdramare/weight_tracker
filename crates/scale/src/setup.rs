mod certificate;

use std::{fmt, io};

use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothUuidHelper};

use super::{Apartment, Scale, check_service_status, open_scale_device};

pub use certificate::check_setup_test_certificate;

/// Connects to the scale and checks for the Xiaomi Standard Auth characteristic.
pub fn probe_setup_service(scale: &Scale) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let device = open_scale_device(scale)?;
    let service_uuid = BluetoothUuidHelper::FromShortId(0xfe95)?;
    let auth_uuid = BluetoothUuidHelper::FromShortId(0x0019)?;
    let result = device
        .GetGattServicesForUuidWithCacheModeAsync(service_uuid, BluetoothCacheMode::Uncached)?
        .join()?;
    check_service_status(result.Status()?)?;
    let services = result.Services()?;
    for index in 0..services.Size()? {
        let result = services
            .GetAt(index)?
            .GetCharacteristicsForUuidWithCacheModeAsync(auth_uuid, BluetoothCacheMode::Uncached)?
            .join()?;
        check_service_status(result.Status()?)?;
        if result.Characteristics()?.Size()? > 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "the scale did not expose the Xiaomi Standard Auth characteristic",
    ))
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
