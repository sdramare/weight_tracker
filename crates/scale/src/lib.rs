//! Discovery, weight readings, and GATT service inspection for the Xiaomi Smart Scale S200.

mod cloud_sign_in;
mod diagnostics;
mod discovery;
mod login_keys;
mod setup;
mod types;
mod weight;

#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
pub mod test_fixtures {
    use super::*;

    pub fn scale(address: u64, connectable: bool, registered: bool) -> Scale {
        let control = if registered { 0x59 } else { 0x58 };
        Scale {
            address: BluetoothAddress(address),
            #[cfg(any(windows, test))]
            address_type: None,
            name: None,
            signal_strength: SignalStrength(-45),
            connectable,
            weight: None,
            setup_info: ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, control, 0xcb, 0x4d]),
        }
    }

    pub fn with_weight(mut scale: Scale, weight: Weight) -> Scale {
        scale.weight = Some(weight);
        scale
    }

    pub use crate::cloud_sign_in::fixture_sign_in_link;
    pub use crate::login_keys::fixture_logins;
    pub use crate::setup::{fixture_profile, fixture_registration};
}

use std::io;
use std::ops::ControlFlow;
use std::time::Duration;

#[cfg(windows)]
use std::{marker::PhantomData, rc::Rc};
#[cfg(windows)]
use windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus;
#[cfg(windows)]
use windows::Devices::Bluetooth::{BluetoothAddressType, BluetoothCacheMode, BluetoothLEDevice};
#[cfg(windows)]
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};

pub use cloud_sign_in::{
    ScaleSetupInteraction, XiaomiSignInLink, verify_xiaomi_cloud_europe, verify_xiaomi_sign_in,
};
pub use diagnostics::{SetupCheck, SetupCheckObserver, SetupCheckStatus, check_scale_setup};
pub use discovery::ScaleScanObserver;
pub use login_keys::{SavedScaleLogins, ScaleLoginToken, default_registration_directory};
pub use setup::{
    ConnectedWeightEvent, RegisteredScale, RegistrationEvent, RegistrationObserver,
    RegistrationStep, ScaleSetupInfo, SetupCertificateReply, SetupProfile, WeightSessionObserver,
    find_registration_scale, listen_for_connected_weight, probe_setup_profile, probe_setup_service,
    register_scale_europe, send_setup_test_certificate, watch_connected_weights,
};
pub use types::{
    BluetoothAddress, GattServiceUuid, ScaleName, SignalStrength, Weight, WeightReading,
};
pub use weight::ScaleBindKey;
#[cfg(windows)]
use weight::WeightDecoder;

pub const MODEL_NAME: ScaleName<'static> = ScaleName("Xiaomi Smart Scale S200");

fn check_cancellation(interaction: &mut dyn ScaleSetupInteraction) -> io::Result<()> {
    if interaction.setup_cancelled() {
        Err(io::ErrorKind::Interrupted.into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scale {
    address: BluetoothAddress,
    #[cfg(any(windows, test))]
    address_type: Option<AddressKind>,
    name: Option<String>,
    signal_strength: SignalStrength,
    connectable: bool,
    weight: Option<Weight>,
    setup_info: Option<ScaleSetupInfo>,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressKind {
    Public,
    #[cfg(windows)]
    Random,
}

#[cfg(not(windows))]
fn bluetooth_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Bluetooth connections to the S200 require Windows 10 or 11",
    )
}

impl Scale {
    pub fn address(&self) -> BluetoothAddress {
        self.address
    }

    pub fn name(&self) -> ScaleName<'_> {
        self.name.as_deref().map(ScaleName).unwrap_or(MODEL_NAME)
    }

    pub fn signal_strength(&self) -> SignalStrength {
        self.signal_strength
    }

    pub fn is_connectable(&self) -> bool {
        self.connectable
    }

    /// The latest stabilized weight received for this scale during the scan.
    pub fn weight(&self) -> Option<Weight> {
        self.weight
    }

    /// The most recent setup information advertised by the scale.
    pub fn setup_info(&self) -> Option<ScaleSetupInfo> {
        self.setup_info
    }
}

/// Reports each recognized scale and subsequent changes to its advertisement data.
/// The observer can end discovery early by returning `ControlFlow::Break`.
#[cfg(windows)]
pub fn discover_scales(duration: Duration, observer: &mut dyn ScaleScanObserver) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::discover(duration, None, observer)
}

#[cfg(not(windows))]
pub fn discover_scales(_: Duration, _: &mut dyn ScaleScanObserver) -> io::Result<()> {
    Err(bluetooth_unavailable())
}

/// Discovers scales and reports weights authenticated with the supplied MiBeacon key.
#[cfg(windows)]
pub fn discover_scales_with_weight(
    duration: Duration,
    key: &ScaleBindKey,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::discover(duration, Some(WeightDecoder::new(key)), observer)
}

#[cfg(not(windows))]
pub fn discover_scales_with_weight(
    _: Duration,
    _: &ScaleBindKey,
    _: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    Err(bluetooth_unavailable())
}

/// Passively watches for scales until stopped by the caller. An optional bind key enables
/// authenticated MiBeacon weight readings from the current advertisement.
#[cfg(windows)]
pub fn watch_scales(
    key: Option<&ScaleBindKey>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::watch(key.map(WeightDecoder::new), observer)
}

#[cfg(not(windows))]
pub fn watch_scales(_: Option<&ScaleBindKey>, _: &mut dyn ScaleScanObserver) -> io::Result<()> {
    Err(bluetooth_unavailable())
}

/// Waits for the first recognized scale that advertises a connection.
pub fn find_connectable_scale(duration: Duration) -> io::Result<Scale> {
    let mut scan = ConnectableScaleSearch::default();
    discover_scales(duration, &mut scan)?;
    scan.finish()
}

#[derive(Default)]
struct ConnectableScaleSearch {
    target: Option<Scale>,
    detected: bool,
}

impl ConnectableScaleSearch {
    fn finish(self) -> io::Result<Scale> {
        self.target.ok_or_else(|| {
            let message = if self.detected {
                "the S200 was detected, but did not offer a connection. Close Xiaomi Home and wake the scale again"
            } else {
                "no Xiaomi Smart Scale S200 was detected. Keep it near the PC and wake it during the scan"
            };
            io::Error::new(io::ErrorKind::NotFound, message)
        })
    }
}

impl ScaleScanObserver for ConnectableScaleSearch {
    fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
        self.detected = true;
        if scale.is_connectable() {
            self.target = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Connects to the scale and returns the UUIDs of its GATT services.
#[cfg(windows)]
pub fn read_services(scale: &Scale) -> io::Result<Vec<GattServiceUuid>> {
    let _apartment = Apartment::initialize()?;
    let device = open_scale_device(scale)?;

    // Uncached discovery contacts the scale over Bluetooth and verifies the connection.
    let result = device
        .GetGattServicesWithCacheModeAsync(BluetoothCacheMode::Uncached)?
        .join()?;
    check_service_status(result.Status()?)?;

    let services = result.Services()?;
    (0..services.Size()?)
        .map(|index| Ok(GattServiceUuid(services.GetAt(index)?.Uuid()?.to_u128())))
        .collect()
}

#[cfg(not(windows))]
pub fn read_services(_: &Scale) -> io::Result<Vec<GattServiceUuid>> {
    Err(bluetooth_unavailable())
}

#[cfg(windows)]
fn open_scale_device(scale: &Scale) -> io::Result<BluetoothLEDevice> {
    let device = match scale.address_type {
        Some(kind) => BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
            scale.address.0,
            match kind {
                AddressKind::Public => BluetoothAddressType::Public,
                AddressKind::Random => BluetoothAddressType::Random,
            },
        )?,
        None => BluetoothLEDevice::FromBluetoothAddressAsync(scale.address.0)?,
    }
    .join()
    .map_err(|error| io::Error::other(format!("Windows could not open the BLE device: {error}")))?;
    Ok(device)
}

#[cfg(windows)]
fn check_service_status(status: GattCommunicationStatus) -> io::Result<()> {
    match status {
        GattCommunicationStatus::Success => {}
        GattCommunicationStatus::Unreachable => {
            return Err(io::Error::other(
                "the scale stopped responding. Close Xiaomi Home and wake the scale again",
            ));
        }
        GattCommunicationStatus::AccessDenied => {
            return Err(io::Error::other(
                "Windows denied access to the scale's GATT services",
            ));
        }
        _ => {
            return Err(io::Error::other(format!(
                "GATT service discovery returned {status:?}"
            )));
        }
    }

    Ok(())
}

#[cfg(windows)]
struct Apartment(PhantomData<Rc<()>>);

#[cfg(windows)]
impl Apartment {
    fn initialize() -> io::Result<Self> {
        // SAFETY: The guard stays on this thread and balances one successful initialization.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        Ok(Self(PhantomData))
    }
}

#[cfg(windows)]
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: This balances one successful RoInitialize on the same thread.
        unsafe { RoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn reports_gatt_status_and_rejects_unavailable_access() {
        assert!(check_service_status(GattCommunicationStatus::Success).is_ok());
        for (status, message) in [
            (GattCommunicationStatus::Unreachable, "stopped responding"),
            (GattCommunicationStatus::AccessDenied, "denied access"),
            (
                GattCommunicationStatus::ProtocolError,
                "GATT service discovery returned",
            ),
        ] {
            assert!(
                check_service_status(status)
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            );
        }
    }

    #[test]
    fn selects_a_connectable_broadcast_and_distinguishes_no_scan_results() {
        let mut scan = ConnectableScaleSearch::default();
        assert!(
            ConnectableScaleSearch::default()
                .finish()
                .unwrap_err()
                .to_string()
                .contains("no Xiaomi")
        );
        let mut scale = Scale {
            address: BluetoothAddress(5),
            address_type: None,
            name: Some("fixture".into()),
            signal_strength: SignalStrength(-65),
            connectable: false,
            weight: None,
            setup_info: None,
        };
        assert!(scan.scale_discovered(&scale, None).is_continue());
        assert!(
            scan.finish()
                .unwrap_err()
                .to_string()
                .contains("did not offer")
        );
        let mut scan = ConnectableScaleSearch::default();
        scale.connectable = true;
        assert!(scan.scale_discovered(&scale, None).is_break());
        assert_eq!(scan.finish().unwrap(), scale);
    }
}
