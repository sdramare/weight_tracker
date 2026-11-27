//! Discovery, weight readings, and GATT service inspection for the Xiaomi Smart Scale S200.

#![cfg(windows)]

mod cloud_sign_in;
mod diagnostics;
mod discovery;
mod login_keys;
mod setup;
mod types;
mod weight;

use std::io;
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::rc::Rc;
use std::time::Duration;

use windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus;
use windows::Devices::Bluetooth::{BluetoothAddressType, BluetoothCacheMode, BluetoothLEDevice};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};

pub use cloud_sign_in::{XiaomiSignInLink, verify_xiaomi_cloud_europe, verify_xiaomi_sign_in};
pub use diagnostics::{SetupCheck, SetupCheckStatus, check_scale_setup};
pub use login_keys::{SavedScaleLogins, ScaleLoginToken, default_registration_directory};
pub use setup::{
    ConnectedWeightEvent, RegisteredScale, RegistrationEvent, RegistrationStep, ScaleSetupInfo,
    SetupCertificateReply, SetupProfile, find_registration_scale, listen_for_connected_weight,
    probe_setup_profile, probe_setup_service, register_scale_europe, register_scale_europe_while,
    send_setup_test_certificate, watch_connected_weights,
};
pub use types::{
    BluetoothAddress, GattServiceUuid, ScaleName, SignalStrength, Weight, WeightReading,
};
pub use weight::ScaleBindKey;
use weight::WeightDecoder;

pub const MODEL_NAME: ScaleName<'static> = ScaleName("Xiaomi Smart Scale S200");

fn check_cancellation(keep_going: &impl Fn() -> bool) -> io::Result<()> {
    if keep_going() {
        Ok(())
    } else {
        Err(io::ErrorKind::Interrupted.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scale {
    address: BluetoothAddress,
    address_type: Option<BluetoothAddressType>,
    name: Option<String>,
    signal_strength: SignalStrength,
    connectable: bool,
    weight: Option<Weight>,
    setup_info: Option<ScaleSetupInfo>,
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
/// The callback can end discovery early by returning `ControlFlow::Break`.
pub fn discover_scales(
    duration: Duration,
    on_scale: impl FnMut(&Scale) -> ControlFlow<()>,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::discover(duration, None, || true, on_scale)
}

/// Discovers scales and reports weights authenticated with the supplied MiBeacon key.
pub fn discover_scales_with_weight(
    duration: Duration,
    key: &ScaleBindKey,
    on_scale: impl FnMut(&Scale) -> ControlFlow<()>,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::discover(duration, Some(WeightDecoder::new(key)), || true, on_scale)
}

/// Watches for scales until stopped by the caller. An optional bind key enables
/// authenticated MiBeacon weight readings. The second callback argument contains
/// the weight carried by the current advertisement, when present.
pub fn watch_scales(
    key: Option<&ScaleBindKey>,
    keep_listening: impl Fn() -> bool,
    on_scale: impl FnMut(&Scale, Option<Weight>) -> ControlFlow<()>,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::watch(key.map(WeightDecoder::new), keep_listening, on_scale)
}

/// Waits for the first recognized scale that advertises a connection.
pub fn find_connectable_scale(duration: Duration) -> io::Result<Scale> {
    let mut target = None;
    let mut detected = false;
    discover_scales(duration, |scale| {
        detected = true;
        if scale.is_connectable() {
            target = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })?;

    target.ok_or_else(|| {
        let message = if detected {
            "the S200 was detected, but did not offer a connection. Close Xiaomi Home and wake the scale again"
        } else {
            "no Xiaomi Smart Scale S200 was detected. Keep it near the PC and wake it during the scan"
        };
        io::Error::new(io::ErrorKind::NotFound, message)
    })
}

/// Connects to the scale and returns the UUIDs of its GATT services.
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
        .map(|index| Ok(GattServiceUuid(services.GetAt(index)?.Uuid()?)))
        .collect()
}

fn open_scale_device(scale: &Scale) -> io::Result<BluetoothLEDevice> {
    let device = match scale.address_type {
        Some(kind) => BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
            scale.address.0,
            kind,
        )?,
        None => BluetoothLEDevice::FromBluetoothAddressAsync(scale.address.0)?,
    }
    .join()
    .map_err(|error| io::Error::other(format!("Windows could not open the BLE device: {error}")))?;
    Ok(device)
}

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

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn initialize() -> io::Result<Self> {
        // SAFETY: The guard stays on this thread and balances one successful initialization.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        Ok(Self(PhantomData))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: This balances one successful RoInitialize on the same thread.
        unsafe { RoUninitialize() };
    }
}
