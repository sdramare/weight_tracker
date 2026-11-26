//! Discovery and GATT service inspection for the Xiaomi Smart Scale S200 on Windows.

#![cfg(windows)]

mod discovery;

use std::io;
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::rc::Rc;
use std::time::Duration;

use windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus;
use windows::Devices::Bluetooth::{BluetoothAddressType, BluetoothCacheMode, BluetoothLEDevice};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};

pub const MODEL_NAME: &str = "Xiaomi Smart Scale S200";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scale {
    address: u64,
    address_type: Option<BluetoothAddressType>,
    name: Option<String>,
    signal_dbm: i16,
    connectable: bool,
}

impl Scale {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn formatted_address(&self) -> String {
        let [_, _, a, b, c, d, e, f] = self.address.to_be_bytes();
        format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
    }

    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or(MODEL_NAME)
    }

    pub fn signal_dbm(&self) -> i16 {
        self.signal_dbm
    }

    pub fn is_connectable(&self) -> bool {
        self.connectable
    }
}

/// Reports each recognized scale and subsequent changes to its advertisement data.
/// The callback can end discovery early by returning `ControlFlow::Break`.
pub fn discover_scales(
    duration: Duration,
    on_scale: impl FnMut(&Scale) -> ControlFlow<()>,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    discovery::discover(duration, on_scale)
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
pub fn read_services(scale: &Scale) -> io::Result<Vec<String>> {
    let _apartment = Apartment::initialize()?;
    let device = match scale.address_type {
        Some(kind) => BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
            scale.address,
            kind,
        )?,
        None => BluetoothLEDevice::FromBluetoothAddressAsync(scale.address)?,
    }
    .join()
    .map_err(|error| io::Error::other(format!("Windows could not open the BLE device: {error}")))?;

    // Uncached discovery contacts the scale over Bluetooth and verifies the connection.
    let result = device
        .GetGattServicesWithCacheModeAsync(BluetoothCacheMode::Uncached)?
        .join()?;
    let status = result.Status()?;
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

    let services = result.Services()?;
    (0..services.Size()?)
        .map(|index| Ok(format!("{:?}", services.GetAt(index)?.Uuid()?)))
        .collect()
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
