mod discovery;

use std::io;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

use windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus;
use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothLEDevice};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};

pub fn run(duration: Duration) -> bool {
    println!(
        "Looking for a Xiaomi Smart Scale S200 for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs(),
    );
    match connect(duration) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("Scale connection failed: {error}");
            false
        }
    }
}

fn connect(duration: Duration) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let (address, address_type) = discovery::find_scale(duration)?;
    println!(
        "Found a Xiaomi Smart Scale S200 at {}. Requesting its GATT services...",
        format_address(address),
    );
    let device = match address_type {
        Some(kind) => {
            BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(address, kind)?
        }
        None => BluetoothLEDevice::FromBluetoothAddressAsync(address)?,
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
    println!(
        "Connected. The scale returned {} GATT services.",
        services.Size()?
    );
    for service in services {
        println!("  {:?}", service.Uuid()?);
    }
    Ok(())
}

fn format_address(address: u64) -> String {
    let [_, _, a, b, c, d, e, f] = address.to_be_bytes();
    format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
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
