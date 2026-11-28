use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementType, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStoppedEventArgs, BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::BluetoothAddressType;
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, IBuffer};

use crate::discovery::{Advertisement, AdvertisementSource, ScanMode};
use crate::{AddressKind, Apartment, BluetoothAddress, SignalStrength};

const SERVICE_DATA_16_BIT: u8 = 0x16;
const XIAOMI_COMPANY_ID: u16 = 0x038f;

pub(super) struct NativeAdvertisements {
    watcher: BluetoothLEAdvertisementWatcher,
    received: Option<i64>,
    stopped: Option<i64>,
    events: Receiver<io::Result<Advertisement>>,
    _apartment: Apartment,
}

impl NativeAdvertisements {
    pub(super) fn start(mode: ScanMode) -> io::Result<Self> {
        let apartment = Apartment::initialize()?;
        let (sender, events) = mpsc::channel();
        let mut source = Self {
            watcher: BluetoothLEAdvertisementWatcher::new()?,
            received: None,
            stopped: None,
            events,
            _apartment: apartment,
        };
        source.watcher.SetScanningMode(winrt_scan_mode(mode))?;
        let _ = source.watcher.SetAllowExtendedAdvertisements(true);

        type ReceivedHandler = TypedEventHandler<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
        >;
        type StoppedHandler = TypedEventHandler<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementWatcherStoppedEventArgs,
        >;
        let received_sender = sender.clone();
        source.received = Some(source.watcher.Received(&ReceivedHandler::new(
            move |_, args| {
                if let Some(args) = args.as_ref()
                    && let Ok(Some(advertisement)) = read_advertisement(args)
                {
                    let _ = received_sender.send(Ok(advertisement));
                }
                Ok(())
            },
        ))?);
        source.stopped = Some(
            source
                .watcher
                .Stopped(&StoppedHandler::new(move |_, args| {
                    if let Some(args) = args.as_ref() {
                        let _ = sender.send(Err(stopped_error(args.Error()?.0)));
                    }
                    Ok(())
                }))?,
        );
        source.watcher.Start()?;
        Ok(source)
    }
}

impl AdvertisementSource for NativeAdvertisements {
    fn next_advertisement(&mut self, timeout: Duration) -> io::Result<Option<Advertisement>> {
        match self.events.recv_timeout(timeout) {
            Ok(event) => event.map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("lost the Windows scan event handler"))
            }
        }
    }

    fn stop(self) -> io::Result<()> {
        Ok(self.watcher.Stop()?)
    }
}

impl Drop for NativeAdvertisements {
    fn drop(&mut self) {
        if let Some(token) = self.received {
            let _ = self.watcher.RemoveReceived(token);
        }
        if let Some(token) = self.stopped {
            let _ = self.watcher.RemoveStopped(token);
        }
    }
}

fn winrt_scan_mode(mode: ScanMode) -> BluetoothLEScanningMode {
    match mode {
        ScanMode::Active => BluetoothLEScanningMode::Active,
        ScanMode::Passive => BluetoothLEScanningMode::Passive,
    }
}

fn stopped_error(code: i32) -> io::Error {
    let message = match code {
        0 => "Windows stopped the scan early",
        1 => "the Bluetooth radio is unavailable or turned off",
        2 => "the Bluetooth radio is busy",
        5 => "Bluetooth is disabled by system policy",
        6 | 9 => "the Bluetooth radio does not support Low Energy scanning",
        7 => "Windows reported Bluetooth disabled in this session",
        8 => "Windows requires permission to scan",
        _ => return io::Error::other(format!("Windows stopped the scan (Bluetooth error {code})")),
    };
    io::Error::other(message)
}

fn read_advertisement(
    args: &BluetoothLEAdvertisementReceivedEventArgs,
) -> windows::core::Result<Option<Advertisement>> {
    let received_at = Instant::now();
    let address = args.BluetoothAddress()?;
    let signal_dbm = args.RawSignalStrengthInDBm()?;
    // WinRT reports anonymous packets at address zero and stale entries at -127 dBm.
    if address == 0 || signal_dbm == -127 {
        return Ok(None);
    }

    let payload = args
        .Advertisement()
        .ok()
        .as_ref()
        .map(read_payload)
        .unwrap_or_default();
    let connectable = match args.AdvertisementType() {
        Ok(
            BluetoothLEAdvertisementType::ConnectableUndirected
            | BluetoothLEAdvertisementType::ConnectableDirected,
        ) => true,
        Ok(BluetoothLEAdvertisementType::Extended) => args.IsConnectable().unwrap_or(false),
        _ => false,
    };
    let address_type = match args.BluetoothAddressType() {
        Ok(BluetoothAddressType::Public) => Some(AddressKind::Public),
        Ok(BluetoothAddressType::Random) => Some(AddressKind::Random),
        _ => None,
    };

    Ok(Some(Advertisement {
        address: BluetoothAddress(address),
        received_at,
        name: payload.name,
        signal_strength: SignalStrength(signal_dbm),
        connectable,
        address_type,
        service_data: payload.service_data,
        xiaomi_manufacturer_data: payload.xiaomi_manufacturer_data,
    }))
}

#[derive(Default)]
struct AdvertisementPayload {
    name: Option<String>,
    service_data: Vec<Vec<u8>>,
    xiaomi_manufacturer_data: Vec<Vec<u8>>,
}

fn read_payload(payload: &BluetoothLEAdvertisement) -> AdvertisementPayload {
    let name = payload.LocalName().ok().map(|name| name.to_string_lossy());
    let service_data = payload
        .GetSectionsByType(SERVICE_DATA_16_BIT)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|section| section.Data().and_then(read_bytes).ok())
        .collect();
    let xiaomi_manufacturer_data = payload
        .GetManufacturerDataByCompanyId(XIAOMI_COMPANY_ID)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|section| section.Data().and_then(read_bytes).ok())
        .collect();
    AdvertisementPayload {
        name,
        service_data,
        xiaomi_manufacturer_data,
    }
}

fn read_bytes(buffer: IBuffer) -> windows::core::Result<Vec<u8>> {
    let reader = DataReader::FromBuffer(&buffer)?;
    let mut bytes = vec![0; reader.UnconsumedBufferLength()? as usize];
    reader.ReadBytes(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementDataSection, BluetoothLEManufacturerData,
    };
    use windows::Storage::Streams::DataWriter;
    use windows::core::HSTRING;

    use super::*;

    fn buffer(bytes: &[u8]) -> IBuffer {
        let writer = DataWriter::new().unwrap();
        writer.WriteBytes(bytes).unwrap();
        writer.DetachBuffer().unwrap()
    }

    #[test]
    fn extracts_raw_advertisement_data_from_winrt_without_a_radio() {
        let _apartment = Apartment::initialize().unwrap();
        let advertisement = BluetoothLEAdvertisement::new().unwrap();
        advertisement
            .SetLocalName(&HSTRING::from("Xiaomi Scale S200"))
            .unwrap();
        let manufacturer = advertisement.ManufacturerData().unwrap();
        let xiaomi_data = [0x10, 0x58, 0xcb, 0x4d];
        for (company, data) in [
            (0xffff, &[0xbe, 0xef][..]),
            (XIAOMI_COMPANY_ID, &xiaomi_data),
        ] {
            manufacturer
                .Append(&BluetoothLEManufacturerData::Create(company, &buffer(data)).unwrap())
                .unwrap();
        }
        let sections = advertisement.DataSections().unwrap();
        let service_data = crate::weight::tests::WITH_MAC;
        for (data_type, data) in [
            (0x09, b"Other".as_slice()),
            (SERVICE_DATA_16_BIT, service_data),
        ] {
            sections
                .Append(
                    &BluetoothLEAdvertisementDataSection::Create(data_type, &buffer(data)).unwrap(),
                )
                .unwrap();
        }

        let payload = read_payload(&advertisement);
        assert_eq!(payload.name.as_deref(), Some("Xiaomi Scale S200"));
        assert_eq!(payload.service_data, [service_data]);
        assert_eq!(payload.xiaomi_manufacturer_data, [xiaomi_data]);
    }

    #[test]
    fn maps_scan_modes_and_stop_reasons_to_winrt() {
        assert_eq!(
            winrt_scan_mode(ScanMode::Active),
            BluetoothLEScanningMode::Active
        );
        assert_eq!(
            winrt_scan_mode(ScanMode::Passive),
            BluetoothLEScanningMode::Passive
        );
        for (code, message) in [
            (0, "stopped the scan early"),
            (1, "radio is unavailable"),
            (2, "radio is busy"),
            (5, "disabled by system policy"),
            (6, "does not support Low Energy"),
            (9, "does not support Low Energy"),
            (7, "disabled in this session"),
            (8, "requires permission"),
            (55, "Bluetooth error 55"),
        ] {
            assert!(stopped_error(code).to_string().contains(message));
        }
    }
}
