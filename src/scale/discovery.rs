use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementType, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStoppedEventArgs, BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::BluetoothAddressType;
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;

struct Advertisement {
    address: u64,
    is_s200: bool,
    connectable: bool,
    address_type: Option<BluetoothAddressType>,
}

#[derive(Default)]
struct Candidate {
    is_s200: bool,
    connectable: bool,
    address_type: Option<BluetoothAddressType>,
}

enum Event {
    Advertisement(Advertisement),
    Stopped(i32),
}

struct Watcher {
    inner: BluetoothLEAdvertisementWatcher,
    received: Option<i64>,
    stopped: Option<i64>,
}

impl Watcher {
    fn start(sender: Sender<Event>) -> io::Result<Self> {
        let mut watcher = Self {
            inner: BluetoothLEAdvertisementWatcher::new()?,
            received: None,
            stopped: None,
        };
        watcher
            .inner
            .SetScanningMode(BluetoothLEScanningMode::Active)?;

        type ReceivedHandler = TypedEventHandler<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
        >;
        type StoppedHandler = TypedEventHandler<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementWatcherStoppedEventArgs,
        >;
        let received_sender = sender.clone();
        watcher.received = Some(watcher.inner.Received(&ReceivedHandler::new(
            move |_, args| {
                if let Some(args) = args.as_ref() {
                    if let Ok(Some(advertisement)) = read_advertisement(args) {
                        let _ = received_sender.send(Event::Advertisement(advertisement));
                    }
                }
                Ok(())
            },
        ))?);
        watcher.stopped = Some(watcher.inner.Stopped(&StoppedHandler::new(move |_, args| {
            if let Some(args) = args.as_ref() {
                let _ = sender.send(Event::Stopped(args.Error()?.0));
            }
            Ok(())
        }))?);
        watcher.inner.Start()?;
        Ok(watcher)
    }

    fn stop(self) -> io::Result<()> {
        Ok(self.inner.Stop()?)
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(token) = self.received {
            let _ = self.inner.RemoveReceived(token);
        }
        if let Some(token) = self.stopped {
            let _ = self.inner.RemoveStopped(token);
        }
    }
}

pub(super) fn find_scale(duration: Duration) -> io::Result<(u64, Option<BluetoothAddressType>)> {
    let (sender, receiver) = mpsc::channel();
    let watcher = Watcher::start(sender)?;
    let result = wait_for_scale(duration, receiver);
    let stopped = watcher.stop();
    let target = result?;
    stopped?;
    Ok(target)
}

fn wait_for_scale(
    duration: Duration,
    receiver: Receiver<Event>,
) -> io::Result<(u64, Option<BluetoothAddressType>)> {
    let deadline = Instant::now() + duration;
    let mut candidates = HashMap::<u64, Candidate>::new();

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(Event::Advertisement(advertisement)) => {
                // Identification and connectability can be reported in separate packets.
                let candidate = candidates.entry(advertisement.address).or_default();
                candidate.is_s200 |= advertisement.is_s200;
                candidate.connectable |= advertisement.connectable;
                candidate.address_type = advertisement.address_type.or(candidate.address_type);
                if candidate.is_s200 && candidate.connectable {
                    return Ok((advertisement.address, candidate.address_type));
                }
            }
            Ok(Event::Stopped(code)) => return Err(stopped_error(code)),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("lost the Windows scan event handler"));
            }
        }
    }

    let message = if candidates.values().any(|candidate| candidate.is_s200) {
        "the S200 was detected, but did not offer a connection. Close Xiaomi Home and wake the scale again"
    } else {
        "no Xiaomi Smart Scale S200 was detected. Keep it near the PC and wake it during the scan"
    };
    Err(io::Error::new(io::ErrorKind::NotFound, message))
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
    let address = args.BluetoothAddress()?;
    // Skip anonymous advertisements and out-of-range notices containing stale data.
    if address == 0 || args.RawSignalStrengthInDBm()? == -127 {
        return Ok(None);
    }

    let payload = args.Advertisement().ok();
    let name = payload
        .as_ref()
        .and_then(|payload| payload.LocalName().ok())
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let is_s200 = name.starts_with("xiaomi scale s200")
        || name.starts_with("xiaomi smart scale s200")
        || payload.as_ref().is_some_and(is_s200_payload);
    let connectable = match args.AdvertisementType() {
        Ok(
            BluetoothLEAdvertisementType::ConnectableUndirected
            | BluetoothLEAdvertisementType::ConnectableDirected,
        ) => true,
        Ok(BluetoothLEAdvertisementType::Extended) => args.IsConnectable().unwrap_or(false),
        _ => false,
    };
    let address_type = args.BluetoothAddressType().ok().filter(|kind| {
        matches!(
            *kind,
            BluetoothAddressType::Public | BluetoothAddressType::Random
        )
    });

    Ok(Some(Advertisement {
        address,
        is_s200,
        connectable,
        address_type,
    }))
}

fn is_s200_payload(payload: &BluetoothLEAdvertisement) -> bool {
    // AD type 0x16 carries 16-bit service data, including Xiaomi MiBeacon.
    let Ok(sections) = payload.GetSectionsByType(0x16) else {
        return false;
    };
    sections.into_iter().any(|section| {
        section
            .Data()
            .and_then(|buffer| DataReader::FromBuffer(&buffer))
            .and_then(|reader| {
                let mut header = [0; 6];
                reader.ReadBytes(&mut header)?;
                Ok(is_s200_service_data(&header))
            })
            .unwrap_or(false)
    })
}

fn is_s200_service_data(data: &[u8]) -> bool {
    // MiBeacon's service UUID (0xFE95) precedes the frame control and product ID.
    matches!(data, [0x95, 0xfe, _, _, low, high, ..]
        if matches!(u16::from_le_bytes([*low, *high]), 0x45c9 | 0x4c04 | 0x4dcb))
}

#[cfg(test)]
mod tests {
    use super::{
        Advertisement, BluetoothAddressType, Duration, Event, is_s200_service_data, mpsc,
        wait_for_scale,
    };

    #[test]
    fn recognizes_s200_mibeacon_headers() {
        assert!(is_s200_service_data(&[0x95, 0xfe, 0x10, 0x5b, 0xcb, 0x4d]));
        assert!(is_s200_service_data(&[0x95, 0xfe, 0x10, 0x59, 0x04, 0x4c]));
        assert!(is_s200_service_data(&[0x95, 0xfe, 0x10, 0x5b, 0xc9, 0x45]));
        assert!(!is_s200_service_data(&[0x95, 0xfe, 0x10, 0x5b, 0xd5, 0x3b]));
        assert!(!is_s200_service_data(&[0x95, 0xfe, 0x10, 0x5b, 0xcb]));
        assert!(!is_s200_service_data(&[0x16, 0x18, 0x10, 0x5b, 0xcb, 0x4d]));
    }

    #[test]
    fn combines_scale_advertisements_from_the_same_address() {
        let (sender, receiver) = mpsc::channel();
        let address_type = Some(BluetoothAddressType::Public);
        for (address, is_s200, connectable) in
            [(12, true, false), (34, false, true), (12, false, true)]
        {
            sender
                .send(Event::Advertisement(Advertisement {
                    address,
                    is_s200,
                    connectable,
                    address_type,
                }))
                .unwrap();
        }

        let found = wait_for_scale(Duration::from_secs(1), receiver).unwrap();
        assert_eq!(found, (12, address_type));
    }
}
