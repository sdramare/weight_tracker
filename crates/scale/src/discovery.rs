use std::collections::HashMap;
use std::io;
use std::ops::ControlFlow;
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

use super::Scale;

struct Advertisement {
    address: u64,
    is_s200: bool,
    name: Option<String>,
    signal_dbm: i16,
    connectable: bool,
    address_type: Option<BluetoothAddressType>,
}

struct Candidate {
    is_s200: bool,
    scale: Scale,
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
                let Some(args) = args.as_ref() else {
                    return Ok(());
                };
                if let Ok(Some(advertisement)) = read_advertisement(args) {
                    let _ = received_sender.send(Event::Advertisement(advertisement));
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

pub(super) fn discover(
    duration: Duration,
    on_scale: impl FnMut(&Scale) -> ControlFlow<()>,
) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel();
    let watcher = Watcher::start(sender)?;
    let result = wait_for_scales(duration, receiver, on_scale);
    result.and(watcher.stop())
}

fn wait_for_scales(
    duration: Duration,
    receiver: Receiver<Event>,
    mut on_scale: impl FnMut(&Scale) -> ControlFlow<()>,
) -> io::Result<()> {
    let deadline = Instant::now() + duration;
    let mut candidates = HashMap::<u64, Candidate>::new();

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(Event::Advertisement(advertisement)) => {
                // Identification and connectability can be reported in separate packets.
                let candidate =
                    candidates
                        .entry(advertisement.address)
                        .or_insert_with(|| Candidate {
                            is_s200: false,
                            scale: Scale {
                                address: advertisement.address,
                                address_type: None,
                                name: None,
                                signal_dbm: advertisement.signal_dbm,
                                connectable: false,
                            },
                        });
                if candidate.update(advertisement) && on_scale(&candidate.scale).is_break() {
                    break;
                }
            }
            Ok(Event::Stopped(code)) => return Err(stopped_error(code)),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("lost the Windows scan event handler"));
            }
        }
    }

    Ok(())
}

impl Candidate {
    fn update(&mut self, advertisement: Advertisement) -> bool {
        let scale = &mut self.scale;
        let address_type = advertisement.address_type.or(scale.address_type);
        let connectable = scale.connectable || advertisement.connectable;
        let name_changed = advertisement
            .name
            .as_ref()
            .is_some_and(|name| scale.name.as_ref() != Some(name));
        let changed = !self.is_s200
            || scale.address_type != address_type
            || scale.signal_dbm != advertisement.signal_dbm
            || scale.connectable != connectable
            || name_changed;

        self.is_s200 |= advertisement.is_s200;
        scale.address_type = address_type;
        scale.signal_dbm = advertisement.signal_dbm;
        scale.connectable = connectable;
        if name_changed {
            scale.name = advertisement.name;
        }
        self.is_s200 && changed
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
    let address = args.BluetoothAddress()?;
    let signal_dbm = args.RawSignalStrengthInDBm()?;
    // Skip anonymous advertisements and out-of-range notices containing stale data.
    if address == 0 || signal_dbm == -127 {
        return Ok(None);
    }

    let payload = args.Advertisement().ok();
    let name = payload
        .as_ref()
        .and_then(|payload| payload.LocalName().ok())
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.trim().is_empty());
    let is_s200 = name.as_ref().is_some_and(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized.starts_with("xiaomi scale s200")
            || normalized.starts_with("xiaomi smart scale s200")
    }) || payload.as_ref().is_some_and(is_s200_payload);
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
        name,
        signal_dbm,
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
        Advertisement, BluetoothAddressType, ControlFlow, Duration, Event, is_s200_service_data,
        mpsc, wait_for_scales,
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
    fn reports_each_scale_and_combines_advertisements_by_address() {
        let (sender, receiver) = mpsc::channel();
        let address_type = Some(BluetoothAddressType::Public);
        for (address, is_s200, connectable) in [
            (12, true, false),
            (34, false, true),
            (12, false, true),
            (12, false, true),
            (56, true, false),
        ] {
            sender
                .send(Event::Advertisement(Advertisement {
                    address,
                    is_s200,
                    name: is_s200.then(|| format!("Xiaomi Scale S200 {address}")),
                    signal_dbm: -60,
                    connectable,
                    address_type,
                }))
                .unwrap();
        }

        let mut updates = Vec::new();
        wait_for_scales(Duration::from_secs(1), receiver, |scale| {
            updates.push((
                scale.address(),
                scale.is_connectable(),
                scale.name().to_owned(),
            ));
            if scale.address() == 56 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
        assert_eq!(
            updates,
            [
                (12, false, "Xiaomi Scale S200 12".to_owned()),
                (12, true, "Xiaomi Scale S200 12".to_owned()),
                (56, false, "Xiaomi Scale S200 56".to_owned()),
            ]
        );
    }
}
