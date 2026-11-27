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

use super::{BluetoothAddress, Scale, ScaleSetupInfo, SignalStrength, Weight, WeightDecoder};

const STOP_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CANDIDATE_LIFETIME: Duration = Duration::from_secs(30);
const XIAOMI_COMPANY_ID: u16 = 0x038f;

/// Receives Bluetooth discoveries and controls how long the scan stays active.
pub trait ScaleScanObserver {
    /// `broadcast_weight` is the weight from this packet. `scale.weight()` retains the latest value.
    /// Return `ControlFlow::Break` to stop the scan after a discovery.
    fn scale_discovered(
        &mut self,
        scale: &Scale,
        broadcast_weight: Option<Weight>,
    ) -> ControlFlow<()>;

    /// Checked before waiting for the next advertisement.
    fn should_scan(&mut self) -> bool {
        true
    }
}

struct Advertisement {
    address: BluetoothAddress,
    is_s200: bool,
    name: Option<String>,
    signal_strength: SignalStrength,
    connectable: bool,
    address_type: Option<BluetoothAddressType>,
    weight: Option<Weight>,
    setup_info: Option<ScaleSetupInfo>,
}

struct Candidate {
    is_s200: bool,
    scale: Scale,
    last_seen: Instant,
}

enum ScanWindow {
    Timed(Instant),
    Continuous,
}

impl ScanWindow {
    fn next_wait(&self) -> Option<Duration> {
        match self {
            Self::Timed(deadline) => deadline
                .checked_duration_since(Instant::now())
                .map(|remaining| remaining.min(STOP_CHECK_INTERVAL)),
            Self::Continuous => Some(STOP_CHECK_INTERVAL),
        }
    }
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
    fn start(sender: Sender<Event>, decoder: Option<WeightDecoder>) -> io::Result<Self> {
        let mut watcher = Self {
            inner: BluetoothLEAdvertisementWatcher::new()?,
            received: None,
            stopped: None,
        };
        watcher
            .inner
            .SetScanningMode(BluetoothLEScanningMode::Active)?;
        // Setup and ordinary discovery need these packets even without a weight key.
        let _ = watcher.inner.SetAllowExtendedAdvertisements(true);

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
                if let Ok(Some(advertisement)) = read_advertisement(args, decoder.as_ref()) {
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
    decoder: Option<WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid scan duration"))?;
    run_scan(ScanWindow::Timed(deadline), decoder, observer)
}

pub(super) fn watch(
    decoder: Option<WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    run_scan(ScanWindow::Continuous, decoder, observer)
}

fn run_scan(
    window: ScanWindow,
    decoder: Option<WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel();
    let watcher = Watcher::start(sender, decoder)?;
    let result = wait_for_scales(window, receiver, observer);
    result.and(watcher.stop())
}

fn wait_for_scales(
    window: ScanWindow,
    receiver: Receiver<Event>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let mut candidates = HashMap::<BluetoothAddress, Candidate>::new();
    let mut next_prune = Instant::now() + CANDIDATE_LIFETIME;

    while observer.should_scan()
        && let Some(remaining) = window.next_wait()
    {
        let now = Instant::now();
        if matches!(window, ScanWindow::Continuous) && now >= next_prune {
            candidates.retain(|_, candidate| {
                now.duration_since(candidate.last_seen) < CANDIDATE_LIFETIME
            });
            next_prune = now + CANDIDATE_LIFETIME;
        }
        match receiver.recv_timeout(remaining) {
            Ok(Event::Advertisement(advertisement)) => {
                let received_weight = advertisement.weight;
                // Identification and connectability can be reported in separate packets.
                let candidate =
                    candidates
                        .entry(advertisement.address)
                        .or_insert_with(|| Candidate {
                            is_s200: false,
                            last_seen: Instant::now(),
                            scale: Scale {
                                address: advertisement.address,
                                address_type: None,
                                name: None,
                                signal_strength: advertisement.signal_strength,
                                connectable: false,
                                weight: None,
                                setup_info: None,
                            },
                        });
                candidate.last_seen = Instant::now();
                let changed = candidate.update(advertisement);
                let fresh_weight = matches!(window, ScanWindow::Continuous)
                    && candidate.is_s200
                    && received_weight.is_some();
                if (changed || fresh_weight)
                    && observer
                        .scale_discovered(&candidate.scale, received_weight)
                        .is_break()
                {
                    break;
                }
            }
            Ok(Event::Stopped(code)) => return Err(stopped_error(code)),
            Err(RecvTimeoutError::Timeout) => {}
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
        let weight = advertisement.weight.or(scale.weight);
        let setup_info = advertisement.setup_info.or(scale.setup_info);
        let name_changed = advertisement
            .name
            .as_ref()
            .is_some_and(|name| scale.name.as_ref() != Some(name));
        let changed = !self.is_s200
            || scale.address_type != address_type
            || scale.signal_strength != advertisement.signal_strength
            || scale.connectable != connectable
            || scale.weight != weight
            || scale.setup_info != setup_info
            || name_changed;

        self.is_s200 |= advertisement.is_s200;
        scale.address_type = address_type;
        scale.signal_strength = advertisement.signal_strength;
        scale.connectable = connectable;
        scale.weight = weight;
        scale.setup_info = setup_info;
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
    decoder: Option<&WeightDecoder>,
) -> windows::core::Result<Option<Advertisement>> {
    let address = args.BluetoothAddress()?;
    let signal_dbm = args.RawSignalStrengthInDBm()?;
    // Skip anonymous advertisements and out-of-range notices containing stale data.
    if address == 0 || signal_dbm == -127 {
        return Ok(None);
    }
    let address = BluetoothAddress(address);

    let payload = args.Advertisement().ok();
    let name = payload
        .as_ref()
        .and_then(|payload| payload.LocalName().ok())
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.trim().is_empty());
    let name_matches = name.as_ref().is_some_and(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized.starts_with("xiaomi scale s200")
            || normalized.starts_with("xiaomi smart scale s200")
    });
    let (setup_info, weight) = payload
        .as_ref()
        .map(|payload| {
            let (info, weight) = inspect_service_data(payload, address, decoder);
            (info.or_else(|| inspect_manufacturer_data(payload)), weight)
        })
        .unwrap_or_default();
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
        is_s200: name_matches || setup_info.is_some(),
        name,
        signal_strength: SignalStrength(signal_dbm),
        connectable,
        address_type,
        weight,
        setup_info,
    }))
}

fn inspect_manufacturer_data(payload: &BluetoothLEAdvertisement) -> Option<ScaleSetupInfo> {
    // Xiaomi also sends MiBeacon without the FE95 prefix under its company ID.
    let sections = payload
        .GetManufacturerDataByCompanyId(XIAOMI_COMPANY_ID)
        .ok()?;
    for section in sections {
        let Ok(reader) = section
            .Data()
            .and_then(|buffer| DataReader::FromBuffer(&buffer))
        else {
            continue;
        };
        let mut header = [0; 4];
        if reader.ReadBytes(&mut header).is_ok()
            && let Some(info) = ScaleSetupInfo::from_mibeacon_frame(&header)
        {
            return Some(info);
        }
    }
    None
}

fn inspect_service_data(
    payload: &BluetoothLEAdvertisement,
    address: BluetoothAddress,
    decoder: Option<&WeightDecoder>,
) -> (Option<ScaleSetupInfo>, Option<Weight>) {
    // AD type 0x16 carries 16-bit service data, including Xiaomi MiBeacon.
    let Ok(sections) = payload.GetSectionsByType(0x16) else {
        return (None, None);
    };
    let mut detected = None;
    for section in sections {
        let Ok(reader) = section
            .Data()
            .and_then(|buffer| DataReader::FromBuffer(&buffer))
        else {
            continue;
        };
        let mut header = [0; 6];
        if reader.ReadBytes(&mut header).is_err() {
            continue;
        }
        let Some(setup_info) = ScaleSetupInfo::from_mibeacon(&header) else {
            continue;
        };
        detected = Some(setup_info);
        let Some(decoder) = decoder else { break };
        let Ok(length) = reader.UnconsumedBufferLength() else {
            continue;
        };
        let mut data = header.to_vec();
        data.resize(header.len() + length as usize, 0);
        if reader.ReadBytes(&mut data[header.len()..]).is_err() {
            continue;
        }
        if let Some(weight) = decoder.decode(address, &data) {
            return (Some(setup_info), Some(weight));
        }
    }
    (detected, None)
}

#[cfg(test)]
mod tests {
    use super::{
        Advertisement, BluetoothAddress, BluetoothAddressType, ControlFlow, Duration, Event,
        Instant, Scale, ScaleScanObserver, ScanWindow, SignalStrength, Weight, mpsc,
        wait_for_scales,
    };

    #[test]
    fn continuous_scan_stays_active_through_idle_wait_and_honors_cancellation() {
        #[derive(Default)]
        struct IdleScan {
            waits: usize,
        }

        impl ScaleScanObserver for IdleScan {
            fn should_scan(&mut self) -> bool {
                self.waits += 1;
                self.waits <= 2
            }

            fn scale_discovered(&mut self, _: &Scale, _: Option<Weight>) -> ControlFlow<()> {
                ControlFlow::Continue(())
            }
        }

        let (_sender, receiver) = mpsc::channel();
        let mut scan = IdleScan::default();
        wait_for_scales(ScanWindow::Continuous, receiver, &mut scan).unwrap();
        assert_eq!(scan.waits, 3);
    }

    #[test]
    fn reports_each_scale_and_combines_advertisements_by_address() {
        let (sender, receiver) = mpsc::channel();
        let address_type = Some(BluetoothAddressType::Public);
        for (address, is_s200, connectable, weight) in [
            (12, true, false, None),
            (34, false, true, None),
            (12, false, true, None),
            (12, false, true, Some(Weight(7255))),
            (12, false, true, None),
            (56, true, false, None),
        ] {
            sender
                .send(Event::Advertisement(Advertisement {
                    address: BluetoothAddress(address),
                    is_s200,
                    name: is_s200.then(|| format!("Xiaomi Scale S200 {address}")),
                    signal_strength: SignalStrength(-60),
                    connectable,
                    address_type,
                    weight,
                    setup_info: None,
                }))
                .unwrap();
        }

        #[derive(Default)]
        struct DiscoveryLog {
            updates: Vec<(BluetoothAddress, bool, String, Option<Weight>)>,
        }

        impl ScaleScanObserver for DiscoveryLog {
            fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
                self.updates.push((
                    scale.address(),
                    scale.is_connectable(),
                    scale.name().to_string(),
                    scale.weight(),
                ));
                if scale.address() == BluetoothAddress(56) {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
        }

        let mut scan = DiscoveryLog::default();
        wait_for_scales(
            ScanWindow::Timed(Instant::now() + Duration::from_secs(1)),
            receiver,
            &mut scan,
        )
        .unwrap();
        assert_eq!(
            scan.updates,
            [
                (
                    BluetoothAddress(12),
                    false,
                    "Xiaomi Scale S200 12".to_owned(),
                    None,
                ),
                (
                    BluetoothAddress(12),
                    true,
                    "Xiaomi Scale S200 12".to_owned(),
                    None,
                ),
                (
                    BluetoothAddress(12),
                    true,
                    "Xiaomi Scale S200 12".to_owned(),
                    Some(Weight(7255)),
                ),
                (
                    BluetoothAddress(56),
                    false,
                    "Xiaomi Scale S200 56".to_owned(),
                    None,
                ),
            ]
        );
    }
}
