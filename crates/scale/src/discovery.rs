#[cfg(any(windows, test))]
use std::collections::HashMap;
#[cfg(any(windows, test))]
use std::io;
use std::ops::ControlFlow;
#[cfg(windows)]
use std::sync::mpsc::{self, Sender};
#[cfg(any(windows, test))]
use std::sync::mpsc::{Receiver, RecvTimeoutError};
#[cfg(any(windows, test))]
use std::time::Duration;
use std::time::Instant;

#[cfg(windows)]
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementType, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStoppedEventArgs, BluetoothLEScanningMode,
};
#[cfg(windows)]
use windows::Devices::Bluetooth::BluetoothAddressType;
#[cfg(windows)]
use windows::Foundation::TypedEventHandler;
#[cfg(windows)]
use windows::Storage::Streams::DataReader;

#[cfg(windows)]
use super::WeightDecoder;
#[cfg(any(windows, test))]
use super::{AddressKind, BluetoothAddress, ScaleSetupInfo, SignalStrength};
use super::{Scale, Weight};

#[cfg(any(windows, test))]
const STOP_CHECK_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(any(windows, test))]
const CANDIDATE_LIFETIME: Duration = Duration::from_secs(30);
#[cfg(windows)]
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

    /// In a continuous scan, receives each advertisement that offers a connection.
    /// The timestamp is captured when Windows delivers the packet.
    fn connection_offered(&mut self, _scale: &Scale, _received_at: Instant) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }

    /// Checked before waiting for the next advertisement.
    fn should_scan(&mut self) -> bool {
        true
    }
}

#[cfg(any(windows, test))]
struct Advertisement {
    address: BluetoothAddress,
    received_at: Instant,
    is_s200: bool,
    name: Option<String>,
    signal_strength: SignalStrength,
    connectable: bool,
    address_type: Option<AddressKind>,
    weight: Option<Weight>,
    setup_info: Option<ScaleSetupInfo>,
}

#[cfg(any(windows, test))]
struct Candidate {
    is_s200: bool,
    scale: Scale,
    last_seen: Instant,
}

#[cfg(any(windows, test))]
enum ScanWindow {
    Timed(Instant),
    Continuous,
}

#[cfg(any(windows, test))]
impl ScanWindow {
    #[cfg(windows)]
    fn scanning_mode(&self) -> BluetoothLEScanningMode {
        match self {
            Self::Timed(_) => BluetoothLEScanningMode::Active,
            Self::Continuous => BluetoothLEScanningMode::Passive,
        }
    }

    fn next_wait(&self) -> Option<Duration> {
        match self {
            Self::Timed(deadline) => deadline
                .checked_duration_since(Instant::now())
                .map(|remaining| remaining.min(STOP_CHECK_INTERVAL)),
            Self::Continuous => Some(STOP_CHECK_INTERVAL),
        }
    }
}

#[cfg(any(windows, test))]
enum Event {
    Advertisement(Advertisement),
    Stopped(i32),
}

#[cfg(windows)]
struct Watcher {
    inner: BluetoothLEAdvertisementWatcher,
    received: Option<i64>,
    stopped: Option<i64>,
}

#[cfg(windows)]
impl Watcher {
    fn start(
        sender: Sender<Event>,
        decoder: Option<WeightDecoder>,
        mode: BluetoothLEScanningMode,
    ) -> io::Result<Self> {
        let mut watcher = Self {
            inner: BluetoothLEAdvertisementWatcher::new()?,
            received: None,
            stopped: None,
        };
        watcher.inner.SetScanningMode(mode)?;
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
pub(super) fn watch(
    decoder: Option<WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    run_scan(ScanWindow::Continuous, decoder, observer)
}

#[cfg(windows)]
fn run_scan(
    window: ScanWindow,
    decoder: Option<WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel();
    let watcher = Watcher::start(sender, decoder, window.scanning_mode())?;
    let result = wait_for_scales(window, receiver, observer);
    result.and(watcher.stop())
}

#[cfg(any(windows, test))]
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
                let received_at = advertisement.received_at;
                let offers_connection = advertisement.connectable;
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
                if matches!(window, ScanWindow::Continuous)
                    && candidate.is_s200
                    && offers_connection
                    && observer
                        .connection_offered(&candidate.scale, received_at)
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

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
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

#[cfg(windows)]
fn read_advertisement(
    args: &BluetoothLEAdvertisementReceivedEventArgs,
    decoder: Option<&WeightDecoder>,
) -> windows::core::Result<Option<Advertisement>> {
    let received_at = Instant::now();
    let address = args.BluetoothAddress()?;
    let signal_dbm = args.RawSignalStrengthInDBm()?;
    // Skip anonymous advertisements and out-of-range notices containing stale data.
    if address == 0 || signal_dbm == -127 {
        return Ok(None);
    }
    let address = BluetoothAddress(address);

    let payload = args.Advertisement().ok();
    let AdvertisementPayload {
        name,
        is_s200,
        setup_info,
        weight,
    } = payload
        .as_ref()
        .map(|payload| inspect_payload(payload, address, decoder))
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
        address,
        received_at,
        is_s200,
        name,
        signal_strength: SignalStrength(signal_dbm),
        connectable,
        address_type,
        weight,
        setup_info,
    }))
}

#[cfg(windows)]
#[derive(Default)]
struct AdvertisementPayload {
    name: Option<String>,
    is_s200: bool,
    setup_info: Option<ScaleSetupInfo>,
    weight: Option<Weight>,
}

#[cfg(windows)]
fn inspect_payload(
    payload: &BluetoothLEAdvertisement,
    address: BluetoothAddress,
    decoder: Option<&WeightDecoder>,
) -> AdvertisementPayload {
    let name = payload
        .LocalName()
        .ok()
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.trim().is_empty());
    let name_matches = name.as_ref().is_some_and(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized.starts_with("xiaomi scale s200")
            || normalized.starts_with("xiaomi smart scale s200")
    });
    let (info, weight) = inspect_service_data(payload, address, decoder);
    let setup_info = info.or_else(|| inspect_manufacturer_data(payload));
    AdvertisementPayload {
        name,
        is_s200: name_matches || setup_info.is_some(),
        setup_info,
        weight,
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
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
    use std::sync::mpsc;

    #[cfg(windows)]
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementDataSection, BluetoothLEManufacturerData,
    };
    #[cfg(windows)]
    use windows::Storage::Streams::{DataWriter, IBuffer};
    #[cfg(windows)]
    use windows::core::HSTRING;

    use super::*;

    #[cfg(windows)]
    fn buffer(bytes: &[u8]) -> IBuffer {
        let writer = DataWriter::new().unwrap();
        writer.WriteBytes(bytes).unwrap();
        writer.DetachBuffer().unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn inspects_real_winrt_advertisement_sections_without_a_radio() {
        let _apartment = crate::Apartment::initialize().unwrap();
        let address = BluetoothAddress(0x1234_5678_9abc);
        let advertisement = BluetoothLEAdvertisement::new().unwrap();
        advertisement.SetLocalName(&HSTRING::from("  ")).unwrap();
        let payload = inspect_payload(&advertisement, address, None);
        assert!(!payload.is_s200);
        assert!(payload.name.is_none());

        advertisement
            .SetLocalName(&HSTRING::from("XIAOMI SMART SCALE S200"))
            .unwrap();
        assert!(inspect_payload(&advertisement, address, None).is_s200);
        advertisement
            .SetLocalName(&HSTRING::from("Other accessory"))
            .unwrap();
        let manufacturer = advertisement.ManufacturerData().unwrap();
        for (company, data) in [
            (0xffff, &[0x10, 0x58, 0xcb, 0x4d][..]),
            (XIAOMI_COMPANY_ID, &[0x10][..]),
            (XIAOMI_COMPANY_ID, &[0x10, 0x58, 0xcb, 0x4d][..]),
        ] {
            manufacturer
                .Append(&BluetoothLEManufacturerData::Create(company, &buffer(data)).unwrap())
                .unwrap();
        }
        let manufacturer_only = inspect_payload(&advertisement, address, None);
        assert!(manufacturer_only.is_s200);
        assert!(manufacturer_only.setup_info.unwrap().is_ms113());

        let sections = advertisement.DataSections().unwrap();
        for bytes in [
            &[0x95, 0xfe][..],
            &[0x01, 0x18, 0x10, 0x59, 0xcb, 0x4d][..],
            &[0x95, 0xfe, 0x10, 0x59, 0x04, 0x4c][..],
            crate::weight::tests::WITH_MAC,
        ] {
            sections
                .Append(&BluetoothLEAdvertisementDataSection::Create(0x16, &buffer(bytes)).unwrap())
                .unwrap();
        }
        let key = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        let decoded = inspect_payload(&advertisement, address, Some(&WeightDecoder::new(&key)));
        assert_eq!(decoded.weight, Some(Weight(7255)));
        assert!(!decoded.setup_info.unwrap().is_ms113());
        let without_key = inspect_payload(&advertisement, address, None);
        assert!(without_key.weight.is_none());
        assert_eq!(without_key.setup_info, decoded.setup_info);
    }

    #[test]
    fn reports_why_windows_stopped_an_active_scan() {
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
            let (sender, receiver) = mpsc::channel();
            sender.send(Event::Stopped(code)).unwrap();
            let error = wait_for_scales(
                ScanWindow::Continuous,
                receiver,
                &mut crate::ConnectableScaleSearch::default(),
            )
            .unwrap_err();
            assert!(error.to_string().contains(message));
        }
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let error = wait_for_scales(
            ScanWindow::Continuous,
            receiver,
            &mut crate::ConnectableScaleSearch::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("lost the Windows scan event handler")
        );
    }

    #[cfg(windows)]
    #[test]
    fn only_timed_discovery_requests_scan_responses() {
        assert_eq!(
            ScanWindow::Continuous.scanning_mode(),
            BluetoothLEScanningMode::Passive
        );
        assert_eq!(
            ScanWindow::Timed(Instant::now()).scanning_mode(),
            BluetoothLEScanningMode::Active
        );
    }

    #[test]
    fn continuous_scan_reports_repeated_connection_offers_from_current_packets() {
        #[derive(Default)]
        struct ConnectionOffers(Vec<Instant>);

        impl ScaleScanObserver for ConnectionOffers {
            fn scale_discovered(&mut self, _: &Scale, _: Option<Weight>) -> ControlFlow<()> {
                ControlFlow::Continue(())
            }

            fn connection_offered(&mut self, _: &Scale, received_at: Instant) -> ControlFlow<()> {
                self.0.push(received_at);
                if self.0.len() == 3 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
        }

        let start = Instant::now();
        let (sender, receiver) = mpsc::channel();
        for (seconds, connectable) in [(0, true), (1, true), (2, false), (3, true)] {
            sender
                .send(Event::Advertisement(Advertisement {
                    address: BluetoothAddress(12),
                    received_at: start + Duration::from_secs(seconds),
                    is_s200: true,
                    name: None,
                    signal_strength: SignalStrength(-60),
                    connectable,
                    address_type: None,
                    weight: None,
                    setup_info: None,
                }))
                .unwrap();
        }
        drop(sender);
        let mut offers = ConnectionOffers::default();
        wait_for_scales(ScanWindow::Continuous, receiver, &mut offers).unwrap();
        assert_eq!(
            offers.0,
            [0, 1, 3].map(|seconds| start + Duration::from_secs(seconds))
        );
    }

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
        let address_type = Some(AddressKind::Public);
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
                    received_at: Instant::now(),
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
