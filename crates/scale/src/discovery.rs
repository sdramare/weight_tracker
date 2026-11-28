use std::collections::HashMap;
use std::io;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use crate::weight::WeightDecoder;
use crate::{
    AddressKind, BluetoothAddress, Scale, ScaleBindKey, ScaleSetupInfo, SignalStrength, Weight,
};

const STOP_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CANDIDATE_LIFETIME: Duration = Duration::from_secs(30);

/// Receives Bluetooth discoveries and controls how long the scan stays active.
pub trait ScaleScanObserver {
    /// The broadcast weight comes from this packet. The scale retains the latest value.
    /// Return ControlFlow::Break to stop the scan after a discovery.
    fn scale_discovered(
        &mut self,
        scale: &Scale,
        broadcast_weight: Option<Weight>,
    ) -> ControlFlow<()>;

    /// In a continuous scan, receives each advertisement that offers a connection.
    /// The source captures the timestamp when it receives the packet.
    fn connection_offered(&mut self, _scale: &Scale, _received_at: Instant) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }

    /// Checked before waiting for the next advertisement.
    fn should_scan(&mut self) -> bool {
        true
    }
}

/// Delivers advertisements from a running Bluetooth scan.
pub(super) trait AdvertisementSource {
    /// An empty result means the wait timed out. A stopped or failed source returns an error.
    fn next_advertisement(&mut self, timeout: Duration) -> io::Result<Option<Advertisement>>;

    fn stop(self) -> io::Result<()>;
}

pub(super) struct Advertisement {
    pub(super) address: BluetoothAddress,
    pub(super) received_at: Instant,
    pub(super) name: Option<String>,
    pub(super) signal_strength: SignalStrength,
    pub(super) connectable: bool,
    pub(super) address_type: Option<AddressKind>,
    pub(super) service_data: Vec<Vec<u8>>,
    pub(super) xiaomi_manufacturer_data: Vec<Vec<u8>>,
}

struct Observation {
    scale: Scale,
    is_s200: bool,
    received_at: Instant,
}

impl Advertisement {
    fn interpret(self, decoder: Option<&WeightDecoder>) -> Observation {
        let (setup_info, weight) = self.inspect_service_data(decoder);
        let setup_info = setup_info.or_else(|| {
            self.xiaomi_manufacturer_data
                .iter()
                .find_map(|data| ScaleSetupInfo::from_mibeacon_frame(data))
        });
        let name = self.name.filter(|name| !name.trim().is_empty());
        let name_matches = name.as_ref().is_some_and(|name| {
            let normalized = name.to_ascii_lowercase();
            normalized.starts_with("xiaomi scale s200")
                || normalized.starts_with("xiaomi smart scale s200")
        });
        Observation {
            scale: Scale {
                address: self.address,
                address_type: self.address_type,
                name,
                signal_strength: self.signal_strength,
                connectable: self.connectable,
                weight,
                setup_info,
            },
            is_s200: name_matches || setup_info.is_some(),
            received_at: self.received_at,
        }
    }

    fn inspect_service_data(
        &self,
        decoder: Option<&WeightDecoder>,
    ) -> (Option<ScaleSetupInfo>, Option<Weight>) {
        let mut detected = None;
        for data in &self.service_data {
            let Some(setup_info) = ScaleSetupInfo::from_mibeacon(data) else {
                continue;
            };
            detected = Some(setup_info);
            let Some(decoder) = decoder else { break };
            if let Some(weight) = decoder.decode(self.address, data) {
                return (Some(setup_info), Some(weight));
            }
        }
        (detected, None)
    }
}

struct Candidate {
    is_s200: bool,
    scale: Scale,
    last_seen: Instant,
}

impl Candidate {
    fn update(&mut self, observation: Observation) -> bool {
        let observed = observation.scale;
        let scale = &mut self.scale;
        let address_type = observed.address_type.or(scale.address_type);
        let connectable = scale.connectable || observed.connectable;
        let weight = observed.weight.or(scale.weight);
        let setup_info = observed.setup_info.or(scale.setup_info);
        let name_changed = observed
            .name
            .as_ref()
            .is_some_and(|name| scale.name.as_ref() != Some(name));
        let changed = !self.is_s200
            || scale.address_type != address_type
            || scale.signal_strength != observed.signal_strength
            || scale.connectable != connectable
            || scale.weight != weight
            || scale.setup_info != setup_info
            || name_changed;

        self.is_s200 |= observation.is_s200;
        scale.address_type = address_type;
        scale.signal_strength = observed.signal_strength;
        scale.connectable = connectable;
        scale.weight = weight;
        scale.setup_info = setup_info;
        if name_changed {
            scale.name = observed.name;
        }
        self.is_s200 && changed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScanMode {
    Active,
    Passive,
}

pub(super) enum ScanWindow {
    Timed(Instant),
    Continuous,
}

impl ScanWindow {
    pub(super) fn timed(duration: Duration) -> io::Result<Self> {
        Instant::now()
            .checked_add(duration)
            .map(Self::Timed)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid scan duration"))
    }

    pub(super) fn mode(&self) -> ScanMode {
        match self {
            Self::Timed(_) => ScanMode::Active,
            Self::Continuous => ScanMode::Passive,
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

pub(super) fn scan(
    window: ScanWindow,
    mut source: impl AdvertisementSource,
    key: Option<&ScaleBindKey>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let decoder = key.map(WeightDecoder::new);
    let result = wait_for_scales(window, &mut source, decoder.as_ref(), observer);
    result.and(source.stop())
}

fn wait_for_scales(
    window: ScanWindow,
    source: &mut impl AdvertisementSource,
    decoder: Option<&WeightDecoder>,
    observer: &mut dyn ScaleScanObserver,
) -> io::Result<()> {
    let mut candidates = HashMap::<BluetoothAddress, Candidate>::new();
    let mut next_prune = Instant::now() + CANDIDATE_LIFETIME;
    let continuous = matches!(window, ScanWindow::Continuous);

    while observer.should_scan()
        && let Some(remaining) = window.next_wait()
    {
        let now = Instant::now();
        if continuous && now >= next_prune {
            candidates.retain(|_, candidate| {
                now.duration_since(candidate.last_seen) < CANDIDATE_LIFETIME
            });
            next_prune = now + CANDIDATE_LIFETIME;
        }

        let Some(advertisement) = source.next_advertisement(remaining)? else {
            continue;
        };
        let observation = advertisement.interpret(decoder);
        let received_weight = observation.scale.weight;
        let received_at = observation.received_at;
        let offers_connection = observation.scale.connectable;
        // Identification and connectability can be reported in separate packets.
        let seen_at = Instant::now();
        let candidate = candidates
            .entry(observation.scale.address)
            .or_insert_with(|| Candidate {
                is_s200: false,
                last_seen: seen_at,
                scale: Scale {
                    address: observation.scale.address,
                    address_type: None,
                    name: None,
                    signal_strength: observation.scale.signal_strength,
                    connectable: false,
                    weight: None,
                    setup_info: None,
                },
            });
        candidate.last_seen = seen_at;
        let changed = candidate.update(observation);
        let fresh_weight = continuous && candidate.is_s200 && received_weight.is_some();
        if (changed || fresh_weight)
            && observer
                .scale_discovered(&candidate.scale, received_weight)
                .is_break()
        {
            break;
        }
        if continuous
            && candidate.is_s200
            && offers_connection
            && observer
                .connection_offered(&candidate.scale, received_at)
                .is_break()
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;

    use super::*;
    use crate::weight::tests::WITH_MAC;

    struct ScriptedAdvertisements<'a> {
        events: VecDeque<io::Result<Option<Advertisement>>>,
        stopped: &'a Cell<bool>,
        stop_error: Option<io::Error>,
    }

    impl<'a> ScriptedAdvertisements<'a> {
        fn new(
            events: impl IntoIterator<Item = io::Result<Option<Advertisement>>>,
            stopped: &'a Cell<bool>,
        ) -> Self {
            Self {
                events: events.into_iter().collect(),
                stopped,
                stop_error: None,
            }
        }
    }

    impl AdvertisementSource for ScriptedAdvertisements<'_> {
        fn next_advertisement(&mut self, timeout: Duration) -> io::Result<Option<Advertisement>> {
            assert!(timeout <= STOP_CHECK_INTERVAL);
            self.events
                .pop_front()
                .expect("the scan should stop after the scripted events")
        }

        fn stop(self) -> io::Result<()> {
            self.stopped.set(true);
            self.stop_error.map_or(Ok(()), Err)
        }
    }

    fn packet(
        address: u64,
        received_at: Instant,
        name: Option<String>,
        connectable: bool,
    ) -> Advertisement {
        Advertisement {
            address: BluetoothAddress(address),
            received_at,
            name,
            signal_strength: SignalStrength(-60),
            connectable,
            address_type: None,
            service_data: Vec::new(),
            xiaomi_manufacturer_data: Vec::new(),
        }
    }

    #[test]
    fn only_timed_discovery_requests_scan_responses() {
        assert_eq!(ScanWindow::Continuous.mode(), ScanMode::Passive);
        assert_eq!(
            ScanWindow::timed(Duration::from_secs(1)).unwrap().mode(),
            ScanMode::Active
        );
        assert!(
            matches!(ScanWindow::timed(Duration::MAX), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn recognizes_names_and_manufacturer_data_and_prefers_authenticated_service_data() {
        let mut advertisement = packet(0x1234_5678_9abc, Instant::now(), Some("  ".into()), false);
        advertisement.xiaomi_manufacturer_data = vec![vec![0x10], vec![0x10, 0x58, 0xcb, 0x4d]];
        advertisement.service_data =
            vec![vec![0x95, 0xfe], vec![0x01, 0x18, 0x10, 0x59, 0xcb, 0x4d]];
        let observation = advertisement.interpret(None);
        assert!(observation.is_s200);
        assert!(observation.scale.name.is_none());
        assert!(observation.scale.setup_info.unwrap().is_ms113());

        let mut advertisement = packet(0x1234_5678_9abc, Instant::now(), None, false);
        advertisement.xiaomi_manufacturer_data = vec![vec![0x10, 0x58, 0xcb, 0x4d]];
        advertisement.service_data =
            vec![vec![0x95, 0xfe, 0x10, 0x59, 0xcb, 0x4d], WITH_MAC.to_vec()];
        let key = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        let decoder = WeightDecoder::new(&key);
        let observation = advertisement.interpret(Some(&decoder));
        assert!(observation.is_s200);
        assert!(!observation.scale.setup_info.unwrap().is_ms113());
        assert_eq!(observation.scale.weight(), Some(Weight(7255)));

        let named = packet(
            7,
            Instant::now(),
            Some("XIAOMI SMART SCALE S200".into()),
            false,
        );
        assert!(named.interpret(None).is_s200);
    }

    #[test]
    fn stops_the_source_after_a_read_error_and_preserves_the_original_error() {
        let stopped = Cell::new(false);
        let mut source =
            ScriptedAdvertisements::new([Err(io::Error::other("radio stopped"))], &stopped);
        source.stop_error = Some(io::Error::other("stop failed"));
        let error = scan(
            ScanWindow::Continuous,
            source,
            None,
            &mut crate::ConnectableScaleSearch::default(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "radio stopped");
        assert!(stopped.get());
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
        let events = [(0, true), (1, true), (2, false), (3, true)].map(|(seconds, connectable)| {
            Ok(Some(packet(
                12,
                start + Duration::from_secs(seconds),
                Some("Xiaomi Scale S200".into()),
                connectable,
            )))
        });
        let stopped = Cell::new(false);
        let mut offers = ConnectionOffers::default();
        scan(
            ScanWindow::Continuous,
            ScriptedAdvertisements::new(events, &stopped),
            None,
            &mut offers,
        )
        .unwrap();
        assert_eq!(
            offers.0,
            [0, 1, 3].map(|seconds| start + Duration::from_secs(seconds))
        );
        assert!(stopped.get());
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

        let stopped = Cell::new(false);
        let source = ScriptedAdvertisements::new([Ok(None), Ok(None)], &stopped);
        let mut observer = IdleScan::default();
        scan(ScanWindow::Continuous, source, None, &mut observer).unwrap();
        assert_eq!(observer.waits, 3);
        assert!(stopped.get());
    }

    #[test]
    fn reports_each_scale_and_combines_advertisements_by_address() {
        #[derive(Default)]
        struct DiscoveryLog(Vec<Scale>);

        impl ScaleScanObserver for DiscoveryLog {
            fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
                self.0.push(scale.clone());
                if scale.address() == BluetoothAddress(56) {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
        }

        let events = [
            (12, true, false, false, Some(AddressKind::Public)),
            (34, false, true, false, None),
            (12, false, true, false, Some(AddressKind::Random)),
            (12, false, true, true, None),
            (12, false, true, false, None),
            (56, true, false, false, None),
        ]
        .map(|(address, named, connectable, has_weight, address_type)| {
            let mut advertisement = packet(
                address,
                Instant::now(),
                named.then(|| format!("Xiaomi Scale S200 {address}")),
                connectable,
            );
            advertisement.address_type = address_type;
            if has_weight {
                advertisement.service_data.push(WITH_MAC.to_vec());
            }
            Ok(Some(advertisement))
        });
        let stopped = Cell::new(false);
        let source = ScriptedAdvertisements::new(events, &stopped);
        let key = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        let mut observer = DiscoveryLog::default();
        scan(
            ScanWindow::timed(Duration::from_secs(2)).unwrap(),
            source,
            Some(&key),
            &mut observer,
        )
        .unwrap();
        assert!(stopped.get());
        let updates = observer
            .0
            .iter()
            .map(|scale| {
                (
                    scale.address(),
                    scale.is_connectable(),
                    scale.name().to_string(),
                    scale.weight(),
                    scale.address_type,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            updates,
            [
                (
                    BluetoothAddress(12),
                    false,
                    "Xiaomi Scale S200 12".into(),
                    None,
                    Some(AddressKind::Public)
                ),
                (
                    BluetoothAddress(12),
                    true,
                    "Xiaomi Scale S200 12".into(),
                    None,
                    Some(AddressKind::Random)
                ),
                (
                    BluetoothAddress(12),
                    true,
                    "Xiaomi Scale S200 12".into(),
                    Some(Weight(7255)),
                    Some(AddressKind::Random)
                ),
                (
                    BluetoothAddress(56),
                    false,
                    "Xiaomi Scale S200 56".into(),
                    None,
                    None
                ),
            ]
        );
    }
}
