use std::io;
use std::ops::ControlFlow;
#[cfg(any(windows, test))]
use std::sync::mpsc;
#[cfg(any(windows, test))]
use std::sync::mpsc::Receiver;
use std::time::Duration;
#[cfg(any(windows, test))]
use std::time::Instant;

#[cfg(any(windows, test))]
use aes::Aes128;
#[cfg(any(windows, test))]
use ccm::Ccm;
#[cfg(any(windows, test))]
use ccm::aead::{
    AeadInOut, KeyInit,
    consts::{U4, U12},
};
#[cfg(any(windows, test))]
use hkdf::Hkdf;
#[cfg(any(windows, test))]
use hmac::{Hmac, Mac};
#[cfg(any(windows, test))]
use sha2::Sha256;
#[cfg(windows)]
use windows::Devices::Bluetooth::{BluetoothConnectionStatus, BluetoothLEDevice};

#[cfg(any(windows, test))]
use super::certificate_transfer::{
    BlockPacketSource, Channel, FRAGMENTS_RECEIVED, PacketWriter, READY, TRANSFER_FAILED,
    block_packets, receive_framed_block,
};
#[cfg(windows)]
use super::{certificate_transfer::Subscription, setup_characteristic, setup_service};
#[cfg(any(windows, test))]
use crate::Weight;
#[cfg(windows)]
use crate::{Apartment, open_scale_device};
use crate::{Scale, ScaleLoginToken, WeightReading};

#[cfg(any(windows, test))]
const LOGIN: [u8; 4] = [0x24, 0, 0, 0];
#[cfg(any(windows, test))]
const APP_RANDOM: u8 = 0x0b;
#[cfg(any(windows, test))]
const APP_PROOF: u8 = 0x0a;
#[cfg(any(windows, test))]
const SCALE_RANDOM: u8 = 0x0d;
#[cfg(any(windows, test))]
const SCALE_PROOF: u8 = 0x0c;
#[cfg(any(windows, test))]
const LOGIN_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(any(windows, test))]
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(any(windows, test))]
const CONNECTION_CHECK_INTERVAL: Duration = Duration::from_millis(250);

#[cfg(any(windows, test))]
type Notification = (Channel, Vec<u8>);
#[cfg(any(windows, test))]
type WeightCipher = Ccm<Aes128, U4, U12>;
#[cfg(any(windows, test))]
type HmacSha256 = Hmac<Sha256>;

/// A successful Bluetooth login or a measurement from the authenticated scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectedWeightEvent {
    Ready,
    Reading(WeightReading),
}

/// Receives ready, live, and settled events from a connected scale.
pub trait WeightSessionObserver {
    /// Return `ControlFlow::Break` to end the session after an event.
    fn on_weight_event(&mut self, event: ConnectedWeightEvent) -> ControlFlow<()>;

    /// Checked before connecting and while a continuous session waits for packets.
    fn should_read_weight(&mut self) -> bool {
        true
    }
}

/// Connects to an ms113 with its saved setup token and reads until a settled weight arrives.
pub fn listen_for_connected_weight(
    scale: &Scale,
    token: &ScaleLoginToken,
    measurement_time: Duration,
    observer: &mut dyn WeightSessionObserver,
) -> io::Result<()> {
    read_connected_weights(scale, token, Some(measurement_time), observer)
}

/// Reads consecutive weights until the scale sleeps, the data channel is idle,
/// or the caller stops listening.
pub fn watch_connected_weights(
    scale: &Scale,
    token: &ScaleLoginToken,
    observer: &mut dyn WeightSessionObserver,
) -> io::Result<()> {
    read_connected_weights(scale, token, None, observer)
}

fn read_connected_weights(
    scale: &Scale,
    token: &ScaleLoginToken,
    measurement_time: Option<Duration>,
    observer: &mut dyn WeightSessionObserver,
) -> io::Result<()> {
    if !observer.should_read_weight() {
        return Ok(());
    }
    read_from_device(scale, token, measurement_time, observer)
}

#[cfg(not(windows))]
fn read_from_device(
    _: &Scale,
    _: &ScaleLoginToken,
    _: Option<Duration>,
    _: &mut dyn WeightSessionObserver,
) -> io::Result<()> {
    Err(crate::bluetooth_unavailable())
}

#[cfg(windows)]
fn read_from_device(
    scale: &Scale,
    token: &ScaleLoginToken,
    measurement_time: Option<Duration>,
    observer: &mut dyn WeightSessionObserver,
) -> io::Result<()> {
    let _apartment = Apartment::initialize()?;
    let device = open_scale_device(scale)?;
    let service = setup_service(&device)?;
    let control = setup_characteristic(&service, 0x0010)?;
    let auth = setup_characteristic(&service, 0x0019)?;
    let data = setup_characteristic(&service, 0x001b)?;
    let (auth_sender, auth_replies) = mpsc::channel();
    let (data_sender, data_replies) = mpsc::channel();
    let _control_subscription =
        Subscription::start(&control, Channel::Control, auth_sender.clone())?;
    let _auth_subscription = Subscription::start(&auth, Channel::Auth, auth_sender)?;
    let _data_subscription = Subscription::start(&data, Channel::Data, data_sender)?;

    let mtu = service.Session()?.MaxPduSize()?;
    let keys = login(&control, &auth, &auth_replies, mtu, token)?;
    WeightStream {
        packets: &data_replies,
        writer: &data,
        connection: &device,
    }
    .read(keys, measurement_time, observer)
}

#[cfg(any(windows, test))]
struct WeightStream<'a> {
    packets: &'a Receiver<Notification>,
    writer: &'a dyn PacketWriter,
    connection: &'a dyn ConnectionState,
}

#[cfg(any(windows, test))]
impl WeightStream<'_> {
    fn read(
        &self,
        keys: LoginKeys,
        measurement_time: Option<Duration>,
        observer: &mut dyn WeightSessionObserver,
    ) -> io::Result<()> {
        if observer
            .on_weight_event(ConnectedWeightEvent::Ready)
            .is_break()
        {
            return Ok(());
        }
        let deadline = measurement_time
            .map(|duration| {
                Instant::now().checked_add(duration).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid measurement timeout")
                })
            })
            .transpose()?;
        let cipher = WeightCipher::new((&keys.device_key).into());
        let mut previous = None;
        loop {
            let payload = if let Some(deadline) = deadline {
                receive_framed_block(
                    self.writer,
                    None,
                    "weight packet",
                    deadline,
                    &mut SettledWeightPackets(self.packets),
                )?
            } else {
                let idle_deadline = Instant::now() + CONNECTION_IDLE_TIMEOUT;
                let mut source = LiveWeightPackets {
                    connection: self.connection,
                    receiver: self.packets,
                    observer,
                };
                match receive_framed_block(
                    self.writer,
                    None,
                    "weight packet",
                    idle_deadline,
                    &mut source,
                ) {
                    Ok(payload) => payload,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotConnected
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            };
            if let Some(reading) = decode_weight(&cipher, keys.device_iv, &payload) {
                let settled = matches!(reading, WeightReading::Settled(_));
                if (settled || previous != Some(reading))
                    && observer
                        .on_weight_event(ConnectedWeightEvent::Reading(reading))
                        .is_break()
                {
                    return Ok(());
                }
                if settled && deadline.is_some() {
                    return Ok(());
                }
                previous = Some(reading);
            }
        }
    }
}

#[cfg(any(windows, test))]
trait ConnectionState {
    fn is_connected(&self) -> io::Result<bool>;
}

#[cfg(windows)]
impl ConnectionState for BluetoothLEDevice {
    fn is_connected(&self) -> io::Result<bool> {
        Ok(self.ConnectionStatus()? != BluetoothConnectionStatus::Disconnected)
    }
}

#[cfg(any(windows, test))]
struct SettledWeightPackets<'a>(&'a Receiver<Notification>);

#[cfg(any(windows, test))]
impl BlockPacketSource for SettledWeightPackets<'_> {
    fn next_block_packet(&mut self, deadline: Instant, _: &str) -> io::Result<Vec<u8>> {
        read_notification(self.0, deadline, "a settled weight").map(|(_, packet)| packet)
    }
}

#[cfg(any(windows, test))]
struct LiveWeightPackets<'a> {
    connection: &'a dyn ConnectionState,
    receiver: &'a Receiver<Notification>,
    observer: &'a mut dyn WeightSessionObserver,
}

#[cfg(any(windows, test))]
impl BlockPacketSource for LiveWeightPackets<'_> {
    fn next_block_packet(&mut self, deadline: Instant, _: &str) -> io::Result<Vec<u8>> {
        while self.observer.should_read_weight() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            match self
                .receiver
                .recv_timeout(remaining.min(CONNECTION_CHECK_INTERVAL))
            {
                Ok((_, packet)) => return Ok(packet),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if !self.connection.is_connected()? {
                        return Err(io::Error::from(io::ErrorKind::NotConnected));
                    }
                }
            }
        }
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }
}

#[cfg(windows)]
fn login(
    control: &dyn PacketWriter,
    auth: &dyn PacketWriter,
    replies: &Receiver<Notification>,
    mtu: u16,
    token: &ScaleLoginToken,
) -> io::Result<LoginKeys> {
    let mut replies = LoginReplies {
        receiver: replies,
        accepted: false,
    };
    let mut app_random = [0; 16];
    getrandom::fill(&mut app_random)
        .map_err(|_| io::Error::other("could not generate the Bluetooth login challenge"))?;
    login_with_challenge(control, auth, &mut replies, mtu, token, app_random)
}

#[cfg(any(windows, test))]
fn login_with_challenge(
    control: &dyn PacketWriter,
    auth: &dyn PacketWriter,
    replies: &mut LoginReplies<'_>,
    mtu: u16,
    token: &ScaleLoginToken,
    app_random: [u8; 16],
) -> io::Result<LoginKeys> {
    control.write(&LOGIN)?;
    replies.send_block(auth, mtu, APP_RANDOM, &app_random, "app challenge")?;
    let scale_random = replies.receive_block(auth, SCALE_RANDOM, "scale challenge")?;
    let scale_random = <[u8; 16]>::try_from(scale_random).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the scale sent an invalid login challenge",
        )
    })?;
    let keys = LoginKeys::derive(token, app_random, scale_random)?;
    let proof = replies.receive_block(auth, SCALE_PROOF, "scale login proof")?;
    keys.verify_device_proof(&proof)?;
    let proof = keys.app_proof()?;
    replies.send_block(auth, mtu, APP_PROOF, &proof, "app login proof")?;
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    while !replies.accepted {
        replies.next(deadline, "login confirmation")?;
    }
    Ok(keys)
}

#[cfg(any(windows, test))]
struct LoginReplies<'a> {
    receiver: &'a Receiver<Notification>,
    accepted: bool,
}

#[cfg(any(windows, test))]
impl LoginReplies<'_> {
    fn next(&mut self, deadline: Instant, stage: &str) -> io::Result<Option<Vec<u8>>> {
        let (channel, packet) = read_notification(self.receiver, deadline, stage)?;
        match (channel, packet.as_slice()) {
            (Channel::Control, [0x21, 0, 0, 0]) => self.accepted = true,
            (Channel::Control, [0x23, 0, 0, 0]) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the S200 rejected its saved Bluetooth login token",
                ));
            }
            (Channel::Control, [0xe0, 0, 0, 0]) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the S200 reported that it is unregistered",
                ));
            }
            (Channel::Auth, packet) if packet.starts_with(&TRANSFER_FAILED) => {
                return Err(io::Error::other(format!(
                    "Bluetooth transfer failed while waiting for {stage}"
                )));
            }
            (Channel::Auth, _) => return Ok(Some(packet)),
            _ => {}
        }
        Ok(None)
    }

    fn auth_packet(&mut self, deadline: Instant, stage: &str) -> io::Result<Vec<u8>> {
        loop {
            if let Some(packet) = self.next(deadline, stage)? {
                return Ok(packet);
            }
        }
    }

    fn receive_block(
        &mut self,
        auth: &dyn PacketWriter,
        kind: u8,
        stage: &str,
    ) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + LOGIN_TIMEOUT;
        receive_framed_block(auth, Some(kind), stage, deadline, self)
    }

    fn send_block(
        &mut self,
        auth: &dyn PacketWriter,
        mtu: u16,
        kind: u8,
        payload: &[u8],
        stage: &str,
    ) -> io::Result<()> {
        let (announce, packets) = block_packets(mtu, kind, payload)?;
        auth.write(&announce)?;
        self.expect_ack(READY, stage)?;
        for packet in packets {
            auth.write(&packet)?;
        }
        self.expect_ack(FRAGMENTS_RECEIVED, stage)
    }

    fn expect_ack(&mut self, expected: [u8; 4], stage: &str) -> io::Result<()> {
        let deadline = Instant::now() + LOGIN_TIMEOUT;
        while self.auth_packet(deadline, stage)? != expected {}
        Ok(())
    }
}

#[cfg(any(windows, test))]
impl BlockPacketSource for LoginReplies<'_> {
    fn next_block_packet(&mut self, deadline: Instant, stage: &str) -> io::Result<Vec<u8>> {
        self.auth_packet(deadline, stage)
    }
}

#[cfg(any(windows, test))]
fn read_notification(
    receiver: &Receiver<Notification>,
    deadline: Instant,
    stage: &str,
) -> io::Result<Notification> {
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the S200 did not send {stage}"),
        )
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(timed_out)?;
    match receiver.recv_timeout(remaining) {
        Ok(notification) => Ok(notification),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "the S200 Bluetooth notifications stopped",
        )),
    }
}

#[cfg(any(windows, test))]
struct LoginKeys {
    device_key: [u8; 16],
    app_key: [u8; 16],
    device_iv: [u8; 4],
    app_random: [u8; 16],
    scale_random: [u8; 16],
}

#[cfg(any(windows, test))]
impl LoginKeys {
    fn derive(
        token: &ScaleLoginToken,
        app_random: [u8; 16],
        scale_random: [u8; 16],
    ) -> io::Result<Self> {
        let mut salt = [0; 32];
        salt[..16].copy_from_slice(&app_random);
        salt[16..].copy_from_slice(&scale_random);
        let mut derived = [0; 64];
        Hkdf::<Sha256>::new(Some(&salt), &token.0)
            .expand(b"mible-login-info", &mut derived)
            .map_err(|_| io::Error::other("could not derive the S200 Bluetooth session keys"))?;
        let mut keys = Self {
            device_key: [0; 16],
            app_key: [0; 16],
            device_iv: [0; 4],
            app_random,
            scale_random,
        };
        keys.device_key.copy_from_slice(&derived[..16]);
        keys.app_key.copy_from_slice(&derived[16..32]);
        keys.device_iv.copy_from_slice(&derived[32..36]);
        Ok(keys)
    }

    fn verify_device_proof(&self, proof: &[u8]) -> io::Result<()> {
        let mut mac = login_mac(&self.device_key)?;
        mac.update(&self.scale_random);
        mac.update(&self.app_random);
        mac.verify_slice(proof).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the saved token did not authenticate this S200",
            )
        })
    }

    fn app_proof(&self) -> io::Result<[u8; 32]> {
        let mut mac = login_mac(&self.app_key)?;
        mac.update(&self.app_random);
        mac.update(&self.scale_random);
        Ok(mac.finalize().into_bytes().into())
    }
}

#[cfg(any(windows, test))]
fn login_mac(key: &[u8; 16]) -> io::Result<HmacSha256> {
    <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
        .map_err(|_| io::Error::other("could not initialize the S200 login authenticator"))
}

#[cfg(any(windows, test))]
fn decode_weight(cipher: &WeightCipher, iv: [u8; 4], bytes: &[u8]) -> Option<WeightReading> {
    let (counter, message) = bytes.split_first_chunk::<2>()?;
    let (ciphertext, tag) = message.split_last_chunk::<4>()?;
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&iv);
    nonce[8..10].copy_from_slice(counter);
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(
            (&nonce).into(),
            &[],
            plaintext.as_mut_slice().into(),
            tag.into(),
        )
        .ok()?;
    parse_weight(&plaintext)
}

#[cfg(any(windows, test))]
fn parse_weight(plaintext: &[u8]) -> Option<WeightReading> {
    let mut live = None;
    for (index, header) in plaintext.windows(2).enumerate() {
        let value = &plaintext[index + 2..];
        match header {
            [length, 0xa0] => {
                if let Some(weight) = value.get(..usize::from(*length)).and_then(settled_weight) {
                    return Some(WeightReading::Settled(weight));
                }
            }
            [2, 0x30] => {
                if let Some((bytes, _)) = value.split_first_chunk::<2>() {
                    live = measured_weight(u32::from(u16::from_le_bytes(*bytes))).or(live);
                }
            }
            _ => {}
        }
    }
    live.map(WeightReading::Live)
}

#[cfg(any(windows, test))]
fn settled_weight(record: &[u8]) -> Option<Weight> {
    let mut fields = std::str::from_utf8(record).ok()?.split(',');
    fields.next()?.parse::<u32>().ok()?;
    fields.next()?.parse::<u32>().ok()?;
    let weight = measured_weight(fields.next()?.parse().ok()?)?;
    fields.next()?.parse::<u32>().ok()?;
    let utc: u64 = fields.next()?.parse().ok()?;
    (utc != 0 && fields.next().is_none()).then_some(weight)
}

#[cfg(any(windows, test))]
fn measured_weight(raw: u32) -> Option<Weight> {
    (raw > 0 && raw < 30_000).then_some(Weight(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::certificate_transfer::tests::PacketLog;

    #[test]
    fn authenticates_with_framed_challenges_and_waits_for_scale_confirmation() {
        let token = ScaleLoginToken([8; 12]);
        let app = [1; 16];
        let scale = [2; 16];
        let keys = LoginKeys::derive(&token, app, scale).unwrap();
        let mut mac = login_mac(&keys.device_key).unwrap();
        mac.update(&scale);
        mac.update(&app);
        let proof = mac.finalize().into_bytes();
        let control = PacketLog::default();
        let auth = PacketLog::default();
        let (sender, receiver) = mpsc::channel();
        for (channel, packet) in [
            (Channel::Data, vec![0x99]),
            (Channel::Auth, READY.to_vec()),
            (Channel::Auth, FRAGMENTS_RECEIVED.to_vec()),
            (
                Channel::Auth,
                [&[0, 0, 2, SCALE_RANDOM][..], &scale].concat(),
            ),
            (
                Channel::Auth,
                [&[0, 0, 2, SCALE_PROOF][..], &proof].concat(),
            ),
            (Channel::Auth, READY.to_vec()),
            (Channel::Auth, FRAGMENTS_RECEIVED.to_vec()),
            (Channel::Control, vec![0x21, 0, 0, 0]),
        ] {
            sender.send((channel, packet)).unwrap();
        }
        drop(sender);
        let mut replies = LoginReplies {
            receiver: &receiver,
            accepted: false,
        };
        let negotiated =
            login_with_challenge(&control, &auth, &mut replies, 247, &token, app).unwrap();
        assert!(replies.accepted);
        assert_eq!(negotiated.device_key, keys.device_key);
        assert_eq!(*control.0.borrow(), [LOGIN]);
        let writes = auth.0.borrow();
        assert_eq!(writes[0], [0, 0, 0, APP_RANDOM, 1, 0]);
        assert_eq!(writes[1][2..], app);
        assert_eq!(writes[4], [0, 0, 0, APP_PROOF, 1, 0]);
        assert_eq!(writes[5][2..], keys.app_proof().unwrap());
    }

    #[test]
    fn reports_login_rejection_and_missing_notifications() {
        for (channel, packet, kind, message) in [
            (
                Channel::Control,
                vec![0x23, 0, 0, 0],
                io::ErrorKind::PermissionDenied,
                "rejected",
            ),
            (
                Channel::Control,
                vec![0xe0, 0, 0, 0],
                io::ErrorKind::PermissionDenied,
                "unregistered",
            ),
            (
                Channel::Auth,
                TRANSFER_FAILED.to_vec(),
                io::ErrorKind::Other,
                "transfer failed",
            ),
            (
                Channel::Data,
                vec![],
                io::ErrorKind::BrokenPipe,
                "notifications stopped",
            ),
        ] {
            let (sender, receiver) = mpsc::channel();
            sender.send((channel, packet)).unwrap();
            drop(sender);
            let mut replies = LoginReplies {
                receiver: &receiver,
                accepted: false,
            };
            let error = replies
                .auth_packet(Instant::now() + LOGIN_TIMEOUT, "proof")
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert!(error.to_string().contains(message));
        }
        let (_sender, receiver) = mpsc::channel();
        let error = read_notification(&receiver, Instant::now(), "challenge")
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    struct ClosedConnection;

    impl ConnectionState for ClosedConnection {
        fn is_connected(&self) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct Cancelled;

    impl WeightSessionObserver for Cancelled {
        fn should_read_weight(&mut self) -> bool {
            false
        }

        fn on_weight_event(&mut self, event: ConnectedWeightEvent) -> ControlFlow<()> {
            panic!("canceled observer received {event:?}");
        }
    }

    #[test]
    fn cancellation_prevents_either_weight_entry_point_from_opening_a_device() {
        let scale = Scale {
            address: crate::BluetoothAddress(1),
            address_type: None,
            name: None,
            signal_strength: crate::SignalStrength(-65),
            connectable: true,
            weight: None,
            setup_info: None,
        };
        let token = ScaleLoginToken([0; 12]);
        listen_for_connected_weight(&scale, &token, Duration::from_secs(1), &mut Cancelled)
            .unwrap();
        watch_connected_weights(&scale, &token, &mut Cancelled).unwrap();
    }

    #[test]
    fn live_notification_wait_stops_on_disconnect_expiry_or_cancellation() {
        let (_sender, receiver) = mpsc::channel();
        for (deadline, kind) in [
            (
                Instant::now() + Duration::from_millis(500),
                io::ErrorKind::NotConnected,
            ),
            (
                Instant::now() - Duration::from_millis(1),
                io::ErrorKind::TimedOut,
            ),
        ] {
            let mut readings = Readings::default();
            let mut source = LiveWeightPackets {
                connection: &ClosedConnection,
                receiver: &receiver,
                observer: &mut readings,
            };
            assert_eq!(
                source
                    .next_block_packet(deadline, "weight")
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
        let mut source = LiveWeightPackets {
            connection: &ClosedConnection,
            receiver: &receiver,
            observer: &mut Cancelled,
        };
        assert_eq!(
            source
                .next_block_packet(Instant::now() + Duration::from_secs(1), "weight")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[derive(Default)]
    struct Readings(Vec<ConnectedWeightEvent>);

    impl WeightSessionObserver for Readings {
        fn on_weight_event(&mut self, event: ConnectedWeightEvent) -> ControlFlow<()> {
            self.0.push(event);
            ControlFlow::Continue(())
        }
    }

    #[test]
    fn reports_live_once_and_stops_timed_reading_after_the_first_settled_frame() {
        let token = ScaleLoginToken(std::array::from_fn(|index| index as u8));
        let keys = || {
            LoginKeys::derive(
                &token,
                std::array::from_fn(|index| index as u8),
                std::array::from_fn(|index| (index + 16) as u8),
            )
            .unwrap()
        };
        let live = [
            0x01, 0, 0xc9, 0x71, 0x5a, 0x4e, 0x10, 0x09, 0xda, 0xff, 0xc6, 0x3c,
        ];
        let settled = [
            0x02, 0, 0xde, 0x8f, 0x41, 0x2e, 0xd2, 0x3d, 0x7a, 0x8b, 0x78, 0xc2, 0x85, 0x54, 0xd0,
            0xcc, 0x57, 0xd5, 0x7c, 0xc2, 0x52, 0xeb, 0xba, 0x70, 0x77, 0xf0, 0xca, 0x63, 0x93,
            0x86,
        ];
        for (time, settled_count) in [(Some(Duration::from_secs(1)), 1), (None, 2)] {
            let log = PacketLog::default();
            let (sender, receiver) = mpsc::channel();
            for payload in [&[0; 2][..], &live, &live, &settled, &settled] {
                sender
                    .send((Channel::Data, [&[0, 0, 2, 0][..], payload].concat()))
                    .unwrap();
            }
            drop(sender);
            let mut readings = Readings::default();
            WeightStream {
                packets: &receiver,
                writer: &log,
                connection: &ClosedConnection,
            }
            .read(keys(), time, &mut readings)
            .unwrap();
            let mut expected = vec![
                ConnectedWeightEvent::Ready,
                ConnectedWeightEvent::Reading(WeightReading::Live(Weight(9070))),
            ];
            expected.extend(std::iter::repeat_n(
                ConnectedWeightEvent::Reading(WeightReading::Settled(Weight(9070))),
                settled_count,
            ));
            assert_eq!(readings.0, expected);
            assert_eq!(log.0.borrow().len(), 3 + settled_count);
        }
    }

    #[test]
    fn verifies_the_scale_and_decodes_authenticated_measurements() {
        let token = ScaleLoginToken(std::array::from_fn(|index| index as u8));
        let app = std::array::from_fn(|index| index as u8);
        let scale = std::array::from_fn(|index| (index + 16) as u8);
        let keys = LoginKeys::derive(&token, app, scale).unwrap();
        let device_proof = [
            0x99, 0x93, 0x6f, 0x1c, 0x9a, 0x0a, 0x1d, 0xcd, 0xa3, 0x73, 0xd0, 0x14, 0x17, 0x2c,
            0xcb, 0xf4, 0x65, 0x64, 0x26, 0x8d, 0x2b, 0x56, 0xc0, 0x2f, 0x0e, 0xf3, 0xec, 0x6e,
            0xad, 0x54, 0x43, 0x33,
        ];
        let app_proof = [
            0x6e, 0xad, 0x8b, 0x83, 0x51, 0x15, 0xa1, 0x4a, 0x79, 0x95, 0x74, 0x76, 0xc5, 0xfa,
            0xc6, 0xe2, 0x95, 0x6a, 0x89, 0x6e, 0xe2, 0x39, 0x55, 0xb3, 0x52, 0x18, 0xef, 0xd4,
            0x0d, 0x68, 0x46, 0x31,
        ];
        assert!(keys.verify_device_proof(&device_proof).is_ok());
        assert!(keys.verify_device_proof(&[0; 32]).is_err());
        assert_eq!(keys.app_proof().unwrap(), app_proof);
        let cipher = WeightCipher::new((&keys.device_key).into());
        let mut live = [
            0x01, 0x00, 0xc9, 0x71, 0x5a, 0x4e, 0x10, 0x09, 0xda, 0xff, 0xc6, 0x3c,
        ];
        let settled = [
            0x02, 0x00, 0xde, 0x8f, 0x41, 0x2e, 0xd2, 0x3d, 0x7a, 0x8b, 0x78, 0xc2, 0x85, 0x54,
            0xd0, 0xcc, 0x57, 0xd5, 0x7c, 0xc2, 0x52, 0xeb, 0xba, 0x70, 0x77, 0xf0, 0xca, 0x63,
            0x93, 0x86,
        ];
        assert_eq!(
            decode_weight(&cipher, keys.device_iv, &live),
            Some(WeightReading::Live(Weight(9070)))
        );
        assert_eq!(
            decode_weight(&cipher, keys.device_iv, &settled),
            Some(WeightReading::Settled(Weight(9070)))
        );
        live[3] ^= 1;
        assert_eq!(decode_weight(&cipher, keys.device_iv, &live), None);
    }
}
