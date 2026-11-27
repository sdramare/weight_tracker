use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use std::{fmt, fs};

use windows::Devices::Bluetooth::BluetoothLEDevice;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattCharacteristicProperties,
    GattClientCharacteristicConfigurationDescriptorValue, GattDeviceService,
    GattValueChangedEventArgs, GattWriteOption,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};

use super::registration_crypto::{Registration, RegistrationKeys};
use super::{
    Apartment, Scale, check_service_status, open_scale_device, registration_status,
    setup_characteristic, setup_service,
};
use crate::login_keys::{CONFIRMED_SUFFIX, PENDING_SUFFIX, REJECTED_SUFFIX};

const TEST_CERTIFICATE_PATH: &str = "crates/scale/src/setup/s200-local-test.der";
const CERTIFICATE_BLOCK: u8 = 0x07;
const CERTIFICATE_MTU: u16 = 23;
const DEVICE_INFO_OR_ID: u8 = 0x00;
const PUBLIC_KEY_BLOCK: u8 = 0x03;
const REQUEST_DEVICE_INFO: [u8; 4] = [0xa2, 0, 0, 0];
const NO_OOB_PROFILE_HEADER: [u8; 4] = [2, 0, 0, 0];
const EXTENDED_DEVICE_INFO_LENGTH: usize = 24;
const START_KEY_EXCHANGE: [u8; 4] = [0x15, 0, 0, 0];
const CONFIRM_REGISTRATION: [u8; 4] = [0x13, 0, 0, 0];
pub(super) const READY: [u8; 4] = [0, 0, 1, 1];
pub(super) const FRAGMENTS_RECEIVED: [u8; 4] = [0, 0, 1, 0];
const SINGLE_PACKET_RECEIVED: [u8; 4] = [0, 0, 3, 0];
pub(super) const TRANSFER_FAILED: [u8; 4] = [0, 0, 1, 5];
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// A device response to transmitting the test certificate over Standard Auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupCertificateReply {
    RegistrationSucceeded,
    RegistrationFailed,
    AlreadyRegistered,
    ReceivedWithoutRegistrationResult,
}

impl fmt::Display for SetupCertificateReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegistrationSucceeded => "the scale reported successful registration",
            Self::RegistrationFailed => "the scale reported registration failure",
            Self::AlreadyRegistered => "the scale reported that it is already registered",
            Self::ReceivedWithoutRegistrationResult => {
                "the scale acknowledged the certificate transfer and gave no registration result"
            }
        })
    }
}

/// The device-information reply from the scale's Standard Auth service.
pub struct SetupProfile(Vec<u8>);

impl SetupProfile {
    /// Checks for the no-OOB profile in either observed ms113 reply format.
    pub fn supports_registration(&self) -> bool {
        let length = self.0.len();
        (length == NO_OOB_PROFILE_HEADER.len() || length == EXTENDED_DEVICE_INFO_LENGTH)
            && self.0.starts_with(&NO_OOB_PROFILE_HEADER)
    }
}

impl fmt::Display for SetupProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.as_slice();
        if let [a, b, c, d, rest @ ..] = bytes {
            write!(formatter, "{a:02X} {b:02X} {c:02X} {d:02X}")?;
            if !rest.is_empty() {
                write!(formatter, " … ({} bytes total)", bytes.len())?;
            }
            return Ok(());
        }
        write!(
            formatter,
            "a device-information block of {} bytes",
            bytes.len()
        )
    }
}

/// Reads the Bluetooth setup profile without starting registration.
pub fn probe_setup_profile(scale: &Scale) -> io::Result<SetupProfile> {
    SetupLink::open(scale)?.read_profile()
}

/// Attempts Standard Auth registration of an unregistered ms113 using a local identity.
///
/// Candidate keys are written to the supplied directory before requesting registration.
pub fn send_setup_test_certificate(
    scale: &Scale,
    credentials_directory: &Path,
) -> io::Result<SetupCertificateReply> {
    let certificate = fs::read(TEST_CERTIFICATE_PATH).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not read local test certificate at {TEST_CERTIFICATE_PATH}: {error}"),
        )
    })?;
    let (reply, credentials) = register_with(scale, |registration| {
        let encrypted_id = registration.encrypted_device_id()?;
        let credentials =
            registration.save_trial_credentials(credentials_directory, scale.address())?;
        Ok((
            RegistrationProof {
                encrypted_id,
                certificate,
            },
            credentials,
        ))
    })?;
    finish_credentials(credentials, reply)?;
    Ok(reply)
}

pub(super) fn finish_credentials(
    path: PathBuf,
    reply: SetupCertificateReply,
) -> io::Result<PathBuf> {
    let suffix = match reply {
        SetupCertificateReply::RegistrationSucceeded => CONFIRMED_SUFFIX,
        SetupCertificateReply::RegistrationFailed | SetupCertificateReply::AlreadyRegistered => {
            REJECTED_SUFFIX
        }
        SetupCertificateReply::ReceivedWithoutRegistrationResult => return Ok(path),
    };
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(PENDING_SUFFIX))
        .ok_or_else(|| io::Error::other("invalid S200 candidate key filename"))?;
    let destination = path.with_file_name(format!("{stem}{suffix}"));
    fs::rename(&path, &destination).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{reply}. Could not update the keys at {}: {error}",
                path.display()
            ),
        )
    })?;
    Ok(destination)
}

pub(super) struct RegistrationProof {
    pub(super) encrypted_id: Vec<u8>,
    pub(super) certificate: Vec<u8>,
}

struct SetupLink {
    _control_subscription: Subscription,
    _auth_subscription: Subscription,
    control: GattCharacteristic,
    auth: GattCharacteristic,
    replies: Receiver<(Channel, Vec<u8>)>,
    service: GattDeviceService,
    _device: BluetoothLEDevice,
    _apartment: Apartment,
}

impl SetupLink {
    fn open(scale: &Scale) -> io::Result<Self> {
        let apartment = Apartment::initialize()?;
        let device = open_scale_device(scale)?;
        let service = setup_service(&device)?;
        let control = setup_characteristic(&service, 0x0010)?;
        let auth = setup_characteristic(&service, 0x0019)?;
        let (sender, replies) = mpsc::channel();
        let control_subscription = Subscription::start(&control, Channel::Control, sender.clone())?;
        let auth_subscription = Subscription::start(&auth, Channel::Auth, sender)?;
        Ok(Self {
            _control_subscription: control_subscription,
            _auth_subscription: auth_subscription,
            control,
            auth,
            replies,
            service,
            _device: device,
            _apartment: apartment,
        })
    }

    fn read_profile(&self) -> io::Result<SetupProfile> {
        write_packet(&self.control, &REQUEST_DEVICE_INFO)?;
        receive_block(
            &self.auth,
            &self.replies,
            DEVICE_INFO_OR_ID,
            "device information",
        )
        .map(SetupProfile)
    }
}

pub(super) fn register_with<T>(
    scale: &Scale,
    authorize: impl FnOnce(&Registration) -> io::Result<(RegistrationProof, T)>,
) -> io::Result<(SetupCertificateReply, T)> {
    registration_status(scale)
        .map_err(|blocker| io::Error::new(io::ErrorKind::InvalidInput, blocker.message()))?;
    let link = SetupLink::open(scale)?;
    let SetupLink {
        control,
        auth,
        replies,
        service,
        ..
    } = &link;
    let mtu = service.Session()?.MaxPduSize()?;
    let profile = link.read_profile()?;
    if !profile.supports_registration() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Connected to S200 {}. Bluetooth setup expected a 4- or 24-byte reply starting with 02 00 00 00. Received {profile}.",
                scale.address()
            ),
        ));
    }

    let exchange = RegistrationKeys::generate();
    write_packet(control, &START_KEY_EXCHANGE)?;
    transmit_block(
        auth,
        replies,
        mtu,
        PUBLIC_KEY_BLOCK,
        exchange.public_key(),
        "app public key",
    )?;
    require_ack(replies, FRAGMENTS_RECEIVED, "app public key")?;
    let peer = receive_block(auth, replies, PUBLIC_KEY_BLOCK, "scale public key")?;
    let registration = exchange.finish(&peer)?;
    let (proof, state) = authorize(&registration)?;

    write_packet(control, &CONFIRM_REGISTRATION)?;
    transmit_block(
        auth,
        replies,
        mtu,
        DEVICE_INFO_OR_ID,
        &proof.encrypted_id,
        "encrypted device ID",
    )?;
    require_ack(replies, FRAGMENTS_RECEIVED, "encrypted device ID")?;

    transmit_block(
        auth,
        replies,
        mtu,
        CERTIFICATE_BLOCK,
        &proof.certificate,
        "registration certificate",
    )?;
    let reply = match await_reply(replies, Some(FRAGMENTS_RECEIVED)) {
        Response::Control(reply) => Ok(reply),
        Response::Acknowledged => match await_reply(replies, None) {
            Response::Control(reply) => Ok(reply),
            Response::TransferFailed => Err(transfer_error("registration certificate")),
            Response::TimedOut | Response::Acknowledged => {
                Ok(SetupCertificateReply::ReceivedWithoutRegistrationResult)
            }
        },
        Response::TransferFailed => Err(transfer_error("registration certificate")),
        Response::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the certificate was sent, but the scale gave no transfer acknowledgment or registration result",
        )),
    }?;
    Ok((reply, state))
}

fn transmit_block(
    auth: &GattCharacteristic,
    replies: &Receiver<(Channel, Vec<u8>)>,
    mtu: u16,
    kind: u8,
    payload: &[u8],
    description: &str,
) -> io::Result<()> {
    let (announcement, fragments) = block_packets(mtu, kind, payload)?;
    write_packet(auth, &announcement)?;
    require_ack(replies, READY, &format!("{description} announcement"))?;
    for fragment in fragments {
        write_packet(auth, &fragment)?;
    }
    Ok(())
}

fn require_ack(
    replies: &Receiver<(Channel, Vec<u8>)>,
    expected: [u8; 4],
    stage: &str,
) -> io::Result<()> {
    match await_reply(replies, Some(expected)) {
        Response::Acknowledged => Ok(()),
        Response::TransferFailed => Err(transfer_error(stage)),
        Response::Control(reply) => Err(io::Error::other(format!(
            "while waiting for the {stage} acknowledgment, {reply}"
        ))),
        Response::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the scale did not acknowledge the {stage}"),
        )),
    }
}

fn receive_block(
    auth: &GattCharacteristic,
    replies: &Receiver<(Channel, Vec<u8>)>,
    kind: u8,
    stage: &str,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    receive_framed_block(auth, Some(kind), stage, || {
        next_auth_packet(replies, deadline, stage)
    })
}

pub(super) fn receive_framed_block(
    characteristic: &GattCharacteristic,
    expected: Option<u8>,
    stage: &str,
    mut next: impl FnMut() -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    loop {
        let packet = next()?;
        match packet.as_slice() {
            [0, 0, 2, block, data @ ..] if expected.is_none_or(|kind| *block == kind) => {
                write_packet(characteristic, &SINGLE_PACKET_RECEIVED)?;
                return Ok(data.to_vec());
            }
            [0, 0, 0, block, low, high] if expected.is_none_or(|kind| *block == kind) => {
                let count = u16::from_le_bytes([*low, *high]);
                if !(1..=32).contains(&count) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid fragment count for {stage}"),
                    ));
                }
                write_packet(characteristic, &READY)?;
                let mut data = Vec::new();
                for index in 1..=count {
                    let fragment = next()?;
                    if !fragment.starts_with(&index.to_le_bytes()) || fragment.len() <= 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("out-of-order fragment for {stage}"),
                        ));
                    }
                    data.extend_from_slice(&fragment[2..]);
                }
                write_packet(characteristic, &FRAGMENTS_RECEIVED)?;
                return Ok(data);
            }
            _ => {}
        }
    }
}

fn next_auth_packet(
    replies: &Receiver<(Channel, Vec<u8>)>,
    deadline: Instant,
    stage: &str,
) -> io::Result<Vec<u8>> {
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match replies.recv_timeout(remaining) {
            Ok((Channel::Auth, packet)) => {
                if packet.starts_with(&TRANSFER_FAILED) {
                    return Err(transfer_error(stage));
                }
                return Ok(packet);
            }
            Ok((Channel::Control, packet)) => {
                if let Some(reply) = registration_reply(&packet) {
                    return Err(io::Error::other(format!(
                        "while waiting for {stage}, {reply}"
                    )));
                }
            }
            Ok((Channel::Data, _)) => {}
            Err(_) => break,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the scale did not send {stage}"),
    ))
}

type BlockPackets = ([u8; 6], Vec<Vec<u8>>);

pub(super) fn block_packets(mtu: u16, kind: u8, payload: &[u8]) -> io::Result<BlockPackets> {
    // The ms113 reported transfer error 0x05 for large certificate fragments at
    // MTU 251. It acknowledged the same DER using at most 20 bytes per write.
    let mtu = if kind == CERTIFICATE_BLOCK {
        mtu.min(CERTIFICATE_MTU)
    } else {
        mtu
    };
    // Bluetooth ATT writes use three bytes. Fragment indexes use two more bytes.
    let write_size = usize::from(mtu)
        .checked_sub(3)
        .filter(|size| *size >= 20)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the scale reported an invalid Bluetooth MTU",
            )
        })?;
    // The S200 capture uses an announced transfer for the app key and device ID
    // even when the entire payload fits in one ATT write.
    let fragments = payload.chunks(write_size - 2);
    let count = u16::try_from(fragments.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let [low, high] = count.to_le_bytes();
    let mut packets = Vec::with_capacity(usize::from(count));
    for (index, fragment) in (1..=count).zip(fragments) {
        let mut packet = index.to_le_bytes().to_vec();
        packet.extend_from_slice(fragment);
        packets.push(packet);
    }
    Ok(([0, 0, 0, kind, low, high], packets))
}

pub(super) fn write_packet(characteristic: &GattCharacteristic, packet: &[u8]) -> io::Result<()> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(packet)?;
    let result = characteristic
        .WriteValueWithResultAndOptionAsync(
            &writer.DetachBuffer()?,
            GattWriteOption::WriteWithoutResponse,
        )?
        .join()?;
    check_service_status(result.Status()?)
}

#[derive(Clone, Copy)]
pub(super) enum Channel {
    Control,
    Auth,
    Data,
}

enum Response {
    Control(SetupCertificateReply),
    Acknowledged,
    TransferFailed,
    TimedOut,
}

fn await_reply(
    replies: &Receiver<(Channel, Vec<u8>)>,
    acknowledgment: Option<[u8; 4]>,
) -> Response {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok((channel, packet)) = replies.recv_timeout(remaining) else {
            break;
        };
        match (channel, packet.as_slice()) {
            (Channel::Control, packet) => {
                if let Some(reply) = registration_reply(packet) {
                    return Response::Control(reply);
                }
            }
            (Channel::Auth, data) if data.starts_with(&TRANSFER_FAILED) => {
                return Response::TransferFailed;
            }
            (Channel::Auth, data)
                if acknowledgment
                    .as_ref()
                    .is_some_and(|expected| data == expected) =>
            {
                return Response::Acknowledged;
            }
            _ => {}
        }
    }
    Response::TimedOut
}

fn transfer_error(stage: &str) -> io::Error {
    io::Error::other(format!(
        "the scale reported transfer error 0x05 for {stage}"
    ))
}

fn registration_reply(packet: &[u8]) -> Option<SetupCertificateReply> {
    match packet {
        [0x11, 0, 0, 0] => Some(SetupCertificateReply::RegistrationSucceeded),
        [0x12, 0, 0, 0] => Some(SetupCertificateReply::RegistrationFailed),
        [0xe1, 0, 0, 0] => Some(SetupCertificateReply::AlreadyRegistered),
        _ => None,
    }
}

pub(super) struct Subscription {
    characteristic: GattCharacteristic,
    token: i64,
}

impl Subscription {
    pub(super) fn start(
        characteristic: &GattCharacteristic,
        channel: Channel,
        sender: Sender<(Channel, Vec<u8>)>,
    ) -> io::Result<Self> {
        let properties = characteristic.CharacteristicProperties()?;
        let delivery = if properties.contains(GattCharacteristicProperties::Notify) {
            GattClientCharacteristicConfigurationDescriptorValue::Notify
        } else if properties.contains(GattCharacteristicProperties::Indicate) {
            GattClientCharacteristicConfigurationDescriptorValue::Indicate
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the S200 characteristic does not support notifications or indications",
            ));
        };
        let handler = TypedEventHandler::<GattCharacteristic, GattValueChangedEventArgs>::new(
            move |_, args| {
                if let Some(args) = args.as_ref() {
                    let data = DataReader::FromBuffer(&args.CharacteristicValue()?)?;
                    let mut bytes = vec![0; data.UnconsumedBufferLength()? as usize];
                    data.ReadBytes(&mut bytes)?;
                    let _ = sender.send((channel, bytes));
                }
                Ok(())
            },
        );
        let subscription = Self {
            characteristic: characteristic.clone(),
            token: characteristic.ValueChanged(&handler)?,
        };
        let status = characteristic
            .WriteClientCharacteristicConfigurationDescriptorAsync(delivery)?
            .join()?;
        check_service_status(status)?;
        Ok(subscription)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _ = self.characteristic.RemoveValueChanged(self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::{CERTIFICATE_BLOCK, PUBLIC_KEY_BLOCK, SetupProfile, block_packets};

    const CERTIFICATE_PAYLOAD: &[u8] = &[0x30; 329];

    #[test]
    fn accepts_both_observed_device_info_formats_with_the_supported_header() {
        assert!(SetupProfile(vec![2, 0, 0, 0]).supports_registration());

        let mut extended = vec![2, 0, 0, 0];
        extended.extend_from_slice(&[0xff; 20]);
        assert!(SetupProfile(extended.clone()).supports_registration());
        assert_eq!(
            SetupProfile(extended.clone()).to_string(),
            "02 00 00 00 … (24 bytes total)"
        );
        extended[0] = 3;
        assert!(!SetupProfile(extended).supports_registration());
        assert!(!SetupProfile(vec![2, 0, 0, 1]).supports_registration());
        assert!(!SetupProfile(vec![2, 0, 0, 0, 0]).supports_registration());
    }

    #[test]
    fn frames_the_entire_certificate_at_small_mtu() {
        let (header, packets) = block_packets(23, CERTIFICATE_BLOCK, CERTIFICATE_PAYLOAD).unwrap();
        assert_eq!(header, [0, 0, 0, 7, 19, 0]);
        assert_eq!(packets.len(), 19);
        assert!(packets.iter().all(|packet| packet.len() <= 20));
        let data: Vec<_> = packets
            .iter()
            .flat_map(|packet| &packet[2..])
            .copied()
            .collect();
        assert_eq!(data, CERTIFICATE_PAYLOAD);
    }

    #[test]
    fn limits_certificate_packets_at_larger_mtu() {
        let minimum_mtu = block_packets(23, CERTIFICATE_BLOCK, CERTIFICATE_PAYLOAD).unwrap();
        assert_eq!(
            block_packets(251, CERTIFICATE_BLOCK, CERTIFICATE_PAYLOAD).unwrap(),
            minimum_mtu
        );
    }

    #[test]
    fn announces_one_key_fragment_when_the_key_fits() {
        let (header, packets) = block_packets(247, PUBLIC_KEY_BLOCK, &[2; 64]).unwrap();
        assert_eq!(header, [0, 0, 0, 3, 1, 0]);
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0][..2], &[1, 0]);
        assert_eq!(&packets[0][2..], &[2; 64]);
    }
}
