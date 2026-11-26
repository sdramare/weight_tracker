use std::fmt;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattClientCharacteristicConfigurationDescriptorValue,
    GattValueChangedEventArgs, GattWriteOption,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};

use super::{
    Apartment, Scale, check_service_status, open_scale_device, setup_characteristic, setup_service,
};

const CERTIFICATE: &[u8] = include_bytes!("s200-local-test.der");
const CERTIFICATE_BLOCK: u8 = 0x07;
const READY: [u8; 4] = [0, 0, 1, 1];
const FRAGMENTS_RECEIVED: [u8; 4] = [0, 0, 1, 0];
const SINGLE_PACKET_RECEIVED: [u8; 4] = [0, 0, 3, 0];
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

/// Sends the bundled certificate block to an unregistered ms113 requesting setup.
///
/// The response belongs to the scale. This probes the certificate transfer alone.
pub fn send_setup_test_certificate(scale: &Scale) -> io::Result<SetupCertificateReply> {
    if !scale
        .setup_info()
        .is_some_and(|info| info.requests_certificate_test())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the scale must be an unregistered ms113 requesting setup",
        ));
    }
    let _apartment = Apartment::initialize()?;
    let device = open_scale_device(scale)?;
    let service = setup_service(&device)?;
    let control = setup_characteristic(&service, 0x0010)?;
    let auth = setup_characteristic(&service, 0x0019)?;
    let (sender, replies) = mpsc::channel();
    let _control_subscription = Subscription::start(&control, Channel::Control, sender.clone())?;
    let _auth_subscription = Subscription::start(&auth, Channel::Auth, sender)?;

    let packets = certificate_packets(service.Session()?.MaxPduSize()?)?;
    let acknowledgment = match packets.as_slice() {
        [packet] => {
            write_packet(&auth, packet)?;
            SINGLE_PACKET_RECEIVED
        }
        [announce, fragments @ ..] => {
            write_packet(&auth, announce)?;
            match await_reply(&replies, Some(READY)) {
                Response::Control(reply) => {
                    return Err(io::Error::other(format!(
                        "before the certificate was sent, {reply}"
                    )));
                }
                Response::Acknowledged => {}
                Response::TimedOut => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the scale did not acknowledge the certificate announcement",
                    ));
                }
            }
            for fragment in fragments {
                write_packet(&auth, fragment)?;
            }
            FRAGMENTS_RECEIVED
        }
        [] => {
            return Err(io::Error::other(
                "the certificate produced no Bluetooth packets",
            ));
        }
    };

    match await_reply(&replies, Some(acknowledgment)) {
        Response::Control(reply) => Ok(reply),
        Response::Acknowledged => match await_reply(&replies, None) {
            Response::Control(reply) => Ok(reply),
            _ => Ok(SetupCertificateReply::ReceivedWithoutRegistrationResult),
        },
        Response::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the test certificate was sent, but the scale gave no transfer acknowledgment or registration result",
        )),
    }
}

fn certificate_packets(mtu: u16) -> io::Result<Vec<Vec<u8>>> {
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
    if CERTIFICATE.len() + 4 <= write_size {
        let mut packet = vec![0, 0, 2, CERTIFICATE_BLOCK];
        packet.extend_from_slice(CERTIFICATE);
        return Ok(vec![packet]);
    }
    let fragments = CERTIFICATE.chunks(write_size - 2);
    let count = u16::try_from(fragments.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let [low, high] = count.to_le_bytes();
    let mut packets = Vec::with_capacity(usize::from(count) + 1);
    packets.push(vec![0, 0, 0, CERTIFICATE_BLOCK, low, high]);
    for (index, fragment) in (1..=count).zip(fragments) {
        let mut packet = index.to_le_bytes().to_vec();
        packet.extend_from_slice(fragment);
        packets.push(packet);
    }
    Ok(packets)
}

fn write_packet(characteristic: &GattCharacteristic, packet: &[u8]) -> io::Result<()> {
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
enum Channel {
    Control,
    Auth,
}

enum Response {
    Control(SetupCertificateReply),
    Acknowledged,
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
            (Channel::Control, [0x11, 0, 0, 0]) => {
                return Response::Control(SetupCertificateReply::RegistrationSucceeded);
            }
            (Channel::Control, [0x12, 0, 0, 0]) => {
                return Response::Control(SetupCertificateReply::RegistrationFailed);
            }
            (Channel::Control, [0xe1, 0, 0, 0]) => {
                return Response::Control(SetupCertificateReply::AlreadyRegistered);
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

struct Subscription {
    characteristic: GattCharacteristic,
    token: i64,
}

impl Subscription {
    fn start(
        characteristic: &GattCharacteristic,
        channel: Channel,
        sender: Sender<(Channel, Vec<u8>)>,
    ) -> io::Result<Self> {
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
            .WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify,
            )?
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
    use super::{CERTIFICATE, certificate_packets};

    #[test]
    fn frames_the_entire_certificate_at_small_mtu() {
        let packets = certificate_packets(23).unwrap();
        assert_eq!(packets[0], [0, 0, 0, 7, 19, 0]);
        assert_eq!(packets.len(), 20);
        assert!(packets.iter().all(|packet| packet.len() <= 20));
        let data: Vec<_> = packets[1..]
            .iter()
            .flat_map(|packet| &packet[2..])
            .copied()
            .collect();
        assert_eq!(data, CERTIFICATE);
    }

    #[test]
    fn sends_one_packet_when_it_fits() {
        let packets = certificate_packets(517).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0][..4], &[0, 0, 2, 7]);
        assert_eq!(&packets[0][4..], CERTIFICATE);
    }
}
