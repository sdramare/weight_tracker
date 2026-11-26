use std::env;
use std::io;
use std::str::FromStr;

use aes::Aes128;
use ccm::Ccm;
use ccm::aead::{
    AeadInPlace, KeyInit,
    consts::{U4, U12},
};

use crate::{BluetoothAddress, Weight};

const BIND_KEY_ENV: &str = "S200_BINDKEY";
const ENCRYPTED: u16 = 0x0008;
const HAS_MAC: u16 = 0x0010;
const HAS_CAPABILITY: u16 = 0x0020;
const HAS_OBJECT: u16 = 0x0040;
const WEIGHT_OBJECT: u16 = 0x4e16;

/// The 16-byte MiBeacon key for an S200 bound to Xiaomi Home.
pub struct ScaleBindKey([u8; 16]);

impl ScaleBindKey {
    /// Loads the key from the current process's S200_BINDKEY environment variable.
    pub fn from_environment() -> io::Result<Option<Self>> {
        match env::var(BIND_KEY_ENV) {
            Ok(key) => key.parse().map(Some),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(invalid_key()),
        }
    }
}

impl FromStr for ScaleBindKey {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        let hex = value.trim().as_bytes();
        let mut key = [0; 16];
        if hex.len() != key.len() * 2 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid_key());
        }
        for (byte, pair) in key.iter_mut().zip(hex.chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid_key())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid_key())?;
        }
        Ok(Self(key))
    }
}

fn invalid_key() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "S200 bind key must contain 32 hexadecimal digits",
    )
}

pub(super) struct WeightDecoder(Ccm<Aes128, U4, U12>);

impl WeightDecoder {
    pub(super) fn new(key: &ScaleBindKey) -> Self {
        Self(Ccm::new((&key.0).into()))
    }

    pub(super) fn decode(&self, address: BluetoothAddress, data: &[u8]) -> Option<Weight> {
        let [
            0x95,
            0xfe,
            control_low,
            control_high,
            product_low,
            product_high,
            frame,
            body @ ..,
        ] = data
        else {
            return None;
        };
        let mut body = body;
        let flags = u16::from_le_bytes([*control_low, *control_high]);
        if !matches!(flags >> 12, 4 | 5)
            || flags & (ENCRYPTED | HAS_OBJECT) != (ENCRYPTED | HAS_OBJECT)
        {
            return None;
        }

        let mac = if flags & HAS_MAC != 0 {
            let (mac, rest) = body.split_first_chunk::<6>()?;
            body = rest;
            *mac
        } else {
            let [a, b, c, d, e, f, _, _] = address.0.to_le_bytes();
            [a, b, c, d, e, f]
        };

        if flags & HAS_CAPABILITY != 0 {
            let (capability, rest) = body.split_first()?;
            body = rest.get(usize::from(capability & 0x20 != 0)..)?;
        }

        let (body, tag) = body.split_last_chunk::<4>()?;
        let (ciphertext, counter) = body.split_last_chunk::<3>()?;
        // MiBeacon v4/v5 authenticates the objects using the sender MAC and frame counters.
        let [a, b, c, d, e, f] = mac;
        let [x, y, z] = *counter;
        let nonce = [
            a,
            b,
            c,
            d,
            e,
            f,
            *product_low,
            *product_high,
            *frame,
            x,
            y,
            z,
        ];
        let mut plaintext = ciphertext.to_vec();
        self.0
            .decrypt_in_place_detached((&nonce).into(), &[0x11], &mut plaintext, tag.into())
            .ok()?;
        weight_object(&plaintext)
    }
}

fn weight_object(mut objects: &[u8]) -> Option<Weight> {
    while let [id_low, id_high, length, body @ ..] = objects {
        let (value, rest) = body.split_at_checked(usize::from(*length))?;
        let id = u16::from_le_bytes([*id_low, *id_high]);
        if let (WEIGHT_OBJECT, [_, a, b, c, d, _, _, _, _]) = (id, value) {
            let weight = u32::from_le_bytes([*a, *b, *c, *d]);
            return (weight > 0).then_some(Weight(weight));
        }
        objects = rest;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{BluetoothAddress, ScaleBindKey, Weight, WeightDecoder, weight_object};

    // Synthetic MiBeacon v5 frames sealed independently with Python's AESCCM.
    const WITH_MAC: &[u8] = &[
        0x95, 0xfe, 0x58, 0x59, 0x04, 0x4c, 0x7a, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x0a, 0x00,
        0x01, 0x38, 0x49, 0x84, 0x59, 0x1f, 0x22, 0x4b, 0x8d, 0xb9, 0x01, 0x02, 0x03, 0x1d, 0xe8,
        0x7b, 0xaf,
    ];
    const WITHOUT_MAC: &[u8] = &[
        0x95, 0xfe, 0x68, 0x59, 0x04, 0x4c, 0x7a, 0x20, 0x00, 0x0a, 0x00, 0x01, 0x38, 0x49, 0x84,
        0x59, 0x1f, 0x22, 0x4b, 0x8d, 0xb9, 0x01, 0x02, 0x03, 0x1d, 0xe8, 0x7b, 0xaf,
    ];

    #[test]
    fn decodes_weight_from_authenticated_frames() {
        let key = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        let decoder = WeightDecoder::new(&key);
        let address = BluetoothAddress(0x1234_5678_9abc);
        assert_eq!(decoder.decode(address, WITH_MAC), Some(Weight(7255)));
        assert_eq!(decoder.decode(address, WITHOUT_MAC), Some(Weight(7255)));
        assert_eq!(Weight(7255).to_string(), "72.55 kg");
    }

    #[test]
    fn rejects_wrong_keys_and_truncated_advertisements() {
        let decoder = WeightDecoder::new(&ScaleBindKey([0xff; 16]));
        let address = BluetoothAddress(0x1234_5678_9abc);
        assert_eq!(decoder.decode(address, WITH_MAC), None);
        let key = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        let decoder = WeightDecoder::new(&key);
        for length in 0..WITH_MAC.len() {
            assert_eq!(decoder.decode(address, &WITH_MAC[..length]), None);
        }
        assert_eq!(
            decoder.decode(address, &[0x95, 0xfe, 0x10, 0x59, 0x04, 0x4c, 0x7a]),
            None
        );
        assert!(
            "000102030405060708090a0b0c0d0e+f"
                .parse::<ScaleBindKey>()
                .is_err()
        );
    }

    #[test]
    fn ignores_empty_and_malformed_weight_objects() {
        assert_eq!(
            weight_object(&[0x16, 0x4e, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
        assert_eq!(weight_object(&[0x16, 0x4e, 9, 0, 0xff]), None);
    }
}
