use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use aes::Aes128;
use ccm::Ccm;
use ccm::aead::{AeadInPlace, KeyInit};
use ccm::consts::{U4, U12};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use sha2::Sha256;

type DeviceIdCipher = Ccm<Aes128, U4, U12>;
const DEVICE_ID_NONCE: [u8; 12] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
];

pub(super) struct RegistrationKeys {
    secret: EphemeralSecret,
    public_key: [u8; 64],
}

pub(super) struct Registration {
    device_id: String,
    keys: [u8; 64],
}

impl RegistrationKeys {
    pub(super) fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let encoded = secret.public_key().to_encoded_point(false);
        let mut public_key = [0; 64];
        public_key.copy_from_slice(&encoded.as_bytes()[1..]);
        Self { secret, public_key }
    }

    pub(super) fn public_key(&self) -> &[u8; 64] {
        &self.public_key
    }

    pub(super) fn finish(self, peer_key: &[u8]) -> io::Result<Registration> {
        let coordinates = <[u8; 64]>::try_from(peer_key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the scale public key is not 64 bytes",
            )
        })?;
        let mut encoded = [0x04; 65];
        encoded[1..].copy_from_slice(&coordinates);
        let peer = PublicKey::from_sec1_bytes(&encoded).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the scale sent an invalid P-256 public key",
            )
        })?;
        let shared = self.secret.diffie_hellman(&peer);
        let keys = derive_keys(shared.raw_secret_bytes().as_ref())?;
        let mut test_id_bytes = [0; 8];
        test_id_bytes[1..].copy_from_slice(&self.public_key[..7]);
        let device_id = format!("test-{:014x}", u64::from_be_bytes(test_id_bytes));
        Ok(Registration { device_id, keys })
    }
}

impl Registration {
    pub(super) fn encrypted_device_id(&self) -> io::Result<Vec<u8>> {
        let cipher = DeviceIdCipher::new_from_slice(&self.keys[28..44])
            .map_err(|_| io::Error::other("could not initialize the setup cipher"))?;
        let mut plain = vec![0];
        plain.extend_from_slice(self.device_id.as_bytes());
        let tag = cipher
            .encrypt_in_place_detached(&DEVICE_ID_NONCE.into(), b"devID", &mut plain)
            .map_err(|_| io::Error::other("could not encrypt the test device ID"))?;
        plain.extend_from_slice(&tag);
        Ok(plain)
    }

    pub(super) fn save_trial_credentials(&self, directory: &Path) -> io::Result<()> {
        fs::create_dir_all(directory)?;
        let path = directory.join(format!("{}.keys", self.device_id));
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        // Retain the keys if the scale enrolls and disconnects before reporting its result.
        for (label, bytes) in [
            ("login_token", &self.keys[..12]),
            ("bind_key", &self.keys[12..28]),
        ] {
            write!(file, "{label}=")?;
            for byte in bytes {
                write!(file, "{byte:02x}")?;
            }
            writeln!(file)?;
        }
        file.sync_all()
    }
}

fn derive_keys(shared: &[u8]) -> io::Result<[u8; 64]> {
    let mut keys = [0; 64];
    Hkdf::<Sha256>::new(None, shared)
        .expand(b"mible-setup-info", &mut keys)
        .map_err(|_| io::Error::other("could not derive the setup keys"))?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::RegistrationKeys;

    #[test]
    fn derives_the_same_keys_on_both_ends() {
        let app = RegistrationKeys::generate();
        let scale = RegistrationKeys::generate();
        let app_public = *app.public_key();
        let scale_public = *scale.public_key();
        let app = app.finish(&scale_public).unwrap();
        let scale = scale.finish(&app_public).unwrap();
        assert_eq!(app.keys, scale.keys);
        assert_eq!(app.encrypted_device_id().unwrap().len(), 24);
    }
}
