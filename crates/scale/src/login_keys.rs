use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{BluetoothAddress, Scale, ScaleSetupInfo};

const REGISTRATION_DIRECTORY: &str = "s200-registration";

/// The 12-byte Standard Auth login token issued during setup.
pub struct ScaleLoginToken(pub(crate) [u8; 12]);

/// Login tokens found in the workspace's saved S200 registrations.
#[derive(Default)]
pub struct SavedScaleLogins {
    addressed: BTreeMap<BluetoothAddress, SavedLogin>,
    legacy: Option<SavedLogin>,
    multiple_legacy: bool,
}

struct SavedLogin {
    token: ScaleLoginToken,
    modified: SystemTime,
}

impl SavedScaleLogins {
    /// Searches the current workspace and the executable's build directory.
    pub fn load_default() -> io::Result<Self> {
        let directory = std::env::current_dir()?
            .join("target")
            .join(REGISTRATION_DIRECTORY);
        let keys = Self::load(&directory)?;
        if !keys.is_empty() {
            return Ok(keys);
        }
        let executable = std::env::current_exe()?;
        if let Some(target) = executable
            .ancestors()
            .find(|path| path.file_name().is_some_and(|name| name == "target"))
        {
            let built_directory = target.join(REGISTRATION_DIRECTORY);
            if built_directory != directory {
                return Self::load(&built_directory);
            }
        }
        Ok(keys)
    }

    fn load(directory: &Path) -> io::Result<Self> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        let mut logins = Self::default();
        for entry in entries {
            let entry = entry?;
            let filename = entry.file_name();
            if !filename
                .to_str()
                .is_some_and(|name| name.starts_with("s200-") && name.ends_with(".keys"))
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let metadata = entry.metadata()?;
            let (address, token) = fs::read_to_string(entry.path())
                .and_then(|contents| parse_login(&contents))
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("read S200 keys from {}: {error}", entry.path().display()),
                    )
                })?;
            let saved = SavedLogin {
                token,
                modified: metadata.modified().unwrap_or(UNIX_EPOCH),
            };
            if let Some(address) = address {
                let latest = logins.addressed.entry(address);
                match latest {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(saved);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry)
                        if saved.modified > entry.get().modified =>
                    {
                        entry.insert(saved);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            } else if logins.legacy.is_none() {
                logins.legacy = Some(saved);
            } else {
                logins.multiple_legacy = true;
            }
        }
        Ok(logins)
    }

    pub fn is_empty(&self) -> bool {
        self.addressed.is_empty() && self.legacy.is_none()
    }

    /// Selects an address-matched token or the sole older token for an ms113.
    pub fn token_for(&self, scale: &Scale) -> Option<&ScaleLoginToken> {
        if let Some(login) = self.addressed.get(&scale.address()) {
            return Some(&login.token);
        }
        if self.multiple_legacy
            || !scale
                .setup_info()
                .as_ref()
                .is_some_and(ScaleSetupInfo::is_ms113)
        {
            return None;
        }
        self.legacy.as_ref().map(|login| &login.token)
    }
}

fn parse_login(contents: &str) -> io::Result<(Option<BluetoothAddress>, ScaleLoginToken)> {
    let fields = || contents.lines().filter_map(|line| line.split_once('='));
    let token = fields()
        .find_map(|(key, value)| (key == "login_token").then_some(value.trim()))
        .and_then(parse_token)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the login token must contain 24 hexadecimal digits",
            )
        })?;
    let address = fields()
        .find_map(|(key, value)| (key == "bluetooth_address").then_some(value.trim()))
        .map(|value| {
            parse_address(value).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the saved Bluetooth address is invalid",
                )
            })
        })
        .transpose()?;
    Ok((address, ScaleLoginToken(token)))
}

fn parse_token(value: &str) -> Option<[u8; 12]> {
    let text = value.as_bytes();
    let mut token = [0; 12];
    if text.len() != token.len() * 2 {
        return None;
    }
    for (byte, pair) in token.iter_mut().zip(text.chunks_exact(2)) {
        *byte = parse_hex_byte(pair)?;
    }
    Some(token)
}

fn parse_address(value: &str) -> Option<BluetoothAddress> {
    let parts: [&str; 6] = value.split(':').collect::<Vec<_>>().try_into().ok()?;
    let mut address = 0;
    for part in parts {
        address = address << 8 | u64::from(parse_hex_byte(part.as_bytes())?);
    }
    Some(BluetoothAddress(address))
}

fn parse_hex_byte(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u8::from_str_radix(std::str::from_utf8(bytes).ok()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_login;

    #[test]
    fn accepts_setup_files_with_and_without_a_saved_address() {
        let keys = "login_token=00112233445566778899aabb\nbind_key=ignored\n";
        let (address, token) = parse_login(keys).unwrap();
        assert!(address.is_none());
        assert_eq!(
            token.0,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
            ]
        );
        let (address, _) =
            parse_login(&format!("{keys}bluetooth_address=D0:7B:6F:00:00:01\n")).unwrap();
        assert_eq!(address.unwrap().to_string(), "D0:7B:6F:00:00:01");
        assert!(parse_login("login_token=missing\n").is_err());
    }
}
