use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{BluetoothAddress, Scale};

const REGISTRATION_DIRECTORY: &str = "s200-registration";
pub(crate) const PENDING_SUFFIX: &str = ".pending.keys";
pub(crate) const CONFIRMED_SUFFIX: &str = ".confirmed.keys";
pub(crate) const REJECTED_SUFFIX: &str = ".rejected.keys";

/// The 12-byte Standard Auth login token issued during setup.
#[derive(PartialEq, Eq)]
pub struct ScaleLoginToken(pub(crate) [u8; 12]);

/// Saved login tokens and any problems encountered while loading them.
#[derive(Default)]
pub struct SavedScaleLogins {
    addressed: BTreeMap<(BluetoothAddress, CredentialState), SavedLogin>,
    unaddressed: Option<SavedLogin>,
    multiple_unaddressed: bool,
    warnings: Vec<io::Error>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CredentialState {
    Legacy,
    Pending,
    Confirmed,
}

struct SavedLogin {
    token: ScaleLoginToken,
    modified: SystemTime,
}

/// Returns the current user's persistent location for S200 credentials.
pub fn default_registration_directory() -> io::Result<PathBuf> {
    let app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Windows Local AppData is unavailable",
            )
        })?;
    Ok(app_data.join("blt_unlock").join(REGISTRATION_DIRECTORY))
}

impl SavedScaleLogins {
    /// Loads per-user credentials and imports valid registrations from older build directories.
    pub fn load_default() -> io::Result<Self> {
        let mut logins = Self::default();
        let persistent = match default_registration_directory() {
            Ok(path) => {
                logins.load_directory(&path, None);
                Some(path)
            }
            Err(error) => {
                logins.warnings.push(error);
                None
            }
        };
        let mut old_targets = BTreeSet::new();
        match std::env::current_dir() {
            Ok(path) => {
                old_targets.insert(path.join("target"));
            }
            Err(error) => logins.warnings.push(error),
        }
        match std::env::current_exe() {
            Ok(executable) => {
                if let Some(target) = executable
                    .ancestors()
                    .find(|path| path.file_name().is_some_and(|name| name == "target"))
                {
                    old_targets.insert(target.to_path_buf());
                }
            }
            Err(error) => logins.warnings.push(error),
        }
        if persistent.is_none() && old_targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "could not locate an S200 credentials directory",
            ));
        }
        for target in old_targets {
            logins.load_directory(&target.join(REGISTRATION_DIRECTORY), persistent.as_deref());
            if let Some(persistent) = &persistent {
                logins.migrate_old_trials(&target.join("s200-setup-test"), persistent);
            }
        }
        Ok(logins)
    }

    fn files(&mut self, directory: &Path) -> Option<fs::ReadDir> {
        match fs::read_dir(directory) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                self.warn("read S200 key directory", directory, error);
                None
            }
        }
    }

    fn load_directory(&mut self, directory: &Path, import_into: Option<&Path>) {
        let Some(entries) = self.files(directory) else {
            return;
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.warn("list S200 keys in", directory, error);
                    continue;
                }
            };
            let name = entry.file_name();
            let Some(state) = name.to_str().and_then(credential_state) else {
                continue;
            };
            let path = entry.path();
            let result = (|| {
                if !entry.file_type()?.is_file() {
                    return Ok(());
                }
                let contents = fs::read_to_string(&path)?;
                let (address, token) = parse_login(&contents)?;
                let modified = entry.metadata()?.modified().unwrap_or(UNIX_EPOCH);
                self.insert(address, state, SavedLogin { token, modified });
                if let Some(destination) = import_into
                    && let Err(error) = import_file(destination, &contents, modified, state)
                {
                    self.warn("migrate S200 keys from", &path, error);
                }
                Ok(())
            })();
            if let Err(error) = result {
                self.warn("read S200 keys from", &path, error);
            }
        }
    }

    fn migrate_old_trials(&mut self, directory: &Path, persistent: &Path) {
        let Some(entries) = self.files(directory) else {
            return;
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.warn("list older S200 trials in", directory, error);
                    continue;
                }
            };
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("test-") && name.ends_with(".keys"))
            {
                continue;
            }
            let path = entry.path();
            let result = (|| {
                if entry.file_type()?.is_file() {
                    let contents = fs::read_to_string(&path)?;
                    parse_login(&contents)?;
                    let modified = entry.metadata()?.modified().unwrap_or(UNIX_EPOCH);
                    import_file(
                        &persistent.join("recovery"),
                        &contents,
                        modified,
                        CredentialState::Legacy,
                    )?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                self.warn("preserve older S200 trial keys from", &path, error);
            }
        }
    }

    fn insert(
        &mut self,
        address: Option<BluetoothAddress>,
        state: CredentialState,
        saved: SavedLogin,
    ) {
        if let Some(address) = address {
            let latest = self.addressed.entry((address, state));
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
        } else if state == CredentialState::Legacy {
            match &self.unaddressed {
                None => self.unaddressed = Some(saved),
                Some(previous) if previous.token != saved.token => self.multiple_unaddressed = true,
                Some(_) => {}
            }
        }
    }

    fn warn(&mut self, operation: &str, path: &Path, error: io::Error) {
        self.warnings.push(io::Error::new(
            error.kind(),
            format!("{operation} {}: {error}", path.display()),
        ));
    }

    /// Lists individual file or directory errors without discarding usable registrations.
    pub fn warnings(&self) -> &[io::Error] {
        &self.warnings
    }

    pub fn is_empty(&self) -> bool {
        self.addressed.is_empty() && (self.unaddressed.is_none() || self.multiple_unaddressed)
    }

    /// Selects a saved token for a scale whose advertisements permit a login attempt.
    pub fn token_for(&self, scale: &Scale) -> Option<&ScaleLoginToken> {
        let registered = scale.setup_info().and_then(|info| info.registered());
        if registered == Some(false) {
            return None;
        }

        let address = scale.address();
        let confirmed = self.addressed.get(&(address, CredentialState::Confirmed));
        let legacy = self.addressed.get(&(address, CredentialState::Legacy));
        let pending = self
            .addressed
            .get(&(address, CredentialState::Pending))
            .filter(|_| registered == Some(true));
        pending
            .into_iter()
            .chain(confirmed.or(legacy))
            .max_by_key(|login| login.modified)
            .or_else(|| {
                self.unaddressed.as_ref().filter(|_| {
                    !self.multiple_unaddressed
                        && scale.setup_info().is_some_and(|info| info.is_ms113())
                })
            })
            .map(|login| &login.token)
    }
}

fn credential_state(name: &str) -> Option<CredentialState> {
    if !name.starts_with("s200-") || !name.ends_with(".keys") || name.ends_with(REJECTED_SUFFIX) {
        return None;
    }
    if name.ends_with(PENDING_SUFFIX) {
        Some(CredentialState::Pending)
    } else if name.ends_with(CONFIRMED_SUFFIX) {
        Some(CredentialState::Confirmed)
    } else {
        Some(CredentialState::Legacy)
    }
}

fn import_file(
    directory: &Path,
    contents: &str,
    modified: SystemTime,
    state: CredentialState,
) -> io::Result<()> {
    let digest: String = Sha256::digest(contents.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let suffix = match state {
        CredentialState::Legacy => ".keys",
        CredentialState::Pending => PENDING_SUFFIX,
        CredentialState::Confirmed => CONFIRMED_SUFFIX,
    };
    let path = directory.join(format!("s200-import-{digest}{suffix}"));
    match write_new_credentials(&path, contents, Some(modified)) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::read_to_string(&path)? == contents {
                Ok(())
            } else {
                Err(error)
            }
        }
        result => result,
    }
}

pub(crate) fn write_new_credentials(
    path: &Path,
    contents: &str,
    modified: Option<SystemTime>,
) -> io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("missing credentials directory"))?;
    fs::create_dir_all(directory)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let saved = (|| {
        file.write_all(contents.as_bytes())?;
        if let Some(modified) = modified {
            file.set_modified(modified)?;
        }
        file.sync_all()
    })();
    if saved.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    saved
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
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    let mut token = [0; 12];
    if pairs.len() != token.len() || !remainder.is_empty() {
        return None;
    }
    for (byte, pair) in token.iter_mut().zip(pairs) {
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
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{CredentialState, SavedLogin, SavedScaleLogins, ScaleLoginToken, parse_login};
    use crate::{BluetoothAddress, Scale, ScaleSetupInfo, SignalStrength};

    fn scale_with_control(control: Option<u8>) -> Scale {
        Scale {
            address: BluetoothAddress(1),
            address_type: None,
            name: None,
            signal_strength: SignalStrength(-60),
            connectable: true,
            weight: None,
            setup_info: control.and_then(|control| {
                ScaleSetupInfo::from_mibeacon(&[0x95, 0xfe, 0x10, control, 0xcb, 0x4d])
            }),
        }
    }

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

    #[test]
    fn imports_a_usable_legacy_key_alongside_a_bad_file() {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("s200-key-migration-{}-{id}", std::process::id()));
        let old = root.join("target").join("s200-registration");
        let persistent = root.join("app-data");
        let original = old.join("s200-valid.keys");
        let broken = old.join("s200-incomplete.keys");
        let contents = format!(
            "login_token={}\nbluetooth_address=00:00:00:00:00:01\n",
            "01".repeat(12)
        );
        fs::create_dir_all(&old).unwrap();
        fs::write(&original, &contents).unwrap();
        fs::write(&broken, "invalid").unwrap();

        let scale = scale_with_control(Some(0x5b));
        let mut logins = SavedScaleLogins::default();
        logins.load_directory(&old, Some(&persistent));
        logins.load_directory(&old, Some(&persistent));
        assert_eq!(logins.token_for(&scale).unwrap().0, [1; 12]);
        assert!(
            logins
                .warnings()
                .iter()
                .all(|warning| warning.to_string().contains("s200-incomplete.keys"))
        );
        assert_eq!(logins.warnings().len(), 2);
        assert_eq!(fs::read_dir(&persistent).unwrap().count(), 1);
        assert_eq!(fs::read_to_string(&original).unwrap(), contents);

        fs::remove_dir_all(&old).unwrap();
        let mut after_cleanup = SavedScaleLogins::default();
        after_cleanup.load_directory(&persistent, None);
        assert_eq!(after_cleanup.token_for(&scale).unwrap().0, [1; 12]);
        assert!(after_cleanup.warnings().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_uses_pending_keys_for_a_registered_advertisement() {
        let mut logins = SavedScaleLogins::default();
        logins.insert(
            Some(BluetoothAddress(1)),
            CredentialState::Pending,
            SavedLogin {
                token: ScaleLoginToken([1; 12]),
                modified: UNIX_EPOCH + Duration::from_secs(1),
            },
        );
        assert!(logins.token_for(&scale_with_control(None)).is_none());
        assert!(logins.token_for(&scale_with_control(Some(0x5a))).is_none());
        assert_eq!(
            logins.token_for(&scale_with_control(Some(0x5b))).unwrap().0,
            [1; 12]
        );
        logins.insert(
            Some(BluetoothAddress(1)),
            CredentialState::Confirmed,
            SavedLogin {
                token: ScaleLoginToken([2; 12]),
                modified: UNIX_EPOCH + Duration::from_secs(2),
            },
        );
        assert!(logins.token_for(&scale_with_control(Some(0x5a))).is_none());
        assert_eq!(
            logins.token_for(&scale_with_control(None)).unwrap().0,
            [2; 12]
        );
        assert_eq!(
            logins.token_for(&scale_with_control(Some(0x5b))).unwrap().0,
            [2; 12]
        );
    }
}
