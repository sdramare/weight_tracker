#[cfg(any(windows, test))]
use std::{collections::BTreeMap, ops::ControlFlow, time::Duration};
use std::{ffi::OsString, process::ExitCode};

#[cfg(any(windows, test))]
use xiaomi_s200::{
    BluetoothAddress, ConnectedWeightEvent, RegistrationEvent, RegistrationObserver,
    RegistrationStep, SavedScaleLogins, Scale, ScaleScanObserver, ScaleSetupInfo,
    ScaleSetupInteraction, SetupCheck, SetupCheckObserver, SetupCheckStatus, Weight, WeightReading,
    WeightSessionObserver, XiaomiSignInLink,
};

#[cfg(any(windows, test))]
mod backend;
#[cfg(windows)]
use backend::WindowsScale;
#[cfg(any(windows, test))]
use backend::{AccountCheck, ScaleOperations, ScaleSelection};
#[cfg(test)]
mod command_tests;

const USAGE: &str = "Usage: blt_unlock [--scale | --weight | --setup-info | --setup-profile | --setup-test-cert | --check-setup] [--seconds <1-60>]\n\
    blt_unlock --register-scale [--seconds <1-60>]\n\
    blt_unlock --xiaomi-sign-in | --xiaomi-check-cloud\n\
    Find a Xiaomi Smart Scale S200 and connect over Bluetooth Low Energy.\n\
    Use --weight to read from an S200 using its saved setup token or S200_BINDKEY.\n\
    Use --setup-info to inspect the setup information in S200 broadcasts.\n\
    Use --setup-profile to read the unpaired S200's Bluetooth setup profile without signing in.\n\
    Use --setup-test-cert to try Standard Auth setup with a local test certificate.\n\
    Use --check-setup for Bluetooth and Xiaomi account checks in one run.\n\
    Use --register-scale to sign in once and register an unregistered S200 ms113.\n\
    Use --xiaomi-sign-in to verify Xiaomi account authorization in your browser.\n\
    Use --xiaomi-check-cloud to verify the session against Xiaomi's Europe API.\n\
    The discovery timeout defaults to 30 seconds.";
const DEFAULT_SECONDS: u64 = 30;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Services,
    Weight,
    SetupInfo,
    SetupProfile,
    SetupTestCertificate,
    SetupCheck,
    RegisterScale,
    XiaomiSignIn,
    XiaomiCloudCheck,
}

fn main() -> ExitCode {
    match parse_args(std::env::args_os().skip(1)) {
        Ok(Some((seconds, command))) => run(seconds, command),
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(()) => usage_error(),
    }
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Option<(u64, Command)>, ()> {
    let mut args = args.into_iter().peekable();
    if matches!(
        args.peek().and_then(|arg| arg.to_str()),
        Some("-h" | "--help")
    ) {
        args.next();
        return if args.next().is_none() {
            Ok(None)
        } else {
            Err(())
        };
    }
    let mut seconds = None;
    let mut command = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--seconds") if seconds.is_none() => {
                seconds = args
                    .next()
                    .and_then(|value| value.to_str()?.parse::<u64>().ok())
                    .filter(|value| (1..=60).contains(value));
                if seconds.is_none() {
                    return Err(());
                }
            }
            Some("--scale") if command.is_none() => command = Some(Command::Services),
            Some("--weight") if command.is_none() => command = Some(Command::Weight),
            Some("--setup-info") if command.is_none() => command = Some(Command::SetupInfo),
            Some("--setup-profile") if command.is_none() => command = Some(Command::SetupProfile),
            Some("--setup-test-cert") if command.is_none() => {
                command = Some(Command::SetupTestCertificate)
            }
            Some("--check-setup") if command.is_none() => command = Some(Command::SetupCheck),
            Some("--register-scale") if command.is_none() => command = Some(Command::RegisterScale),
            Some("--xiaomi-sign-in") if command.is_none() => command = Some(Command::XiaomiSignIn),
            Some("--xiaomi-check-cloud") if command.is_none() => {
                command = Some(Command::XiaomiCloudCheck)
            }
            _ => return Err(()),
        }
    }

    if matches!(
        command,
        Some(Command::XiaomiSignIn | Command::XiaomiCloudCheck)
    ) && seconds.is_some()
    {
        return Err(());
    }
    Ok(Some((
        seconds.unwrap_or(DEFAULT_SECONDS),
        command.unwrap_or(Command::Services),
    )))
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(windows)]
fn run(seconds: u64, command: Command) -> ExitCode {
    run_with(seconds, command, &WindowsScale)
}

#[cfg(any(windows, test))]
fn run_with(seconds: u64, command: Command, backend: &impl ScaleOperations) -> ExitCode {
    let duration = Duration::from_secs(seconds);
    let (result, error_label) = match command {
        Command::Services => {
            println!(
                "Looking for a Xiaomi Smart Scale S200 for up to {seconds} seconds. Step on the scale to wake it."
            );
            (
                show_connection(duration, backend),
                "Scale connection failed",
            )
        }
        Command::Weight => (show_weight(duration, backend), "Scale weight unavailable"),
        Command::SetupInfo => (
            show_setup_info(duration, backend),
            "Scale setup information unavailable",
        ),
        Command::SetupProfile => (
            show_setup_profile(duration, backend),
            "Bluetooth setup profile unavailable",
        ),
        Command::SetupTestCertificate => (
            show_setup_certificate_test(duration, backend),
            "Scale setup test incomplete",
        ),
        Command::SetupCheck => return check_setup(duration, backend),
        Command::RegisterScale => (
            register_scale(duration, backend),
            "Scale registration incomplete",
        ),
        Command::XiaomiSignIn => (show_xiaomi_sign_in(backend), "Xiaomi sign-in incomplete"),
        Command::XiaomiCloudCheck => (check_xiaomi_cloud(backend), "Xiaomi cloud check incomplete"),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error_label}: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(any(windows, test))]
fn check_setup(duration: Duration, backend: &impl ScaleOperations) -> ExitCode {
    println!(
        "Step on the S200 to wake it. The Bluetooth scan lasts up to {} seconds.",
        duration.as_secs()
    );
    let mut checks = TerminalSetupChecks::default();
    backend.check_setup(duration, &mut checks);
    let TerminalSetupChecks {
        passed,
        failed,
        skipped,
    } = checks;
    println!("Setup checks: {passed} passed, {failed} failed, {skipped} skipped.");
    if failed == 0 && skipped == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct TerminalSetupChecks {
    passed: usize,
    failed: usize,
    skipped: usize,
}

#[cfg(any(windows, test))]
impl ScaleSetupInteraction for TerminalSetupChecks {
    fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink) {
        present_xiaomi_link(link);
    }
}

#[cfg(any(windows, test))]
impl SetupCheckObserver for TerminalSetupChecks {
    fn report_setup_check(&mut self, check: SetupCheck, status: SetupCheckStatus<'_>) {
        match status {
            SetupCheckStatus::Started => println!("[RUN]  {check}"),
            SetupCheckStatus::Passed => {
                self.passed += 1;
                println!("[PASS] {check}");
            }
            SetupCheckStatus::Failed(error) => {
                self.failed += 1;
                println!("[FAIL] {check} — {error}");
            }
            SetupCheckStatus::Skipped(prerequisite) => {
                self.skipped += 1;
                println!("[SKIP] {check} — requires {prerequisite}");
            }
        }
    }
}

#[cfg(any(windows, test))]
fn show_xiaomi_sign_in(backend: &impl ScaleOperations) -> std::io::Result<()> {
    println!("Requesting a browser sign-in link from Xiaomi...");
    backend.sign_in(&mut TerminalSignIn, AccountCheck::SignIn)?;
    println!("Xiaomi issued a smart-home account session. Sign-in confirmed.");
    Ok(())
}

#[cfg(any(windows, test))]
fn check_xiaomi_cloud(backend: &impl ScaleOperations) -> std::io::Result<()> {
    println!("Requesting a browser sign-in link to check Xiaomi's Europe API...");
    backend.sign_in(&mut TerminalSignIn, AccountCheck::EuropeApi)?;
    println!("Xiaomi's Europe API accepted the signed request.");
    Ok(())
}

#[cfg(any(windows, test))]
struct TerminalSignIn;

#[cfg(any(windows, test))]
impl ScaleSetupInteraction for TerminalSignIn {
    fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink) {
        present_xiaomi_link(link);
    }
}

#[cfg(any(windows, test))]
fn present_xiaomi_link(link: &XiaomiSignInLink) {
    println!("Open this one-time link in your browser and sign in on Xiaomi’s page.");
    println!("{link}");
    println!("Keep this terminal open while Xiaomi confirms sign-in.");
}

#[cfg(any(windows, test))]
fn show_connection(duration: Duration, backend: &impl ScaleOperations) -> std::io::Result<()> {
    let scale = backend.find_scale(duration, ScaleSelection::Connectable)?;
    println!(
        "Found a Xiaomi Smart Scale S200 at {}. Requesting its GATT services...",
        scale.address(),
    );
    let services = backend.services(&scale)?;
    println!(
        "Connected. The scale returned {} GATT services.",
        services.len()
    );
    for service in services {
        println!("  {service}");
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn show_weight(duration: Duration, backend: &impl ScaleOperations) -> std::io::Result<()> {
    use std::io;

    let logins = match backend.logins() {
        Ok(logins) => logins,
        Err(error) => {
            eprintln!("S200 credentials: {error}");
            SavedScaleLogins::default()
        }
    };
    for warning in logins.warnings() {
        eprintln!("S200 credentials: {warning}");
    }
    let bind_key = match backend.bind_key() {
        Err(error) if !logins.is_empty() => {
            eprintln!("S200 bind key: {error}");
            None
        }
        result => result?,
    };
    if logins.is_empty() && bind_key.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No saved S200 login token. Register the scale or set S200_BINDKEY for MiBeacon weight.",
        ));
    }
    println!(
        "Looking for the S200 for up to {} seconds. Tap it to wake it.",
        duration.as_secs()
    );
    let mut scan = TerminalWeightScan {
        logins: &logins,
        target: None,
        reading: None,
    };
    if let Some(key) = bind_key {
        backend.scan(duration, Some(&key), &mut scan)?;
    } else {
        backend.scan(duration, None, &mut scan)?;
    }
    if let Some(scale) = scan.target
        && let Some(token) = logins.token_for(&scale)
    {
        let address = scale.address();
        println!("Connecting to {address} with its saved login token...");
        return backend.read_weight(
            &scale,
            token,
            duration,
            &mut TerminalWeightDisplay { address },
        );
    }
    let (address, weight) = scan.reading.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "No S200 with matching saved keys or authenticated weight was found during the scan.",
        )
    })?;
    println!("{address}  {weight}");
    Ok(())
}

#[cfg(any(windows, test))]
struct TerminalWeightScan<'a> {
    logins: &'a SavedScaleLogins,
    target: Option<Scale>,
    reading: Option<(BluetoothAddress, Weight)>,
}

#[cfg(any(windows, test))]
impl ScaleScanObserver for TerminalWeightScan<'_> {
    fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
        if let Some(weight) = scale.weight() {
            self.reading = Some((scale.address(), weight));
            return ControlFlow::Break(());
        }
        if scale.is_connectable() && self.logins.token_for(scale).is_some() {
            self.target = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

#[cfg(any(windows, test))]
struct TerminalWeightDisplay {
    address: BluetoothAddress,
}

#[cfg(any(windows, test))]
impl WeightSessionObserver for TerminalWeightDisplay {
    fn on_weight_event(&mut self, event: ConnectedWeightEvent) -> ControlFlow<()> {
        let address = self.address;
        match event {
            ConnectedWeightEvent::Ready => println!("Connected. Step on the scale and hold still."),
            ConnectedWeightEvent::Reading(WeightReading::Live(weight)) => {
                println!("{address}  {weight} (live)")
            }
            ConnectedWeightEvent::Reading(WeightReading::Settled(weight)) => {
                println!("{address}  {weight} (settled)")
            }
        }
        ControlFlow::Continue(())
    }
}

#[cfg(any(windows, test))]
fn show_setup_info(duration: Duration, backend: &impl ScaleOperations) -> std::io::Result<()> {
    use std::io;

    println!(
        "Listening for S200 setup information for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let mut scan = TerminalSetupInfo::default();
    backend.scan(duration, None, &mut scan)?;
    if scan.reports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No S200 MiBeacon setup information arrived.",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct TerminalSetupInfo {
    reports: BTreeMap<BluetoothAddress, ScaleSetupInfo>,
}

#[cfg(any(windows, test))]
impl ScaleScanObserver for TerminalSetupInfo {
    fn scale_discovered(&mut self, scale: &Scale, _: Option<Weight>) -> ControlFlow<()> {
        let Some(info) = scale.setup_info() else {
            return ControlFlow::Continue(());
        };
        let address = scale.address();
        if self.reports.insert(address, info) != Some(info) {
            println!("{address}  {info}");
        }
        ControlFlow::Continue(())
    }
}

#[cfg(any(windows, test))]
fn show_setup_profile(duration: Duration, backend: &impl ScaleOperations) -> std::io::Result<()> {
    println!(
        "Scanning for an unpaired S200 for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let scale = backend.find_scale(duration, ScaleSelection::Unregistered)?;
    if let Some(info) = scale.setup_info() {
        println!("{}  {info}", scale.address());
    }
    let profile = backend.profile(&scale)?;
    println!("Bluetooth setup profile: {profile}");
    if profile.supports_registration() {
        println!("This profile supports the app's registration flow.");
    } else {
        println!(
            "Registration expects a 4- or 24-byte reply starting with 02 00 00 00 and a valid device ID when one is included."
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn run(_seconds: u64, _command: Command) -> ExitCode {
    eprintln!("Connecting to the scale requires Windows 10 or 11.");
    ExitCode::FAILURE
}

#[cfg(any(windows, test))]
fn register_scale(duration: Duration, backend: &impl ScaleOperations) -> std::io::Result<()> {
    let credentials = backend.credentials_directory()?;
    let scale = backend.register(
        duration,
        &credentials,
        &mut TerminalRegistration {
            scan_time: duration,
        },
    )?;
    println!("Scale setup complete for {}.", scale.address());
    println!(
        "Confirmed keys saved in {}.",
        scale.credentials_file().display()
    );
    Ok(())
}

#[cfg(any(windows, test))]
struct TerminalRegistration {
    scan_time: std::time::Duration,
}

#[cfg(any(windows, test))]
impl ScaleSetupInteraction for TerminalRegistration {
    fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink) {
        present_xiaomi_link(link);
    }
}

#[cfg(any(windows, test))]
impl RegistrationObserver for TerminalRegistration {
    fn report_registration(&mut self, event: RegistrationEvent<'_>) {
        match event {
            RegistrationEvent::Started(step) => {
                println!("[RUN]  {step}");
                if step == RegistrationStep::ScaleDiscovery {
                    println!(
                        "Step on the S200 you want to register. The Bluetooth scan lasts up to {} seconds.",
                        self.scan_time.as_secs()
                    );
                }
            }
            RegistrationEvent::Passed(step) => println!("[PASS] {step}"),
            RegistrationEvent::CredentialsSaved(path) => {
                println!("Pending S200 keys saved locally in {}.", path.display());
            }
        }
    }
}

#[cfg(any(windows, test))]
fn show_setup_certificate_test(
    duration: Duration,
    backend: &impl ScaleOperations,
) -> std::io::Result<()> {
    use std::io;
    use xiaomi_s200::SetupCertificateReply;

    println!(
        "Looking for an unregistered S200 ms113 for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let scale = backend.find_scale(duration, ScaleSelection::Unregistered)?;
    if let Some(info) = scale.setup_info() {
        println!("{info}");
    }
    println!("Starting Standard Auth setup with {}.", scale.address());
    let credentials_directory = backend.credentials_directory()?;
    let reply = backend.test_certificate(&scale, &credentials_directory)?;
    match reply {
        SetupCertificateReply::RegistrationSucceeded => {
            println!(
                "{reply}. Keys saved under {}.",
                credentials_directory.display()
            );
            Ok(())
        }
        SetupCertificateReply::ReceivedWithoutRegistrationResult => {
            println!(
                "{reply}. Pending keys saved under {}.",
                credentials_directory.display()
            );
            Ok(())
        }
        SetupCertificateReply::RegistrationFailed | SetupCertificateReply::AlreadyRegistered => {
            Err(io::Error::other(reply.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_args};

    #[test]
    fn parses_defaults_and_each_command() {
        assert_eq!(parse_args([]), Ok(Some((30, Command::Services))));
        for (flag, command) in [
            ("--scale", Command::Services),
            ("--weight", Command::Weight),
            ("--setup-info", Command::SetupInfo),
            ("--setup-profile", Command::SetupProfile),
            ("--setup-test-cert", Command::SetupTestCertificate),
            ("--check-setup", Command::SetupCheck),
            ("--register-scale", Command::RegisterScale),
            ("--xiaomi-sign-in", Command::XiaomiSignIn),
            ("--xiaomi-check-cloud", Command::XiaomiCloudCheck),
        ] {
            assert_eq!(parse_args([flag.into()]), Ok(Some((30, command))));
        }
        assert_eq!(
            parse_args(["--seconds", "1", "--weight"].map(Into::into)),
            Ok(Some((1, Command::Weight)))
        );
        assert_eq!(
            parse_args(["--scale", "--seconds", "60"].map(Into::into)),
            Ok(Some((60, Command::Services)))
        );
    }

    #[test]
    fn accepts_help_only_when_used_alone_and_rejects_invalid_invocations() {
        for help in ["--help", "-h"] {
            assert_eq!(parse_args([help.into()]), Ok(None));
        }
        for args in [
            &["--help", "--scale"][..],
            &["--scale", "--help"],
            &["--seconds"],
            &["--seconds", "0"],
            &["--seconds", "61"],
            &["--seconds", "NaN"],
            &["--seconds", "1", "--seconds", "2"],
            &["--weight", "--scale"],
            &["--xiaomi-sign-in", "--seconds", "1"],
            &["--seconds", "1", "--xiaomi-check-cloud"],
            &["unknown"],
        ] {
            assert_eq!(
                parse_args(args.iter().copied().map(Into::into)),
                Err(()),
                "{args:?}"
            );
        }
    }
}
