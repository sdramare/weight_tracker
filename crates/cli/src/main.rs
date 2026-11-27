use std::process::ExitCode;

const USAGE: &str = "Usage: blt_unlock [--scale | --weight | --setup-info | --setup-test-cert | --check-setup] [--seconds <1-60>]\n\
    blt_unlock --register-scale [--seconds <1-60>]\n\
    blt_unlock --xiaomi-sign-in | --xiaomi-check-cloud\n\
    Find a Xiaomi Smart Scale S200 and connect over Bluetooth Low Energy.\n\
    Use --weight to read from an S200 using its saved setup token or S200_BINDKEY.\n\
    Use --setup-info to inspect the setup information in S200 broadcasts.\n\
    Use --setup-test-cert to try Standard Auth setup with a local test certificate.\n\
    Use --check-setup for Bluetooth and Xiaomi account checks in one run.\n\
    Use --register-scale to sign in once and register an unregistered S200 ms113.\n\
    Use --xiaomi-sign-in to verify Xiaomi account authorization in your browser.\n\
    Use --xiaomi-check-cloud to verify the session against Xiaomi's Europe API.\n\
    The discovery timeout defaults to 30 seconds.";
const DEFAULT_SECONDS: u64 = 30;

enum Command {
    Services,
    Weight,
    SetupInfo,
    SetupTestCertificate,
    SetupCheck,
    RegisterScale,
    XiaomiSignIn,
    XiaomiCloudCheck,
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.len() == 1
        && matches!(
            args.peek().and_then(|arg| arg.to_str()),
            Some("-h" | "--help")
        )
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
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
                    return usage_error();
                }
            }
            Some("--scale") if command.is_none() => command = Some(Command::Services),
            Some("--weight") if command.is_none() => command = Some(Command::Weight),
            Some("--setup-info") if command.is_none() => command = Some(Command::SetupInfo),
            Some("--setup-test-cert") if command.is_none() => {
                command = Some(Command::SetupTestCertificate)
            }
            Some("--check-setup") if command.is_none() => command = Some(Command::SetupCheck),
            Some("--register-scale") if command.is_none() => command = Some(Command::RegisterScale),
            Some("--xiaomi-sign-in") if command.is_none() => command = Some(Command::XiaomiSignIn),
            Some("--xiaomi-check-cloud") if command.is_none() => {
                command = Some(Command::XiaomiCloudCheck)
            }
            _ => return usage_error(),
        }
    }

    if matches!(
        command,
        Some(Command::XiaomiSignIn | Command::XiaomiCloudCheck)
    ) && seconds.is_some()
    {
        return usage_error();
    }
    run(
        seconds.unwrap_or(DEFAULT_SECONDS),
        command.unwrap_or(Command::Services),
    )
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(windows)]
fn run(seconds: u64, command: Command) -> ExitCode {
    use std::time::Duration;

    let duration = Duration::from_secs(seconds);
    let (result, error_label) = match command {
        Command::Services => {
            println!(
                "Looking for a Xiaomi Smart Scale S200 for up to {seconds} seconds. Step on the scale to wake it."
            );
            (show_connection(duration), "Scale connection failed")
        }
        Command::Weight => (show_weight(duration), "Scale weight unavailable"),
        Command::SetupInfo => (
            show_setup_info(duration),
            "Scale setup information unavailable",
        ),
        Command::SetupTestCertificate => (
            show_setup_certificate_test(duration),
            "Scale setup test incomplete",
        ),
        Command::SetupCheck => return check_setup(duration),
        Command::RegisterScale => (register_scale(duration), "Scale registration incomplete"),
        Command::XiaomiSignIn => (show_xiaomi_sign_in(), "Xiaomi sign-in incomplete"),
        Command::XiaomiCloudCheck => (check_xiaomi_cloud(), "Xiaomi cloud check incomplete"),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error_label}: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn check_setup(duration: std::time::Duration) -> ExitCode {
    use xiaomi_s200::SetupCheckStatus;

    println!(
        "Step on the S200 to wake it. The Bluetooth scan lasts up to {} seconds.",
        duration.as_secs()
    );
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    xiaomi_s200::check_scale_setup(
        duration,
        present_xiaomi_link,
        |check, status| match status {
            SetupCheckStatus::Started => println!("[RUN]  {check}"),
            SetupCheckStatus::Passed => {
                passed += 1;
                println!("[PASS] {check}");
            }
            SetupCheckStatus::Failed(error) => {
                failed += 1;
                println!("[FAIL] {check} — {error}");
            }
            SetupCheckStatus::Skipped(prerequisite) => {
                skipped += 1;
                println!("[SKIP] {check} — requires {prerequisite}");
            }
        },
    );
    println!("Setup checks: {passed} passed, {failed} failed, {skipped} skipped.");
    if failed == 0 && skipped == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
fn show_xiaomi_sign_in() -> std::io::Result<()> {
    println!("Requesting a browser sign-in link from Xiaomi...");
    xiaomi_s200::verify_xiaomi_sign_in(present_xiaomi_link)?;
    println!("Xiaomi issued a smart-home account session. Sign-in confirmed.");
    Ok(())
}

#[cfg(windows)]
fn check_xiaomi_cloud() -> std::io::Result<()> {
    println!("Requesting a browser sign-in link to check Xiaomi's Europe API...");
    xiaomi_s200::verify_xiaomi_cloud_europe(present_xiaomi_link)?;
    println!("Xiaomi's Europe API accepted the signed request.");
    Ok(())
}

#[cfg(windows)]
fn present_xiaomi_link(link: &xiaomi_s200::XiaomiSignInLink) {
    println!("Open this one-time link in your browser and sign in on Xiaomi’s page.");
    println!("{link}");
    println!("Keep this terminal open while Xiaomi confirms sign-in.");
}

#[cfg(windows)]
fn show_connection(duration: std::time::Duration) -> std::io::Result<()> {
    let scale = xiaomi_s200::find_connectable_scale(duration)?;
    println!(
        "Found a Xiaomi Smart Scale S200 at {}. Requesting its GATT services...",
        scale.address(),
    );
    let services = xiaomi_s200::read_services(&scale)?;
    println!(
        "Connected. The scale returned {} GATT services.",
        services.len()
    );
    for service in services {
        println!("  {service}");
    }
    Ok(())
}

#[cfg(windows)]
fn show_weight(duration: std::time::Duration) -> std::io::Result<()> {
    use std::io;
    use std::ops::ControlFlow;
    use xiaomi_s200::{ConnectedWeightEvent, SavedScaleLogins, WeightReading};

    let logins = match SavedScaleLogins::load_default() {
        Ok(logins) => logins,
        Err(error) => {
            eprintln!("S200 credentials: {error}");
            SavedScaleLogins::default()
        }
    };
    for warning in logins.warnings() {
        eprintln!("S200 credentials: {warning}");
    }
    let bind_key = match xiaomi_s200::ScaleBindKey::from_environment() {
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
    let mut target = None;
    let mut reading = None;
    let on_scale = |scale: &xiaomi_s200::Scale| {
        if let Some(weight) = scale.weight() {
            reading = Some((scale.address(), weight));
            return ControlFlow::Break(());
        }
        if scale.is_connectable() && logins.token_for(scale).is_some() {
            target = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    if let Some(key) = bind_key {
        xiaomi_s200::discover_scales_with_weight(duration, &key, on_scale)?;
    } else {
        xiaomi_s200::discover_scales(duration, on_scale)?;
    }
    if let Some(scale) = target
        && let Some(token) = logins.token_for(&scale)
    {
        let address = scale.address();
        println!("Connecting to {address} with its saved login token...");
        return xiaomi_s200::listen_for_connected_weight(&scale, token, duration, |event| {
            match event {
                ConnectedWeightEvent::Ready => {
                    println!("Connected. Step on the scale and hold still.")
                }
                ConnectedWeightEvent::Reading(WeightReading::Live(weight)) => {
                    println!("{address}  {weight} (live)");
                }
                ConnectedWeightEvent::Reading(WeightReading::Settled(weight)) => {
                    println!("{address}  {weight} (settled)");
                }
            }
            ControlFlow::Continue(())
        });
    }
    let (address, weight) = reading.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "No S200 with matching saved keys or authenticated weight was found during the scan.",
        )
    })?;
    println!("{address}  {weight}");
    Ok(())
}

#[cfg(windows)]
fn show_setup_info(duration: std::time::Duration) -> std::io::Result<()> {
    use std::collections::BTreeMap;
    use std::io;
    use std::ops::ControlFlow;

    println!(
        "Listening for S200 setup information for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let mut reports = BTreeMap::new();
    xiaomi_s200::discover_scales(duration, |scale| {
        let Some(info) = scale.setup_info() else {
            return ControlFlow::Continue(());
        };
        let address = scale.address();
        if reports.insert(address, info) != Some(info) {
            println!("{address}  {info}");
        }
        ControlFlow::Continue(())
    })?;
    if reports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No S200 MiBeacon setup information arrived.",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn run(_seconds: u64, _command: Command) -> ExitCode {
    eprintln!("Connecting to the scale requires Windows 10 or 11.");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn register_scale(duration: std::time::Duration) -> std::io::Result<()> {
    use xiaomi_s200::{RegistrationEvent, RegistrationStep};

    let credentials = xiaomi_s200::default_registration_directory()?;
    let scale = xiaomi_s200::register_scale_europe(
        duration,
        &credentials,
        present_xiaomi_link,
        |event| match event {
            RegistrationEvent::Started(step) => {
                println!("[RUN]  {step}");
                if step == RegistrationStep::ScaleDiscovery {
                    println!(
                        "Step on the S200 you want to register. The Bluetooth scan lasts up to {} seconds.",
                        duration.as_secs()
                    );
                }
            }
            RegistrationEvent::Passed(step) => println!("[PASS] {step}"),
            RegistrationEvent::CredentialsSaved(path) => {
                println!("Pending S200 keys saved locally in {}.", path.display());
            }
        },
    )?;
    println!("Scale setup complete for {}.", scale.address());
    println!(
        "Confirmed keys saved in {}.",
        scale.credentials_file().display()
    );
    Ok(())
}

#[cfg(windows)]
fn show_setup_certificate_test(duration: std::time::Duration) -> std::io::Result<()> {
    use std::io;
    use xiaomi_s200::SetupCertificateReply;

    println!(
        "Looking for an unregistered S200 ms113 for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let scale = xiaomi_s200::find_registration_scale(duration)?;
    if let Some(info) = scale.setup_info() {
        println!("{info}");
    }
    println!("Starting Standard Auth setup with {}.", scale.address());
    let credentials_directory = xiaomi_s200::default_registration_directory()?;
    let reply = xiaomi_s200::send_setup_test_certificate(&scale, &credentials_directory)?;
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
