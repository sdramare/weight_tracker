use std::process::ExitCode;

const USAGE: &str = "Usage: blt_unlock [--scale | --weight | --setup-info | --setup-test-cert | --check-setup] [--seconds <1-60>]\n\
    blt_unlock --xiaomi-sign-in | --xiaomi-check-cloud\n\
    Find a Xiaomi Smart Scale S200 and connect over Bluetooth Low Energy.\n\
    Use --weight with S200_BINDKEY set to wait for a stabilized weight.\n\
    Use --setup-info to inspect the setup information in S200 broadcasts.\n\
    Use --setup-test-cert to try Standard Auth setup with the bundled test certificate.\n\
    Use --check-setup for Bluetooth and Xiaomi account checks in one run.\n\
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

    let key = xiaomi_s200::ScaleBindKey::from_environment()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Set S200_BINDKEY to the scale's MiBeacon bind key.",
        )
    })?;
    println!(
        "Listening for weight for up to {} seconds. Step on the scale and wait for the reading to settle.",
        duration.as_secs()
    );
    let mut reading = None;
    xiaomi_s200::discover_scales_with_weight(duration, &key, |scale| {
        if let Some(weight) = scale.weight() {
            reading = Some((scale.address(), weight));
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })?;
    let (address, weight) = reading.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "No authenticated weight arrived. Check the bind key and weigh again.",
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
fn show_setup_certificate_test(duration: std::time::Duration) -> std::io::Result<()> {
    use std::path::Path;
    use std::{io, ops::ControlFlow};
    use xiaomi_s200::SetupCertificateReply;

    println!(
        "Looking for an unregistered S200 ms113 for up to {} seconds. Step on the scale to wake it.",
        duration.as_secs()
    );
    let mut candidate = None;
    xiaomi_s200::discover_scales(duration, |scale| {
        if scale.is_connectable()
            && scale
                .setup_info()
                .is_some_and(|info| info.requests_certificate_test())
        {
            candidate = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })?;
    let scale = candidate.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no connectable, unregistered S200 ms113 requested setup",
        )
    })?;
    if let Some(info) = scale.setup_info() {
        println!("{info}");
    }
    println!("Starting Standard Auth setup with {}.", scale.address());
    let credentials_directory = Path::new("target/s200-setup-test");
    let reply = xiaomi_s200::send_setup_test_certificate(&scale, credentials_directory)?;
    match reply {
        SetupCertificateReply::RegistrationSucceeded => {
            println!(
                "{reply}. Keys saved under {}.",
                credentials_directory.display()
            );
            Ok(())
        }
        SetupCertificateReply::ReceivedWithoutRegistrationResult => {
            println!("{reply}.");
            Ok(())
        }
        SetupCertificateReply::RegistrationFailed | SetupCertificateReply::AlreadyRegistered => {
            Err(io::Error::other(reply.to_string()))
        }
    }
}
