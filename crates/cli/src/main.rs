use std::process::ExitCode;

const USAGE: &str = "Usage: blt_unlock [--scale | --weight] [--seconds <1-60>]\n\
    Find a Xiaomi Smart Scale S200 and connect over Bluetooth Low Energy.\n\
    Use --weight with S200_BINDKEY set to wait for a stabilized weight.\n\
    The discovery timeout defaults to 30 seconds.";
const DEFAULT_SECONDS: u64 = 30;

enum Command {
    Services,
    Weight,
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
            _ => return usage_error(),
        }
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

#[cfg(not(windows))]
fn run(_seconds: u64, _command: Command) -> ExitCode {
    eprintln!("Connecting to the scale requires Windows 10 or 11.");
    ExitCode::FAILURE
}
