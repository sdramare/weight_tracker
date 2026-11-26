use std::process::ExitCode;

const USAGE: &str = "Usage: blt_unlock [--scale] [--seconds <1-60>]\n\
    Find a Xiaomi Smart Scale S200 and connect over Bluetooth Low Energy.\n\
    The discovery timeout defaults to 30 seconds.";
const DEFAULT_SECONDS: u64 = 30;

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
    let mut scale_flag_seen = false;
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
            Some("--scale") if !scale_flag_seen => scale_flag_seen = true,
            _ => return usage_error(),
        }
    }

    run(seconds.unwrap_or(DEFAULT_SECONDS))
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(windows)]
fn run(seconds: u64) -> ExitCode {
    use std::time::Duration;

    println!(
        "Looking for a Xiaomi Smart Scale S200 for up to {seconds} seconds. Step on the scale to wake it."
    );
    match show_connection(Duration::from_secs(seconds)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Scale connection failed: {error}");
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

#[cfg(not(windows))]
fn run(_seconds: u64) -> ExitCode {
    eprintln!("Connecting to the scale requires Windows 10 or 11.");
    ExitCode::FAILURE
}
