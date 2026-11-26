use std::process::ExitCode;

#[cfg(windows)]
mod scale;

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
    let duration = std::time::Duration::from_secs(seconds);
    if scale::run(duration) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(windows))]
fn run(_seconds: u64) -> ExitCode {
    eprintln!("Connecting to the scale requires Windows 10 or 11.");
    ExitCode::FAILURE
}
