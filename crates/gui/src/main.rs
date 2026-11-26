#[cfg(windows)]
mod desktop;

#[cfg(windows)]
fn main() -> eframe::Result {
    desktop::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("Finding the scale requires Windows 10 or 11.");
    std::process::ExitCode::FAILURE
}
