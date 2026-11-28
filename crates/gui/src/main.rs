#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(windows, test))]
mod desktop;
#[cfg(any(windows, test))]
mod history;
#[cfg(any(windows, test))]
mod scale_setup;
#[cfg(windows)]
mod tray;
#[cfg(any(windows, test))]
mod weight_plot;

#[cfg(windows)]
fn main() -> eframe::Result {
    desktop::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("Finding the scale requires Windows 10 or 11.");
    std::process::ExitCode::FAILURE
}
