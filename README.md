# Xiaomi S200 Bluetooth tools

A Rust workspace for the Xiaomi Smart Scale S200 on Windows. The desktop app lists nearby scales and their signal strength. The CLI connects to the first scale that offers a connection and prints its GATT service UUIDs.

## Requirements

- A Windows 10 or 11 PC with Bluetooth Low Energy support
- A Xiaomi Smart Scale S200
- Rust and Cargo, with the Clippy component for checked builds

## Run

From the repository root, run this in PowerShell to open the desktop app.

```powershell
cargo run -p blt_unlock_gui
```

The window scans for 30 seconds and shows each scale's name, Bluetooth address, signal strength, and whether it offers a connection. Step on the scale to wake it while the scan is running. Select **Scan again** to start a new scan.

Run the CLI with the default discovery timeout or set a longer one.

```powershell
cargo run
cargo run -- --seconds 45
```

The second command extends the default 30-second discovery timeout. If the CLI sees the scale but cannot connect, close Xiaomi Home if it is connected to the scale, then wake the scale again.

## Build and test

```powershell
.\build.cmd
cargo test --locked --workspace
```

The build script runs Clippy across all workspace targets before compiling the CLI and desktop app.

## Workspace

| Package | Role |
| --- | --- |
| [`xiaomi-s200`](crates/scale) | Shared Windows BLE discovery and GATT service inspection |
| [`blt_unlock`](crates/cli) | Terminal connection tool |
| [`blt_unlock_gui`](crates/gui) | egui desktop discovery app |

Open the [SVG connection guide](docs/scale-connection.html) in a browser for diagrams and troubleshooting.
