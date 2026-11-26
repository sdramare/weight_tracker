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

## Read a weight

Use the 32-digit hexadecimal MiBeacon bind key for your scale. [Home Assistant’s Xiaomi BLE guide](https://www.home-assistant.io/integrations/xiaomi_ble/#encryption) describes how to obtain it for a device bound to your Xiaomi account.

In PowerShell, enter the key and launch the desktop app in the same session.

```powershell
$key = Read-Host 'S200 bind key' -AsSecureString
$env:S200_BINDKEY = [System.Net.NetworkCredential]::new('', $key).Password
cargo run -p blt_unlock_gui
```

Step on the scale during a scan and wait for its display to settle. The desktop app shows the latest stabilized weight in kilograms. Weight display requires the scale to transmit its measurement in a MiBeacon v4 or v5 advertisement.

With the same environment variable set, the CLI prints the first authenticated reading it receives.

```powershell
cargo run -- --weight --seconds 45
```

## Inspect scale setup

```powershell
cargo run -- --setup-info --seconds 30
```

Step on the scale during the scan. This read-only command reports the advertised product ID and MiBeacon version without a bind key. For MiBeacon v5 it also reports the authentication mode, registration status, and whether the scale is requesting setup.

A capture of first-time registration on the S200 `ms113` shows a key exchange and a Xiaomi Cloud certificate. The capture documents this firmware variant and provides a starting point for a Rust setup flow. [S200 registration capture](https://github.com/Scuner/xiaomiS200_reversing_connection/blob/main/docs/PROTOCOL.md#registration-for-completeness-not-needed-in-practice)

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
