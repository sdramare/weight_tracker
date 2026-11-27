# Xiaomi S200 Bluetooth tools

A Rust workspace for the Xiaomi Smart Scale S200 on Windows. The desktop app registers nearby S200 ms113 scales and shows live and settled weight. The CLI also supports GATT inspection and scale setup.

## Requirements

- A Windows 10 or 11 PC with Bluetooth Low Energy support
- A Xiaomi Smart Scale S200
- Rust and Cargo, with the Clippy component for checked builds

## Run

From the repository root, run this in PowerShell to open the desktop app.

```powershell
cargo run -p blt_unlock_gui
```

The desktop app keeps listening while it is running and lists the scales it discovers. Step on the S200 to start a reading. The app connects as soon as the registered scale advertises and resumes listening automatically when it sleeps. Minimize the window to keep monitoring in the system tray. Double-click the tray icon to restore the window, or right-click it for **Show weight window** and **Quit**. Closing the window also stops monitoring.

Run the CLI with the default discovery timeout or set a longer one.

```powershell
cargo run -p blt_unlock
cargo run -p blt_unlock -- --seconds 45
```

The second command extends the default 30-second discovery timeout. If the CLI sees the scale but cannot connect, close Xiaomi Home if it is connected to the scale, then wake the scale again.

## Read a weight

For an S200 ms113 registered by this program, open the desktop app or run the terminal reader from the project folder.

```powershell
cargo run -p blt_unlock_gui
cargo run -p blt_unlock -- --weight
```

Step on the scale and hold still. The desktop app shows live weight in kilograms as it arrives and keeps the last settled reading visible between weigh-ins. The terminal reader exits after one settled reading and uses an authenticated broadcast if discovery already supplied one. Both readers load saved Bluetooth tokens from `%LOCALAPPDATA%\blt_unlock\s200-registration`. On startup they copy valid registrations still available in older `target/s200-registration` folders into the per-user store. [S200 Bluetooth protocol capture](https://github.com/Scuner/xiaomiS200_reversing_connection/blob/main/docs/PROTOCOL.md#data-channel)

For a scale that broadcasts authenticated MiBeacon weight, you can use its 32-digit bind key instead. [Home Assistant’s Xiaomi BLE guide](https://www.home-assistant.io/integrations/xiaomi_ble/#encryption)

```powershell
$key = Read-Host 'S200 bind key' -AsSecureString
$env:S200_BINDKEY = [System.Net.NetworkCredential]::new('', $key).Password
cargo run -p blt_unlock_gui
```

## Weight history

The desktop app stores the first settled weight and saves another only when more than 24 hours have elapsed since the last saved record. The live display updates on every weigh-in. Weight history stays in `data/weights.sqlite3` in the project folder.

Select **By day**, **By week**, or **By month** to group readings by your local calendar. Weekly and monthly points show average weight for that period. After three saved readings, the chart adds a dashed 30-day forecast based on the trend in up to the last 30 readings.


## Register an S200 ms113

In the desktop app, select **Set up scale**, then **Open Xiaomi sign-in**. Sign in in your browser and return to the app. When it starts scanning, step on the unregistered S200 you want to set up. The app resumes weight monitoring after setup, with the new keys ready to use.

To register from the terminal, run:

```powershell
cargo run -p blt_unlock -- --register-scale
```

Sign in once using the link from Xiaomi. When the Bluetooth scan starts, step on the unregistered S200 you want to register. The CLI reuses the Europe session to allocate a device ID and request Xiaomi's signed authorization during the Bluetooth handshake.

Wait for `Scale setup complete`. The CLI saves pending keys to the per-user store before sending authorization over Bluetooth. When the scale confirms setup, the CLI marks the keys confirmed and prints their final path.

## Inspect scale setup

```powershell
cargo run -p blt_unlock -- --check-setup
```

Wake the S200 during the scan. The command checks Bluetooth discovery, the advertised registration mode, and the Standard Auth GATT characteristic. If Xiaomi supplies a browser link, sign in once. The same session is used to check the Europe API. The terminal reports pass, fail, or skip for each check. These checks are read-only.

To inspect only the setup information in the scale's broadcasts, run:

```powershell
cargo run -p blt_unlock -- --setup-info --seconds 30
```

Step on the scale during the scan. This read-only command reports the advertised product ID and MiBeacon version without a bind key. For MiBeacon v5 it also reports the authentication mode, registration status, and whether the scale is requesting setup.

To check the setup capability reply over Bluetooth without signing in or starting registration, use `cargo run -p blt_unlock -- --setup-profile` and wake the unpaired scale during the scan.

The connection guide shows how the app derives the login token and bind key with P-256 ECDH and HKDF-SHA256, requests Xiaomi's signed authorization, and sends it to the scale. [Registration algorithm](docs/scale-connection.html#registration-heading) · [S200 registration capture](https://github.com/Scuner/xiaomiS200_reversing_connection/blob/main/docs/PROTOCOL.md#registration-for-completeness-not-needed-in-practice)

To try local Standard Auth setup on an unregistered S200 `ms113`, place your test certificate at `crates/scale/src/setup/s200-local-test.der`, run from the repository root, and wake the scale when the scan starts.

```powershell
cargo run -p blt_unlock -- --setup-test-cert --seconds 30
```

The CLI requests setup information, exchanges P-256 public keys, and sends an encrypted local test device ID followed by the local test certificate. It saves pending keys with the scale’s address in the per-user store before sending the proof. A transfer acknowledgment confirms delivery only. When the scale’s control characteristic confirms registration, both readers can use the saved keys.

## Verify Xiaomi browser sign-in

```powershell
cargo run -p blt_unlock -- --xiaomi-sign-in
```

Open the one-time link printed in the terminal. Enter your credentials on Xiaomi's page and keep the terminal open until it confirms the smart-home session. The command checks account authorization. Scale registration is a separate step.

To check whether the Europe API accepts the session, sign in through a new one-time link.

```powershell
cargo run -p blt_unlock -- --xiaomi-check-cloud
```

The command makes a read-only, signed request for your account's device count and reports whether Xiaomi accepted it. The session stays in memory for that run.

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

Open the [connection guide](docs/scale-connection.html) in a browser for SVG diagrams and step-by-step details on discovery, registration, weight decoding, history, and diagnostics.
