# S200 project code review

Reviewed the Windows CLI, desktop app, and shared Bluetooth and Xiaomi cloud library at commit `17887e2`. The highest-priority finding is loss of the saved scale login during routine build cleanup.

## P1 · Cargo cleanup deletes the scale's login credentials

The default registration command saves the login token and bind key in `target/s200-registration`. On a default workspace build, `cargo clean` removes that directory along with the binaries. Rebuilding restores the reader, but a user whose only key file was there loses access to connected weight readings. I verified this with `cargo clean --dry-run --verbose` against a disposable target directory. Cargo listed the dummy registration file for removal. Store new registrations in a persistent per-user application data directory and migrate existing files while they are still available. [Registration destination](crates/cli/src/main.rs#L310) · [Default key lookup](crates/scale/src/login_keys.rs#L29)

## P2 · One malformed key file disables every saved login

The first parse error exits `SavedScaleLogins::load` and discards all usable entries. The CLI propagates the error before checking `S200_BINDKEY`. The GUI substitutes an empty login set, so every scale that relies on a login token becomes unreadable. In an isolated directory with one valid registration, one incomplete file, and a valid-format bind key, `--weight` exited with code 1 before discovery. Keep successfully parsed entries, report the offending file, and let each credential source work independently. [Directory loader](crates/scale/src/login_keys.rs#L68) · [CLI startup](crates/cli/src/main.rs#L207) · [Desktop startup](crates/gui/src/desktop.rs#L94)

## P2 · The weight readers cannot use a successful local certificate registration

`--setup-test-cert` writes `target/s200-setup-test/test-*.keys`. Both readers look in `s200-registration` and accept only filenames starting with `s200-`. Even when the scale confirms the local registration, the next weigh-in has no discoverable login token. With a dummy file in the writer's exact format and location, an isolated copy of the CLI reported “No saved S200 login token.” On confirmed success, save an address-matched registration where both readers look. Keep the candidate file available for recovery if the result is uncertain. [Trial key writer](crates/scale/src/setup/registration_crypto.rs#L100) · [CLI success path](crates/cli/src/main.rs#L350) · [Reader filename filter](crates/scale/src/login_keys.rs#L60)

## P2 · The desktop monitor attempts login after registration has failed

Cloud registration saves an address-matched token before requesting the certificate. If the certificate request fails, the scale is still unregistered. On its next launch the desktop app loads that token and stops discovery whenever the address advertises as connectable, even if the same advertisement explicitly reports an unregistered scale. The login fails and the monitor retries two seconds later, repeatedly interrupting discovery while the scale is awake. Skip login when the advertised status is unregistered, and distinguish confirmed credentials from pending attempts so an interrupted registration remains recoverable. [Registration sequence](crates/scale/src/setup/registration.rs#L93) · [Monitor selection and retry](crates/gui/src/desktop.rs#L276) · [Unregistered login response](crates/scale/src/setup/connected_weight.rs#L222)

## P2 · The CLI discards an authenticated weight when GATT is also available

When a connectable scale has a saved token and the bind key has already decoded a settled weight, the discovery callback selects the GATT connection and exits before copying the weight. If the scale sleeps before the connection opens or the saved token is stale, `--weight` returns an error despite already having the requested reading. Return the decoded weight first and use GATT when discovery has supplied no reading. [Discovery callback](crates/cli/src/main.rs#L224) · [GATT return path](crates/cli/src/main.rs#L240)

## P2 · A temporary SQLite error at startup disables history for the whole session

The monitor opens the database and loads its rows once. If either operation fails, for example because an exclusive lock outlasts the 500 ms busy timeout, it reports the error and stores `None`. Releasing the lock lets other processes use the database again, but every later weigh-in in this app skips persistence until restart. Retry opening and loading history after a transient failure, and refresh the displayed rows when it succeeds. [Busy timeout](crates/gui/src/history.rs#L33) · [Initialization and recording](crates/gui/src/desktop.rs#L241)

## P2 · Setup diagnostics can select an already registered scale

With two S200s nearby, `--check-setup` stops at the first connectable scale with any setup information. If an already registered scale advertises first, the CLI reports failed readiness and probes that device even when an eligible, unregistered ms113 advertises within the scan window. The actual registration command would continue scanning and select the eligible scale. Use the registration-readiness predicate for early success and keep the best other candidate for diagnostics at timeout. [Diagnostic selection](crates/scale/src/diagnostics.rs#L113) · [Registration selection](crates/scale/src/setup.rs#L26)

## P3 · Two open monitors can show different weight histories

Both windows load history at startup. If window A records a reading, window B's next insert within 24 hours correctly returns `None`, but B never reloads A's row. B can show an empty or stale chart for the rest of the session while the database contains the reading. Refresh rows added by another connection, for example on window restoration or after detecting a database change. [History loading and insert handling](crates/gui/src/desktop.rs#L241) · [Chart updates](crates/gui/src/desktop.rs#L179) · [SQLite insert rule](crates/gui/src/history.rs#L72)

## Verification

- `build.cmd` completed on Windows. Clippy flagged two uses of `chunks_exact(2)`. The compiler also warned that five GUI float literals rely on type inference that a future toolchain will reject.
- `cargo test --locked --workspace` passed all 26 tests, including 22 in the scale library and four in the GUI. The CLI has no unit tests.
- The cleanup and credential-loader checks used disposable files and the built CLI. Bluetooth sessions, live Xiaomi sign-in, and native tray interaction were outside runtime verification. The remaining findings follow the cited code paths.
