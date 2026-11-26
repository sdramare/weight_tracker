# Repository instructions

After each significant, verified change, make a Git commit that describes the change. Keep unrelated work in separate commits.

Use `build.cmd` for checked builds. It runs Clippy across all workspace targets before compiling the executables.

Update [the scale connection guide](docs/scale-connection.html) in the same change whenever command-line usage, the desktop app, scale discovery, Bluetooth connection behavior, or troubleshooting output changes. Keep its SVG diagrams and examples consistent with the Rust code and check the rendered page after editing it.
