@echo off
setlocal
pushd "%~dp0" || exit /b 1

cargo clippy --locked --workspace --all-targets && cargo build --locked --workspace
set "build_status=%errorlevel%"

popd
exit /b %build_status%
