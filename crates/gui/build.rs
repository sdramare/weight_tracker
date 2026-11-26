fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=assets/scale-icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/scale-icon.ico")
            .set("ProductName", "Xiaomi S200 Weight Monitor")
            .compile()?;
    }
    Ok(())
}
