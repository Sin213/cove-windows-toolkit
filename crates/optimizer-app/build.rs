fn main() {
    // Embed a manifest that always requests administrator elevation. Cove's
    // core features (DISM, SFC, Defender, network resets, CPU temperature
    // sensors via the LHM Ring0 driver) all require admin rights.
    let manifest = include_str!("windows-app-manifest.xml");
    let attributes = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(manifest),
    );
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
