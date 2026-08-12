fn main() {
    // Embed the administrator manifest required by system repair commands.
    let manifest = include_str!("windows-app-manifest.xml");
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(manifest));
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
