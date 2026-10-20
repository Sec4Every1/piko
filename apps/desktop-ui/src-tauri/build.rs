#![forbid(unsafe_code)]

fn main() {
    if std::env::var("PROFILE").as_deref() == Ok("release")
        && std::env::var_os("CARGO_FEATURE_CUSTOM_PROTOCOL").is_none()
    {
        panic!("Release desktop requires embedded assets: use npm run tauri -- build --no-bundle --ci -- --offline, or cargo build --release --features custom-protocol");
    }
    tauri_build::build();
}
