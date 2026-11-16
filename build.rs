use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-env-changed=OSMAP_BUILD_REVISION");
    let revision = std::env::var("OSMAP_BUILD_REVISION")
        .ok()
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|v| v.status.success())
                .and_then(|v| String::from_utf8(v.stdout).ok())
        })
        .unwrap_or_else(|| "unknown".into());
    let revision = revision.trim();
    assert!(
        revision == "unknown"
            || (revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    println!("cargo:rustc-env=OSMAP_BUILD_REVISION={revision}");
}
