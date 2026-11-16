//! Separate private Rust admin entry; no public mailbox bootstrap is invoked.
fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).take(4).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--version" {
        println!(
            "OSMAP-ADMIN {} git_commit={}",
            env!("CARGO_PKG_VERSION"),
            env!("OSMAP_BUILD_REVISION")
        );
        return std::process::ExitCode::SUCCESS;
    }
    #[cfg(unix)]
    match osmap::admin_entry(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("ADMIN_PLATFORM_UNSUPPORTED");
        std::process::ExitCode::FAILURE
    }
}
