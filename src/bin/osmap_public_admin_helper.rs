//! Helper-principal entrypoint. No certificate content or secret is a CLI argument.
use osmap::openpgp_public_admin_runtime::Service;
fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 2 {
        Service::from_operator_files(
            std::path::Path::new(&args[0]),
            std::path::Path::new(&args[1]),
        )
        .and_then(Service::serve)
    } else {
        Err(osmap::openpgp_public_admin_protocol::Error::Invalid)
    };
    if result.is_err() {
        eprintln!("Public administration service unavailable.");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
