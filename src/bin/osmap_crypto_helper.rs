//! Operator-created crypto service. Private material never enters CLI arguments.
use osmap::openpgp_crypto_runtime::Service;
fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 2 {
        Service::from_operator_files(
            std::path::Path::new(&args[0]),
            std::path::Path::new(&args[1]),
        )
        .and_then(Service::serve)
    } else {
        Err(osmap::openpgp_inventory::Error::Invalid)
    };
    if result.is_err() {
        eprintln!("Crypto service unavailable.");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
