//! Fixed account admission endpoint. No credentials enter arguments or logs.
use osmap::account_admission_runtime::Service;
fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 2 {
        osmap::openbsd::AccountAdmissionSignals::install()
            .map_err(|_| osmap::account_admission::Error::Unavailable)
            .and_then(|signals| {
                Service::from_operator_files(
                    std::path::Path::new(&args[0]),
                    std::path::Path::new(&args[1]),
                )
                .and_then(|service| service.serve(signals.stop_flag()))
            })
    } else {
        Err(osmap::account_admission::Error::Invalid)
    };
    if result.is_err() {
        eprintln!("Account admission service unavailable.");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
