//! Operator-only inventory service. Paths never arrive over its socket.
use osmap::openpgp_inventory_runtime::Service;
use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = if args.len() == 3 {
        Service::from_operator_files(Path::new(&args[1]), Path::new(&args[2]))
            .and_then(Service::serve)
    } else {
        Err(osmap::openpgp_inventory::Error::Invalid)
    };
    if result.is_err() {
        eprintln!("Public inventory service unavailable.");
        std::process::exit(1);
    }
}
