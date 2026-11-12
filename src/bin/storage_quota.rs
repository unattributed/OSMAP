//! Fixed read-only kernel-quota worker. No privilege change or daemon state.
use std::io::Write;

fn main() -> std::process::ExitCode {
    // Seven entries distinguish extra arguments without an unbounded collection.
    let arguments = std::env::args_os().skip(1).take(7).collect::<Vec<_>>();
    match osmap::storage_quota_worker(&arguments) {
        Ok(bytes) if std::io::stdout().lock().write_all(&bytes).is_ok() => {
            std::process::ExitCode::SUCCESS
        }
        _ => {
            eprintln!("storage_quota_unavailable");
            std::process::ExitCode::FAILURE
        }
    }
}
