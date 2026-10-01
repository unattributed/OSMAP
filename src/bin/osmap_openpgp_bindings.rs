//! Trusted operator entry point. Inventory is authenticated through the existing
//! helper Client; this command is never an HTTP mutation/step-up substitute.
use osmap::openpgp_bindings::{
    AccountBinding, BindingStore, ProtectionPolicy, RecipientBinding, Update,
};
use osmap::openpgp_inventory_runtime::Client;
use serde::Deserialize;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    account_binding: Option<AccountBinding>,
    recipient_bindings: Vec<RecipientBinding>,
    policy: ProtectionPolicy,
}
fn provision(args: &[String]) -> Result<u64, ()> {
    if args.len() != 7 {
        return Err(());
    }
    let revision = args[2].parse().map_err(|_| ())?;
    let uid = args[6].parse().map_err(|_| ())?;
    let path = Path::new(&args[3]);
    let input_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    let metadata = input_file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > 128 * 1024 {
        return Err(());
    }
    let mut bytes = Vec::new();
    input_file
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 128 * 1024 {
        return Err(());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let inventory = Client::from_operator_files(Path::new(&args[4]), Path::new(&args[5]), uid)
        .map_err(|_| ())?
        .read(&args[1])
        .map_err(|_| ())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    BindingStore::new(&args[0])
        .replace_operator(
            &args[1],
            revision,
            Update {
                account_binding: input.account_binding,
                recipient_bindings: input.recipient_bindings,
                policy: input.policy,
            },
            &inventory,
            now,
        )
        .map(|record| record.revision)
        .map_err(|_| ())
}
fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match provision(&args) {
        Ok(revision) => {
            println!("binding_revision={revision}");
            std::process::ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("Operator binding update unavailable.");
            std::process::ExitCode::FAILURE
        }
    }
}
