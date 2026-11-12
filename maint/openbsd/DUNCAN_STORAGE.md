# Retired account-specific storage profile

The historical `osmap_duncan_storage` deployment profile is retired. Its
installable rc script has been removed. Do not recreate its named service,
mount entries or special SQL mapping when adding or deploying OSMAP accounts.

Use [account-based mail storage and quota](MAIL_STORAGE.md): the mail stack
resolves every account's mailbox path and quota; the existing Rust mailbox
helper reports the authenticated account. No per-account OSMAP service is needed.

The approved obsd1 correction preserved the newest retained mailbox's 469 raw
message files, all 28 mailbox identities, message UIDs/GUIDs/flags/dates and 26
subscriptions. It retained the original filesystem image, prior home, external
metadata and private migration evidence. The old home contained earlier state
and was not merged back into the current mailbox. Historical receipts remain
historical; this retirement is not permission to delete retained data.

Documents was removed from the product scope. Its retained data is preserved;
its removed HTTP entry points do not enable storage operations. A rollback after
new mailbox writes requires delta reconciliation, never a blind old-home switch.
