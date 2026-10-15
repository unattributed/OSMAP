# Engineering-owned reconciliation of a retained folder change

Scope: S08-02 private folder Rename/Move/Bin/Restore. This runbook implements the
explicit safe retained-state disposition allowed by approved R3. It does not
claim automatic recovery of an arbitrary crashed native child. A missing
settlement witness remains UNKNOWN; snapshots and flock acquisition are not
proof that a previously dispatched child has finished.

## User-visible contract and ownership

The authenticated pending-result/recovery page shows the account, original
operation reference and source/intended folder. It explicitly says the change
has not completed successfully, affected folder changes remain paused, mail
reading can continue, and the action must not be repeated or either location
deleted. The user gives the reference to the mail service administrator; the
engineering owner performs diagnosis and safe reconciliation. This is not an
operator UAT request, a request for a private passphrase, or end-user debugging.

The engineering integration owner owns the incident until a supported terminal
outcome or an independently reviewed safe retained disposition is recorded.
Assign that owner in the existing epic execution ledger and issue, not a new
project framework. Capture the next concrete action and its owner. Do not close
an incident solely because a generic error was displayed or an agent stopped.

## First bounded action: read-only preservation and diagnosis

Budget the initial inspection to five minutes and at most two failed reads at
one boundary. A failed access/identity check ends that read sequence; it does
not authorize another command, a different host, credential extraction or a
retry of the mutation. Continue independent development while the named
engineering owner resolves the exact boundary.

1. Verify the deployed helper/web source and target identities. Frontend state
   belongs to its configured settings directory on obsd1; authoritative helper
   completion state belongs to the configured mail backend. Verify
   mail.blackbagsecurity.com before using authoritative mailbox observations.
   Read the running configuration for exact paths/identities; never guess a
   runtime directory, account, socket or historical process ID.
2. Preserve only this account's exact original web role, helper completion and
   any Bin/Restore receipt. Helper records reside beneath the configured
   runtime_dir/folder-rename-completions and use namespace
   osmap-folder-rename-helper-v1. Web role uses
   osmap-folder-roles-v1. Their account-bound filenames are SHA-256 of
   namespace, one NUL byte and canonical account, as implemented by
   private_account_file.rs. Validate owner/mode/single-link/bounds through the
   existing readers; do not bypass a refused reader. Do not copy the entire
   runtime directory or any grant key/session/credential file.
3. Verify original account/action nonce, request equality, root/parent GUIDs,
   finite descendant suffix/GUID map, disposition receipt and any reserved/
   dispatched recovery nonce. Preserve the original serialized bytes/hash;
   do not edit, remove, replace, unlock or manufacture a terminal record.
4. Use the normal authenticated read-only FolderMetadata and MailboxStatus
   operations to enumerate the account's private namespace and each exact
   before/after path in that original map (at most nine original containers,
   eighteen paths). Keep existing ten-second command/output bounds. Read
   current message identity/count information through the ordinary mailbox
   reader, including retained attachments; preserve private Label/Snooze rows.
   Do not expunge, rename, move, subscribe, change roles or fetch unrelated
   accounts. Retain content evidence privately, never in committed logs.
5. Classify each original GUID as exactly-before, exactly-after, duplicated,
   missing or foreign/changed. Record service/native-child observations
   separately. Stable snapshots, an absent historical PID, process-name text,
   a new helper process and an acquired account lock never prove settlement.
   Do not signal a historical PID or restart services as a substitute for that
   proof. Record actual unknowns without inventing a failure cause.

Use the existing sprint root with owner-only incident storage. Commit only
sanitized observations, evidence hashes, exact deployed versions and the
engineering disposition. Do not commit message/attachment bodies, private
account records, cookies, credentials or keys.

## Supported reconciliation decision

- **Durable original Renamed witness plus exact full destination GUID map:**
  use the existing authenticated Check original result action. It still
  verifies current parents/tree, reconciles descendant Label/Snooze metadata
  and Bin/Restore receipts, then clears the web role. No native mutation is
  repeated. Current placement alone cannot enter this success branch.
- **Durable NoMutation witness plus exact full original GUID map:** use the
  same existing Check action. It releases only the unchanged action and
  preserves messages/indexes. Do not relabel an unconfirmed action NoMutation.
- **Exact partial map plus helper-derived original native settlement and no
  unconfirmed dispatched recovery:** use the existing explicitly reviewed,
  CSRF-confirmed Recover action for one proven-owned original child. Keep its
  nonce; a lost reply is inspected with that same nonce. Never redispatch the
  original root action. Existing finite capacity and parent/role/account
  refusals remain binding. Recheck after each result; stop on uncertainty.
- **Missing original outcome/settlement or an unconfirmed child step:** retain
  the role, original completion record, receipt and both locations unchanged.
  Record `RETAINED—LIFECYCLE UNCONFIRMED` with engineering owner and next action.
  Normal reading remains available; affected folder/preferences mutations stay
  paused. No root/child retry, record reset, manual receipt completion or
  index relabelling is allowed. Escalate internally to the mail administrator
  and integration owner for a separately reviewed, account-scoped maintenance
  plan that proves child quiescence before any repair. Do not ask the end user
  to diagnose or provide a passphrase. If no such proof is presently possible,
  preservation is the explicit disposition and repair remains open; it is not
  reported as successful completion.
- **Missing/duplicate/foreign GUID, changed parent, extra container or refused
  private record:** preserve the same hold and assign the exact discrepancy
  to engineering. Do not merge/delete/overwrite either location. A future
  repair must bind the exact current owned containers and preserve unrelated
  mail, indexes, services, keys and configuration.

## Evidence and closure

The before-witness regression injects a consumed original request without a
published outcome/settlement; it reconstructs backends from durable files and
proves no original/child redispatch, unchanged private records and retained
mail/indexes. A fully placed snapshot still cannot pass the success predicate
without the original helper witness. The browser regression injects an Unknown
outcome and checks HTTP nonsuccess, actionable reference and retained pending
state. These are controlled local faults, not an actual process crash or
kernel-quiescence qualification.

For a real incident, record actual reads, classification, preservation,
engineering owner and next action. Close the incident as repaired only after
supported checks/repair, matching current data, independent review and removal
of the pending role through the existing authenticated workflow. An explicitly
reviewed safe hold may qualify the tested failure-handling contract under R3;
it never invents successful user-operation completion or acceptance of the
entire slice/sprint. No human UAT invitation precedes agent-owned PASS.
