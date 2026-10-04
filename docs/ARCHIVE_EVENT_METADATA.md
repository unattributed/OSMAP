# Known Archive action dates

The approved Archive/Bin table displays Archived; row actions retain Received
separately. Archived records
the server time of a confirmed OSMAP Archive action. It is not the message's
Received date, a filesystem modification date, or an inferred historical event.
Older mail without a matching event displays Unknown. An unreadable or invalid
metadata record displays Unavailable.

After an explicit Archive action confirms the mail move, the route resolves the
current destination summary for the authenticated account. It requires one
matching message GUID and stores the destination folder, UID and mailbox GUID.
Source UIDs and mailbox GUIDs cannot identify the destination after a move.
An ordinary Move, Bin or Restore action does not create a new Archive event.

The web runtime persists this metadata beneath its existing settings directory
in `archive-events-v1`. The account namespace is hashed; no browser value becomes
a path. Existing private-file checks, account locking, atomic publication and
directory synchronization apply. Records contain identity and event time, not
message subjects, addresses, bodies, attachments or credentials. A store holds
at most 2000 events and 8 MiB. Reconciliation of the same confirmed destination
preserves its first recorded time; a bounded mailbox list does not imply unseen
events should be pruned.

Missing destination identity, capacity, contention, corruption or an unconfirmed
write never converts a confirmed mail move into a failed move. The UI tells the
user that metadata recording could not be confirmed and offers read-only
reconciliation. It must not ask the user to repeat the move. A bulk operation
reports an earlier confirmed move's metadata uncertainty alongside later
refused, uncertain or unattempted mail actions.

Source, native integration, installed workflow and human UAT are distinct
qualification steps. See the current execution ledger for the assessed source
and actual outcomes; this document does not assert whole-slice acceptance.
