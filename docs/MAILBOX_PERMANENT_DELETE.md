# Permanent-delete backend integration

Permanent deletion is separate from reversible Bin moves. The backend accepts
one canonical account, exact folder, UID, mailbox GUID, message GUID and retention
revision. It executes an exact conjoined native query once, then confirms absence.
A lost result after dispatch is `Unknown`; callers must never automatically retry.

The web gateway uses only the authenticated mailbox helper. Configure all three
of `OSMAP_MAILBOX_HELPER_SOCKET_PATH`, `OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH` and
`OSMAP_MAILBOX_HELPER_PEER_UID`. The UID is the actual local Unix service peer
(in a relayed deployment, the local relay), not a guessed remote UID. Missing
configuration refuses deletion without direct native fallback. The existing
mail mutation quota is reserved before any helper write.

The helper receives `OSMAP_MAILBOX_RETENTION_POLICY_PATH`, an absolute canonical
path to a trusted, root-owned regular file. It is optional and absent by default.
The file must have one link, no group/other write permission, safe owned ancestry,
and no symlink. Only helper mode adds its explicit read-only confinement rule.
Browser forms and account preferences cannot configure this path or its owner.

The strict bounded JSON contract is:

```json
{"version":1,"rules":[{"account":"alice@example.test","mailbox_name":"Deleted","revision":7,"permanent_delete":"allowed"}]}
```

Use `"denied"` for an explicit refusal. Revisions are positive integers; change
the revision whenever permission changes. Unknown fields, duplicate rules,
malformed or inaccessible files, absent rules and unsafe ownership return
`Unavailable`, rather than granting permission. No age, message flag or Bin
preference implies permission. This file grants an operator-selected permission;
it is not an automatic retention scheduler or a legal-hold inference engine.

The production helper shares one mutation gate with move and flag operations.
Policy replacement must hold that same gate or take place while the helper is
stopped. An arbitrary external file rewrite does not have an atomicity guarantee.
The helper checks the policy and current stored identity under this gate before
native mutation. Existing reader and reversible Bin paths retain their expunge
bans.

The helper client checks the configured Unix peer before writing, signs all target
and policy fields with the existing grant key, and requires the reply to echo the
complete request and nonce. One bounded deadline covers connect, write and read;
finite refusals remain distinct from uncertain completion. The helper retains
its existing authenticated request and replay admission checks.

At this checkpoint, configuration parsing, confinement planning, gateway quota,
helper transport and isolated native Dovecot operation have executable coverage.
The application candidate is not installed. Browser confirmation, bounded bulk,
matching deployment and operator UAT remain incomplete; backend tests do not
establish an accepted UX slice or successful email delivery.
