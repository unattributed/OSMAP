# S08-07 — Junk in Archive / Bin

## Outcome and boundary — 2026-11-11

The owner requests Junk as a third folder on the existing Archive / Bin page.
The account's existing literal `Junk` mailbox appears beside Archive and Trash;
opening it shows its messages, search, reader and current account-owned move
controls. Junk shows received dates, not invented archive action dates. The
shared left navigation names all three views. When Junk is absent, the page
shows an unavailable tab rather than inventing or creating a mailbox.

This is a presentation and navigation extension of the existing authenticated
mailbox and move contracts. It does not add spam classification, training,
sender blocking, automatic delivery routing, retention, deletion authority,
mail service configuration, a new helper, or a preference store. The existing
generic Move action handles Junk to Inbox/Trash; only the saved Trash retains
Restore, Empty trash and permanent deletion. Preserve the accepted original
S08 and S08-05, the separately pending S08-06 owner checks, owner mail/keys and
public services. The frozen page reference remains unchanged; this owner image
is the visual change request.

Use S05's failure → analyse → smallest supported correction → focused retest
loop. Root owns integration, source, Git, delivery and evidence;
`/root/s08_delivery_review` independently reviews source, security and results.
The working source is the existing Archive/Bin renderer, authenticated mailbox
listing and exact-account move path. First inspect their actual contracts.
Two failures at one boundary stop retries for combined reassessment. Initial
bounded effort allowance: 7,200 seconds, with actual elapsed/failures retained;
UNKNOWN earlier costs remain UNKNOWN.

Minimum checks: (1) account-owned Junk available/missing/denied/foreign and
read-only navigation; (2) Archive, Trash and Junk tabs, true active state,
received versus archived columns, escaped rows, correct search/reader context
and Bin-only destructive controls; (3) existing move identity/CSRF/stale and
foreign refusals, with one bounded synthetic end-to-end Junk→Inbox round trip;
(4) compact desktop Icons/Text labels and touch-visible controls; (5) matching
OpenBSD build, installed Web identity, protected-state and HTTPS checks. Run
normal signed delivery hooks and fresh GitHub equality. Source/render checks
do not imply installed or owner UAT PASS. Human exit is a short visual and
functional review of the third tab and a disposable Junk message.

Status: **UAT_READY**. Source, native and installed qualification are complete;
owner UAT is pending. Existing accepted and pending outcomes retain their
separate states.

## Source and browser checkpoint

The scoped source candidate uses an explicit Archive/Bin/Junk rendering kind.
Junk shows Received dates; the confirmed Sent role and configured Archive/Bin
roles take precedence if an account deliberately points one of those roles at
`Junk`. The third tab appears only when the existing account-owned Junk mailbox
is available. The existing generic bounded Move form returns Junk messages to
Inbox; no new mutation authority or backend protocol was added.

Five focused Rust cases pass with no failures or ignores, including the
metadata-bearing negative for Bin-only deletion, Sent-role collision,
missing/denied/foreign folder lists, third-view rendering and one synthetic
Junk-to-Inbox move with reload. Existing shell navigation seven, Bin one and
Archive one matching cases also pass. Synthetic Chromium browser checks pass
26 scoped assertions: saved Archive setup, twelve page fits, twelve view checks
across Icons/Text labels and two desktop sizes, and one touch Junk check. No
external request or send occurred; exact fixture cleanup passed. Retained
private evidence: `/home/foo/Downloads/osmap-ux-s08/s08-07/source-result2.json`
SHA256 `aa9a482bbc99c49140c6696162cd094ec3fcfaae7a100138b80817a1ced04973`,
browser report SHA256
`0769346bbe479b3d660170929ca78d1fcc852db7080c832755054ab5e3084842`,
focused Rust log SHA256
`4ec471c11404a395ec32295f7f5cca1f496e5225573db07ad637262feb74edd5`.
Independent source/security review is GO. Browser screenshots test layout and
read-only controls; the Rust route case supplies the separate synthetic move
proof. Matching native/installed qualification is recorded below; owner UAT
remains pending.

Retained source/browser failures: browser1 used system Python without
Playwright and stopped before fixture startup; browser2 expected the Archive
layout without saving an Archive preference, and browser3 guessed an absent
literal Archive folder in the preview fixture. Both started fixture runs
completed cleanup. Combined independent review selected the actual existing
`INBOX.Projects` folder through the Copies form for browser4. These failures
remain historical and do not establish product failure or PASS.

## Native and installed checkpoint

Signed source `18962ce66bcd2e38287639a8b9168fdf0eafbbff` passed the normal
push hook; fresh GitHub fetch proved exact local/remote equality and zero
ahead/behind. The first push passed its security check, then the SSH transport
closed before publication (exit 141). The precise close reason is UNKNOWN. A
normal retry with SSH keepalives passed the unchanged hook and published the
commit. The transport failure remains
separate from the successful source result.

On obsd1, the exact source archive built five focused native-compiled Junk
cases with zero failures or ignores. The dispatcher read back all 598 compiler
inputs and four native logs by hash. This proves the changed renderer and
synthetic BrowserApp move boundary on OpenBSD; it does not claim a new
Runtime-to-mailbox-helper/Dovecot persistence test. The existing backend
operation was unchanged. Retained private native result:
`/home/foo/Downloads/osmap-ux-s08/s08-07/native_method1/native1-result.json`
SHA256 `b81302dc5791065563a20b031aa058d8c19d19a8db3835b04f76371b0b1f044f`.
The actual producer/consumer admission check and pre-host refusal are in
`method-integration-result.json` SHA256
`8cf4c2339a38ce5d33ea5dd616a2d8bd2e5003094a369933ff730ab135eee137`.

The reviewed Web-only installer loaded binary
`10e2c2831f1d144be508284e26458efab10aa8534e72e011e5b4c22580ddd7f3`.
Readback showed unchanged configuration, public mail PIDs, account/helper/GPG
processes and a retained exact rollback copy. A bounded startup probe returned
502 once, then 200; the explicit obsd1 peer returned HTTPS 200. No owner mail
was mutated and no public mail service was restarted. Retained private install
result: `install-evidence1-result.json` SHA256
`8e9b71d8fb641519094bfe99a68bc70c88890a9efccaffe08683a50cca571989`.
Independent delivery/security review checked the exact native and installation
receipts and gave GO for owner UAT. The owner should open Archive / Bin / Junk,
select Junk, confirm Received dates and reader/search controls, and use one
disposable Junk message to check Move to Inbox if available. An absent Junk
mailbox should show the unavailable tab and should not create one. The owner
has not yet reported S08-07 UAT PASS.
