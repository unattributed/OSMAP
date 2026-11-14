# Design and technical decision log

OSMAP's engineering history, in ascending date order. Each day records the
problem, the decision and its consequences, with links to the source changes
and supporting records. This is a design history for maintainers and operators;
use the [project README](../README.md) for installation and the
[current status record](CURRENT_PROJECT_STATUS.md) for scoped acceptance.

## Reading and provenance

This reconstruction was made on **2026-11-14** from the existing decision log,
all fetched `origin` branches and local branch history. The fetched public refs
contain **1,031 distinct commits across 105 author-date days**. Two additional
decision dates, May 16 and May 19, come from the original written record. Local
preparation history was compared with its public successors; the refused private
publication and other private retained refs are not reproduced. No private
mailbox, credential, proof or raw
execution artifact is included.

Dates preserve explicitly documented event dates. Where a development day has
no separate dated decision, its heading uses the commit's recorded author date,
including that timestamp's timezone. A later commit or squash can therefore
publish an earlier event. Documentation dates, build dates, deployment and owner
acceptance are different observations. Days without a recorded development or
decision event are not filled with invented activity.

Repeated preparation notes and superseded status snapshots are consolidated
below. Their exact wording, hashes, execution timings and failure receipts remain
in the [pre-rewrite decision log at main `14a5250`](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md)
and the linked slice records and [execution ledger](UX_EXECUTION_LEDGER.md).
A local/component pass does not establish OpenBSD, installed, owner or release
acceptance. Cleanup success does not convert a failed journey into a pass;
`UNKNOWN`, `NOT RUN`, retained resources and later supersession remain explicit.

Public branch coverage at reconstruction:

| Ref | Recorded tip | Treatment |
| --- | --- | --- |
| `origin/main` | [`14a5250`](https://github.com/unattributed/OSMAP/commit/14a5250f41b880bf924357743f888d58ddcb58da) | Published project baseline, including UX promotion and production-host recovery repair/acceptance. |
| `origin/feat/ux-completion-20260929` | [`6809c6a`](https://github.com/unattributed/OSMAP/commit/6809c6a861428760ec67446ab12caa3c9f313cd0) | Detailed UX development history; promoted to main through [`43d5475`](https://github.com/unattributed/OSMAP/commit/43d547569543d9db004031d819d65dc10df8fcd3). |
| `origin/bbs/toronto-recovery-contact` | [`accaeb5`](https://github.com/unattributed/OSMAP/commit/accaeb5cfa9daf7f105b3efccd5752e42cb10e9d) | Detailed repair history; published through PR #82. |
| `origin/bbs/toronto-recovery-uat` | [`6be6a8d`](https://github.com/unattributed/OSMAP/commit/6be6a8dce5dfdea358bd739f9614afbb7811c528) | Scoped owner acceptance; published through PR #83. |
| `origin/bbs/toronto-ux-deployment-evidence` | [`740da6a`](https://github.com/unattributed/OSMAP/commit/740da6abaa47dac8c37c93886a9baccf6f4b47dd) | Deployment observations, including permissions failures and their correction. |
| `origin/docs/osmap-admin-project-plan-20261113` | [`85d483a`](https://github.com/unattributed/OSMAP/commit/85d483a48dc636f488188650237e8ae8d3ff4644) | Separate OSMAP-ADMIN proposal and sanitizer remediation; not present in this main baseline. |
| `origin/feature/totp-lifecycle-rotation-recovery` | [`afadac2`](https://github.com/unattributed/OSMAP/commit/afadac2f8cda24e9bf4b126823771829a842f8bd) | Earlier operator lifecycle work and host-target clarification. |
| `origin/feature/totp-revocation-operator-tool` | [`d8deaab`](https://github.com/unattributed/OSMAP/commit/d8deaaba60c61efc6754ff8ce95f94e9a7a3cf99) | Earlier revocation implementation, also represented by its merge. |
| `origin/fix/openbsd-cargo-target-test` | [`2a6993f`](https://github.com/unattributed/OSMAP/commit/2a6993fe7df42a57f0cbb5fe3e33e331b400fef9) | Portability regression correction, recorded separately from deployment. |
| `origin/governance/sprint-artifact-evidence-sop` | [`c6ee726`](https://github.com/unattributed/OSMAP/commit/c6ee726463c2d9554a982413abfb65fb26f3ff7f) | Sprint-scoped retained-artifact layout. |

Local preparation `1a91a2c` was reconciled against its published successor
[`8d79901`](https://github.com/unattributed/OSMAP/commit/8d79901c512f73f146397ebaf5ade12d6e2a620d). Local `docs/post-v1-account-switching` points to [`2d7f264`](https://github.com/unattributed/OSMAP/commit/2d7f264f2dc965c7d52768565094a4bc9ed5b443); the remaining local
branch tips duplicate public history or the preparation/publication distinctions
above. Branch presence records source provenance, not deployment or acceptance.

Navigate by period: [March](#2026-03-24--establish-the-project-repository),
[April](#2026-04-02--decompose-the-runtime-and-add-safe-html),
[May](#2026-05-02--make-resource-and-release-controls-explicit),
[June](#2026-06-01--bind-wstg-release-evidence-to-the-assessed-source),
[July](#2026-07-28--tighten-dependency-and-http-field-admission),
[August](#2026-08-16--close-the-bounded-v15-http-differential-corpus),
[September](#2026-09-02--normalize-the-reviewed-stable-toolchain-version),
[October](#2026-10-01--connect-native-openpgp-to-account-owned-browser-workflows),
[November](#2026-11-01--make-key-import-and-recipient-selection-practical).

## 2026-03-24 — Establish the project repository

Create OSMAP as a documented OpenBSD secure mail access project and clarify the
README's purpose. This establishes the repository, not a working or qualified
mail service. Sources: [`c94d267`](https://github.com/unattributed/OSMAP/commit/c94d267499ec0de20511d7352ebe823892870d8d), [`2e0f22d`](https://github.com/unattributed/OSMAP/commit/2e0f22d768d20046ca449e5214109e9b9ceda13c).

## 2026-03-27 — Choose a narrow Rust frontend with separate mailbox authority

- **Product and platform:** define a mail-only browser frontend to the existing
  Dovecot/Postfix stack, preserving native clients and the initial VPN-first
  posture. Keep public planning non-sensitive, select an ISC license, and make
  OpenBSD confinement and simple release mechanics architectural requirements.
- **Application:** start with dependency-minimal Rust and server-rendered HTML.
  Separate bootstrap from HTTP service; implement password verification followed
  by file-backed TOTP, bounded sessions with derived identifiers, logout and
  revocation. Gate mailbox operations on validated sessions.
- **Mail and browser boundaries:** use fixed `doveadm` operations for mailbox,
  message and MIME reads and the local `sendmail` interface for submission.
  Start plain-text-first; add bounded upload/download and attachment metadata,
  reply/forward drafts, session-bound CSRF and strict transport/cache policy.
  Force downloads rather than introduce attachment previews.
- **Privilege separation:** actual host authentication and mailbox identity
  requirements rule out broad mailbox access in the web process. Introduce a
  permissioned Unix-socket helper and migrate listing, message retrieval and
  attachments to it. Keep nginx as TLS edge and HTTP on loopback. Dedicated
  Dovecot auth/userdb sockets and per-role `pledge`/`unveil` policies replace
  speculative broad filesystem grants. Positive authentication and mailbox
  access remain separate proof points.

Sources: [`956a549`](https://github.com/unattributed/OSMAP/commit/956a5490f817cc1e22aaedc91841ab8f4104067d), [`92feca4`](https://github.com/unattributed/OSMAP/commit/92feca4b16adf59e33f96809c09bea61f85b764b), [`9336b05`](https://github.com/unattributed/OSMAP/commit/9336b056391ec333544c8f8438056a90c99f5ed3), [`eca245b`](https://github.com/unattributed/OSMAP/commit/eca245bb087a463d067e79c408937da9ef239f7c), [`2793ef7`](https://github.com/unattributed/OSMAP/commit/2793ef7cf0b1ecd9d467cae1470a9d362465d4f2), [`59a06fa`](https://github.com/unattributed/OSMAP/commit/59a06fadc879ab03981f426fbb2a2c970bb1a765),
[`c8b06c8`](https://github.com/unattributed/OSMAP/commit/c8b06c8b21d6eb81e15f3ec4bb5885be52aa6738), [`735ef06`](https://github.com/unattributed/OSMAP/commit/735ef06b2b078ee16c8d41d4debcb65bf821cb77), [`8d13de8`](https://github.com/unattributed/OSMAP/commit/8d13de817e983eff591cb6b0af9dcd157397f7df);
[architecture](ARCHITECTURE.md), [security model](SECURITY_MODEL.md).

## 2026-03-28 — Prove the helper boundary and harden browser parsing

Qualify helper-backed reads under enforced OpenBSD confinement and remove
unneeded Dovecot paths. Reject ambiguous framing, cookies, paths, form fields,
content types and oversized headers before routing. Add browser session
management, backend-authoritative mailbox search and one-message helper-backed
move without widening mailbox authority.

Establish the repository Rust/CWE gate and reconcile GitHub's CodeQL/default
setup with actual runner formatting and Clippy behavior. Treat `docs/` as the
documentation source and diagnose workflow failures from observed runs.
Sources: [`a22b3a4`](https://github.com/unattributed/OSMAP/commit/a22b3a42fee5e1c5ce3e64cceae6195431a76b9e), [`6612c74`](https://github.com/unattributed/OSMAP/commit/6612c74f42286c7f0ff025ff84e5fe481735fe0d), [`a451ff1`](https://github.com/unattributed/OSMAP/commit/a451ff1df5dc2fe7ebfd922c205f338e4122f451), [`7673c9c`](https://github.com/unattributed/OSMAP/commit/7673c9c87df6159bc00787dedec10acbd994e641), [`c854e22`](https://github.com/unattributed/OSMAP/commit/c854e2222b7d07a086ba906424984f5b41a83d05), [`9b47a0e`](https://github.com/unattributed/OSMAP/commit/9b47a0e6c4a0f040de47c9ec69cce219360699a3),
[`6b3778b`](https://github.com/unattributed/OSMAP/commit/6b3778bce0a180e80d53ace445dc1cea5a9b2b19), [`3af9ad7`](https://github.com/unattributed/OSMAP/commit/3af9ad7119d19eedfb5054ae2c17dfae272a586c).

## 2026-04-02 — Decompose the runtime and add safe HTML

Split the growing HTTP, gateway, mailbox and helper modules into parser,
transport, route, service, model and backend components while preserving their
contracts. Keep CI formatting authoritative rather than repeatedly changing
behavior to address style failures.

Use an allowlist sanitizer for optional HTML with plain-text fallback; persist
that account preference in the explicit state tree. Add bounded login,
submission and move throttles, including remote-only login accounting. Live
HTML/settings and mutation observations are scoped host evidence, not a broader
release. Sources: [`1ca1293`](https://github.com/unattributed/OSMAP/commit/1ca1293fd5ca739697e5e9cad8734ea5fea29a79), [`783e6c6`](https://github.com/unattributed/OSMAP/commit/783e6c6f498ab2540cf7ac4051fa31c867b756f2), [`58b480e`](https://github.com/unattributed/OSMAP/commit/58b480e948ad46c602f64462892c16c481fbdf61), [`c100301`](https://github.com/unattributed/OSMAP/commit/c100301ace8b0847e2558cfbfa7f11ca1fab4d57), [`482ce1a`](https://github.com/unattributed/OSMAP/commit/482ce1aef6a01c353330e1ada5b35974ab4f074c),
[`a4d3b1d`](https://github.com/unattributed/OSMAP/commit/a4d3b1ddca75522d0c4beaa749f39f83f17de36d).

## 2026-04-03 — Bound HTTP concurrency and make failures observable

Replace the sequential listener with capped concurrent handling, bounded I/O,
accept backoff and request-completion accounting. Distinguish empty,
truncated/timed-out connections from malformed requests; surface sustained
accept/write failure and recovery. Add an observation harness and standardize
host validation on the intended checkout. Reassess V1 closure separately from
V2 deferrals. Sources: [`c8bd591`](https://github.com/unattributed/OSMAP/commit/c8bd591a441d69b2350586c2e61f11004baac808), [`3466f44`](https://github.com/unattributed/OSMAP/commit/3466f448a6133211f400c03877e546b9d4c3270e), [`bc1737b`](https://github.com/unattributed/OSMAP/commit/bc1737be6707042e7efec2fdb3e5e37bf06cc2a5), [`5577aab`](https://github.com/unattributed/OSMAP/commit/5577aabe5cc28d85446145e7e8cd0c390ac59950), [`03b2bd0`](https://github.com/unattributed/OSMAP/commit/03b2bd0a6c59b286f56635698784c75124cc092f),
[`d268886`](https://github.com/unattributed/OSMAP/commit/d268886466bd4636c6e36afe17a919b9712961f8), [`641d501`](https://github.com/unattributed/OSMAP/commit/641d50192036e05c3b69560732eaba22d48a72b9).

## 2026-04-09 — Freeze the production helper split and complete bounded search

Treat thread-spawn failure and worker panic as availability faults; report
response completion only when delivery succeeds. Add an account-configured
Archive shortcut and bounded search across visible mailboxes, with live
search/session/write-observability proof. Require the mailbox helper in
production `serve` configuration, keeping the web runtime unprivileged.
Sources: [`7a1053e`](https://github.com/unattributed/OSMAP/commit/7a1053e783c16744e67752e795002e72dcb249b3), [`d05e709`](https://github.com/unattributed/OSMAP/commit/d05e709d198f5260703ff380c5fb8f1f5ecaf394), [`d5ce6d6`](https://github.com/unattributed/OSMAP/commit/d5ce6d603ddcb1e073968f2ab203a05b4b299a9e), [`4bacf48`](https://github.com/unattributed/OSMAP/commit/4bacf4857b10e57250c557c5dbfbfe7d3d9784ac), [`ab46fc1`](https://github.com/unattributed/OSMAP/commit/ab46fc1973a49555638a8f0503a0a70ab6238d97), [`f407c0e`](https://github.com/unattributed/OSMAP/commit/f407c0e7ece449e53025228994d21f4d6c68ab92),
[`db08506`](https://github.com/unattributed/OSMAP/commit/db0850600e92b844e4e6682a57c67004ddd68fb1), [`3407bdc`](https://github.com/unattributed/OSMAP/commit/3407bdc0bdf197ee2e48813d1b5682d750c93b25).

## 2026-04-10 — Package the OpenBSD split runtime and V1 closeout

Add native `rc.d` service scaffolding and a dedicated helper attachment operation.
Make the state root read-only and permit writes only to named mutable children;
narrow each service's dependency view. Assemble one V1 closeout entry point,
reviewable summary and SSH wrapper so operators can repeat the same proof set.
The wrapper's existence is not itself V1 acceptance.
Sources: [`75eb9e7`](https://github.com/unattributed/OSMAP/commit/75eb9e73e0c6359b20c29d61058de890c3fba67b), [`43446c2`](https://github.com/unattributed/OSMAP/commit/43446c2dc9d23ecc6faf48fa232c26a6088af5dd), [`cd5da2b`](https://github.com/unattributed/OSMAP/commit/cd5da2bb88e34db43e5eaf882a39ccb766de27eb), [`2072868`](https://github.com/unattributed/OSMAP/commit/2072868dee973ea19b30130788aff298d7489f71), [`5fce556`](https://github.com/unattributed/OSMAP/commit/5fce556f8e3cf7adfea47fd03fb7094e1491a321), [`365e518`](https://github.com/unattributed/OSMAP/commit/365e5183d9067af64fb078dc2c5cdf64948d3ec4),
[`0f15870`](https://github.com/unattributed/OSMAP/commit/0f158706565f7ecf27422e85e611709e1d3d97fc), [`a712aef`](https://github.com/unattributed/OSMAP/commit/a712aef3ab3b9f7d5a57b5e24183d41797a35771).

## 2026-04-11 — Correct and rerun the actual V1 closeout path

Repair helper-boundary validation and the SSH wrapper's multi-step/path assembly;
add focused wrapper regressions. Record the full host closeout pass for the
assessed source and configuration, preserving the earlier wrapper defects.
Sources: [`e187577`](https://github.com/unattributed/OSMAP/commit/e187577f2cd372e474fe064b5c50ec260696b46e), [`74553a1`](https://github.com/unattributed/OSMAP/commit/74553a1b43e17bac34ccac72d979f2fc5e74af5c), [`b144360`](https://github.com/unattributed/OSMAP/commit/b144360ea6d0580fb2e60c49ab384b4ff1e3dfee), [`afa13f5`](https://github.com/unattributed/OSMAP/commit/afa13f53a204bc1b879cf97772eb5233f2754334), [`26645f5`](https://github.com/unattributed/OSMAP/commit/26645f5e17b6fac5f2b78d00efcd0e15046bcbff).

## 2026-04-12 — Make V1 verification repeatable and scope security claims

Consolidate temporary validation-password handling in one host helper with
restoration checks, then prove both SSH subsets and the full current-tip
closeout. Retain a real browser walkthrough as supplemental user evidence.
Pair the CWE review with a bounded ASVS baseline and exact ASVS 5.0 identifiers;
this is documented coverage, not full ASVS certification.
Sources: [`f95fcb3`](https://github.com/unattributed/OSMAP/commit/f95fcb392b9a9c631116da64dbc5e20d8cc86b39), [`723e404`](https://github.com/unattributed/OSMAP/commit/723e404b7eb19b324f673dfdeac0f69dbd684f47), [`9133607`](https://github.com/unattributed/OSMAP/commit/9133607d87b6da3deb4801da90ccc28de3652379), [`0724b88`](https://github.com/unattributed/OSMAP/commit/0724b88b0c40a3613766c3a3025a220499b06f2e), [`4d41082`](https://github.com/unattributed/OSMAP/commit/4d410828df1680417872b072676240cda0437489), [`a9790dc`](https://github.com/unattributed/OSMAP/commit/a9790dca146a5d3ca41794ab8f4b5a817f3a4f78).

## 2026-04-13 — Strengthen local caller, secret-file and POST boundaries

Enforce the helper's trusted local caller, normalize password/TOTP browser
failures, require safe TOTP file custody, use unique atomic settings writes and
require same-origin metadata on authenticated POSTs. Decode encoded headers and
show bounded Content-ID/inline-image policy information without rendering remote
images. Add live proof and hook-installation/pre-push checks, and codify signed
source delivery. Sources: [`ddf2e63`](https://github.com/unattributed/OSMAP/commit/ddf2e63d744830dea492735da350adba653db67e), [`dac45d6`](https://github.com/unattributed/OSMAP/commit/dac45d66066c88611f553a59954d0e9bf46a7b46), [`e12cf06`](https://github.com/unattributed/OSMAP/commit/e12cf060ca5f12d7d1e52c2e90a7b2d752db27d4), [`4b69579`](https://github.com/unattributed/OSMAP/commit/4b69579d26a96d16cfedfe3a0c2fbb82ae1dbe99),
[`6bb6808`](https://github.com/unattributed/OSMAP/commit/6bb6808bdb5dabc98e3e27e6bc210e5d02f6609d), [`d1222cc`](https://github.com/unattributed/OSMAP/commit/d1222cca9066e10b9855586953bb12d1a69e6e41), [`bb43cd3`](https://github.com/unattributed/OSMAP/commit/bb43cd3066ea1cfc90bb31eef8595f6cfbb765bd), [`1af22c4`](https://github.com/unattributed/OSMAP/commit/1af22c44c3a2b09e71dbf3be23b52de22fa7f5d8), [`5b22ac3`](https://github.com/unattributed/OSMAP/commit/5b22ac3e7cdbd4fc62c16f886d037e7fcc22b4e4).

## 2026-04-14 — Bind helper trust to the configured web runtime UID

Fail helper startup unless its auth-socket ownership matches the expected web
runtime identity. Shorten test socket paths to respect the actual Unix-socket
contract and archive the hardened V1 closeout evidence. Historical host proof
remains tied to that host and source. Sources: [`a8607c9`](https://github.com/unattributed/OSMAP/commit/a8607c9f7e0f857cc9583d12d999166712790cbd), [`278a0d1`](https://github.com/unattributed/OSMAP/commit/278a0d1a8d47ace873af4bab644d294c96853e47), [`ce54b6e`](https://github.com/unattributed/OSMAP/commit/ce54b6e811624d433c1504ca28f616a21e285fbc).

## 2026-04-17 — Prepare controlled public browser access

Define V2 around migration-capable public access with a selected pilot cohort,
not permanent VPN-only use. Add readiness, hostile-path and internet-exposure
assessment, an explicit nginx/PF cutover and rollback plan, rehearsal artifacts
and service enablement validation. Correct synthetic-session identifiers used by
negative tests rather than relax real session validation. Exposure assessment
and preparatory reports do not independently authorize or prove final cutover.
Sources: [`8ea61e7`](https://github.com/unattributed/OSMAP/commit/8ea61e70369a370140c5b532506b21188b47fd80), [`8de03ee`](https://github.com/unattributed/OSMAP/commit/8de03ee6ee58d1437b41fcfc255dac9fc5ae2cfe), [`5220d84`](https://github.com/unattributed/OSMAP/commit/5220d846662117c7dddad86a91559686b39802b7), [`a51557c`](https://github.com/unattributed/OSMAP/commit/a51557cbf73caa845a5ed15c25b87f3d66468134), [`74d9222`](https://github.com/unattributed/OSMAP/commit/74d92225feb525f0c881ac12fe84837125db9ec6), [`c1c9e4b`](https://github.com/unattributed/OSMAP/commit/c1c9e4bce74f36a7c3938dd0580b58698b6834a9),
[`9b10f22`](https://github.com/unattributed/OSMAP/commit/9b10f22e9f3b6b00fa19eb01a931cf56348d2de6), [`fbd5afe`](https://github.com/unattributed/OSMAP/commit/fbd5afe9bf4cad821991b770b3f5955040eadf58).

## 2026-04-18 — Activate the reviewed edge and retain the public/private split

Work through actual binary, runtime-group, service-artifact and `rc.d` blockers
before recording service activation and outside-in browser proof. Keep public
OSMAP exposure bounded and preserve private control-plane access. Forward real
client identity through nginx, restore auth observability and show subject/from
in message rows. Browser origin handling is changed only through the documented
trusted fallback, not unrestricted cross-origin acceptance.

The OCSP-stapling commit did not establish supported stapling for the actual
certificate: the recorded decision keeps it disabled where the certificate lacks
a usable responder. Sources: [`70fa951`](https://github.com/unattributed/OSMAP/commit/70fa951ee94c95b78557de4c633c486f911d6f0c), [`0b73b8a`](https://github.com/unattributed/OSMAP/commit/0b73b8abc41dabc933f0f048b9c00aaea60d9f58), [`5a6bfde`](https://github.com/unattributed/OSMAP/commit/5a6bfde69d58209d163977fe4883fb2928883fe7), [`74a3d1d`](https://github.com/unattributed/OSMAP/commit/74a3d1dd87420a913535c1b2b9bc9b2b002a75bb),
[`21aa5cc`](https://github.com/unattributed/OSMAP/commit/21aa5cc8a4c436609593d791afa1b6b7ea7ade83), [`7d20d20`](https://github.com/unattributed/OSMAP/commit/7d20d204b538649f5d74ea05614c11140183ceb0), [`c790cf5`](https://github.com/unattributed/OSMAP/commit/c790cf54dcd8c4060c9dfb7f4b3806b643de2c6e), [`a24b2b4`](https://github.com/unattributed/OSMAP/commit/a24b2b42f6fd8bb03291f3459228c5fceda7dc7b), [`9161c76`](https://github.com/unattributed/OSMAP/commit/9161c76458760e68a1a2e8861f7da1c260962978);
[historical certificate decision](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#stop-short-of-nginx-ocsp-stapling-on-the-current-mail-host-certificate).

## 2026-04-19 — Separate public HTTPS evidence and protect running services

Split public OSMAP HTTPS from private mail/admin control-plane HTTPS and validate
public submission audit correlation. Make V2 readiness service-safe rather than
stopping existing services. Accept real folded Dovecot headers and retain the
matching deployment/parser proof. Sources: [`b0b9e1d`](https://github.com/unattributed/OSMAP/commit/b0b9e1dc44b2ccff02fd45590d2d5ee0510cb61f), [`1c7cefb`](https://github.com/unattributed/OSMAP/commit/1c7cefbda9f15982ca76776593491a7b447087b9), [`bfa7476`](https://github.com/unattributed/OSMAP/commit/bfa747668f8ca5c06b138d36acbeaa499b27bedc),
[`8d30cac`](https://github.com/unattributed/OSMAP/commit/8d30cac33794b1592cb4c64ca4a79bd2173e19bd), [`c29bb90`](https://github.com/unattributed/OSMAP/commit/c29bb90ddd0868ec2019aaad6f88aff6dd597685), [`96160a9`](https://github.com/unattributed/OSMAP/commit/96160a9d53cc0f3fd0e875e6f93aaee29bd9974d), [`615924b`](https://github.com/unattributed/OSMAP/commit/615924b7f4f071ae93a8e434ed2218f7a8e1bbee).

## 2026-04-20 — Add selected-message archive through existing authority

Expose selected archive as a bounded CSRF/same-origin POST, revalidating each
message and reusing helper-backed single-message move and throttling. Report
partial failure explicitly; do not introduce arbitrary mailbox-wide operations.
Source: [`a77c32a`](https://github.com/unattributed/OSMAP/commit/a77c32aa093f9557347c75954c1531fc4e523699).

## 2026-04-22 — Qualify selected archive and real MIME output

Repair isolated validator PID cleanup, Sent flow parsing and quoted multiline
values. Prove selected archive, sanitized HTML and attachment downloads in the
actual V2 path, then stabilize the complete readiness set. Parser fixes follow
observed native output rather than an invented fixture grammar.
Sources: [`c48d5ea`](https://github.com/unattributed/OSMAP/commit/c48d5ea6961f1da6537f2e55621c9394fdbf7caf), [`8317d29`](https://github.com/unattributed/OSMAP/commit/8317d29f24c344bc49f7ca7cc8971779d91957df), [`75a42a7`](https://github.com/unattributed/OSMAP/commit/75a42a770bf4b2f5f52dda4c3f781859a5b01a99), [`5aec650`](https://github.com/unattributed/OSMAP/commit/5aec650a337b707d7e6bb2e5324de95cb54c512e), [`4a246a7`](https://github.com/unattributed/OSMAP/commit/4a246a77a5b3fd5208a54d21565566b95e9222ee).

## 2026-04-23 — Strengthen sessions and controlled pilot validation

Add bulk session revocation and idle-expiry behavior, matching live proof and a
readiness step-set drift guard. Provide the reusable WSTG pack with protected
interactive authentication and explicit pilot execution/closure. Add trash-first
message deletion instead of immediate irreversible deletion.
Sources: [`7d29634`](https://github.com/unattributed/OSMAP/commit/7d29634bea4e09586fe5941ad0088fb604632a0b), [`3ea9297`](https://github.com/unattributed/OSMAP/commit/3ea9297a40a17b1167eacf7bcc7bd94554243503), [`a82aebc`](https://github.com/unattributed/OSMAP/commit/a82aebcfab2290a484b26d69b1583cc721b0eb94), [`b056a7e`](https://github.com/unattributed/OSMAP/commit/b056a7e9ddea864981103df46788d189f262628a), [`a3dd487`](https://github.com/unattributed/OSMAP/commit/a3dd4872bf7a334d6d999666a9019cc1106b86b4), [`f28dfde`](https://github.com/unattributed/OSMAP/commit/f28dfdeb89fd8eed7adba080161fd7de278da0d9),
[`b7ac387`](https://github.com/unattributed/OSMAP/commit/b7ac387c9042862cd839bfb345d45dc6640f2338).

## 2026-04-24 — Close V2 narrowly and define V3 daily-driver work

Close the selected V2 pilot without expanding its accepted cohort or workflows.
Define V3's adoption boundary around real MIME correctness, reliable workflows
and stronger release evidence. Decode supported transfer encodings and RFC 2231
attachment filenames; keep validation independent of build duration.
Sources: [`e197015`](https://github.com/unattributed/OSMAP/commit/e1970151266eb683f9da1d6db15e32b3c38a7496), [`31a0f55`](https://github.com/unattributed/OSMAP/commit/31a0f552c9824b04689f3351143913df4abc592c), [`c73bf8c`](https://github.com/unattributed/OSMAP/commit/c73bf8c850e1f4710fbc280d726eead9efe3a373), [`f1702b3`](https://github.com/unattributed/OSMAP/commit/f1702b351698f0ad41d9d71054b50f3718fd3b12), [`77ae1be`](https://github.com/unattributed/OSMAP/commit/77ae1be80fc33b09cce695fb6a1b908510bfff34), [`7d0c16f`](https://github.com/unattributed/OSMAP/commit/7d0c16fc828052b3355c549e4e2ac13b8458a105).

## 2026-04-28 — Improve security-test usability and publication hygiene

Organize WSTG checks by section, add bounded border probes and interactive auth,
and use the canonical intended SSH host. Keep protected authentication and raw
artifacts outside public evidence. Publication hygiene is a source-delivery
control, not evidence that every live test ran.
Sources: [`9c01670`](https://github.com/unattributed/OSMAP/commit/9c0167021fd4f5374db983a9743e227f49ada00d), [`db9e81b`](https://github.com/unattributed/OSMAP/commit/db9e81b11281c7b992f3814d186f34175e0a151f), [`454fa06`](https://github.com/unattributed/OSMAP/commit/454fa06292d107fd70911d97afb9af2fb99b20b9), [`2aef2ac`](https://github.com/unattributed/OSMAP/commit/2aef2acabd6cc3380286e108fe0e8ea1a98892eb), [`64de771`](https://github.com/unattributed/OSMAP/commit/64de77143e12b3a182832c4dfb3cf30b5801c325), [`5a01659`](https://github.com/unattributed/OSMAP/commit/5a016593d0aacfd53bc6f668aae8a0a58e1f93f9).

## 2026-04-29 — Bound commands and resource lists without expanding the UI stack

Polish the server-rendered login/mail surface while retaining the browser trust
boundary. Add enforced Rust supply-chain checks, portable advisory fetch,
external-command output/runtime caps, same-process session serialization and
bounded rendered resource lists. Extend MIME and route resource regressions.
Sources: [`22b20a6`](https://github.com/unattributed/OSMAP/commit/22b20a629d5d35cd548448542ad94504ff0dffac), [`49380ec`](https://github.com/unattributed/OSMAP/commit/49380ecfb0c1b5e0c8e49c982715ce25f7b1e391), [`18e2fb3`](https://github.com/unattributed/OSMAP/commit/18e2fb3a9e741020d8316d683c5ae9c955f481ca), [`9656ce4`](https://github.com/unattributed/OSMAP/commit/9656ce4ec35f5d4abdd1c5452e1d38c8128e8c9c), [`a2e1a64`](https://github.com/unattributed/OSMAP/commit/a2e1a64a26ef21a3a477cfd8f27f34a67afb3cdd).

## 2026-04-30 — Enforce per-class worker budgets

Extend MIME fixtures toward observed mail shapes and apply worker budgets first
to search/message routes. Record matching host proof and clarify evidence-bound
V3 release checks. Scope CI concurrency by commit so a later run does not cancel
needed main checks; fix duplicate-dependency parsing rather than waive it.
Sources: [`6aa2afd`](https://github.com/unattributed/OSMAP/commit/6aa2afd396d1a42667af1c97d3038ee80564b96c), [`ee11b91`](https://github.com/unattributed/OSMAP/commit/ee11b912116ba7ab96cc237c7b10dd0c5432f685), [`681f742`](https://github.com/unattributed/OSMAP/commit/681f7422563064304d9105f75f1d4761a75d3b89), [`c115343`](https://github.com/unattributed/OSMAP/commit/c115343eaa3b0fd9a07cfe84facbea1be024a0dd), [`d6aa83b`](https://github.com/unattributed/OSMAP/commit/d6aa83badc9d120eb33e600f49b2e693ac5596d3), [`7ee789a`](https://github.com/unattributed/OSMAP/commit/7ee789a129a471d8c4ca30b8e8d00906262feb78).

## 2026-05-02 — Make resource and release controls explicit

Keep production HTTP loopback-only. Propagate original route deadlines through
expensive auth/send/mail operations and require matching resource-timeout,
TLS and credential-backed evidence in the strict V3 release gate. Archive CBC
cleanup observations as measured TLS evidence. Developer checks and missing-live
context modes cannot create a release pass.
Sources: [`b8415f6`](https://github.com/unattributed/OSMAP/commit/b8415f61904fcc65df4b61623bb2cbecb2fc54af), [`dfe63ff`](https://github.com/unattributed/OSMAP/commit/dfe63ff9bb70fe82736e84eb3b2e888fa6cec9bb), [`1e5fe06`](https://github.com/unattributed/OSMAP/commit/1e5fe065393bda295fb513212e802867c99f9791), [`c18ed72`](https://github.com/unattributed/OSMAP/commit/c18ed72098c9750b0db5dc6a0ce19b8ab856f359), [`32e7f2d`](https://github.com/unattributed/OSMAP/commit/32e7f2dfbe9d891bb236837aa598ca47452d2983), [`d615c17`](https://github.com/unattributed/OSMAP/commit/d615c179c5b3a5a2817ed5ac3ca7cdf29dfc6115),
[`04a4b9e`](https://github.com/unattributed/OSMAP/commit/04a4b9e296f88b8a7248f3d87cf72dd4c96772d7), [`0b170a4`](https://github.com/unattributed/OSMAP/commit/0b170a4c48ed8c0dd9cfe65f68a9d2b224805b74), [`9eb2aed`](https://github.com/unattributed/OSMAP/commit/9eb2aedc5b732d094a755aaa9675b7b7700b4b1e).

## 2026-05-03 — Redact persisted session identifiers and expand MIME assurance

Remove bearer-equivalent session identifiers from audit output. The original
written record also dates the V3 live MIME/HTML proof plan and regression
expansion to this day; the related implementation commits follow on May 4–6.
These plans do not imply that live proof already passed.
Sources: [`3aea101`](https://github.com/unattributed/OSMAP/commit/3aea1018805098669fbf577250afb83f07e8414e);
[original MIME planning entries](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-05-03-define-v3-live-mime-and-html-proof-plan).

## 2026-05-04 — Expand decoding and hostile-HTML regression cases

Add realistic MIME/header decoding cases and strengthen sanitized-HTML
regressions before claiming wider rendering safety. Keep accepted fallback and
sanitizer behavior explicit. Sources: [`16552e8`](https://github.com/unattributed/OSMAP/commit/16552e8cd37ac906b877b21963b2de88494228cd), [`c2aa6ce`](https://github.com/unattributed/OSMAP/commit/c2aa6ced0a8114edc2f5f40cb0e3f37e790aa906), [`8ecb17e`](https://github.com/unattributed/OSMAP/commit/8ecb17efe655088aef4ca88a4d7ac5c97333f2e3).

## 2026-05-05 — Harden attachment metadata parsing

Extend attachment metadata regressions rather than broaden supported content or
introduce previews. Source: [`73d8b19`](https://github.com/unattributed/OSMAP/commit/73d8b19e030672fe06bdb5c4b769d596573418da).

## 2026-05-06 — Add explicit drafts and live MIME release proof

**Define V3 draft save and resume boundary; Wire V3 draft browser routes.**
Implement private persisted draft save/resume and browser routes under existing
session, CSRF and account boundaries. Keep concurrent sessions explicit rather
than silently imposing single-session behavior. Build and integrate the live
MIME/HTML validator, retaining failed captures and checking actual encoded
headers, inline-image policy and attachment metadata. Map WSTG evidence to the
product's stated security coverage. Sources: [`067ab89`](https://github.com/unattributed/OSMAP/commit/067ab890fbb849590dbd376a5ba112486fdadf1f), [`d9e924b`](https://github.com/unattributed/OSMAP/commit/d9e924b941d0ebf86a4f09c19001ca79812d4d10), [`162d1d1`](https://github.com/unattributed/OSMAP/commit/162d1d180b609fb74a10f022bb540a2775ddb093),
[`69b017a`](https://github.com/unattributed/OSMAP/commit/69b017ac1922090b716f5b4480b36f7c3f01784c), [`abf3aa8`](https://github.com/unattributed/OSMAP/commit/abf3aa883eb643ef5e906857f06822c4287803f3), [`6454783`](https://github.com/unattributed/OSMAP/commit/64547838bafa9d9a3495c582029ac0d4ea852dfa).

## 2026-05-07 — Admit a bounded draft pilot and normalize auth failure

**Add V3 draft WSTG route evidence; Admit limited V3 draft save and resume pilot workflow.**
Qualify draft routes with fail-closed send/cleanup handling and admit only the
limited draft workflow supported by that evidence. Normalize backend-unavailable
login presentation and adjust the test probe bound without weakening production
throttles. Sources: [`d042406`](https://github.com/unattributed/OSMAP/commit/d04240671050d8aa698617851f88d7968b390610), [`c6afec4`](https://github.com/unattributed/OSMAP/commit/c6afec4d16f35cd652612235ca05219b76eac4cb), [`481718b`](https://github.com/unattributed/OSMAP/commit/481718b32aa1437765f20819303240b2ab19c0ca), [`a6b2cf7`](https://github.com/unattributed/OSMAP/commit/a6b2cf7c69f0e42d7ecc1e082f3f8ffa16a514fb), [`748de73`](https://github.com/unattributed/OSMAP/commit/748de7309a49c6f312c793213a91ae017470add0).

## 2026-05-11 — Make original-attachment reuse explicit

**Define V3 reply and forward attachment boundary.** Require deliberate
selection of reply/forward source attachments; retain exact
source identity and fail safely if a selected attachment changes or cannot be
read. Add positive/failure tests and credential-backed WSTG coverage. Align draft
and worker-budget environment examples with the actual configuration.
Sources: [`b974119`](https://github.com/unattributed/OSMAP/commit/b974119dc143a2b7beef1e8c5f6c298da3997452), [`cd0ca55`](https://github.com/unattributed/OSMAP/commit/cd0ca556f0fdd564ef84091b69aeef95425fc5e5), [`f915770`](https://github.com/unattributed/OSMAP/commit/f9157707b09f803db8bb3826736b06735edf99f1), [`5f256e9`](https://github.com/unattributed/OSMAP/commit/5f256e9056341845d8dcd650d23a0305ef631093), [`39d31d4`](https://github.com/unattributed/OSMAP/commit/39d31d4d4e317af7b0989e77f90901a7d76e864c), [`2ded828`](https://github.com/unattributed/OSMAP/commit/2ded828712e5c921494f52c47996bba45172a323).

## 2026-05-13 — Enforce TLS policy and strengthen helper authorization

Define project-wide TLS 1.2 minimum, prefer TLS 1.3 and require strong
forward-secret AEAD suites with certificate/hostname verification. Support the
host's LibreSSL probes and tighten helper grants and release gates rather than
rely on proxy configuration alone. Sources: [`85d8847`](https://github.com/unattributed/OSMAP/commit/85d8847a7d981ed7cad7ce4be7897debfd742f52), [`7e1eb62`](https://github.com/unattributed/OSMAP/commit/7e1eb6222cf2dcf81116777014e0657cdcc06f57), [`a8270e1`](https://github.com/unattributed/OSMAP/commit/a8270e1697f0f8c5e56a58df55da84b941a65b91);
[TLS standard](TLS_STANDARD.md).

## 2026-05-15 — Add allowlisted search refinements and repair grant evidence

Add bounded column sorting and `all`/`subject`/`from` search fields with fixed
backend keys and signed helper payloads. Correct grant signature encoding and
provide the required keys to live validators. Count backend-unavailable login
attempts toward abuse limits. Release validation requires real human WSTG proof;
a source-only pass cannot supply it.
Sources: [`722f484`](https://github.com/unattributed/OSMAP/commit/722f48461d80736d39be1e85a145d8c736a8ddff), [`e1fecf3`](https://github.com/unattributed/OSMAP/commit/e1fecf3bb13bcd5b4bd0ad909e440fc164b42cfb), [`0dac311`](https://github.com/unattributed/OSMAP/commit/0dac311648fbaffd210afc13d416021b0b8419bf), [`affe0b9`](https://github.com/unattributed/OSMAP/commit/affe0b9f56c04bba73d92d6a87ade5a19cd7ae05), [`5984432`](https://github.com/unattributed/OSMAP/commit/59844327f5eba8c18324ff5d04eb31f9dbdf1ea3), [`2c97a4e`](https://github.com/unattributed/OSMAP/commit/2c97a4e7e8aefe095d9564e47ac299f7bbbff212),
[`44fdabf`](https://github.com/unattributed/OSMAP/commit/44fdabfcce2d8474274a566eed3d34012162c513).

## 2026-05-16 — Reuse matching WSTG evidence and keep bulk actions bounded

The separately dated decision record confirms the search whitelist and names
bounded bulk folder actions as the next target. Do not redeploy and prompt for
credential-backed WSTG after every internal slice; rerun when a relevant auth,
session, CSRF, helper or public-edge boundary changes, and against the final
release candidate. The earlier capture assessed an older host revision, so it
cannot qualify the newer search source.

Bulk work must cap selections, revalidate source/destination/UID, preserve CSRF
and throttling, and disclose partial outcomes. This date is documentary history,
not an invented commit day. Source:
[original May 16 decisions](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-05-16-treat-richer-bounded-search-as-a-whitelist-only-v3-slice).

## 2026-05-17 — Add bounded folder cleanup and prove weak-cipher refusal

Reuse the existing move boundary for selected-message folder actions, holding
one mailbox worker budget across the operation and reporting partial success.
Require explicit rejection of deliberately weak TLS offers rather than infer
policy from a successful default handshake.
Sources: [`6537ca8`](https://github.com/unattributed/OSMAP/commit/6537ca8b82a2d5284bd4410f0fc516980716d602), [`f66de03`](https://github.com/unattributed/OSMAP/commit/f66de039051c844a12fd684071455dc6bf9d6544), [`8aa88d5`](https://github.com/unattributed/OSMAP/commit/8aa88d5ae1cb2743daa4bbf144f94101c13f1b82).

## 2026-05-18 — Require a real selected-cohort rehearsal

Add a sanitized capture helper and strict release requirement for actual
password/TOTP, mail, drafts, attachments, folder and session workflows without
Roundcube fallback. Operator confirmations supply rehearsal evidence; fixtures
and report structure alone do not. Sources: [`2ae6b8b`](https://github.com/unattributed/OSMAP/commit/2ae6b8b5d3f3ea01e41d9e148c0d53c9c3e6e8c0), [`1b02a44`](https://github.com/unattributed/OSMAP/commit/1b02a44c55a83cdfa2b412a51c43f7125430f7de).

## 2026-05-19 — Make WSTG due diligence a release workstream

The original decision expands V3 beyond the existing partial WSTG pack: inventory
applicability, account isolation, sessions, webmail inputs, transport, business
logic, browser/storage and disclosure. Missing required authenticated/TOTP proof
and unexplained deferrals block V3 release. The implementation is recorded on
May 20. Source:
[original May 19 decision](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-05-19-make-v3-wstg-due-diligence-a-release-blocking-workstream).

## 2026-05-20 — Implement source-pinned WSTG coverage and command-injection checks

Create the due-diligence plan/matrix and first-party command-injection coverage;
correct release evidence paths and strengthen validation. Keep generated private
captures out of publication. Sources: [`6fd118e`](https://github.com/unattributed/OSMAP/commit/6fd118e0a51bdf2d8173f4cbb5bbae513975d07b), [`7be9948`](https://github.com/unattributed/OSMAP/commit/7be994865644ba719e5654c09c090a1e7de962b2), [`2d4bfaa`](https://github.com/unattributed/OSMAP/commit/2d4bfaa2408bc737099bfd6b77434ee90a7c5b12),
[`f25550b`](https://github.com/unattributed/OSMAP/commit/f25550b1b8cc5d71f75e051a97d5ae347e05da1c), [`b1869f1`](https://github.com/unattributed/OSMAP/commit/b1869f1ea645aa7321a5be3dfe999fd08e80d4ca), [`9b33b14`](https://github.com/unattributed/OSMAP/commit/9b33b145261a91e76cd32f5eede9ae28930a94b8).

## 2026-05-22 — Map isolation, sessions and webmail input coverage

Record source metadata and applicability dispositions, then add authorization,
account-isolation, session-lifecycle and mail-specific input-validation evidence.
Coverage is tied to actual routes and rejected probes rather than broad claims
that every OWASP category is solved. Sources: [`e20b0cb`](https://github.com/unattributed/OSMAP/commit/e20b0cb0335f36ab5738d9e2e789f262ecd3a725), [`41329c2`](https://github.com/unattributed/OSMAP/commit/41329c26ee1c3a0e2b7e0e4f7fb651dffa2b8404), [`4e0977c`](https://github.com/unattributed/OSMAP/commit/4e0977c3f92e5be118837b87f8a1c2751f16096f),
[`d1a4285`](https://github.com/unattributed/OSMAP/commit/d1a4285832c2ce44d6dabfaa58dd9a08a4a1064d).

## 2026-05-23 — Cover form transitions, transport and HTTP ambiguity

Extend WSTG evidence to form state transitions, cryptographic transport,
IMAP/SMTP-related injection applicability, raw Host/smuggling and tampering.
Keep applicability/source analysis distinct from actual dynamic execution.
Sources: [`05ef83a`](https://github.com/unattributed/OSMAP/commit/05ef83a285fd1100f81a88cbab03e5f40226396e), [`2219ca1`](https://github.com/unattributed/OSMAP/commit/2219ca18e42300424a89f6a585593fc9b5c15fe6), [`2bedc4d`](https://github.com/unattributed/OSMAP/commit/2bedc4d8084d1ea4041602693aff9e19f8e6fe4d), [`84a9224`](https://github.com/unattributed/OSMAP/commit/84a9224df366c51cd423938c0e5735fdd9274a1d), [`73008e3`](https://github.com/unattributed/OSMAP/commit/73008e3241125afd512a2ea0cebe9bfc7315c12f).

## 2026-05-27 — Add browser and information-disclosure evidence

Cover client-side behavior, error disclosure, public reconnaissance and
sensitive-file exposure. Record what is actually reachable and what remains
source/applicability review. Sources: [`8998722`](https://github.com/unattributed/OSMAP/commit/8998722cad98287e15f2e3d70c31f0c7941460c2), [`f6f95b4`](https://github.com/unattributed/OSMAP/commit/f6f95b40e5ef70205e5eecf7e11e0f4ecebe4b1a), [`3eb03a3`](https://github.com/unattributed/OSMAP/commit/3eb03a3b0492f77df96621f36c23c643b877caab),
[`d6bef55`](https://github.com/unattributed/OSMAP/commit/d6bef55a5ec443f9a8dc847c3d47f302a69ddb17).

## 2026-05-29 — Raise attachment limits within bounded resource controls

Increase compose upload limits as an explicit product change while retaining
request, command and worker budgets. Source: [`5bdbbb5`](https://github.com/unattributed/OSMAP/commit/5bdbbb516bfda5dec256e3ed25c5f705ba831c8f).

## 2026-05-30 — Finish permission and hosting-applicability review

Add WSTG evidence for file permissions/subdomains and evaluate RIA/cloud-storage
applicability against this server-rendered, operator-hosted application.
Non-applicability needs reasons, not silent omissions.
Sources: [`1e2f93e`](https://github.com/unattributed/OSMAP/commit/1e2f93ef69ccfdb373f3613b753aa7283384af5a), [`0c4368f`](https://github.com/unattributed/OSMAP/commit/0c4368fecde3c05955d1608e1182efe2e860fbcb).

## 2026-05-31 — Pin the WSTG matrix and account-lifecycle dispositions

Record the selected latest-track WSTG identifiers and evidence for implemented
identity/authentication features. Keep unsupported or manual account lifecycle
functions explicit instead of marking them tested. Sources: [`83086c2`](https://github.com/unattributed/OSMAP/commit/83086c232c156641db6bf04e09fba5cc06a1192b),
[`180f9ac`](https://github.com/unattributed/OSMAP/commit/180f9acb99427a8918baebfa2a067caea4363140), [`16de8af`](https://github.com/unattributed/OSMAP/commit/16de8af98c493e549fc5163465215284743c357c).

## 2026-06-01 — Bind WSTG release evidence to the assessed source

Stabilize credential-backed capture and tighten session-revoke, command-injection
and applicability assertions. Refresh evidence when assessed source changes;
old reports cannot qualify a new commit merely because the validator accepts
their format. Align toolchain version checking with actual stable formatting.
Sources: [`c221252`](https://github.com/unattributed/OSMAP/commit/c22125293891a79d083603facce4c713f1cbcd93), [`4e992bc`](https://github.com/unattributed/OSMAP/commit/4e992bc2dd8b0864ece467a116d52fdd425f21df), [`ca02bd4`](https://github.com/unattributed/OSMAP/commit/ca02bd4eaca5660afb108f2997f3d7c104e96be5), [`5337761`](https://github.com/unattributed/OSMAP/commit/5337761e5babfe484219b5bc962d07742e9b22f4), [`097374c`](https://github.com/unattributed/OSMAP/commit/097374cac1f6236870a100612063817a12f59966), [`78cad66`](https://github.com/unattributed/OSMAP/commit/78cad661717ae1f17f3a8df5a5125a2322ae99d2),
[`2aefef2`](https://github.com/unattributed/OSMAP/commit/2aefef21ea061440db284b22b3f7c1698e4afda8).

## 2026-06-02 — Start V4 hostile-content assurance

Expand the sanitizer corpus and add live hostile-content proof. Narrow browser
assertions to actual supported page behavior while preserving security
requirements. A fixed corpus bounds the claim; it does not establish universal
hostile-email safety. Sources: [`fcc9c0a`](https://github.com/unattributed/OSMAP/commit/fcc9c0ab1d71ece8c98409ee83300f63bf6afaa8), [`42bd239`](https://github.com/unattributed/OSMAP/commit/42bd23914a10c1f81342fa0efb3555d84fd28c96), [`7057c4f`](https://github.com/unattributed/OSMAP/commit/7057c4fb6d72afee898c898a8b9ab3bb3a3349a8), [`3a88481`](https://github.com/unattributed/OSMAP/commit/3a884816b5623fac57a001c1a189b21eff93c57b).

## 2026-06-11 — Make V4 deployment and evidence dependencies explicit

Assemble hostile-content/MIME ambiguity evidence, consistency guard and operator
handoff. Place daemon logs under `/var/log/osmap`, require the actual service
grant keys and keep protected environment files readable by their intended
runtime groups. These are working service prerequisites, not optional prose.
Sources: [`a3f6e98`](https://github.com/unattributed/OSMAP/commit/a3f6e984f8f1152a9fb20e63af488a6405c50474), [`09a95b7`](https://github.com/unattributed/OSMAP/commit/09a95b7f4e9744a20bcd85430e4f0428cafeebe7), [`987f8c3`](https://github.com/unattributed/OSMAP/commit/987f8c3236318e9c28c09fc15853eb129bf3e0b5), [`59da020`](https://github.com/unattributed/OSMAP/commit/59da020a6f7d04535515cf7d5c3b26b4f3496ec8), [`15f19f9`](https://github.com/unattributed/OSMAP/commit/15f19f98f7761da6269429d98883e15de95bbec8), [`516c025`](https://github.com/unattributed/OSMAP/commit/516c02558c7a5c12fbb3026df570042e3983d49f),
[`6d42d2a`](https://github.com/unattributed/OSMAP/commit/6d42d2a3fe999b778a16e2b7e8be172c6bcad292), [`8b18644`](https://github.com/unattributed/OSMAP/commit/8b18644f96c56662e5ed7d7af204cc1f9a436568).

## 2026-06-12 — Require route-backed hostile-content observations

Integrate the fixed V4 corpus and its archive into release checks, keep developer
runs temporary, and add route-backed observations. Emit UTC RFC3339 timestamps
and harden edge logging for correlation. Restore chronological log structure;
later append drift is repaired by the November 14 rewrite.
Sources: [`517061a`](https://github.com/unattributed/OSMAP/commit/517061a307bcc6c2cbaa83f6ddc09d73960cdb93), [`6f6fdfb`](https://github.com/unattributed/OSMAP/commit/6f6fdfb927e492efe9018c46341d4b5fa81e06d9), [`b9d48ab`](https://github.com/unattributed/OSMAP/commit/b9d48abda43c1bf09b27ec9e320cab13f2b31f87), [`9a12f08`](https://github.com/unattributed/OSMAP/commit/9a12f08b249e15e4a3f5be58b4e5a9c2e09851e6), [`e3ed7b8`](https://github.com/unattributed/OSMAP/commit/e3ed7b8627f9c74726444e9ce6d082ec0c6e0863),
[`492347e`](https://github.com/unattributed/OSMAP/commit/492347e246999fe8bb93f40ea452dd8c123740bf), [`f559a09`](https://github.com/unattributed/OSMAP/commit/f559a096386ebdd89959b4cb74da3709531a8769).

## 2026-06-13 — Gate security claims and reproduce the V4 release tuple

Strengthen hostile-content gates, source/toolchain reproduction and the claim
matrix. Add CWE weak-pattern checks and remove literal credential-like test
fixtures. Preserve the exact assessed source/configuration/evidence tuple;
review posture is not full WSTG/ASVS certification.
Sources: [`24a44f2`](https://github.com/unattributed/OSMAP/commit/24a44f26299f1df17da4999268a561adca4dd4b7), [`27c0acd`](https://github.com/unattributed/OSMAP/commit/27c0acd2de8cc6e09b8250ed27f829b2980a8b41), [`4074d35`](https://github.com/unattributed/OSMAP/commit/4074d3599641f25143ed75699ca92f0dfc02003a), [`405f1bf`](https://github.com/unattributed/OSMAP/commit/405f1bff9c9232de13a6d89cf2677237cdb8c611), [`d1fd3eb`](https://github.com/unattributed/OSMAP/commit/d1fd3ebd31034aeb315c71d1a2f65fdb751ce122), [`c0abbb3`](https://github.com/unattributed/OSMAP/commit/c0abbb3b77eede109e86d91e6ede15bc10e38326),
[`c0c8cab`](https://github.com/unattributed/OSMAP/commit/c0c8cabb6dd08af78731202f0f9ebea6b29e86ea), [`1a70220`](https://github.com/unattributed/OSMAP/commit/1a70220364c4e90234066bb3a960972c5fce8e02).

## 2026-06-14 — Harden identity, Host and response boundaries in V5

Validate canonical mail identities and loaded session identities; centralize
response-header validation and security headers on text/error responses. Enforce
configured Host/Origin policy independently of proxy routing and document strict
framing rejection. Retain publication-safe fixtures and the scoped V5 production
deployment record. Typed HTML wrappers are initially deferred following review;
they are completed on June 18. Sources: [`419ab8c`](https://github.com/unattributed/OSMAP/commit/419ab8c7503bd30b4fe43b0111f7c30d3ad441e6), [`7cc44e3`](https://github.com/unattributed/OSMAP/commit/7cc44e3b414dbf77446d6f2f7a233e75c6273b6b), [`49bd569`](https://github.com/unattributed/OSMAP/commit/49bd5690d0518f96671f54c7280f920c4d2f20c7),
[`a74699b`](https://github.com/unattributed/OSMAP/commit/a74699b0ee705041825b56d51dabca5f899fbd0f), [`1358ef1`](https://github.com/unattributed/OSMAP/commit/1358ef11222c543b8109ab3e6eacbc6af0a9073f), [`b9f840a`](https://github.com/unattributed/OSMAP/commit/b9f840adfa85fc9f12d93ad931388fa065f89b61), [`2612b75`](https://github.com/unattributed/OSMAP/commit/2612b754e334810438443f68b81d3bc5354f1acb), [`927516f`](https://github.com/unattributed/OSMAP/commit/927516f77dd7a92e199ced8f5f90fe894e584a48), [`4961d09`](https://github.com/unattributed/OSMAP/commit/4961d099dc09b53e1792a5992d652fd43cc98b93).

## 2026-06-18 — Complete typed rendering and controlled retirement readiness

Finish the deferred trusted-HTML type boundary. Define V6 around selected-cohort
retirement readiness with binary/environment rollback pairs, no-fallback
rehearsal, observability and resilience proof. Add cross-process session locking
and preserve explicit source attachments through drafts.

V7 hardening follows measured boundaries, including file-backed throttle
transactions. Historical V6 retirement terminology describes that earlier
migration milestone; it is not a requirement to reintroduce Roundcube later.
Sources: [`93de442`](https://github.com/unattributed/OSMAP/commit/93de442c0615a186d6487f29fc606c005c3844be), [`a1db775`](https://github.com/unattributed/OSMAP/commit/a1db775eea482896480fec4e4ce05c49a4123528), [`bb941d9`](https://github.com/unattributed/OSMAP/commit/bb941d99d4a765178d1cef3851cffb9a79fbff53), [`c7a4099`](https://github.com/unattributed/OSMAP/commit/c7a4099f4175c4709099d49cb1e5e5a349545d3f), [`d818584`](https://github.com/unattributed/OSMAP/commit/d818584cfcbac399777ef43bba12e8b191facd0b), [`d064c1b`](https://github.com/unattributed/OSMAP/commit/d064c1bd6801ecaf215798c7e2c8b7200dcfee17),
[`f6776af`](https://github.com/unattributed/OSMAP/commit/f6776af33590bce480a76ad89a79a7be9e260a42), [`657e12c`](https://github.com/unattributed/OSMAP/commit/657e12c38c545da4e1170dec7911d02490ce0ed6), [`81f41c9`](https://github.com/unattributed/OSMAP/commit/81f41c9ea3248b048c067fcc02d3cb9d46fa6db4), [`ffd475a`](https://github.com/unattributed/OSMAP/commit/ffd475ae5e48a03cd8c2e12917c84d494897ab7f), [`49e436e`](https://github.com/unattributed/OSMAP/commit/49e436e93e217260c63db4577d3ce510995fb582), [`c9a6e93`](https://github.com/unattributed/OSMAP/commit/c9a6e93ee8fef66503607056548d2f241e0aea0e).

## 2026-06-19 — Treat login availability and bounded rendering as invariants

The decision record reopens V7 to retain the authentication-availability gap and
throttle race rather than bury it in prior closeout wording. Raise the bounded
message-view envelope for legitimate mail while preserving resource controls;
subsequent V9 work owns production convergence. Sources: [`025d1e5`](https://github.com/unattributed/OSMAP/commit/025d1e5fa7210acd87ce9b06ea9fda2307a4e192);
[original V7 availability decision](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-06-19-reopen-v7-and-make-login-availability-a-release-invariant).

## 2026-06-20 — Stabilize mail workflows and file accepted submissions in Sent

Support Windows-1252 HTML within the existing safe rendering model and restore
rendering regression coverage. Establish V8 workflow, attachment, mailbox,
session, resource and final-regression matrices. Store accepted outgoing mail
in Sent, separating transport acceptance from successful copy storage.
Sources: [`e638e08`](https://github.com/unattributed/OSMAP/commit/e638e081d167c3b3ba40fcf3d50c3bb2fc5fd349), [`cf878ed`](https://github.com/unattributed/OSMAP/commit/cf878ed6e98975d168f75fac335e16d372c43922), [`ed993d7`](https://github.com/unattributed/OSMAP/commit/ed993d799e41828b7f64e2590676e1e4c27ff501), [`a549ae8`](https://github.com/unattributed/OSMAP/commit/a549ae813db9c3dc4eeee0271874544be9b803d6), [`297460b`](https://github.com/unattributed/OSMAP/commit/297460b6980d27a78322d388e77db5e65111e299), [`8a4f39d`](https://github.com/unattributed/OSMAP/commit/8a4f39db9a0afd2445f084def3a11d43755eb01a),
[`1f69ceb`](https://github.com/unattributed/OSMAP/commit/1f69ceb3afbd6d2d439d01983f2194602384fd19), [`ebbe5b0`](https://github.com/unattributed/OSMAP/commit/ebbe5b035809585dbdffa9cc48a845f9c3b4c7e0), [`ac2dfdd`](https://github.com/unattributed/OSMAP/commit/ac2dfdd856011ec99a5238079f9eda8073577d83), [`f8eed70`](https://github.com/unattributed/OSMAP/commit/f8eed70a3e3833254b149193dcccf6429e8e4d1a).

## 2026-06-22 — Close concurrency and persistence races before production convergence

Consume accepted TOTP counters once, bound helper concurrency, make draft
persistence transactional, cap multipart part headers and create private state
with restrictive modes immediately. Bound forwarded bodies and align supply-chain
bootstrap behavior. Start V9 production convergence while keeping source passes
separate from deployed evidence. Sources: [`7f54d76`](https://github.com/unattributed/OSMAP/commit/7f54d7685575b23c6b769bb47b52078f4395d85a), [`fc3f416`](https://github.com/unattributed/OSMAP/commit/fc3f416e34d08b3c8a0eb3f9dd53c572e53b9f7c), [`b49407d`](https://github.com/unattributed/OSMAP/commit/b49407d57504cc5358565da04cc498265c4c6855),
[`46152b3`](https://github.com/unattributed/OSMAP/commit/46152b3c9911f13eb35586aa4de73efad4b9f654), [`27595c5`](https://github.com/unattributed/OSMAP/commit/27595c5bd7401149355d9d379617bef61477050f), [`bec77b5`](https://github.com/unattributed/OSMAP/commit/bec77b5057f8c7619a6f0353db17d47b73162e46), [`49c9f23`](https://github.com/unattributed/OSMAP/commit/49c9f230d7865f01deadbc6a5a0f6e876c63e89b);
[V9 record](V9_RELEASE_CANDIDATE_CLOSEOUT.md).

## 2026-06-23 — Reconcile V9 production-convergence claims

Update the documentation to reflect observed deployment and remaining work,
preserving the earlier source/runtime distinction. Source: [`fcf3605`](https://github.com/unattributed/OSMAP/commit/fcf360587daeda57f2de515ef8f85fc69d016f4e).

## 2026-06-24 — Record V7 availability and V9 release-candidate closeout

Publish the production-availability evidence and V9 release-candidate decision,
then reconcile the current documentation. These are bounded historical release
records, not qualification of later UX or host migrations.
Sources: [`a8915c0`](https://github.com/unattributed/OSMAP/commit/a8915c0993b96a9d53de083dc84cb7520aef0097), [`82f2b21`](https://github.com/unattributed/OSMAP/commit/82f2b212ffac476695d33acaac51eaadfa0fa1aa), [`571ec8f`](https://github.com/unattributed/OSMAP/commit/571ec8fba3dd3d9306e00101c775b96eaeca3123).

## 2026-06-25 — Audit fail-closed assumptions and add CC/BCC routing

Start V10 governance from observed source claims; inventory Rust assumptions,
remediate demonstrated fail-open paths and gate their dispositions. Carry the
runtime work into V11 while adding CC/BCC envelope routing through existing
submission authority. Sources: [`ec72b6f`](https://github.com/unattributed/OSMAP/commit/ec72b6f55687b716c0d21bdd4f44480b99ae5163), [`9d34ea5`](https://github.com/unattributed/OSMAP/commit/9d34ea5a754dd475d4b54825aeadbf71e31c1d03), [`318d698`](https://github.com/unattributed/OSMAP/commit/318d6983719fceb15a49f35451cdba144d30d08e), [`0e9b92c`](https://github.com/unattributed/OSMAP/commit/0e9b92c717ca553d16bd83eec6bf09f7a5e804cd),
[`e91758b`](https://github.com/unattributed/OSMAP/commit/e91758b8f8a769052c3168cdbd1dfc795cbc31c7), [`98ea0a8`](https://github.com/unattributed/OSMAP/commit/98ea0a8cede4bbfc5929635e12c3f2011279203b), [`5fb6d89`](https://github.com/unattributed/OSMAP/commit/5fb6d892cc708d0339e434718902061c9cf17441), [`99c3ffa`](https://github.com/unattributed/OSMAP/commit/99c3ffa9b8b1a4ef560993cca71a36f7b6d40457).

## 2026-06-26 — Publish V11 runtime fail-closed closure

Merge the bounded V11 closure. This milestone concerns the audited runtime
failure paths and does not qualify later OpenPGP or complete application
security. Source: [`9c9820c`](https://github.com/unattributed/OSMAP/commit/9c9820c85cdc5941a88cffd7abbad9690fc244c9).

## 2026-06-27 — Separate OpenPGP foundations from credentialed assurance

Complete V12's typed protocol, account-bound policy and fail-closed OpenPGP
foundation while documenting capability limits. Close the recorded V13
credential-backed WSTG/integrity/adversarial and operational evidence gaps.
Separate authentication dependency deadlines from heavier mailbox work to
preserve login availability. Refresh source-bound release records rather than
reuse stale commit claims. Sources: [`6d660c5`](https://github.com/unattributed/OSMAP/commit/6d660c524a7525ba6e18be9ab4a493cea5c6d665), [`1508f0c`](https://github.com/unattributed/OSMAP/commit/1508f0c97b613e58e9573d2ca8bd93f55cd1eaa3), [`ecaab69`](https://github.com/unattributed/OSMAP/commit/ecaab698f01971544603718d0bda8ab248eae7ca),
[`a5dc971`](https://github.com/unattributed/OSMAP/commit/a5dc97170bc31197d736bbf74058edab24251e1d), [`7009b15`](https://github.com/unattributed/OSMAP/commit/7009b15322c4e7795c797c1387b403e0f4935adb), [`a80b28b`](https://github.com/unattributed/OSMAP/commit/a80b28b146ce6ee10428a8ef589b3e9949e0be0a), [`b96e98e`](https://github.com/unattributed/OSMAP/commit/b96e98e059b71e531609304e7ec8b57fcaed407b), [`ccdb296`](https://github.com/unattributed/OSMAP/commit/ccdb2966b57514772b106b293f332186a1854506).

## 2026-06-28 — Modernize the server-rendered UI without activating crypto

**V14 Streamline WebUI and OpenPGP UX integration.** Define the shared
CSS/icons, authenticated shell, message list and reader trust
strip. Present truthful OpenPGP states using the existing backend facts. Keep
UI modernization separate from runtime decrypt/sign/encrypt activation.
Sources: [`33a85f4`](https://github.com/unattributed/OSMAP/commit/33a85f49cee74aa75a57f9e4ba58ae0ecf429259), [`79be5db`](https://github.com/unattributed/OSMAP/commit/79be5db1dc6f5bbc8e8589dfd723862fef78198e), [`50d9409`](https://github.com/unattributed/OSMAP/commit/50d9409f00f333551cda437aab260962332548e7), [`5ffaa45`](https://github.com/unattributed/OSMAP/commit/5ffaa459080b658485d7edf3a2406515ad527acd), [`191fd80`](https://github.com/unattributed/OSMAP/commit/191fd8089b2c38e0bb9972ecca1abe466c8d1396).

## 2026-06-29 — Close V14 UI and accessibility within its stated scope

Add reader, compose and account OpenPGP controls; require the no-JavaScript,
low-dependency posture and responsive/accessibility regressions. Record final
bounded V14 proof without claiming runtime cryptography or broader release
readiness. Sources: [`b09fcb0`](https://github.com/unattributed/OSMAP/commit/b09fcb006ed36707c9368cf24cb8f50a709119e2), [`4ec92af`](https://github.com/unattributed/OSMAP/commit/4ec92af1aa8e46ae6891bf10842d17bf296a4193), [`b3bcd79`](https://github.com/unattributed/OSMAP/commit/b3bcd79dc53b440d8f74d54c0e36c3174c04fbd9), [`b208d4a`](https://github.com/unattributed/OSMAP/commit/b208d4ac453736426cf86ceb82a4cbd7fd5abff3), [`a109f7a`](https://github.com/unattributed/OSMAP/commit/a109f7af48def9585901ac1fdb68697f20db51dd),
[`890666a`](https://github.com/unattributed/OSMAP/commit/890666a8e1dfd82db451b668cd8bfac9023b62fa).

## 2026-07-28 — Tighten dependency and HTTP field admission

Update the sanitizer, protect worktree hooks and apply risk-based dependency
admission. Reject ambiguous HTTP field names before routing. Add a reviewed
Debian development bootstrap while preserving OpenBSD as the production target.
Sources: [`2a7c8d3`](https://github.com/unattributed/OSMAP/commit/2a7c8d39b4d649c8512d8142161c0fe041f58eb2), [`6c38927`](https://github.com/unattributed/OSMAP/commit/6c389278c86451b9276023e3e91af588ab0ca0df), [`42e7375`](https://github.com/unattributed/OSMAP/commit/42e737588fb9c06b5bf53fe0369c7e4a92e14c4a), [`742e7de`](https://github.com/unattributed/OSMAP/commit/742e7de7ecbe4f93bf86eac019f9458b879a18eb).

## 2026-07-29 — Compare edge and origin behavior directly

Add the V15 edge/origin differential harness and fix remote Python quoting so
the intended probes execute. Stabilize untrusted-helper-peer rejection without
changing the production peer boundary. Sources: [`2b833e2`](https://github.com/unattributed/OSMAP/commit/2b833e2de3e8af5bf57aee922e6b3871c1174d95), [`f92ba3e`](https://github.com/unattributed/OSMAP/commit/f92ba3e75058fad167155a616c3442dc1fa62f5e), [`abb88e2`](https://github.com/unattributed/OSMAP/commit/abb88e20f8e8f82099aafef4695c01072bb28f22).

## 2026-07-30 — Reject ambiguous request lines and retain bounded proof

Harden HTTP request-line parsing and record the corresponding V15 slice result.
Parser refusal is measured against the fixed corpus rather than inferred from
nginx alone. Sources: [`315534f`](https://github.com/unattributed/OSMAP/commit/315534ff915f4ae3e5ba8a5778060891ccefec07), [`e44d8bc`](https://github.com/unattributed/OSMAP/commit/e44d8bc13b9fb0b992a92c73dc5c62d68899bc84).

## 2026-08-16 — Close the bounded V15 HTTP differential corpus

Finalize policy classifications and close the recorded 37-case offline/live
corpus without policy/cardinality failures. Reconcile assumption inventories
and public README claims. This evidence addresses the tested parser/proxy shapes,
not every HTTP attack or future source revision.
Sources: [`158f61d`](https://github.com/unattributed/OSMAP/commit/158f61d3735712faac019cae97f7ef3e26787973), [`6e28ae4`](https://github.com/unattributed/OSMAP/commit/6e28ae4ed8b83584ba5df1e522e17b358e5e8ebd), [`ef2be70`](https://github.com/unattributed/OSMAP/commit/ef2be701a8c18e31befbf6f6e368e7a0a3a24a41), [`9d7e605`](https://github.com/unattributed/OSMAP/commit/9d7e6057982a52c75aaaa3835a59690cd4b3cac6), [`8c70fe5`](https://github.com/unattributed/OSMAP/commit/8c70fe5cf7e09d9dada367b65714b8d7a46a7db6);
[V15 assurance](V15_HTTP_DIFFERENTIAL_ASSURANCE.md).

## 2026-08-27 — Standardize signed delivery and passwordless Git transport

Require Shopkeeper-signed source review/delivery, retain signature verification,
and use the workstation's configured agent/passwordless GitHub SSH. Do not
retrieve or expose a key passphrase to automate Git. Later operator direction
removes redundant push-approval pauses while preserving signatures and hooks.
Sources: [`b03a150`](https://github.com/unattributed/OSMAP/commit/b03a15067e107c4c53b88e4400ae9b284a3fe03b), [`f44c610`](https://github.com/unattributed/OSMAP/commit/f44c610d9f78b22cfef2495ee7be04c24e2a1901).

## 2026-09-02 — Normalize the reviewed stable toolchain version

Correct stable rustfmt release-version handling in the gate rather than create
an accidental formatter incompatibility requirement. Source: [`b46c43d`](https://github.com/unattributed/OSMAP/commit/b46c43d9ad21f7a026ad3e7be097ce546a7fc2e0).

## 2026-09-03 — Keep retained sprint artifacts under one private root

Adopt sprint-specific delivery/evidence directories and portable basename-only
SHA-256 sidecars. Preserve unrelated Downloads contents. Synchronize the accepted
source and SOP; storage layout is evidence custody, not product qualification.
Sources: [`c6ee726`](https://github.com/unattributed/OSMAP/commit/c6ee726463c2d9554a982413abfb65fb26f3ff7f), [`f3366e6`](https://github.com/unattributed/OSMAP/commit/f3366e63e77423046ba2875baeb977ceb630f745).

## 2026-09-08 — Add governed TOTP provisioning and revocation

Provide interim operator provisioning and bounded revocation through existing
account/session boundaries. Treat factor administration as privileged lifecycle
work rather than an ordinary browser setting, and keep temporary secrets out of
retained public evidence. Sources: [`0f76a72`](https://github.com/unattributed/OSMAP/commit/0f76a72a0ac4921f4950e56a47f2163a2dfd0450), [`d8deaab`](https://github.com/unattributed/OSMAP/commit/d8deaaba60c61efc6754ff8ce95f94e9a7a3cf99), [`beab168`](https://github.com/unattributed/OSMAP/commit/beab168d2b0e04c7885e514a58eaedd090255862);
[TOTP lifecycle sprint](TOTP_LIFECYCLE_SPRINT.md).

## 2026-09-14 — Add rotation and recovery with explicit host scope

Implement governed authenticator rotation and recovery. Lost-authenticator
recovery requires independent human identity/private-terminal attestations;
synthetic native checks do not replace those decisions or live acceptance.
Distinguish the migrated authoritative host from historical on-premises evidence;
use obsd1 only for the operator-selected lifecycle sprint. Sources: [`77dc836`](https://github.com/unattributed/OSMAP/commit/77dc836b7b8da27ca5c98bf5d7bd25315411227c),
[`cdb8c29`](https://github.com/unattributed/OSMAP/commit/cdb8c29cff9b33a1749f406251a4e893e9e89631), [`691b960`](https://github.com/unattributed/OSMAP/commit/691b9606694080e67e3aa060b449dd510254f230).

## 2026-09-15 — Close the lifecycle sprint with residuals and plan full UX

Record bounded recovery rehearsal and administrative sprint closure with real
cleanup/recovery residuals still visible. Separate controlled test custody from
real-user MFA recovery; do not replay expired or consumed approvals. Plan the
full-functional UX/OpenPGP epic and record the emergency host alias distinction.
Isolate build caches per checkout to avoid cross-worktree gate interference.
Sources: [`87a10da`](https://github.com/unattributed/OSMAP/commit/87a10dad103d565f65f09edca850945d5e0ce551), [`b97d65c`](https://github.com/unattributed/OSMAP/commit/b97d65c0f03c695ae11dbfe029d1926027f54409), [`74522e5`](https://github.com/unattributed/OSMAP/commit/74522e5f99024720a3c47a3744207ff453de5731), [`afadac2`](https://github.com/unattributed/OSMAP/commit/afadac2f8cda24e9bf4b126823771829a842f8bd), [`2d7f264`](https://github.com/unattributed/OSMAP/commit/2d7f264f2dc965c7d52768565094a4bc9ed5b443).

## 2026-09-23 — Repair the OpenBSD Cargo target regression

Correct native test syntax without treating that source repair as installed
qualification or a new platform restriction. Source: [`2a6993f`](https://github.com/unattributed/OSMAP/commit/2a6993fe7df42a57f0cbb5fe3e33e331b400fef9).

## 2026-09-29 — Start the approved full-functional UX implementation

Pin reference designs and the revision-two acceptance map before implementing
the shared shell, persisted account light/dark/system theme, navigation, accessible
rows, filters, pagination and bounded global search. Bind read/star/move and bulk
actions to fresh account/message identity. Preserve reader navigation, source
escaping, reply threading and approved sender context. Native-host, deployed and
owner acceptance remain separate from synthetic route/browser proof.
Sources: [`167ab90`](https://github.com/unattributed/OSMAP/commit/167ab909fef11fa8af3959840565d2377ac53ac4), [`1866f6b`](https://github.com/unattributed/OSMAP/commit/1866f6b653b0a1d2419859657ed14f273729d963), [`53d3655`](https://github.com/unattributed/OSMAP/commit/53d3655d79b13aafe8bfbd9b4edabc1afb2f608f), [`85e1701`](https://github.com/unattributed/OSMAP/commit/85e17015ed1d4f93fae3842bfaa08c9db7d32329), [`46c9d6b`](https://github.com/unattributed/OSMAP/commit/46c9d6bc42bb3a3b27ee67e80ed5b2d2b30032a2), [`8161dd8`](https://github.com/unattributed/OSMAP/commit/8161dd8d21f0951a2a35faa4704c3820610d7952),
[`c1a9f9e`](https://github.com/unattributed/OSMAP/commit/c1a9f9eb97177227ce07d7209fa9b0606014f9e5), [`8d3211a`](https://github.com/unattributed/OSMAP/commit/8d3211a33d062b88364acb7ea9eaa11f848ed565), [`f2b2665`](https://github.com/unattributed/OSMAP/commit/f2b2665fd0a93fb24f023e98986ace9fe5bcc7b5), [`61bfb09`](https://github.com/unattributed/OSMAP/commit/61bfb092b0da75eb98b1b1867accf603c2d57732), [`bf20f08`](https://github.com/unattributed/OSMAP/commit/bf20f08a77cec24420e7dedcd982260368f26a78), [`6b3ce8f`](https://github.com/unattributed/OSMAP/commit/6b3ce8fff27ca3dabf87039d54098bd9967a2e42);
[epic](UX_FULL_FUNCTIONAL_EPIC.md), [UX decisions](UX_DECISIONS.md).

## 2026-09-30 — Build durable authoring and account-owned mail controls

Add private contacts and the approved composer/settings surfaces. Persist draft
revisions, attachment cards and removal, reject stale authoring changes, and
preserve text through interrupted saves or changed source attachments. Introduce
truthful send attempts, authorized identities/signatures, preferences, labels,
snooze, notifications, archive navigation and verified folder hierarchy/private
subfolder creation. Implementation of visible controls does not establish the
complete journeys later audited in October.
Sources: [`dfe6ba8`](https://github.com/unattributed/OSMAP/commit/dfe6ba8ffb92b6a31f9bf316d6a06732f2f48673), [`0985f26`](https://github.com/unattributed/OSMAP/commit/0985f26a6092c355529dcb2fdcc16a8634345036), [`ef97e61`](https://github.com/unattributed/OSMAP/commit/ef97e61e6e1d5b7b5a067df32748ed736df4c51a), [`8f386c2`](https://github.com/unattributed/OSMAP/commit/8f386c2d39d5fbde1c151dbeeae53a37847e9f68), [`d3abe67`](https://github.com/unattributed/OSMAP/commit/d3abe6791e67a6f1f4de978539f857654621bf6c), [`422f058`](https://github.com/unattributed/OSMAP/commit/422f058e2fedf3768be4a6f1e7c115e640efbc40),
[`86e50e2`](https://github.com/unattributed/OSMAP/commit/86e50e2db1a87c35806b60373b5e75a488618bf9), [`8f91944`](https://github.com/unattributed/OSMAP/commit/8f91944f9b1ac0d85c5156beea8566997713e532), [`ab09031`](https://github.com/unattributed/OSMAP/commit/ab090312bf6fbdbccd4dcd687d70f26b4ff9ddf9), [`02b9653`](https://github.com/unattributed/OSMAP/commit/02b9653485fcaddf69db8ea694209d18589e10fa), [`7485ace`](https://github.com/unattributed/OSMAP/commit/7485aceac1495740d95d194f46c37922d4acc285), [`f70d74c`](https://github.com/unattributed/OSMAP/commit/f70d74cd3c6937f23b2e9f17036b395f1855865e).

## 2026-10-01 — Connect native OpenPGP to account-owned browser workflows

Use the existing GPGME engine and typed Rust/helper boundaries for public
inventory, protected reading and exact prepared-byte outbound policy. Support
reviewed installed curves/integrity modes; keep workstation signing separate
from mailbox key custody. Introduce a distinct authenticated public-key
administration helper and activate only the qualified obsd1 scope.

Repair confinement/key clients, confirmation and service supervision through
actual native observations. Public-key UI activation is not private-key unlock,
arbitrary correspondent authority or complete encrypted-mail acceptance.
Sources: [`edfb2f0`](https://github.com/unattributed/OSMAP/commit/edfb2f03466976390bd4aaaa6d6ab8d985334852), [`ab4c11f`](https://github.com/unattributed/OSMAP/commit/ab4c11fbfe81fc279212d0a98c2e207cab5db67c), [`a03467d`](https://github.com/unattributed/OSMAP/commit/a03467da04c32f3b9d2a8a55d4b5c0398e7824d3), [`3cb6c8a`](https://github.com/unattributed/OSMAP/commit/3cb6c8adcac8aec2eac81a300dbc54ebfd3dfd87), [`ab405ce`](https://github.com/unattributed/OSMAP/commit/ab405ce95ba57d7826e8a639156d5746756d4ec3), [`73e630e`](https://github.com/unattributed/OSMAP/commit/73e630e151d6ad8834c4b0d50022a6334f4f65b7).

## 2026-10-02 — Keep the production mail host authoritative and make protected-send refusal usable

Connect obsd1's UX to the authoritative production mail backend through the reviewed
restricted bridge, rather than synchronize independent local mailbox contents.
Repair late-start helper recovery, mailbox Pinentry and form navigation.
Persist compose protection choices/defaults and allow explicit current-key
review of stale drafts. Resolve self recipients only through approved account
keys; explain policy refusal without silently weakening protection.

Recorded native/binding and scoped live outcomes do not close unresolved
protected-send acceptance. Sources: [`efb8a88`](https://github.com/unattributed/OSMAP/commit/efb8a88d344d902df3c829666e40d6796b93354f), [`959dba7`](https://github.com/unattributed/OSMAP/commit/959dba700ee8494b9e628341edbadcaf11bc30f3), [`2eb46f0`](https://github.com/unattributed/OSMAP/commit/2eb46f0a4987027c7d56f091a4766abf7e2be938),
[`beb374f`](https://github.com/unattributed/OSMAP/commit/beb374f46181556569b172e8f7dac2a9aacbc515), [`360df32`](https://github.com/unattributed/OSMAP/commit/360df3216510a520a78962867fad64c5e17a8838), [`12699ff`](https://github.com/unattributed/OSMAP/commit/12699ff5529ff24eff60858be84cee28ab273e96), [`0038811`](https://github.com/unattributed/OSMAP/commit/0038811926cbd7eef3fa3feff91879a16c43e5b9), [`f746c2d`](https://github.com/unattributed/OSMAP/commit/f746c2d3e8ae9ad0880e62cdeaa76aafea7d6daf), [`fa2ebeb`](https://github.com/unattributed/OSMAP/commit/fa2ebeb69275e978612bd90c50e48fcd6ff7feff), [`9032cf0`](https://github.com/unattributed/OSMAP/commit/9032cf01d0db6722746afa4c439973b76be16d79).

## 2026-10-03 — Deliver real mail journeys and test Runtime delegation

Adopt the functional delivery framework: a rendered page, fixture or build is
not a completed frontend/backend/persistence journey. Reconcile identities,
finite stores, deployment authority and actionable R2 acceptance cases.

Repair appearance lock lifetime and persistent themes; connect the security
view to actual keys and improve protected-send guidance. Fix cross-folder search
with an authenticated batch helper and whole-operation deadline. Preserve exact
filter/order/focus through reader navigation, apply saved mark-read/display
choices and implement bounded conversations. Make Bin preference, reversible
bulk operations, confirmed deletion and archive dates real backend behaviors.
Native/backend proof stays separate from the browser Runtime composition.
Sources: [`6706f4f`](https://github.com/unattributed/OSMAP/commit/6706f4f024f5575c4f86afaf9ad8d9b8e8e42e8b), [`cacde9e`](https://github.com/unattributed/OSMAP/commit/cacde9ecfe636774faa12539cff926619109ee30), [`dfd5d08`](https://github.com/unattributed/OSMAP/commit/dfd5d08d22c3aa83ccf7f613e8986947fd8de559), [`ad26980`](https://github.com/unattributed/OSMAP/commit/ad2698010d9b318d6459881da6c35791972af6e9), [`3217db6`](https://github.com/unattributed/OSMAP/commit/3217db6eb332a6e2974afed8b7598dc4fdf709c0), [`1b0d435`](https://github.com/unattributed/OSMAP/commit/1b0d43503576f04570afa86d3b38e93a28e62cfd),
[`364381e`](https://github.com/unattributed/OSMAP/commit/364381ea5ccf70e0e206bafb39935b8f9b37c397), [`ff39151`](https://github.com/unattributed/OSMAP/commit/ff39151b20ee6613a651d852e331fdc9d1e563f9), [`e2ecd0f`](https://github.com/unattributed/OSMAP/commit/e2ecd0f81a51a6e2d51099b3e48fa86950f91f67), [`8a97de2`](https://github.com/unattributed/OSMAP/commit/8a97de228fa1d8d06b39ba8c864733c77fbebb13), [`976ae33`](https://github.com/unattributed/OSMAP/commit/976ae3399af0e7d21a748d130077767fbe17981a), [`103b466`](https://github.com/unattributed/OSMAP/commit/103b466a756a889d013a8109e2ace30549a629a7),
[`917119e`](https://github.com/unattributed/OSMAP/commit/917119ecd1690553e7df149abb7a72454445f763), [`656351b`](https://github.com/unattributed/OSMAP/commit/656351b1e88f6e11b92c6da42967e8cd03b65d3d), [`a789c31`](https://github.com/unattributed/OSMAP/commit/a789c315fd06d8b0ac8dab4dd37e6ce3b1f61930).

## 2026-10-04 — Qualify submission, Sent and Drafts before password activation

Preserve all-search reader context and exact message identity on Retry. Exercise
ordinary/reply/forward/formatted submission and exact native Sent MIME through
the actual route; distinguish accepted transport from failed Sent storage and
retain a recovery outcome rather than replay a send.

Implement saved Save Sent choice, owned Sent/Drafts destinations, captured sender
authority and autosave with final-artifact/native checks. Notification digest
preferences cannot suppress security events. Begin own-password authorization
and supervised mutation prerequisites with the UI disabled: carry one original
preparation deadline, guarded issuer/epoch and owned transport/cleanup authority.
Startup and component progress do not enable installed password change.
Sources: [`f960bdd`](https://github.com/unattributed/OSMAP/commit/f960bdd71b61d7eb22c7fe7be7e0d42148d4600f), [`4e6ed08`](https://github.com/unattributed/OSMAP/commit/4e6ed0816ed856063f1abe71e414b20b8bb03974), [`362b37c`](https://github.com/unattributed/OSMAP/commit/362b37cbb97851cb05bd500cae44e4a2aa0bf46f), [`21580d4`](https://github.com/unattributed/OSMAP/commit/21580d49a329ed74b28b5cf9651b9e1a1fed13c0), [`d4700c9`](https://github.com/unattributed/OSMAP/commit/d4700c9be1b9a8ac25970985b2b08a9b23fd6989), [`373c72f`](https://github.com/unattributed/OSMAP/commit/373c72f29abda99af93dfcf3f7d906e27e47c4f5),
[`427757f`](https://github.com/unattributed/OSMAP/commit/427757f24f9bef967f0e58d8a0998cbeb8eb32f9), [`6f54991`](https://github.com/unattributed/OSMAP/commit/6f549911e66a40fabb964317e0efe8e8d80cd623), [`f20f1ed`](https://github.com/unattributed/OSMAP/commit/f20f1eda5aae8f1794749d6c23011f48fdd3a277), [`c9ddc50`](https://github.com/unattributed/OSMAP/commit/c9ddc5020e410103d4040259a254adfc24cd0353), [`6390a40`](https://github.com/unattributed/OSMAP/commit/6390a40dbaccdc205de0e58531af90aaee7dfe7d), [`7ae4623`](https://github.com/unattributed/OSMAP/commit/7ae4623e2b01c4293fc4c55ef9f2b3d31b6ec9bb),
[`60ddb22`](https://github.com/unattributed/OSMAP/commit/60ddb2223fae2465fb57873041d85bc38833cb9a), [`8126da2`](https://github.com/unattributed/OSMAP/commit/8126da2f7afdf83d6cf8db91719f5e4c03f414ac), [`2802eb2`](https://github.com/unattributed/OSMAP/commit/2802eb2d1f20ef7bfb1a5cb8b87c22f0dd1f4673), [`13a493f`](https://github.com/unattributed/OSMAP/commit/13a493f5b572e50482e3f45402239fd35819882d), [`cb6fbe5`](https://github.com/unattributed/OSMAP/commit/cb6fbe5baa598cf40d32a0721a97d2f39a236fb4).

## 2026-10-05 — Carry original password authority through every phase

Bind password mutation, session invalidation and browser cleanup to captured
preparation authority; an authentication fence must not reopen on recovered
clocks. Keep stored-transport fixtures on the actual operation clock, own SMTP
publication and accept only the measured fixed Dovecot proxy success profile.
Isolate hash configuration from routing metadata, preserving bounded reads.
Sources: [`558cdca`](https://github.com/unattributed/OSMAP/commit/558cdca8acf936dcc1c8f67b5ee9165ba14bc354), [`c7e1608`](https://github.com/unattributed/OSMAP/commit/c7e1608712003c8bc1da962494bf0fd2e1f2356b), [`16c5088`](https://github.com/unattributed/OSMAP/commit/16c508866e171ebceca18e6aa9df0eca60860547), [`10aa45d`](https://github.com/unattributed/OSMAP/commit/10aa45d8508f242c8f397dddac0c8d8369304756), [`a2c45b9`](https://github.com/unattributed/OSMAP/commit/a2c45b9027d879358ee5f6a32cdbcaddcc8acd34), [`439f500`](https://github.com/unattributed/OSMAP/commit/439f50007033b2c38306ab43ef6ad9e8c7c133a1),
[`896ac63`](https://github.com/unattributed/OSMAP/commit/896ac63f0c01e11f0b6839f2789da8196eb9fc90), [`100fa1d`](https://github.com/unattributed/OSMAP/commit/100fa1db87427c1380319f35650a0ad8d9144152).

## 2026-10-06 — Separate command roles and refocus on working mail

Keep SQL, password hash, primary verification and SMTP cancellation as distinct
role-bound command authorities. Refuse special/replaced bootstrap files before
blocking opens; preserve original deadlines, source provenance, listener admission
and unresolved cleanup. Native command success is narrower than complete
production-graph custody or installed password qualification.

Refocus on ordinary mail recovery and an observed functional baseline. Implement
Documents through the existing helper and qualify first-save provisioning, Bin,
restore and confirmed deletion; retain native failures. Add folder rename with
durable outcomes and bind reads/search/mutations to the actual configured helper
identity. These early Documents decisions are superseded by its explicit removal
on November 5–6. Sources: [`a167558`](https://github.com/unattributed/OSMAP/commit/a167558421565a9cea0ae521fb13fc2530a92c46), [`b2955a6`](https://github.com/unattributed/OSMAP/commit/b2955a66da8eac0f7fe0dd32cbb59838ab90a133), [`695f45c`](https://github.com/unattributed/OSMAP/commit/695f45c703af125d1b6e9da7ed63c3cc619be354), [`dfecbc4`](https://github.com/unattributed/OSMAP/commit/dfecbc454d3eaf88fd272eecdefa6c8a9a8ee150),
[`6924976`](https://github.com/unattributed/OSMAP/commit/692497650bdea5b4cc52e0becbb28cf0ad30fde6), [`f7f8c38`](https://github.com/unattributed/OSMAP/commit/f7f8c385e4087937b5683848bb39d583c0282434), [`23e5fee`](https://github.com/unattributed/OSMAP/commit/23e5feee16ebfae73656f35ec8b8863c9fc54594), [`4801807`](https://github.com/unattributed/OSMAP/commit/4801807b5c5e4f0145cadedbee666c7194a30dc2), [`a0ac6ad`](https://github.com/unattributed/OSMAP/commit/a0ac6ad4ce13f52e69f1396a3a7ce8a0b78834b3), [`b83d9b7`](https://github.com/unattributed/OSMAP/commit/b83d9b70a5dc2cff9bf5dc8b7d1ad5fab3218707),
[`5b8ee7f`](https://github.com/unattributed/OSMAP/commit/5b8ee7f9b261b1045082fcefdbb2b961567e05e8), [`2753e04`](https://github.com/unattributed/OSMAP/commit/2753e0435935483b64febf0ba04bcb85a849bf93), [`fd7cf95`](https://github.com/unattributed/OSMAP/commit/fd7cf95417c239f11086052e285c16188eda297d), [`93016e6`](https://github.com/unattributed/OSMAP/commit/93016e606c7e8c6c76d19b10bc256c31a01fd7ea), [`ee36032`](https://github.com/unattributed/OSMAP/commit/ee360329d2051a0ea93b36411dab523a54fd37bb);
[mail-delivery refocus](UX_MAIL_DELIVERY_REFOCUS_20261006.md).

## 2026-10-14 — Recover ordinary mail and supervise crypto ownership

Resume from actual boot/service recovery and prove ordinary installed mail before
advancing the epic. Support encrypted BCC with the qualified recipient-privacy
boundary, recover stale private-key agents safely and give Crypto direct listener
ownership with correct termination. Restore private folder moves and the
requested Folders entry points without widening account authority.

Apply the operator-approved R3 delivery correction: agents own engineering,
matching installed QA and independent review; the owner supplies final judgment,
not troubleshooting of incomplete journeys. Sources: [`90461aa`](https://github.com/unattributed/OSMAP/commit/90461aa1f6530ce16f0c86bdc6e456d80f19dc17), [`cfa140a`](https://github.com/unattributed/OSMAP/commit/cfa140a6d562d3e6bae896356d080f69171e9620),
[`ba170ef`](https://github.com/unattributed/OSMAP/commit/ba170efa0ab7e38392eb16e470ee3d0e3f16db43), [`7c23455`](https://github.com/unattributed/OSMAP/commit/7c2345525e37a8986b4719429ae18bcf3454c5a5), [`afc0223`](https://github.com/unattributed/OSMAP/commit/afc02239b832a2ebc7904f99549740d824d10809), [`f2a117c`](https://github.com/unattributed/OSMAP/commit/f2a117c17dbd93b634f9914c5608473dc682d8e0), [`bd0dcf4`](https://github.com/unattributed/OSMAP/commit/bd0dcf4045e5a0de805fa78b103aa88b317baee0), [`9858d04`](https://github.com/unattributed/OSMAP/commit/9858d04e27ce07f7514ffb96784a52905ff6f1fa);
[R3 amendment](UX_PLAN_AMENDMENT_R3.md).

## 2026-10-15 — Complete folders and expose the actual password composition gaps

- **Folders:** implement recoverable subtree Bin/Restore and confirmed empty
  deletion with fresh ownership/completion witnesses. Preserve uncertain earlier
  effects through rollback. Repair virtual subtree metadata, assigned label
  display and read amplification by batching fresh folder facts. A distinguishing
  regression proves the browser Runtime forwards the optimized operation rather
  than inheriting a default. Record engineering and scoped owner Folders/attachment
  acceptance; broader sprint/epic scope remains open.
- **Password integration:** pair browser and account services, bind primary
  verification to command custody and refuse configured fallback. Integrate the
  real HTTP/settings path, sealed clients, native SMTP metadata and issuer.
  Account/session/epoch authority must survive transport without renewal.
- **Platform and failure semantics:** observe actual SQL pipe/TTY, null-device,
  pre-seal metadata and `unveil` behavior before changing guards. Cleanup does not
  prove authentication. Preserve the failed native HTTP/cache boundaries and
  owned resources; two failures require combined reassessment, not an unchanged
  retry. Delivery accounting and review cover the complete success path.

Sources: [`b974064`](https://github.com/unattributed/OSMAP/commit/b974064183b43eb6f03ae744925a3a1d60fd82d3), [`a391839`](https://github.com/unattributed/OSMAP/commit/a391839fd0f0ba1d1d932410d7265f2d975115b9), [`a902761`](https://github.com/unattributed/OSMAP/commit/a902761d1e97975056bae8d6df19c93955f267ba), [`d8cdc82`](https://github.com/unattributed/OSMAP/commit/d8cdc822725c60bedb26dbbebf787362e11d1c39), [`c4e318b`](https://github.com/unattributed/OSMAP/commit/c4e318bf2602998885ea1b4aa9432ff0a572031b), [`c497b9c`](https://github.com/unattributed/OSMAP/commit/c497b9cfbcd2c86eafec35f7c53fb71a35caa25d),
[`e0b34a8`](https://github.com/unattributed/OSMAP/commit/e0b34a871b13a0fae73c7aa55186e593a7dfddc1), [`bd7a9e3`](https://github.com/unattributed/OSMAP/commit/bd7a9e3e6b6d29aecbc3f2be302169f645272dc5), [`a22fee6`](https://github.com/unattributed/OSMAP/commit/a22fee6f97ca9c63040397889a2da3a505c31f10), [`03dfd4a`](https://github.com/unattributed/OSMAP/commit/03dfd4ab2645ca684da10e6388640e013093fc2c), [`ce3e920`](https://github.com/unattributed/OSMAP/commit/ce3e920cfbbe2e105c28bce35746674ecc9e5293), [`0b270fa`](https://github.com/unattributed/OSMAP/commit/0b270fa2d6c1c3ff68e7c317275c7c5982a3f499),
[`1893c44`](https://github.com/unattributed/OSMAP/commit/1893c44b069509128c18e30d735547fc50512d25), [`fc43301`](https://github.com/unattributed/OSMAP/commit/fc4330196b316bfbb4731783290d308b4e14ee1f);
[folder engineering/acceptance record](UX_EXECUTION_LEDGER.md), [password slice](UX_SLICE_S04_02.md).

## 2026-10-16 — Preserve verified password effects separately from failed workflows

Require each slice's design/outcome/test contract before implementation. Repair
relay shutdown, private Dovecot control configuration, SMTP endpoint and captured
cancellation. Preserve authoritative password-write time through incomplete
post-write effects; authenticated stale-epoch denial must remain denial.

Native HTTP12/14 and later cases retain uncertain or failed postconditions.
HTTP20 completes the password journey but lacks its final process report, so the
aggregate remains failed. HTTP21/22 retain SMTP postcondition/timeouts. Controlled
HTTP24 later passes its disposable private workflow; it does not qualify the
normal installed form. Compile/ABI proof for a native IMAP module does not mean
it was loaded or qualified.

Correct null-device custody using stable device identity instead of volatile
timestamps; keep regular-file guards. Fix test exec construction through the
existing fixed `cfg(test)` command-builder boundary after both security consumers
reject earlier arrangements. Retain gate failures rather than weaken guards.
Sources: [`432666f`](https://github.com/unattributed/OSMAP/commit/432666f484a04c3c2a2075caf95a1a3d52d08d44), [`765446e`](https://github.com/unattributed/OSMAP/commit/765446e49210ffe9bddc7ca19e576828e7e8285d), [`11e8090`](https://github.com/unattributed/OSMAP/commit/11e8090dcf959592b8a4833667ccfc17fa06bf87), [`357301e`](https://github.com/unattributed/OSMAP/commit/357301e20d3b466b822fd364fa8a25f19874f7dd), [`f9ab641`](https://github.com/unattributed/OSMAP/commit/f9ab641789ed152ce39f401694d998c66ee0e9b8), [`13572c5`](https://github.com/unattributed/OSMAP/commit/13572c503826b0992a3ea68b6d204f5daa12ce17),
[`ee80ca8`](https://github.com/unattributed/OSMAP/commit/ee80ca8975e57ee335f5eb2364b30b9c47c589d7), [`d1f50a9`](https://github.com/unattributed/OSMAP/commit/d1f50a9b3699a97f24dcb69c8095e36ce1c70449), [`557b668`](https://github.com/unattributed/OSMAP/commit/557b668a990df775af6665185380ccece6722673);
[password slice and retained outcomes](UX_SLICE_S04_02.md).

## 2026-10-17 — Accept only the narrowed settings scope and preserve the stop

Honor the operator stop, preserving password failures and incomplete activation.
Correct timezone/saved-value reset and unsaved appearance preview under approved
R4. S04-01 closes only its narrowed settings/session core after engineering,
installed review and owner `S04_01_UAT=PASS`; eleven follow-up controls remain
required. Other stopped slices do not resume through this acceptance.

Apply the mandatory sanitizer security patch without claiming the stopped
password workflow is fixed. Historical source-preservation authority is later
superseded by explicit resumption and standing synchronization directions.
Sources: [`4725057`](https://github.com/unattributed/OSMAP/commit/4725057a6901d8b5e917637aa780f418e99398cf), [`0c5dac8`](https://github.com/unattributed/OSMAP/commit/0c5dac8fec6466c0834af2a229a57325c5ea38f7), [`8e47119`](https://github.com/unattributed/OSMAP/commit/8e47119be63a79695cd95b34b8ca8e66f56b9e1c), [`675844f`](https://github.com/unattributed/OSMAP/commit/675844f2834612aa0445b0ee37d089a4bf8a0f30), [`d8ddf8d`](https://github.com/unattributed/OSMAP/commit/d8ddf8dd79a0a3ae7456971fef08f4ba477b7c47), [`2bddb4b`](https://github.com/unattributed/OSMAP/commit/2bddb4bfba33cc6b44da990f5b60076a35e19590),
[`0eacfd9`](https://github.com/unattributed/OSMAP/commit/0eacfd9f5e49177c9ffa3b16e8454409fb5cf632), [`2d99ff4`](https://github.com/unattributed/OSMAP/commit/2d99ff4bb1a75d9d5446a62e0aca7f6728ca67b6);
[R4 amendment](UX_PLAN_AMENDMENT_R4.md).

## 2026-10-18 — Resume S04-02 with a Rust service and fixed native utilities

Replace the unsupported authentication-graph approach with OSMAP-owned Rust
workflow/helper code and fixed existing MariaDB/Dovecot commands. Preserve real
SQL/hash outcome diagnostics, role identity, native source and exact-owned
recovery. Avoid the broken OpenBSD `waitid` union accessor; foreign-session
`getsid`/ESRCH is not proof of historical descendant absence or signaling authority.

Audit the complete guardian/fixture/helper exec chain: a parent's blocked stop
signal mask is inherited by its child, so restoring only the parent is
insufficient. Restore intended masks at each changed boundary. Cold startup
progress exposes later sealed FSTAT/recheck and descriptor-ownership failures;
keep their distinct observed phases and unknown causes. Native startup or source
admission does not complete the password journey.
Sources: [`3529ef4`](https://github.com/unattributed/OSMAP/commit/3529ef4f2ba82c4490d8a423001dc1990ef3b1d8), [`34598a9`](https://github.com/unattributed/OSMAP/commit/34598a9325a515b949b38af00448419a6aeafa69), [`515a99c`](https://github.com/unattributed/OSMAP/commit/515a99c9a1f6e6ca62cb9b55b7db47b4082e49c6), [`abe5b7b`](https://github.com/unattributed/OSMAP/commit/abe5b7b71e35b195359f7f6d570bd2625d5acb67), [`daed290`](https://github.com/unattributed/OSMAP/commit/daed2908e7da75678697b5023e49c10a1e2a33b2), [`fd608c1`](https://github.com/unattributed/OSMAP/commit/fd608c13012b6fd90ee2ff186dd95f3ba2028897),
[`ecfd0cd`](https://github.com/unattributed/OSMAP/commit/ecfd0cd1526bdbd5b081cce1719f9c282ef07389), [`3e003d0`](https://github.com/unattributed/OSMAP/commit/3e003d0b32864112f7396744f44a3825b47c6348), [`d393ffe`](https://github.com/unattributed/OSMAP/commit/d393ffedd916fa9046a94b47548a0adc5aeb4b3b), [`8c0a84c`](https://github.com/unattributed/OSMAP/commit/8c0a84c61056c7ede8fe14b246a816e91a47258c), [`e22aeed`](https://github.com/unattributed/OSMAP/commit/e22aeedc789bd368d978571668c086c321416dec), [`9b240f7`](https://github.com/unattributed/OSMAP/commit/9b240f7192d402145f1606a22c3326882ff38c93).

## 2026-10-19 — Retire tests requiring public mail downtime

Actual prerequisite evidence identifies unsupported SQL/configuration assumptions;
carry those blockers into dependent dispatch. Apply the outcome-first delivery
SOP to all work and preserve cumulative failures. A confirmed backend outage is
restored, but its unique historical cause remains unknown.

The operator rules that OSMAP is the frontend: new password development/tests
must not stop, restart/reload or reconfigure public Dovecot, Postfix or MariaDB.
Retire the downtime fixture and use bounded existing account operations. Simplify
the stock password backend and correct actual executable admission rather than
build another infrastructure layer. OSMAP service control remains separately
permitted within scope. Sources: [`e850a08`](https://github.com/unattributed/OSMAP/commit/e850a08da7acbf81da53cecd6acf0c3ed64259d9), [`e5a5ee4`](https://github.com/unattributed/OSMAP/commit/e5a5ee417851cd51cb67d9605d3d865c69ecf62d), [`5561df2`](https://github.com/unattributed/OSMAP/commit/5561df229bd438d5da2f72b7bdeb2e82bd522c3b), [`67711cd`](https://github.com/unattributed/OSMAP/commit/67711cd5ba817a13b37bc94e8ccf68b0f668758e),
[`3cad60f`](https://github.com/unattributed/OSMAP/commit/3cad60f10a7fb9093f1075c874cbf7b8ec5f0922); [delivery framework](AGENT_DEVELOPMENT_FRAMEWORK.md).

## 2026-10-20 — Remove unused startup work and retain failed HTTP evidence

Defer unused primary-password profile construction during read-only epoch
admission. Preserve actual startup, HTTP80, restoration81 and aggregate expiry
outcomes under the explicitly bounded continuations. No source repair or
restoration success supplies the missing installed password result; do not retry
an unchanged expired fixture or infer its mutation state.
Source: [`d23092e`](https://github.com/unattributed/OSMAP/commit/d23092e8bbc5feefc61a0daaa36643a10b362e2a) and the
[dated retained execution record](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-10-20--actual80-http-boundary-and81-backend-restoration).

## 2026-10-21 — diagnostic104 locates an error inside the backend helper

- **Diagnose before retry:** controlled attempts90/95 fail before the helper
  journey; workflow99 returns an intentionally generic login401. Preserve exact
  disposition, absent observations and retained scratch instead of guessing the
  authentication branch. Add closed numeric stage diagnostics through the
  existing trusted channel, test the actual producer/consumer and distinguish
  local diagnostic success from a native observation.
- **diagnostic104:** locate the failure inside the backend helper rather than
  blame password/TOTP from the public response. Continue with bounded helper
  observations and the installed library mismatch; do not replay credential
  actions to obtain missing diagnostics.
- **Installed dependencies:** replace stale snapshot/public-config pins, lexical
  library selection, fixed Python minor and fixed service UID assumptions with
  protected installed capability discovery and lifetime rechecks. Retire the
  unsupported native factories, retain strict private custody and disabled
  qualification flags. Source/bundle tests are not OpenBSD installed proof.
- **Execution and delivery:** support the required single-host endpoint topology;
  do not mandate a second host. Make public-safe signed GitHub preservation part
  of ordinary delivery, keeping normal hooks and fresh local/remote SHA proof.
  The operator also rejects the added 6-GiB RAM admission floor; the removal
  reaches source on October22. Preserve attempt109's compiler failure and
  attempt113's precompiler refusal as different outcomes.

Sources: [`6c12a45`](https://github.com/unattributed/OSMAP/commit/6c12a45a2e415b82bf0bc43f7df92b4af481275a), [`aba1b57`](https://github.com/unattributed/OSMAP/commit/aba1b57149e5101a20d4d2c95e3925d029e5bb0c), [`7549f9f`](https://github.com/unattributed/OSMAP/commit/7549f9f4c364b657ee6c5458ab0bbf6a48bf4541), [`15fee61`](https://github.com/unattributed/OSMAP/commit/15fee6158dfe69aa28b163c3008acc37905f334b), [`ac33600`](https://github.com/unattributed/OSMAP/commit/ac336004e74191f9fbace7a38d18eb17d676d151);
[original diagnostic104 record](https://github.com/unattributed/OSMAP/blob/14a5250f41b880bf924357743f888d58ddcb58da/docs/DECISION_LOG.md#2026-10-21--diagnostic104-locates-an-error-inside-the-backend-helper).

## 2026-10-22 — Remove the invented memory floor and admit current dependencies

Remove the agent-added fixed free-memory prerequisite without replacing it with
another arbitrary threshold or requiring a full optimized library build for
every milestone. Admit actual installed C++ library names and supported stock
configuration queries. Existing failed compiler/admission records remain history;
these changes do not prove server inadequacy or password acceptance.
Sources: [`13d47a1`](https://github.com/unattributed/OSMAP/commit/13d47a172ebb0d8589569ba4e211882fc5f162bd), [`91d9bf3`](https://github.com/unattributed/OSMAP/commit/91d9bf32275804154d9499e4778a3a260bd889a0), [`72bc5e9`](https://github.com/unattributed/OSMAP/commit/72bc5e91692f069ff87a94868a27f3b56f53946a).

## 2026-10-23 — Test capabilities and narrow the execution gate

Remove active OpenBSD release-string parsing/pinning and default release-numbered
images/helpers. Require OpenBSD and the concrete APIs/schema/confinement
capabilities actually consumed. Simplify acceptance pre-action checking to exact
action/source/recipe/target/prerequisites/runtime and any explicit operator expiry;
historical ledger clocks do not expire direct operator authority.

Harden the paired password service and qualify current-source native startup
milestones1/2. Milestone3 remains failed before READY with no mutation request;
one-shot authority is consumed. Correct timing and producer/cleanup/consumer
contracts without turning diagnostic receipts into product acceptance. Explicit
operator expirations and real safety/failure stops remain binding.
Sources: [`b4bc371`](https://github.com/unattributed/OSMAP/commit/b4bc371bd645ea009e4d257b269c73bd7294c8e9), [`77f6379`](https://github.com/unattributed/OSMAP/commit/77f63794d3f60e4003db157eada39f4bd4222b6a), [`9b3326e`](https://github.com/unattributed/OSMAP/commit/9b3326efe3b29929472398535b2f707abcb9ef01), [`032e484`](https://github.com/unattributed/OSMAP/commit/032e4846d4c78aa1c81144cc47bbecce11703492), [`e317fee`](https://github.com/unattributed/OSMAP/commit/e317feeba7056b6c08fd05c45e33fb229f9a7d5b), [`f947c35`](https://github.com/unattributed/OSMAP/commit/f947c3502c73a043759f46a26b27b804636e42d6),
[`2512a24`](https://github.com/unattributed/OSMAP/commit/2512a243c610e923dc4dae591f975356ca3dd5cc), [`213b2f3`](https://github.com/unattributed/OSMAP/commit/213b2f3b9ee878fcbaf37e27acb45743a3782434), [`b10721b`](https://github.com/unattributed/OSMAP/commit/b10721be06f99f6c912f3701d2931a9056e56d29), [`3a2d8e0`](https://github.com/unattributed/OSMAP/commit/3a2d8e09e242096bc678dbfa74a981a48373a5d9).

## 2026-10-24 — Preserve bounded diagnostics and prove credential freshness

Require every failure to retain a sanitized actionable diagnostic before cleanup.
Keep earliest failure, submission state, cleanup and authoritative-state certainty
separate; export only source-owned codes, process outcomes and bounded stream
accounting. Read back and hash durable evidence before removing its sources.
Unknown initiating causes and uncertain resources remain explicit.

Carry Rust construction/admission/startup detail through native capture; diagnose
confinement without exporting arbitrary exception/native text. Correct actual
endpoint custody and duplicate cold graph verification. Native read-only helper
admission R1/R2 passes after earlier preparation/client-launch failures; this is
not a password transaction. Then prove current-credential freshness by refusing
a deliberately obsolete credential before trying the current one, so cache
refresh cannot hide a stale acceptance. Retain the independent no-write proof
and native/current-source scope.
Sources: [`8848ba8`](https://github.com/unattributed/OSMAP/commit/8848ba89950270a2c10b36e1c14a5315a17aa47e), [`4668a51`](https://github.com/unattributed/OSMAP/commit/4668a5122e1bf1f4870be7dde022a15065eb0265), [`6d1af10`](https://github.com/unattributed/OSMAP/commit/6d1af10eaa4dbfd66fc65094c991e3334e7379a6), [`dd660a0`](https://github.com/unattributed/OSMAP/commit/dd660a094ec35902505fe6857667b7110f5150a2), [`4e4fa31`](https://github.com/unattributed/OSMAP/commit/4e4fa31fe693347dbad7de27cb99a2e5ec2cf15c), [`040abcc`](https://github.com/unattributed/OSMAP/commit/040abccea0543369f3761cac5e3884eec7c7614d),
[`0150845`](https://github.com/unattributed/OSMAP/commit/015084569d8f6f610e82f0adefa3cd0cb4b62c21), [`5a8ab20`](https://github.com/unattributed/OSMAP/commit/5a8ab20d6655ecbb2fe4989335dcdb5540e405c4), [`afe7175`](https://github.com/unattributed/OSMAP/commit/afe7175ca7d47b11c1c6691ee370b2fe01bd48ad), [`b4b1d3c`](https://github.com/unattributed/OSMAP/commit/b4b1d3c7716efaaf1479960666c823434e0f7a37), [`e6d5ce7`](https://github.com/unattributed/OSMAP/commit/e6d5ce7c4b9f25a1b568cf962e1112b774cb5ec5), [`a8aff9a`](https://github.com/unattributed/OSMAP/commit/a8aff9a83871bee795dfacb6c9fad3592413cad4),
[`8f09b48`](https://github.com/unattributed/OSMAP/commit/8f09b48844bc3668f7531e3dba0f2c977307e9aa), [`ff33c40`](https://github.com/unattributed/OSMAP/commit/ff33c40536428b3cc1b7626ea5caa2d2ca8e23c0).

## 2026-10-25 — Accept the ordinary local password journey after real transaction proof

Complete the native credential transaction, epoch/session consistency and the
normal Runtime/browser path. Retain a separate restricted result capability so
a completed password change remains discoverable after the old session expires,
without granting settings access or another mutation. Resolve Dovecot modules,
protected MariaDB aliases and Postdrop loader context through observed native
contracts.

Install the ordinary obsd1 path and isolate its development profile from production
credential authority. The owner's known no-write refusal reveals stock raw
bcrypt storage: accept only well-formed supported unprefixed bcrypt alongside
scheme-prefixed representations, without normalizing the stored snapshot.
Controlled conditional update, old/new credential and session witnesses then
pass. Owner successful login/change/replacement-login closes S04-02 T09 for the
selected local development scope. It does not qualify the production host or
all accounts. Earlier startup, parser and failed workflow evidence remains.
Sources: [`efb8c75`](https://github.com/unattributed/OSMAP/commit/efb8c754e36351424a3f94441f4b317ef7e7edb0), [`25cb317`](https://github.com/unattributed/OSMAP/commit/25cb31717258fe32ef9f203a90f7cdc8ec5b0adb), [`8b27d33`](https://github.com/unattributed/OSMAP/commit/8b27d33a25d9de01f8973bdcd615e40e65b33cc6), [`769784b`](https://github.com/unattributed/OSMAP/commit/769784bd64d9414b57addd30a687c09ae782f2f3), [`16d7bf4`](https://github.com/unattributed/OSMAP/commit/16d7bf4d0126e2f3186390234ffcf26ab14ad3a4), [`0c9f699`](https://github.com/unattributed/OSMAP/commit/0c9f699793d3911aa8472694462b14ade992cda9),
[`703ed2e`](https://github.com/unattributed/OSMAP/commit/703ed2eed8ccd1d74db084f1b7ee86ad5837683c), [`a740272`](https://github.com/unattributed/OSMAP/commit/a740272427cb2ebc92f90ee3cbc8e2db4c82b4aa), [`8f3ce62`](https://github.com/unattributed/OSMAP/commit/8f3ce62a0ed14eb0351b6e9813d0f71fff7d0763), [`67148da`](https://github.com/unattributed/OSMAP/commit/67148da77971da244618d5f6f89a717af7b322c4), [`e4b2164`](https://github.com/unattributed/OSMAP/commit/e4b21648eba5028d6f4199e371b92d02f3eb3dfc), [`b94eacb`](https://github.com/unattributed/OSMAP/commit/b94eacb9a583f0cc1a999504285dbd813763202e);
[replication/development profile](UX_SLICE_S04_02.md).

## 2026-10-26 — Implement recovery contacts through existing account and mail boundaries

Serialize account-private contact state and require fresh primary/TOTP authority;
use bounded mail delivery with proof entered through authenticated POST rather
than tokens in URLs. Prevent local proof/status mail from escaping its approved
scope and preserve validated nonsecret input after trusted form refusal.

Restore OpenPGP helper/binding configuration omitted by the development-profile
cutover without re-importing keys or resetting trust. Installed lifecycle and
contact-specific negatives qualify their own boundaries; keep the interrupted
aggregate failed and its unexecuted generic logout test unclaimed. Local
engineering readiness remains distinct from external delivery and owner UAT.
Sources: [`eeb748d`](https://github.com/unattributed/OSMAP/commit/eeb748d8a5c36a0162c63807ba431ad49ab306e0), [`3c11641`](https://github.com/unattributed/OSMAP/commit/3c11641ba7f0fdebe6f07dcd86cc3040caa01044), [`7fa6e67`](https://github.com/unattributed/OSMAP/commit/7fa6e6790ba20c8cef036355856959d8017774d6), [`9eb4cb6`](https://github.com/unattributed/OSMAP/commit/9eb4cb6973e139138354bbca4da30513f6cffe04), [`94b9895`](https://github.com/unattributed/OSMAP/commit/94b989519c720abd759c317df44c0b2182bd4684), [`6a83828`](https://github.com/unattributed/OSMAP/commit/6a8382881c87c6564bb084792dd3f2e43a09c88e),
[`d3e4f0d`](https://github.com/unattributed/OSMAP/commit/d3e4f0da839030554489d0bdce7abb2eb6362ac2), [`5eb9f9b`](https://github.com/unattributed/OSMAP/commit/5eb9f9b44120a861a1f2baa8ea7667347df66a3f), [`56f0561`](https://github.com/unattributed/OSMAP/commit/56f056109f68a905999a91e04a2a0a29f064dec5);
[recovery contact slice](UX_SLICE_S04_03.md),
[OpenPGP restoration](UX_OPENPGP_DEVELOPMENT_RESTORATION_20261026.md).

## 2026-10-27 — Enable explicit external recovery delivery and accept S04-03

Add the deliberately configured external recovery mail path, retain sanitized
relay observations and prove the installed journey. Record the owner's recovery
contact UAT separately from local-only evidence. This acceptance covers contact
verification, not lost-authenticator/password recovery or later production
portability. Sources: [`2307fb7`](https://github.com/unattributed/OSMAP/commit/2307fb719366a657de81e9a0138292ae3eff8112), [`d9e2fad`](https://github.com/unattributed/OSMAP/commit/d9e2fad286ce26b0b39c82bac61d4502a2d9bdce), [`2aa266d`](https://github.com/unattributed/OSMAP/commit/2aa266dd8b904655e111bf1e4152c86366801156), [`6c509a5`](https://github.com/unattributed/OSMAP/commit/6c509a542dfc30129e23b838b1faf7cd01608f4e).

## 2026-10-29 — Coordinate recovery without inventing human identity evidence

Implement governed recovery with identity-only signed input, epoch containment,
session revocation and a durable one-attempt factor replacement/release state.
Browser requests/status are untrusted projections. Require complete frontend
profile epoch coverage before mutation; helper allowlists alone are insufficient.

Retain fixture ownership, enrollment and installation failures. A manual controlled
password initialization is fixture maintenance, not product lost-password proof.
Native component and loaded-environment checks establish preparation only; whole
LOCAL-profile scope and later bridge restoration must be explicit. Refuse public
artifact publication before private copied-byte verification. The private rejected
publication is not copied into this public log. Sources: [`3f8c2b3`](https://github.com/unattributed/OSMAP/commit/3f8c2b3664561b1edca8e0cf031a33f815e7fbc5), [`93cbb88`](https://github.com/unattributed/OSMAP/commit/93cbb888595c9d36eec8176087c3d5843b7bb663),
[`122b0b3`](https://github.com/unattributed/OSMAP/commit/122b0b36c3d51d816e27e012862553743cb2cae7), [`03c9e50`](https://github.com/unattributed/OSMAP/commit/03c9e50cd105851c697c21be3d9de18728241b8d), [`dca8275`](https://github.com/unattributed/OSMAP/commit/dca8275051d49960b517a1a6d9a47e1b072c8eca), [`feee88a`](https://github.com/unattributed/OSMAP/commit/feee88a4c50881f1545cc434f3b4db5743faf86a), [`b689b40`](https://github.com/unattributed/OSMAP/commit/b689b40bd197b876f8e82ade033fca5aa8a49329), [`b416ae2`](https://github.com/unattributed/OSMAP/commit/b416ae2561fac235691c59e8493c12651fd846e4),
[`8e9045e`](https://github.com/unattributed/OSMAP/commit/8e9045e0023205e4a15ae32df92ffcc3aff28505), [`b47c4d7`](https://github.com/unattributed/OSMAP/commit/b47c4d75dc5ebc8325b0661dfaa45ad46e8fa0f6);
[recovery slice](UX_SLICE_S04_04.md).

## 2026-10-30 — Deliver browser authenticator reset and access recovery

Replace request-only recovery with the reviewed browser TOTP reset/access
recovery flow while preserving independent human identity/private-terminal
requirements where applicable. Use captured native custody after sealing,
preserve browser origin and audit mail outcomes. Correct the post-write stock
cache witness and reconcile accounts before recording owner S04-04 acceptance.
Prior failures and source/native/installed/human distinctions remain intact.
Sources: [`d9dd469`](https://github.com/unattributed/OSMAP/commit/d9dd4692658e88099362d77d2028aebb4a334dc7), [`efd41d1`](https://github.com/unattributed/OSMAP/commit/efd41d19cd9f3ef5a2ed9eb41afce009515c812b), [`4d00385`](https://github.com/unattributed/OSMAP/commit/4d00385ca49c4be8f60651dc2baf98e528d4f195), [`2cdaf8c`](https://github.com/unattributed/OSMAP/commit/2cdaf8c6d986cb47ed9f7af34ab94db31f4fce53), [`42137e0`](https://github.com/unattributed/OSMAP/commit/42137e0c83d3326216ba3d233499268a27a412bf),
[`a77bb9c`](https://github.com/unattributed/OSMAP/commit/a77bb9c296100d029dd71891457d81b5e7f87823), [`5e3ebb5`](https://github.com/unattributed/OSMAP/commit/5e3ebb5d2e3a82823f44854f7a249c361da69dfe), [`043adb6`](https://github.com/unattributed/OSMAP/commit/043adb622c8b30202eaa1e0b1f9d4916c0053f3f), [`35719f0`](https://github.com/unattributed/OSMAP/commit/35719f01b36b67d11a567c8cebed09a209773102).

## 2026-10-31 — Reuse the Rust OpenPGP route and expose practical key policies

Validate operations before allocating/cloning requests, retain the existing typed
client/service, native GPGME engine and bounded worker. Use the actual successful
compiler profile rather than invent a new memory prerequisite. S05-01 native
composition qualifies infrastructure, not owner key management.

Make current imported keys, certificate email identities and applied policies
the main S05-02 surface. Keep Optional encryption off by default, retain explicit
choices and hold the stored-session lease through fresh authorization/effects.
Correct real Welcome placeholders and rotation/expiry behavior. Installed
engineering readiness precedes the owner's later import tests.
Sources: [`8577e12`](https://github.com/unattributed/OSMAP/commit/8577e12a2be6fa98db0eb115b70935960974483d), [`cebd672`](https://github.com/unattributed/OSMAP/commit/cebd67291f800bb9304a189a12995a75d980ca0c), [`279df22`](https://github.com/unattributed/OSMAP/commit/279df22e6ceb384410b151a4acc9134e67dc3e25), [`fa26102`](https://github.com/unattributed/OSMAP/commit/fa26102d5c2603cc5c298c845910a01ae072766c), [`831516b`](https://github.com/unattributed/OSMAP/commit/831516bff45677411f7622b05a299a8ae928d40a), [`fe500fb`](https://github.com/unattributed/OSMAP/commit/fe500fb9c3232c0507d5023365e0ef543d9e09d4);
[S05-01](UX_SLICE_S05_01.md), [S05-02](UX_SLICE_S05_02.md).

## 2026-11-01 — Make key import and recipient selection practical

- **Import:** preserve the owner's failed import; correct validated armor
  whitespace forwarding and distinguish unresolved primary refusal. Native
  reproduction locates a worker umask defect: successful GPG import creates
  `0644` files rejected by strict custody. Set private `077` in the isolated
  worker/launcher, retain custody guards, and qualify the running-helper path.
  Replace paste with a bounded `.asc` upload through the existing multipart,
  primary/TOTP and helper pipeline.
- **Identities and Contacts:** derive email associations from current public
  certificate metadata rather than require manual binding or duplicate durable
  state. Preserve exact local-part case, reject ambiguity, default new policy
  matches to Optional and recheck protected-send freshness. Feed those owned
  identities into Compose and a practical People table with saved-contact names,
  search and explicit edit actions. Record the owner's Contacts/Compose UAT;
  it does not imply every key-lifecycle control is accepted.
- **Runtime:** retain bounded worker cancellation/process ownership, correct
  private-test ordering and qualify IPC/helper/recovery behavior through the
  existing Rust machinery. Record S05-03 owner T09 and separate recipient-side
  readable-message proof from relay `250` acceptance. Browser-abort propagation
  and S05-04 isolation are not inferred.

Sources: [`80585ec`](https://github.com/unattributed/OSMAP/commit/80585eccc31c3b7d45e2864413060becf4c347c6), [`617e11f`](https://github.com/unattributed/OSMAP/commit/617e11fd840ceb1337128958814768309d7946bf), [`379edb2`](https://github.com/unattributed/OSMAP/commit/379edb24511e46de525ae2b52cef2c57f4f31ee1), [`7fd9c42`](https://github.com/unattributed/OSMAP/commit/7fd9c424a425f3d916c00fc72021d42090051390), [`6c799d9`](https://github.com/unattributed/OSMAP/commit/6c799d920a56de0c6d6a6d20f6a0058dbfd505fe), [`160652b`](https://github.com/unattributed/OSMAP/commit/160652b7c5ad93202b99e5b423ed482d6663fc6a),
[`e08068a`](https://github.com/unattributed/OSMAP/commit/e08068a4fa55c8990b6c68b24b681f75b41eb4e6), [`2e1ddb5`](https://github.com/unattributed/OSMAP/commit/2e1ddb551586cb6db9b894693acdc2e83a0a94c5), [`5ebe610`](https://github.com/unattributed/OSMAP/commit/5ebe610204b602a2c715a8854164b42495d92ffc), [`69f712b`](https://github.com/unattributed/OSMAP/commit/69f712b4d50ac00646da4f2f1d459ce401f8e49d), [`9acd928`](https://github.com/unattributed/OSMAP/commit/9acd9286c67f11e7c3eb1623b6e1ac494c364637), [`95ed861`](https://github.com/unattributed/OSMAP/commit/95ed861a92bb72b6a52f5f352af0fcc1114e3beb);
[S05-03](UX_SLICE_S05_03.md).

## 2026-11-02 — Qualify helper isolation and correct protected-reader failures

Retire Python principal fixtures whose temporary user/database changes invalidate
the account helper's pinned backend. Refresh only OSMAP dependencies and retain
the owner's restored login; the earliest cold observer response was not retained,
so its original cause remains unknown. Replace fixtures with existing Rust/native
fixed-principal tests and disposable homes without account-database changes or
UID-wide signaling. Require process-group ownership, stop inventory admission
and drain existing requests under original deadlines. Record S05-04 native,
installed and owner T01–T09 acceptance with its original failures preserved.

Derive Welcome status from the authenticated account's mailbox/key/session facts,
not placeholder host-health assertions; record bounded F3 owner acceptance while
missing backup/update sources remain explicit. For S06, reuse the processor,
worker, sanitizer and content routes, enforce stored protected transport's
seven-bit profile, and distinguish missing signing keys, malformed decrypt and
Locked/opaque states. Fix GPG output handling and replace operational Python
`assert` with explicit guards. Owner protected-reading UAT follows on November3.
Sources: [`cfa8efd`](https://github.com/unattributed/OSMAP/commit/cfa8efdfa599e4c6baf9c89b8c294c0495cb9816), [`39d66ba`](https://github.com/unattributed/OSMAP/commit/39d66ba8f8f26dbe75bdb5cab08bf17c8d7afd68), [`d6d11d8`](https://github.com/unattributed/OSMAP/commit/d6d11d8959e6b3c09962cddb7ee80a046ca9b7d5), [`4c04150`](https://github.com/unattributed/OSMAP/commit/4c041501b76996e6948deeea42a24e4db2d4c231), [`ceaa053`](https://github.com/unattributed/OSMAP/commit/ceaa0539ed07a3248d69161225eb3c2e38955abe), [`d7a8757`](https://github.com/unattributed/OSMAP/commit/d7a87574c220e1b1474fdb8378e671ed159ba987),
[`cefd085`](https://github.com/unattributed/OSMAP/commit/cefd08517fa0e5b060fc197f50be042853da17c0), [`182b006`](https://github.com/unattributed/OSMAP/commit/182b006ff96b680481bfce45792eb2a2ed371a35), [`ba618c8`](https://github.com/unattributed/OSMAP/commit/ba618c8875cf2621858b8e2115d808de12e285d9);
[S05-04](UX_SLICE_S05_04.md), [S06-04](UX_SLICE_S06_04.md),
[F3 status repair](UX_FOLLOWUP_F3_ACCOUNT_STATUS.md).

## 2026-11-03 — Accept protected reading and session-bound personal-key controls

Correct unavailable encrypted-attachment metadata/size hints, complete controlled
reader acceptance and close S06-04 with the recorded owner result. Qualify S07
protected send and real Sent storage, include the account public certificate in
signed mail, and add session-bound personal key controls with the approved
finite eight-hour unlock policy. Record successful owner signing/S07 UAT.
General Settings security facts come from the signed-in account rather than
static assurances. Sources: [`bf0dc44`](https://github.com/unattributed/OSMAP/commit/bf0dc44bd19f7829555219a072a66dfa8923666a), [`0866340`](https://github.com/unattributed/OSMAP/commit/0866340cc55c54cb660018e50ce3959a8a0ed536), [`ef41693`](https://github.com/unattributed/OSMAP/commit/ef41693a605fe8471ed6437c24ac27a16abb15d6), [`ef9ba7c`](https://github.com/unattributed/OSMAP/commit/ef9ba7cb05a6df8e9420f819276a31f5f6f4dee2),
[`d5738d9`](https://github.com/unattributed/OSMAP/commit/d5738d9bd530e573c5c02e642878f0679cf31a62), [`f1b8875`](https://github.com/unattributed/OSMAP/commit/f1b88759ce6bb5203fc48d3079859ad19a7763a0), [`e99455d`](https://github.com/unattributed/OSMAP/commit/e99455d84a253bc301364f9fe48a27eb6880fda8), [`12b3da5`](https://github.com/unattributed/OSMAP/commit/12b3da5c19af31be3e73cc8b3252a269cba2397c), [`d7ded56`](https://github.com/unattributed/OSMAP/commit/d7ded56f02a86f5d000f995e9f69357e4e0a35c7), [`e861595`](https://github.com/unattributed/OSMAP/commit/e861595971c412c4214c3b6fbd31e361938f07d5),
[`2e33352`](https://github.com/unattributed/OSMAP/commit/2e33352220ad861cbf1e28d79b48f6c38bab4ccf); [S07 slice](UX_SLICE_S07_01.md).

## 2026-11-04 — Bind remembered key access to epoch and refuse unqualified storage

Remember personal-key access only inside the existing finite window and browser
gateway, with a required credential epoch; native controls and owner UAT close
that scoped behavior. Assess own signed messages against the account key.

Storage reporting exposes the actual shared-quota gap: simultaneous Documents
saves can exceed the nominal allowance, and a shared mail UID cannot supply
per-account filesystem isolation. Refuse unqualified writes instead of presenting
reporting as enforcement. Native mixed-writer/migration and sealed-helper
experiments remain fixture evidence, not active owner migration or Documents
acceptance. Sources: [`7efa4df`](https://github.com/unattributed/OSMAP/commit/7efa4df260359eb921d8003473dfe6aca6ee16ed), [`c1a54d3`](https://github.com/unattributed/OSMAP/commit/c1a54d3a71b95fcd8977344411e8cc548bdb1e93), [`013060b`](https://github.com/unattributed/OSMAP/commit/013060be2589e8763479fd4d687f48dd4257fe96), [`ef05600`](https://github.com/unattributed/OSMAP/commit/ef05600ff20fd28e4a560b84df8cc1d2191407dd), [`274df73`](https://github.com/unattributed/OSMAP/commit/274df731545633920591051d7765e27d5376788b),
[`0c31a1f`](https://github.com/unattributed/OSMAP/commit/0c31a1ff7618ca82dff15f98a189bd301e0058e7), [`8914063`](https://github.com/unattributed/OSMAP/commit/89140631bf031b53feacf568bc070b274594b840), [`a13fb89`](https://github.com/unattributed/OSMAP/commit/a13fb8936e9290bf5c3539d29c9aa567e671d8ed);
[storage slice](UX_SLICE_S08_01.md).

## 2026-11-05 — Add scheduling and factual notifications; remove Documents from scope

- **Storage:** report authenticated account mail bytes/quota through the native
  helper. A metadata change invalidates the persistent account helper; credential-free
  admission and the owner's fresh login confirm the dependency refresh. Apply the
  selected obsd1 development quota only within explicit authority. Earlier shared
  quota/cutover tests retain their limits. Owner storage-sidebar UAT does not
  qualify all Documents operations.
- **Scheduling:** capture bounded jobs through the existing protected-send/Sent
  pipeline and qualify actual confined background dispatch and duplicate
  suppression together. Interpret input in the saved account timezone, store UTC
  instants and preserve existing schedules. Separate relay acceptance, exact Sent
  and recipient receipt; the owner's scheduled-delivery pass covers that test,
  with local-time/cancellation follow-ups still separate.
- **Notifications:** use account-private factual events, explicit browser consent,
  read-all/dismiss and requested delete-all controls. Record owner acceptance of
  the delivered controls without treating notices as host monitoring.
- **Scope correction:** the operator removes Documents and stops its development
  and UAT. Preserve prior data/evidence; do not silently roll it back or portray
  earlier readiness as acceptance. November6 retires the runtime/UI dependency.

Sources: [`9ef9b71`](https://github.com/unattributed/OSMAP/commit/9ef9b71cb8cfbb3693be274e5131629325992bf0), [`3314088`](https://github.com/unattributed/OSMAP/commit/3314088a934fbf17abe1b03bf79289d6f0a3464c), [`1af693c`](https://github.com/unattributed/OSMAP/commit/1af693c0895228e268bfff22882e280270a9b945), [`bd9b1ba`](https://github.com/unattributed/OSMAP/commit/bd9b1baa7011e641e582a7bf2c83b0e2874daf49), [`fff478b`](https://github.com/unattributed/OSMAP/commit/fff478be01d9ddff87607248ea34069e369227bd),
[`55b0f3d`](https://github.com/unattributed/OSMAP/commit/55b0f3d262639931240803a6d833d5fd5af35a79), [`5b24dc3`](https://github.com/unattributed/OSMAP/commit/5b24dc3ed8ed7aa253ede02c99155f56864fae00), [`12160fa`](https://github.com/unattributed/OSMAP/commit/12160fadd490c0e929a5fd2e636d616508d6a8cb), [`ca3277c`](https://github.com/unattributed/OSMAP/commit/ca3277c4b51ac2546abb5a86365b1076c2092acb), [`a2eccb3`](https://github.com/unattributed/OSMAP/commit/a2eccb3c861e5f07424f6beb5e5dd49dcfd50245), [`5f2e549`](https://github.com/unattributed/OSMAP/commit/5f2e5497aa86e330b9392aac0c06883f49dca22f),
[`5277fcf`](https://github.com/unattributed/OSMAP/commit/5277fcf6259d84c5ddc8e43075e65910e7e18fb4), [`dcbc207`](https://github.com/unattributed/OSMAP/commit/dcbc2072de9fbb5264494ba92e4d388b73c82a11), [`85ce6d2`](https://github.com/unattributed/OSMAP/commit/85ce6d2d88a513be2f8119af06ba298351916179);
[scheduling](UX_SLICE_S08_03.md), [notifications](UX_SLICE_S08_04.md).

## 2026-11-06 — Use mail-stack account quotas and finish usable Trash/labels controls

Replace the named storage service/fstab dependency with account-generic
mail-stack path/quota discovery. Retire Documents routes/UI while preserving
mailboxes, messages, subscriptions, credentials/key state and retained originals.
Qualify different account paths/limits and foreign-state refusal; record storage
owner UAT separately from general portability.

Fix repeated Drafts/Bin failures: scheduled source copies need enabled selection
and explicit safe discard without rearming delivery. Add practical Trash review,
selective deletion and confirmed Empty trash; record only the actual owner-tested
deletions as accepted. Make label management discoverable, add real list/reader
assignment/removal controls and an accessible compact reader control. New label
owner reacceptance follows on November7.
Sources: [`045d639`](https://github.com/unattributed/OSMAP/commit/045d63929522e0a4357de733c275a9fd13ead9eb), [`8d8231e`](https://github.com/unattributed/OSMAP/commit/8d8231e9882ad6057a8174e372a1f782c1a37093), [`6a9f7b2`](https://github.com/unattributed/OSMAP/commit/6a9f7b2aa0c6331c1977cff95c1ceb9b2b89fefb), [`e3d7416`](https://github.com/unattributed/OSMAP/commit/e3d7416dad4355263b77b51072fc0e0be7e4f586), [`4b794e2`](https://github.com/unattributed/OSMAP/commit/4b794e2f77a826d447c5d23f083464bcc6db4134),
[`639464e`](https://github.com/unattributed/OSMAP/commit/639464e2801cd2a5d91949b945e1a51ad5d414ad), [`260db20`](https://github.com/unattributed/OSMAP/commit/260db20cbb7a18fe2006f90f136bec538e22426d), [`1ad960a`](https://github.com/unattributed/OSMAP/commit/1ad960a6c7bcbb5f77acf34602753e46ebcda36f), [`565bf06`](https://github.com/unattributed/OSMAP/commit/565bf062a6ae1d3003113e9d7d61886effe19871), [`7d8dac3`](https://github.com/unattributed/OSMAP/commit/7d8dac32c37c31a751475137ae1747abfaae757c), [`ac0c0db`](https://github.com/unattributed/OSMAP/commit/ac0c0dbfb7ad628199acf58d782e496c20c7b456).

## 2026-11-07 — Preserve unsaved authoring and accept the visible-label repair

Protect unsaved Compose work during navigation through the existing draft flow.
Record owner label-workflow UAT after the installed compact-label correction;
do not invent separate rename/delete/remove acceptance from one broader report.
Compose navigation acceptance and remaining S08 work retain separate scope.
Sources: [`111da08`](https://github.com/unattributed/OSMAP/commit/111da089d2e1c2665f3b13ba2dd40e8786acebe1), [`991494f`](https://github.com/unattributed/OSMAP/commit/991494f43a035902bc027993b83e837cc67bd997).

## 2026-11-08 — Add an account-scoped Outbox with honest failure reasons

Keep unsent attempts account-owned and provide safe review/recovery controls
without silently replaying uncertain submissions. Explain blocked sends with
recorded typed failure reasons. Record the owner's Outbox recovery UAT rather
than equate rendering or cleanup with successful delivery.
Sources: [`fbaccc5`](https://github.com/unattributed/OSMAP/commit/fbaccc5ab947ecd6cb8a1480415bf07dbd5ffcb9), [`4a65cf3`](https://github.com/unattributed/OSMAP/commit/4a65cf32d6439bd406bb93729ed637bec13a960e), [`501f643`](https://github.com/unattributed/OSMAP/commit/501f6430a5ec2eda95e8d6a942fee2268ab4e6a6).

## 2026-11-09 — Reconcile checkouts without overwriting concurrent work

Preserve superseded S05/local deltas with hashes and reconstruction proof, retire
only the superseded edits and fast-forward the older UX checkout. Restrict source
delivery to the account service's volatile-directory startup repair with named
group custody; exclude the other chat's active S08 work. Retain failed/interrupted
publication gates and their actual runner-environment reassessment. This is
source-only, not deployment/native qualification.
Sources: [`1e8bbef`](https://github.com/unattributed/OSMAP/commit/1e8bbef355f30987eb640fd4eac6f683a0005b3c), [`623e503`](https://github.com/unattributed/OSMAP/commit/623e503b080e6ead223f131b3ec4994abb3e1b43), [`5a4845a`](https://github.com/unattributed/OSMAP/commit/5a4845a6daec79fd3456346058370789e639caef), [`4389ae0`](https://github.com/unattributed/OSMAP/commit/4389ae033ce94d2a68eb1b150e352687255d3a08);
[checkout reconciliation](OSMAP_CHECKOUT_RECONCILIATION_20261109.md).

## 2026-11-10 — Keep application identity and presentation controls consistent

Reuse the login logo throughout the application, record owner logo-continuity
acceptance and preserve the failed push transport separately from its passing
hook. Add account presentation-style controls and remove a redundant Welcome
shortcut bar. Retain each installed/owner result within its actual scope.
Sources: [`ca64ec1`](https://github.com/unattributed/OSMAP/commit/ca64ec1b16b2b7a19d66a0b71ea523b7918a6872), [`e67a298`](https://github.com/unattributed/OSMAP/commit/e67a298d48d17e74b245b6dad64149b354efbf0f), [`c76c7c4`](https://github.com/unattributed/OSMAP/commit/c76c7c436d580bda20d278fc87979c24636f1ade), [`01a0db4`](https://github.com/unattributed/OSMAP/commit/01a0db41aa2e9349ac2798ce889b3c15559a4e9a), [`0bb6a72`](https://github.com/unattributed/OSMAP/commit/0bb6a72382ae89883ab14bc4407b472c65559514),
[`4985639`](https://github.com/unattributed/OSMAP/commit/49856393af4abfcab8b6456c2db6d5c050cdc9cf), [`1fa4335`](https://github.com/unattributed/OSMAP/commit/1fa43354535aaf2d15e837d5910bc0c0d30b48f7).

## 2026-11-11 — Finish usability corrections and open whole-application security review

Make expected public-key fingerprints optional while retaining validation when
provided. Correct responsive controls, autosave refusal, contextual panel actions
and dashboard links; record scoped owner results. Add Junk to the Archive/Bin
view and accept the observed Archive-to-Junk journey without inventing untested
Junk search/return behavior.

Start S10 whole-application assessment, add cross-origin login protection and
remove private mailbox search terms from audit logs. Record bounded public-route
WSTG/sensitive-path observations and distinguish them from actual-helper protected
reader proof and full release closure. Preserve the push-hook fixture failure
and later transport failure as separate delivery outcomes.
Sources: [`4a6eae5`](https://github.com/unattributed/OSMAP/commit/4a6eae5fa2991186c6f7be53bddd3dede0fbc0df), [`16bcefc`](https://github.com/unattributed/OSMAP/commit/16bcefcd7e923bf2c0b3b66eab42b57d61d29cbd), [`f693d7d`](https://github.com/unattributed/OSMAP/commit/f693d7d48c2aabcc7b1d194bccaf307de73c35d1), [`aac276a`](https://github.com/unattributed/OSMAP/commit/aac276a680fcb539aafe8c9475e6a8e774a87380), [`d01a604`](https://github.com/unattributed/OSMAP/commit/d01a604fb4079fa3eac36c3fdd4417bd1c9e3c18), [`9daba33`](https://github.com/unattributed/OSMAP/commit/9daba33f9d3b9d0d620d5112afafad20a86ce003),
[`18962ce`](https://github.com/unattributed/OSMAP/commit/18962ce66bcd2e38287639a8b9168fdf0eafbbff), [`0c1e287`](https://github.com/unattributed/OSMAP/commit/0c1e2876ace85a8b0f0b996ab5fe243dec2541a5), [`4c91ff3`](https://github.com/unattributed/OSMAP/commit/4c91ff3cf1cedcd7e3812f13f2c07f83b83d0a4b), [`b0a594f`](https://github.com/unattributed/OSMAP/commit/b0a594f9c40403d7d719f0836cd070bca7296498), [`99cb01f`](https://github.com/unattributed/OSMAP/commit/99cb01fd341db7a288d9ffc3e4faaf89dd45e269), [`7ba9b72`](https://github.com/unattributed/OSMAP/commit/7ba9b72656e4935ea061c3a2a1a6c9506a4c9cf3),
[`1b01351`](https://github.com/unattributed/OSMAP/commit/1b01351a0a0a3b353a691210b6729b3308219735), [`d0989fe`](https://github.com/unattributed/OSMAP/commit/d0989fee42e9602a1671d8137b30f85fb1f5aab2), [`d5ca7e1`](https://github.com/unattributed/OSMAP/commit/d5ca7e13bc82a1047913eb6a1424b8b7237af44c).

## 2026-11-12 — Close S09 under R5, promote UX and repair production installation

The operator-approved R5 amendment keeps per-message remote-content exceptions
disabled and requires truthful unavailable controls. Close S09 UX/accessibility
against final UI, matching installed Web, actual 200% zoom, independent review
and owner keyboard/screen-reader UAT. **All ten PAGE-18 security controls remain
open in S10 and block epic/release acceptance.** Preserve earlier narrower UAT
and proposed-amendment states as history.

Promote UX source [`6809c6a`](https://github.com/unattributed/OSMAP/commit/6809c6a861428760ec67446ab12caa3c9f313cd0) into main through [`43d5475`](https://github.com/unattributed/OSMAP/commit/43d547569543d9db004031d819d65dc10df8fcd3). That squash preserves the
accepted source tree but does not make all source commits ancestors of main;
this is why the branch history is included here. The promotion title does not
close S10 or the complete release.

Record the failed and corrected binary cutover/ACME scope, then the owner's
login/Inbox/key-unlock/decrypted-reader evidence on the production host. Helper log-directory traversal
and session-directory mode were concrete installation defects; correct those
permissions and preserve the earlier failures. Production-host journey evidence does
not establish all-account storage/control portability or reboot readiness.
Recovery-contact repair is published through PR #82; detailed activation and
owner acceptance are dated November13.
Sources: [`d4d48f8`](https://github.com/unattributed/OSMAP/commit/d4d48f8d9b259cabe3974ab221e78d549b2f75c5), [`fb604a4`](https://github.com/unattributed/OSMAP/commit/fb604a47b1e68cc2eb558bb3b7e33c308bfd0296), [`8064460`](https://github.com/unattributed/OSMAP/commit/8064460a89628f71cd976f7b203c5f7dc6e3013f), [`414fbf8`](https://github.com/unattributed/OSMAP/commit/414fbf8dac35d318fdd289e8606235f151fef4b9), [`437b95c`](https://github.com/unattributed/OSMAP/commit/437b95c2d4bdbf086c7bea37f7c3c19e79f09e25),
[`ae3386c`](https://github.com/unattributed/OSMAP/commit/ae3386c5b9ad5a477cbddfb3b879202a7a07c02e), [`d88793b`](https://github.com/unattributed/OSMAP/commit/d88793b03f8d84192645f4ad6b91fbba5e96d516), [`2cf48d8`](https://github.com/unattributed/OSMAP/commit/2cf48d8d335c25f51b6719463ecc0258db7cf7bf), [`86172bd`](https://github.com/unattributed/OSMAP/commit/86172bda880fa05b1e5a1f8802779a84b22d3e45), [`6809c6a`](https://github.com/unattributed/OSMAP/commit/6809c6a861428760ec67446ab12caa3c9f313cd0), [`43d5475`](https://github.com/unattributed/OSMAP/commit/43d547569543d9db004031d819d65dc10df8fcd3),
[`740da6a`](https://github.com/unattributed/OSMAP/commit/740da6abaa47dac8c37c93886a9baccf6f4b47dd), [`bdcbe26`](https://github.com/unattributed/OSMAP/commit/bdcbe2612eea1fb6555ef3b9086e2c401cec0f79);
[R5 amendment](UX_PLAN_AMENDMENT_R5.md),
[deployment/acceptance ledger](UX_EXECUTION_LEDGER.md).

## 2026-11-13 — Accept selected-account production recovery and retain branch-only proposals

- **Production mail host:** complete native admission/mutation clients with distinct locally
  born purpose keys and selected-owner enrollment. Require actual signed helper
  readiness before the Web captures clients. Use the optimized helper's finite
  30-second startup budget and support numeric `fstat` headers with/without names.
  Controlled HTTPS contact verification, refusal, restart persistence and
  exact-owned disposition pass. Record the owner's verified-contact UAT through
  PR #83. Both native allowlists and the Web selector remain restricted to the
  **selected pilot account**;
  all-user enrollment, other writers/reset, reboot readiness, independent-host
  portability and general release qualification remain separate.
- **OSMAP-ADMIN proposal:** publish the project plan and design/acceptance
  specifications on `docs/osmap-admin-project-plan-20261113` (PR #84). It proposes
  administrative architecture, database, identity lifecycle, UX, installation,
  migration/rollback and acceptance work. These are planning documents on a
  separate branch, not an implemented administrator product in main.
- **Sanitizer remediation on that branch:** advisory refresh reports
  RUSTSEC-2026-0533 for ammonia 4.1.8. Move the branch to 4.1.9 with an explicit
  compatible floor, upstream-trigger/product-policy regressions and refreshed
  security inventories. No OSMAP exploit is demonstrated. Keep the strict
  sanitizer/URL/CSP policy. Preserve two publication-gate environment failures:
  a long Unix-socket path and a fixture child ignoring its selected `TMPDIR`.
  Correct the test parent's private-root contract and retain passing normal
  local delivery evidence within its scope. This branch work does not establish
  main remediation, hosted CI, native qualification or deployment.

Sources: [`8d79901`](https://github.com/unattributed/OSMAP/commit/8d79901c512f73f146397ebaf5ade12d6e2a620d), [`42a80aa`](https://github.com/unattributed/OSMAP/commit/42a80aa93806edefcca5e9530312614ae7d700a8), [`e554811`](https://github.com/unattributed/OSMAP/commit/e554811979f6ceb6b2205041fd8740b7bccb19b5), [`9cf77a8`](https://github.com/unattributed/OSMAP/commit/9cf77a823a2a6ab02eed53fbdec959ca2468ad3f),
[`accaeb5`](https://github.com/unattributed/OSMAP/commit/accaeb5cfa9daf7f105b3efccd5752e42cb10e9d), [`6be6a8d`](https://github.com/unattributed/OSMAP/commit/6be6a8dce5dfdea358bd739f9614afbb7811c528), [`14a5250`](https://github.com/unattributed/OSMAP/commit/14a5250f41b880bf924357743f888d58ddcb58da), [`32ca9ac`](https://github.com/unattributed/OSMAP/commit/32ca9ac7f53bdcd8a87f90a71e3ac23bbe8a038d), [`fd9cf26`](https://github.com/unattributed/OSMAP/commit/fd9cf26849f7dbfcbebb1ced2cc75537d41765eb), [`b205ce0`](https://github.com/unattributed/OSMAP/commit/b205ce0d5f7f08a1bf176268edbf1040080a9855),
[`3f529eb`](https://github.com/unattributed/OSMAP/commit/3f529eb28db0f3c513a9600b8e45437d5e6cfe98), [`ae05996`](https://github.com/unattributed/OSMAP/commit/ae05996ff1b4f0af99de4208970c447381c0f72a), [`85d483a`](https://github.com/unattributed/OSMAP/commit/85d483a48dc636f488188650237e8ae8d3ff4644);
[PR #82](https://github.com/unattributed/OSMAP/pull/82),
[PR #83](https://github.com/unattributed/OSMAP/pull/83),
[PR #84 proposal/remediation branch](https://github.com/unattributed/OSMAP/pull/84).

## 2026-11-14 — Rebuild the public README and decision chronology

The owner requests a professional project entry point for sysadmins/developers
and a complete coherent design history reconstructed from main, branches and
commits. Limit this work to `README.md` and `docs/DECISION_LOG.md`: verify the
actual configuration/service/install/monitoring contracts, consolidate duplicate
and superseded statements, restore one descriptive heading per recorded day and
link historical evidence. Preserve branch-only proposals, failures, unknowns and
scoped acceptance instead of inventing broader completion.

Root owns writing/integration and Git delivery; a separate reviewer checks the
final Markdown and source claims. The exit is reviewed documentation with valid
local links/anchors and clean Markdown diff, followed by the normal signed commit
and non-forced push to `origin/main` with fresh SHA equality. Runtime, live-host,
cryptographic and broad Rust qualification are outside this documentation task.
Validation and publication results are reported with the delivered commit; this
entry is not evidence that an unexecuted check passed.

### Same day — Authorize both-host sanitizer dependency remediation

After the documentation push fails its existing ammonia4.1.8 dependency audit,
the operator explicitly requests immediate updates on the production mail host and obsd1. Carry
the published4.1.9 manifest/lock, namespace regressions and matching test/inventory
corrections from PR #84 into main, retaining the independent ADMIN proposal on its
branch. The product's strict HTML policy already excludes known prerequisite
tags; an OSMAP exploit is unproven. Qualify the real OpenBSD sanitizer/rendering
boundary, then use the existing atomic Web-only install and rollback method on
both hosts. Preserve public mail, private account/key/configuration state and
all earlier failed outcomes. The [remediation work order](UX_EXECUTION_LEDGER.md)
records the bounded tests and deployment contract; source publication and actual
installed results remain separate observations.

### Same day — Install the qualified sanitizer fix on both OpenBSD hosts

Build the exact signed source `cf7d226` with ammonia4.1.9 and verify all1519
source hashes before/after native qualification. Eleven sanitizer and32 rendering
cases pass, including the namespace triggers and legitimate formatting/fallback.
Both hosts now load the same qualified Web SHA-256
`b0fa8955b4e3a86013923214bea8e5d9efc943d77f57e8bb9484ccd840814b1d`.
Fresh loaded-image, configuration/key/account/process-preservation and TLS login
checks pass. Restart only Web and retain original binary/environment rollback
copies. No owner mail or credential operation and no full release claim.

Preserve the production host's optional-file preflight refusal and later incorrect-HTTPS-peer
failure/rollback as separate failed attempts. Read actual configuration semantics,
DNS/listeners and current recovery before the independently reviewed changed
attempt; avoid treating an administrative SSH address as the public TLS endpoint.
The existing method's success/refusal/rollback checks catch stale local consumer
assumptions and require explicit shell refusal guards. Method checks are not
native product results. See the [actual result](UX_EXECUTION_LEDGER.md).

After both server updates, the operator explicitly requests review and complete
integration of PR #84 into origin/main. Main's required-PR/local-CI protection
rejects the direct push after its normal checks pass. Integrate both signed
histories into the existing PR branch, preserve this rewritten chronology when
resolving the historical-log conflict, and keep the ADMIN specifications clearly
proposed. Ordinary signing/hooks, reviewed local-CI evidence and a protected merge
remain required; final synchronization is not inferred from the attempted push.

### Same day — Reconcile the proposed ADMIN contracts before integration

Independent PR #84 review identifies four design-document inconsistencies.
Use `pending` for first-admin enrollment, reserve `disabled` for suspension, and
require both an empty registry and unused one-shot state for bootstrap. Preserve
the current public Web TOTP verifier's reviewed user-factor/replay access while
keeping ADMIN Web out of those stores. Put proposed admin proof verification,
authoritative sessions/revocation and signing custody in the account/auth service,
with Web limited to proof relay, opaque handles and UI/CSRF state. Explicitly
retain active-frontend credential/session theft as residual risk. Align the
architecture, lifecycle, installation, UX and acceptance documents with those
boundaries. This corrects a proposed design; it implements no ADMIN service or
mail/database migration and changes neither deployed Web binary.

### Same day — Link the companion mail-platform bootstrap

The operator identifies the missing relationship between OSMAP installation and
[openbsd-mailstack](https://github.com/unattributed/openbsd-mailstack). Link its
published new-host installation, phased configuration/verification and backend
operations path before OSMAP-specific setup. Keep the existing-host path and
OSMAP's current helper/authentication/configuration contracts explicit. Its wider
Roundcube/PostfixAdmin application set does not become an OSMAP browser runtime
prerequisite, and its dated integration observations do not replace current
OSMAP procedures. This is a two-file documentation correction; no bootstrap,
host operation, service change or new installation qualification is performed.
