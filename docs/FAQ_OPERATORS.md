# FAQ For Operators

## What is OSMAP Version 1 trying to replace

Version 1 is intended to replace Roundcube's core browser-based mail workflow.
It is not intended to replace the entire mail stack and it is not intended to
replace SOGo.

## Will this replace Postfix or Dovecot

No. Version 1 is explicitly defined to preserve compatibility with the existing
IMAP and SMTP submission model rather than replace the core transport layer.

## Is this supposed to replace Thunderbird

No. Native clients remain first-class. The project is designed to coexist with
Thunderbird and other established client workflows rather than force all access
through the browser.

## Is calendar or groupware part of Version 1

No. Calendar, contacts sync, and broader groupware remain out of scope for the
first release.

## Is this meant to be publicly exposed immediately

OSMAP now has approved limited direct public browser exposure on the validated
host under the conditions recorded in `INTERNET_EXPOSURE_STATUS.md`.

That approval is intentionally narrow. Public HTTPS serves the OSMAP browser
surface through nginx, while control-plane and operator-only applications stay
on the loopback and WireGuard HTTPS listener. If those exposure conditions or
the reviewed edge shape change, the internet-exposure gate must be rerun before
the approval is carried forward.

## Why keep the first release so small

Because scope control is part of the security strategy. The project is trying to
produce a more defensible replacement than Roundcube, not a broader feature
suite with more complexity.

## What must users be able to do in Version 1

At minimum:

- sign in with strong authentication
- browse mailboxes and folders
- read messages
- search mail
- compose, reply, and forward
- work with attachments
- manage sessions and log out

## What is intentionally excluded from Version 1

The first release excludes:

- plugin ecosystems
- theming frameworks
- groupware features
- mobile apps
- multi-tenant SaaS ambitions
- Proton-style zero-access claims
- broad admin surfaces in the end-user UI
