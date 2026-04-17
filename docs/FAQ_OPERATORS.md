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

No. The current validated host still uses a narrow staged exposure model for
webmail and user mail access, and OSMAP should not be treated as direct-public
ready until the repo-defined internet-exposure gate is passed.

That said, the intended Version 2 target is direct public browser access
through a hardened HTTPS edge, not a permanent VPN-only product posture.

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
