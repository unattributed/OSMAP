# Emergency obsd1 OSMAP host aliases — 2026-09-14

## Decision

During the Vultr Toronto storage outage, the surviving LAN host was published
at `https://obsd1.blackbagsecurity.com/` and
`https://obsd1.mail.blackbagsecurity.com/` for owner access. The production
serve environment explicitly allowlists those two exact Host values alongside
the canonical `mail.blackbagsecurity.com`; arbitrary Host headers remain
rejected. Nginx terminates TLS for the two emergency names and continues to
proxy only to the loopback OSMAP service.

This is an availability measure, not a change to the canonical production
identity or V13 release evidence. `mail.blackbagsecurity.com` remains the Vultr
mail host, and historical evidence is not requalified against obsd1.

## Validation

The owner authenticated with password plus TOTP, opened the mailbox list, and
sent a controlled message. Postfix queue `D698A3CEA59` was accepted, delivered
through the existing Brevo relay, and removed; OSMAP stored Sent UID 261.

The OSMAP developer security gate passed after the allowlist change. No
credential, TOTP seed, session cookie, API token, or message body is retained
in this record.

## Rollback

Remove only the two obsd1 values from `OSMAP_ALLOWED_HOSTS`, restore the saved
host-local environment file, restart `osmap_serve`, and remove the emergency
DNS alias only after Toronto browser service is healthy. The canonical
`mail.blackbagsecurity.com` value must remain.
