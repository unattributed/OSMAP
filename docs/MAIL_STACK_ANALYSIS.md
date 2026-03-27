# Mail Stack Analysis

## Purpose

This document summarizes the current mail stack components that the OSMAP
replacement must preserve compatibility with.

## Confirmed Platform Components

Observed installed packages include:

- `postfix-3.10.1`
- `dovecot-2.3.21.1`
- `dovecot-mysql`
- `dovecot-pigeonhole`
- `mariadb-server-11.4.7`
- `nginx-1.26.3`
- `php-8.3.26`
- `roundcubemail-1.6.11`
- `rspamd-3.11.1p1`
- `redis-6.2.20`
- `sogo-5.11.2`

## Role Of Each Component

### Postfix

Observed behavior and notes indicate that Postfix currently provides:

- inbound SMTP on port 25
- authenticated client submission on ports 587 and 465
- the transport layer that Roundcube and native clients rely on for outbound
  mail

OSMAP must preserve that submission path or replace it only behind a compatible
interface.

### Dovecot

Observed Dovecot configuration shows:

- `protocols = imap lmtp`
- `listen = 10.44.0.1 127.0.0.1`
- `ssl = required`
- `auth_mechanisms = plain login`
- IMAP, auth, and LMTP service blocks present
- ManageSieve support enabled through the `20-managesieve.conf` path

This means the current environment already depends on a Dovecot-centered access
model that supports both browser-based and native-client mail workflows.

### Roundcube

Observed Roundcube configuration shows:

- IMAPS to `mail.blackbagsecurity.com:993`
- SMTP submission with STARTTLS to `mail.blackbagsecurity.com:587`
- application state in a local MariaDB database
- secrets layered from host-local include files
- active plugins including `archive` and `managesieve`

Roundcube is therefore a client of the mail stack, not the stack itself.

### MariaDB

Roundcube uses a dedicated local MariaDB database and secret-backed DSN. That
means migration is not purely a frontend concern. Application-side state,
sessions, preferences, and schema handling all matter.

### nginx And PHP-FPM

The web layer is split between nginx and PHP-FPM inside the OpenBSD web chroot.
Roundcube, PostfixAdmin, and other applications all rely on that operational
pattern today.

### Rspamd, Redis, And ClamAV

These services represent the anti-spam and content-inspection path around the
mail transport layer. OSMAP does not need to replace them, but it must avoid
breaking expectations around message flow, user behavior, and operational
monitoring.

### SOGo

SOGo is installed and routed through nginx, but it remains out of scope for
version 1 replacement work. Its presence still matters because it shares host
resources, namespace, and operator attention with the rest of the control plane.

## Integration Facts That Matter For OSMAP

- Mailbox users already have a working IMAP and submission model
- Native clients are part of the supported reality, not an afterthought
- Browser mail access is only one consumer of shared account credentials and
  transport services
- Authentication and session hardening decisions will have ripple effects beyond
  a single web UI

## Sysadmin Implication

From an operations perspective, the safest OSMAP design is one that minimizes
new moving parts and reuses stable mail services where possible.

## Developer Implication

From an implementation perspective, OSMAP should be treated as a thin, explicit,
well-bounded consumer of established mail services rather than as a reinvention
of the entire mail system.
