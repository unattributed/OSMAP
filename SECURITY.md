# Security Policy

## Supported State

OSMAP is still prototype-grade software. The repository contains real
implementation, but it is not yet represented as a production-ready stable
release stream.

For now, the project treats the following as in scope for responsible security
reporting:

- the current `main` branch
- the current prototype runtime and supporting documentation

## How to Report a Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Instead, report vulnerabilities privately to:

- `shopkeeper@unattributed.blog`

Please include:

- a concise summary of the issue
- affected file paths, routes, or commands if known
- reproduction steps or proof-of-concept details
- impact assessment if you have one
- whether the issue is already known to be exploitable in a live deployment

If you are unsure whether something is security-sensitive, err on the side of
private reporting first.

## What to Avoid Sending Publicly

Do not publish these in public issues or pull requests before coordination:

- secrets or credentials
- private host details not already intentionally public
- exploit chains against live systems
- attachment or message content taken from real user data

## Maintainer Response Goals

The project will try to:

- acknowledge receipt within 5 business days
- follow up with a triage assessment as soon as practical
- coordinate on disclosure timing if the report is accepted as valid

These are goals, not guaranteed SLAs.

## Disclosure Expectations

The project prefers coordinated disclosure.

Maintainers may ask reporters to delay public disclosure for a reasonable
period while:

- validating the report
- preparing a fix or mitigation
- updating deployment guidance if necessary

## Project-Specific Expectations

Because OSMAP is intended for security-sensitive OpenBSD deployments, reports in
these areas are especially valuable:

- authentication and MFA
- session lifecycle and CSRF
- HTTP parsing and malformed request handling
- attachment and message rendering behavior
- helper execution boundaries
- privilege, filesystem, and confinement issues
- dependency and supply-chain concerns

## Safe Harbor

Good-faith security research intended to improve the project is welcome.
Please avoid destructive testing, privacy violations, denial-of-service against
live systems, or persistence on systems you do not own or administer.
