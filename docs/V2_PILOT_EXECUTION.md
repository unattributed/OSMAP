# OSMAP V2 Pilot Execution Plan

## 1. Purpose
This pilot formally validates whether OSMAP V2 is:
- secure under constrained public exposure
- operationally usable for a defined user profile
- viable as a limited-scope replacement for Roundcube

This is a closure activity, not exploratory testing.
No feature development is permitted during this phase.

## 2. Scope Definition (Locked)

### 2.1 In-Scope User Profile
- security-first operators
- low to moderate email volume
- minimal reliance on advanced mailbox features
- acceptance of constrained UI and workflow

Users outside this definition are out of scope for V2.

### 2.2 Pilot Users
- duncan@blackbagsecurity.com
- duncan@redactedsecurity.ca
- ops@blackbagsecurity.io

All users:
- receive live mail
- will use OSMAP against real mailboxes
- must have TOTP enabled before testing

## 3. Pre-Pilot Setup

### 3.1 TOTP Enrollment Requirement
All users MUST:
- be provisioned with unique TOTP secrets
- successfully authenticate using password + TOTP twice

Failure blocks participation.

### 3.2 Environment Validation
Confirm:
- mail delivery functional (Postfix, Dovecot)
- login stable
- session handling working
- TLS, CSP, HSTS enforced

## 4. Pilot Duration
- minimum: 3 days
- recommended: 5 days

## 5. Mandatory Daily Workflow
Each user must perform:

1. Login (password + TOTP)
2. Inbox navigation
3. Read at least 5 emails
4. Execute 3 searches
5. Download attachment
6. Compose email
7. Reply
8. Forward
9. Logout and re-login

## 6. Edge Case Testing
Each user must test:

- invalid login + TOTP
- session expiry
- rate limiting
- large or complex emails

## 7. Logging Requirements

Each action must include:
- timestamp
- action
- expected result
- actual result
- classification (low, medium, blocking)

No vague feedback allowed.

## 8. Issue Classification

### Acceptable
- minor friction
- does not block workflow

### V3 Required
- improves usability
- not required for baseline

### V2 Blocking
- prevents workflow completion
- breaks reliability

ANY blocking issue = V2 not closed

## 9. Migration Simulation

Users must:
- stop using Roundcube
- use OSMAP only

If fallback occurs:
- record why
- record when
- record missing capability

## 10. Security Validation
- re-run WSTG scripts
- capture outputs
- verify auth, sessions, CSRF, headers

## 11. Final User Verdict

Each user must answer:

- Can I operate daily email? yes/no
- Would I adopt this? yes/no

## 12. V2 Closure Criteria

V2 is complete ONLY if:
- no blocking issues
- full workflow succeeds
- migration works for defined user
- security validation passes
- limitations documented

## 13. Deliverables

Commit:
- pilot logs
- WSTG outputs
- classification summary
- updated KNOWN_LIMITATIONS.md
- updated V2_DEFINITION.md
- new V2_CLOSEOUT.md

## 14. Expected Outcome

OSMAP is:
- secure
- constrained
- usable for defined operators

## 15. Enforcement Rule

During pilot:
- no feature development
- no scope expansion
- no architecture changes

Only:
- validation
- classification
- documentation

