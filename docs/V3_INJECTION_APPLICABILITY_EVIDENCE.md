# V3 Injection Applicability Evidence

## Scope

`OSMAP-WSTG-INPV-007` records the Slice 4 applicability evidence for remaining
WSTG v4.2 injection classes that do not map to a live OSMAP browser feature:

- `WSTG-v42-INPV-05` SQL injection
- `WSTG-v42-INPV-06` LDAP injection
- `WSTG-v42-INPV-07` XML injection
- `WSTG-v42-INPV-08` SSI injection
- `WSTG-v42-INPV-09` XPath injection
- `WSTG-v42-INPV-11` code injection
- `WSTG-v42-INPV-13` format string injection
- `WSTG-v42-INPV-14` incubated vulnerability
- `WSTG-v42-INPV-18` server-side template injection
- `WSTG-v42-INPV-19` server-side request forgery

## Applicability Decisions

SQL injection is not applicable to the current OSMAP browser surface. The Rust
crate manifest has no SQL database driver such as Diesel, SQLx, rusqlite,
Postgres, or MySQL, and the application stores state in bounded flat files.

LDAP injection is not applicable. OSMAP has no LDAP client, LDAP bind, or LDAP
filter construction surface.

XML and XPath injection are not applicable. OSMAP has no XML parser, no XPath engine,
XSLT processor, SOAP endpoint, XML upload route, or XML-backed state
transition.

SSI injection is not applicable. OSMAP has no server-side include interpreter
or web-server-side dynamic include feature in the browser runtime.

Code injection and server-side template injection are not applicable. OSMAP is
compiled Rust, has no eval surface, no plugin loader, no script interpreter, and
no server-side template engine such as Tera, Handlebars, Minijinja, or Askama.

Format string injection is not applicable in the WSTG sense. Rust format macros
use compile-time format strings in OSMAP; user-controlled values are supplied as
data arguments and are HTML-escaped or treated as plain text where rendered.

SSRF is not applicable. OSMAP has no outbound HTTP client such as reqwest, ureq,
or hyper client, and the browser surface does not accept user-controlled URLs
for server-side fetching. HTML email remote-fetch surfaces are stripped by the
sanitizer rather than fetched by the server.

Incubated vulnerability coverage for the current input-validation surface is
handled by the named Slice 4 evidence lanes: reflected/stored HTML handling,
command-boundary checks, IMAP/SMTP and MIME validation, HTTP method and
parameter tampering, raw HTTP host/smuggling checks, and this applicability
review.

## Review Inputs

The runner checks:

- `Cargo.toml` and `Cargo.lock` for SQL, LDAP, XML, XPath, template-engine, and
  outbound HTTP client dependencies
- `src/` for eval-like, include-like, and outbound HTTP client markers
- parser and rendering modules for the positive controls used by adjacent
  Slice 4 evidence

If one of these technologies is added later, this row must move from
not-applicable evidence to dynamic negative testing for the new surface.
