# Version 3 Client-Side Browser Security Evidence

## Scope

OSMAP is server-rendered and intentionally avoids a client-side scripting
dependency. This document records Slice 8 evidence for the remaining
client-side WSTG rows.

Mapped rows:

- `OSMAP-WSTG-CLNT-003`
- `WSTG-v42-CLNT-02` JavaScript execution
- `WSTG-v42-CLNT-03` HTML injection
- `WSTG-v42-CLNT-04` client-side URL redirect
- `WSTG-v42-CLNT-05` CSS injection
- `WSTG-v42-CLNT-06` client-side resource manipulation
- `WSTG-v42-CLNT-08` cross site flashing
- `WSTG-v42-CLNT-10` WebSockets
- `WSTG-v42-CLNT-11` web messaging
- `WSTG-v42-CLNT-12` browser storage
- `WSTG-v42-CLNT-13` cross site script inclusion

## Decisions

OSMAP has no client-side scripting dependency, no WebSocket route, no web messaging surface,
and no browser storage use. There is no Flash/SWF surface.

The current browser surface is server-rendered HTML with:

- `default-src 'none'`
- `frame-ancestors 'none'`
- escaped application text
- sanitized message HTML
- `UrlRelative::Deny` for sanitized links
- stripped scriptable tags and remote-fetch surfaces
- `rel="noopener noreferrer nofollow"` on sanitized links

HTML and CSS injection are covered by the existing rendering policy and live
HTML rendering evidence. JavaScript execution, client-side redirect, client-side
resource manipulation, Cross Site Flashing, WebSockets, web messaging, browser
storage, and cross-site script inclusion are not applicable to the current
server-rendered surface.

Future trigger: if OSMAP adds JavaScript, browser storage, WebSockets, web
messaging, service workers, client-side redirects, or another browser-executed
resource-loading feature, the affected CLNT row must move from static
applicability proof to dynamic browser tests.
