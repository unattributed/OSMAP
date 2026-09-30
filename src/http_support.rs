//! Shared HTTP response, logging, and low-level helper functions.
//!
//! These helpers are kept separate from routing so the browser boundary remains
//! easier to review without mixing protocol utilities and route behavior in one
//! file.

use crate::appearance::AppearancePreference;
use crate::attachment::DownloadedAttachment;
use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::html::{EscapedHtml, TrustedHtml};
use crate::http::HttpResponse;
use crate::logging::{EventCategory, LogEvent};
use crate::session::SessionError;
use crate::throttle::LoginThrottleError;

/// Builds a redirect response with the current browser-safety headers.
pub(crate) fn redirect_response(
    status_code: u16,
    reason_phrase: &'static str,
    location: &str,
) -> HttpResponse {
    html_response(
        status_code,
        reason_phrase,
        "Continue",
        TrustedHtml::from_template(format!(
            "<main class=\"redirect-page panel\"><h1>Continue</h1><p>Continue to <a href=\"{}\">{}</a>.</p></main>",
            escape_html(location),
            escape_html(location),
        )),
    )
    .with_header("Location", location)
}

/// Builds an HTML response with the current browser-safety headers.
///
/// Dynamically assembled strings cannot cross this boundary without first
/// becoming typed template or sanitizer output:
///
/// ```compile_fail
/// use osmap::http_support::html_response;
///
/// let untyped_html = format!("<p>{}</p>", "dynamic");
/// let _ = html_response(200, "OK", "Example", untyped_html);
/// ```
pub fn html_response(
    status_code: u16,
    reason_phrase: &'static str,
    title: &str,
    body_html: impl Into<TrustedHtml>,
) -> HttpResponse {
    let body_html = body_html.into();
    let body_html = if body_html.contains("<main ") || body_html.contains("<main>") {
        body_html
    } else {
        TrustedHtml::from_template(format!(
            "<main id=\"main-content\" class=\"standalone-notice\" tabindex=\"-1\"><section class=\"panel\"><h1>{}</h1>{}<nav aria-label=\"Return navigation\"><a class=\"button-link\" href=\"/\">Return to mail</a></nav></section></main>",
            escape_html(title), body_html))
    };
    HttpResponse::text(
        status_code,
        reason_phrase,
        format!(
            "<!doctype html><html lang=\"en\" data-appearance=\"system\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>{}</style></head><body>{}</body></html>",
            escape_html(title),
            browser_css(),
            body_html,
        ),
    )
    .with_header("Content-Type", "text/html; charset=utf-8")
    .with_header("Cache-Control", "no-store")
    .with_header("Content-Security-Policy", browser_csp())
    .with_header("Cross-Origin-Resource-Policy", "same-origin")
    .with_header("Referrer-Policy", "no-referrer")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header("X-Frame-Options", "DENY")
}

/// Presentation changes are restricted to the fixed root of our own templates.
pub(crate) fn apply_appearance(response: &mut HttpResponse, cookie: Option<&str>) {
    const PREFIX: &[u8] = b"<!doctype html><html lang=\"en\" data-appearance=\"";
    if !response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Content-Type") && value == "text/html; charset=utf-8"
    }) || response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Content-Disposition"))
        || !response.body.starts_with(PREFIX)
        || !response.body[PREFIX.len()..].starts_with(b"system\">")
    {
        return;
    }
    let appearance = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Set-Cookie"))
        .find_map(|(_, value)| {
            value
                .strip_prefix("osmap_appearance=")
                .and_then(|value| value.split(';').next())
                .and_then(AppearancePreference::parse)
        })
        .unwrap_or_else(|| AppearancePreference::from_cookie_header(cookie));
    response.body.splice(
        PREFIX.len()..PREFIX.len() + b"system".len(),
        appearance.as_str().bytes(),
    );
}

/// Builds a plain-text response with baseline non-cacheable browser headers.
///
/// CSP is intentionally omitted here because the response is served as
/// `text/plain` with `X-Content-Type-Options: nosniff`; HTML responses carry
/// the browser CSP.
pub fn plain_text_response(
    status_code: u16,
    reason_phrase: &'static str,
    body: impl Into<String>,
) -> HttpResponse {
    HttpResponse::text(status_code, reason_phrase, body)
        .with_header("Content-Type", "text/plain; charset=utf-8")
        .with_header("Cache-Control", "no-store")
        .with_header("Cross-Origin-Resource-Policy", "same-origin")
        .with_header("Referrer-Policy", "no-referrer")
        .with_header("X-Content-Type-Options", "nosniff")
}

/// Builds a forced-download response for one resolved attachment payload.
pub fn attachment_download_response(attachment: &DownloadedAttachment) -> HttpResponse {
    HttpResponse::binary(200, "OK", attachment.body.clone())
        .with_header("Content-Type", attachment.content_type.clone())
        .with_header(
            "Content-Disposition",
            build_attachment_content_disposition(&attachment.filename),
        )
        .with_header("Cache-Control", "no-store")
        .with_header("Cross-Origin-Resource-Policy", "same-origin")
        .with_header("Referrer-Policy", "no-referrer")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("X-Frame-Options", "DENY")
        .with_header(
            "Content-Security-Policy",
            "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
}

/// Returns the current narrow content-security-policy for HTML responses.
pub fn browser_csp() -> &'static str {
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

/// Returns the dependency-free CSS used by the server-rendered browser pages.
fn browser_css() -> &'static str {
    concat!(
        ":root{color-scheme:light;--bg:#f5f7fb;--panel:#ffffff;--panel-soft:#f0f4fa;--ink:#172033;--muted:#526175;--line:#d1dae6;--line-strong:#7d8999;--accent:#2563eb;--accent-strong:#1d4ed8;--on-accent:#ffffff;--link:#164db4;--selected:#e6efff;--ok:#137333;--ok-bg:#eefaf1;--ok-ink:#14532d;--ok-line:#579869;--warn:#8b5500;--warn-bg:#fff6df;--warn-ink:#684200;--warn-line:#ac791e;--danger:#b42318;--danger-bg:#fff1f0;--danger-ink:#8a1f16;--danger-line:#bd635d;--focus:#075dd7;--shadow:rgba(15,23,42,.16)}",
        ":root[data-appearance=dark]{color-scheme:dark;--bg:#0d1526;--panel:#152136;--panel-soft:#1c2b43;--ink:#ebf2fd;--muted:#aebed4;--line:#3c506d;--line-strong:#7488a4;--accent:#8dbcff;--accent-strong:#b1d0ff;--on-accent:#10213c;--link:#9bc4ff;--selected:#243f63;--ok:#8de0a9;--ok-bg:#163a2b;--ok-ink:#a3edbb;--ok-line:#589c71;--warn:#edc77b;--warn-bg:#3b301c;--warn-ink:#f4d699;--warn-line:#b18b47;--danger:#ffaba5;--danger-bg:#472725;--danger-ink:#ffc1ba;--danger-line:#c6817a;--focus:#9bc4ff;--shadow:rgba(0,0,0,.3)}",
        "@media(prefers-color-scheme:dark){:root:not([data-appearance=light]){color-scheme:dark;--bg:#0d1526;--panel:#152136;--panel-soft:#1c2b43;--ink:#ebf2fd;--muted:#aebed4;--line:#3c506d;--line-strong:#7488a4;--accent:#8dbcff;--accent-strong:#b1d0ff;--on-accent:#10213c;--link:#9bc4ff;--selected:#243f63;--ok:#8de0a9;--ok-bg:#163a2b;--ok-ink:#a3edbb;--ok-line:#589c71;--warn:#edc77b;--warn-bg:#3b301c;--warn-ink:#f4d699;--warn-line:#b18b47;--danger:#ffaba5;--danger-bg:#472725;--danger-ink:#ffc1ba;--danger-line:#c6817a;--focus:#9bc4ff;--shadow:rgba(0,0,0,.3)}}",
        "*{box-sizing:border-box}",
        "body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:var(--bg);color:var(--ink);max-width:none;margin:0;padding:0;line-height:1.5}",
        "a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}",
        "main{width:100%}",
        "h1,h2,h3,p{margin-top:0}",
        "table{border-collapse:separate;border-spacing:0;width:100%;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}",
        "th,td{border-bottom:1px solid var(--line);padding:.65rem .75rem;text-align:left;vertical-align:top}",
        "th{background:var(--panel-soft);font-size:.8rem;text-transform:uppercase;color:var(--ink);letter-spacing:0}",
        "tr:last-child td{border-bottom:0}",
        "form{margin:0}",
        "label{font-weight:650;color:var(--ink)}",
        "fieldset{margin:0;border:0}legend{font-weight:800;margin-bottom:.5rem}",
        "input,textarea,select{display:block;margin:.3rem 0 1rem;padding:.7rem .75rem;width:100%;max-width:48rem;border:1px solid var(--line-strong);border-radius:7px;background:var(--panel);color:var(--ink);font:inherit}",
        "input[type=checkbox],input[type=radio]{display:inline-block;width:auto;margin:.15rem .45rem .15rem 0}",
        "textarea{min-height:16rem}",
        "button,.button-link{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;min-height:2.35rem;padding:.55rem .9rem;border:1px solid var(--line-strong);border-radius:7px;background:var(--panel);color:var(--ink);font:inherit;font-weight:650;cursor:pointer;text-decoration:none}",
        "button:hover,.button-link:hover{border-color:var(--line-strong);text-decoration:none}",
        ".primary-button{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}",
        ".primary-button:hover{background:var(--accent-strong);border-color:var(--accent-strong)}",
        "a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--focus);outline-offset:2px}",
        "nav{margin:0}",
        "summary:focus-visible{outline:3px solid var(--focus);outline-offset:2px}",
        "input[type=checkbox],input[type=radio]{accent-color:var(--accent)}",
        ".appearance-panel{margin:1rem 0}.appearance-choices{display:flex;flex-wrap:wrap;gap:.7rem;margin-bottom:1rem}.appearance-choice{display:inline-flex;align-items:center;gap:.35rem;padding:.7rem 1rem;border:1px solid var(--line-strong);border-radius:7px;background:var(--panel-soft)}",
        ".redirect-page{max-width:40rem;margin:2rem auto}",
        ".muted{color:var(--muted)}",
        ".page-shell{min-height:100vh;padding:1.5rem;scroll-margin-top:1rem}",
        ".page-shell:focus{outline:none}",
        ".skip-link{position:absolute;left:.75rem;top:.75rem;z-index:10;transform:translateY(-150%);padding:.55rem .75rem;border:1px solid var(--line-strong);border-radius:7px;background:var(--panel);color:var(--link);font-weight:750}",
        ".skip-link:focus{transform:translateY(0);text-decoration:none}",
        ".topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1rem;padding:.8rem 1rem;background:var(--panel);border:1px solid var(--line);border-radius:8px}",
        ".brand{display:flex;align-items:center;gap:.65rem;font-weight:800;letter-spacing:.01em}",
        ".ui-icon{display:inline-block;width:1rem;height:1rem;flex:0 0 auto;vertical-align:-.15em;color:currentColor}",
        ".brand-icon{width:1.25rem;height:1.25rem}",
        ".brand-mark{display:inline-grid;place-items:center;width:2.1rem;height:2.1rem;border-radius:7px;background:var(--selected);color:var(--link);border:1px solid var(--line);font-weight:900}",
        ".top-actions,.toolbar,.status-row,.badge-list{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}",
        ".top-actions a{display:inline-flex;align-items:center;min-height:2.15rem;padding:.42rem .58rem;border-radius:7px;color:var(--ink);text-decoration:none}",
        ".top-actions a:hover,.top-actions a[aria-current=page]{background:var(--selected);color:var(--link);text-decoration:none}",
        ".logout-form{display:inline-flex}",
        ".logout-button{min-height:2.15rem;padding:.42rem .58rem}",
        ".auth-status{justify-content:flex-end}",
        ".identity-chip strong{font-weight:800}",
        ".shell-session-chip{white-space:nowrap}",
        ".badge,.status-pill{display:inline-flex;align-items:center;gap:.35rem;border:1px solid var(--line);border-radius:999px;background:var(--panel);padding:.35rem .6rem;color:var(--ink);font-size:.86rem}",
        ".badge-ok{border-color:var(--ok-line);background:var(--ok-bg);color:var(--ok-ink)}",
        ".badge-warn{border-color:var(--warn-line);background:var(--warn-bg);color:var(--warn-ink)}",
        ".notice{border:1px solid var(--line);border-radius:8px;background:var(--panel-soft);padding:.75rem .9rem;margin:.75rem 0}",
        ".notice-success{border-color:var(--ok-line);background:var(--ok-bg);color:var(--ok-ink)}",
        ".notice-error{border-color:var(--danger-line);background:var(--danger-bg);color:var(--danger-ink)}",
        ".login-page{position:relative;min-height:100vh;display:grid;justify-items:center;align-items:start;padding:2.4rem 1.5rem 1.4rem;overflow:hidden;background:radial-gradient(circle at 23% 46%,rgba(37,99,235,.1),transparent 15rem),radial-gradient(circle at 86% 30%,rgba(37,99,235,.08),transparent 14rem),linear-gradient(180deg,var(--panel) 0%,var(--panel-soft) 100%)}",
        ".login-decor{position:absolute;z-index:0;pointer-events:none;color:var(--link);opacity:.42}",
        ".login-decor-left{left:8.5%;top:18%;width:min(28vw,27rem);min-width:18rem}",
        ".login-decor-right{right:6%;top:13%;width:min(22vw,20rem);min-width:14rem;opacity:.32}",
        ".login-decor svg{display:block;width:100%;height:auto}",
        ".login-card{position:relative;z-index:1;width:min(100%,31.5rem);background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:0 20px 50px var(--shadow);padding:1.55rem 1.7rem 1.35rem}",
        ".login-brand{display:flex;align-items:center;justify-content:center;gap:1.15rem;margin-bottom:.9rem}",
        ".login-shield{flex:0 0 auto;width:4.65rem;height:4.65rem;color:var(--link);filter:drop-shadow(0 10px 14px rgba(37,99,235,.18))}",
        ".login-brand-text{min-width:0}",
        ".login-title{font-size:3rem;line-height:.94;margin:0;font-weight:850;letter-spacing:0;color:var(--ink)}",
        ".login-subtitle{font-weight:800;color:var(--link);margin:.25rem 0 0;font-size:1.05rem}",
        ".login-rule{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:.7rem;color:var(--line-strong);margin:.95rem 0 1rem}",
        ".login-rule:before,.login-rule:after{content:\"\";height:1px;background:var(--line)}",
        ".login-rule svg{width:1.1rem;height:1.1rem}",
        ".login-kicker{text-align:center;font-size:1.05rem;font-weight:800;margin:0 0 .45rem;color:var(--ink)}",
        ".login-helper{text-align:center;color:var(--muted);margin:0 auto 1rem;max-width:21rem;line-height:1.35}",
        ".login-form label{font-size:.86rem}",
        ".login-field{position:relative}",
        ".login-field svg{position:absolute;left:.85rem;top:2.35rem;width:1rem;height:1rem;color:var(--muted);pointer-events:none}",
        ".login-field input{height:2.4rem;margin:.25rem 0 .8rem;padding:.58rem .75rem .58rem 2.4rem;max-width:none;border-color:var(--line-strong);box-shadow:0 1px 0 rgba(15,23,42,.02)}",
        ".login-form .primary-button{width:100%;height:2.65rem;margin-top:.1rem;font-size:1rem}",
        ".login-lock{width:1rem;height:1rem}",
        ".login-help{margin:.75rem 0 0;text-align:center;font-size:.86rem;color:var(--link)}",
        ".security-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem;margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--line)}",
        ".security-item{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.5rem;align-items:start;padding:.25rem .1rem}",
        ".security-item svg{width:1.55rem;height:1.55rem;color:var(--ink)}",
        ".security-item strong{display:block;font-size:.78rem;line-height:1.15;text-transform:none}",
        ".security-item span{display:block;color:var(--muted);font-size:.72rem;line-height:1.2;margin-top:.15rem}",
        ".login-footer{position:relative;z-index:1;margin-top:1.05rem;text-align:center;color:var(--muted);font-size:.84rem}",
        ".login-seal{display:inline-grid;place-items:center;width:2.05rem;height:2.05rem;margin-right:.5rem;border-radius:50%;border:1px solid var(--warn-line);background:var(--warn-bg);color:var(--warn-ink);font-size:.72rem;font-weight:900;vertical-align:middle}",
        ".mail-shell{display:grid;grid-template-columns:minmax(12rem,16rem) minmax(0,1fr);gap:1rem;align-items:start}",
        ".mail-shell-three{grid-template-columns:minmax(12rem,16rem) minmax(16rem,24rem) minmax(0,1fr)}",
        ".folder-pane,.content-pane,.reading-pane,.message-summary-pane,.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px}",
        ".folder-pane{padding:.8rem}",
        ".folder-pane h2,.panel h2,.message-summary-pane h2,.reading-pane h2{font-size:.9rem;text-transform:uppercase;color:var(--ink);letter-spacing:0;margin:0 0 .65rem}",
        ".folder-list{list-style:none;padding:0;margin:0;display:grid;gap:.15rem}",
        ".folder-list a{display:block;padding:.45rem .55rem;border-radius:6px;color:var(--ink)}",
        ".folder-list a[aria-current=page],.folder-list a:hover{background:var(--selected);text-decoration:none}",
        ".content-pane,.reading-pane,.message-summary-pane,.panel{padding:1rem;min-width:0}",
        ".section-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem}",
        ".section-title{margin:0;font-size:1.35rem}",
        ".search-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.65rem;align-items:end;margin:1rem 0}",
        ".search-row input{margin-bottom:0;max-width:none}",
        ".search-row label:last-child{grid-column:1/-1}",
        ".table-wrap{overflow:auto}",
        ".message-list-table td,.message-list-table th{white-space:nowrap}",
        ".message-list-table td:nth-child(3),.message-list-table td:nth-child(4){white-space:normal}",
        ".message-list-summary{justify-content:flex-end}",
        ".message-row{background:var(--panel)}",
        ".message-row:hover{background:var(--panel-soft)}",
        ".message-row[data-selected=true]{background:var(--selected)}.message-row .message-subject-link{font-weight:500}.message-unread .message-subject-link{font-weight:800}.message-unread .message-subject-link::before{content:\"\";display:inline-block;width:.45rem;height:.45rem;margin-right:.5rem;border-radius:50%;background:var(--link)}",
        ".message-filters,.list-pagination{display:flex;gap:.65rem;align-items:center;flex-wrap:wrap}.list-navigation{margin:1rem 0;display:flex;align-items:center;justify-content:space-between;gap:.6rem 1rem;flex-wrap:wrap}.list-window{margin:0;font-size:.86rem}.filter-link{padding:.45rem .75rem;border:1px solid var(--line-strong);border-radius:.5rem;color:var(--ink)}.filter-link[aria-current=page]{background:var(--selected);color:var(--link);font-weight:750}.list-pagination{font-size:.86rem}.message-star{font-size:1.15rem;color:var(--muted);margin-right:.45rem}.message-star[aria-label=Starred]{color:var(--warn)}",
        ".message-state-controls{display:flex;align-items:center;gap:.4rem;flex-wrap:wrap}.message-state-form{display:inline-flex;margin:0}.flag-control{min-height:36px;min-width:36px;padding:.3rem .5rem;font-size:.85rem}.flag-control[aria-pressed=true]{background:var(--selected);color:var(--link)}.state-unavailable{display:block;font-size:.75rem}.attachment-count{font-size:.75rem}",
        ".message-uid-cell,.message-size-cell,.message-action-cell{white-space:nowrap}",
        ".message-subject-cell{min-width:18rem;white-space:normal}",
        ".message-subject-link{display:inline-block;font-weight:800;color:var(--link);overflow-wrap:anywhere}",
        ".message-preview-meta{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.18rem;color:var(--muted);font-size:.84rem}",
        ".message-from-cell,.message-date-cell,.message-flags-cell{color:var(--ink)}",
        ".message-flags{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:.12rem .45rem;background:var(--panel-soft);font-size:.82rem;white-space:nowrap}",
        ".message-empty-state{padding:1.2rem;text-align:center;background:var(--panel-soft);border:1px dashed var(--line-strong);border-radius:8px}",
        ".message-meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.35rem .75rem;margin:0 0 1rem}",
        ".message-meta dt{font-weight:750;color:var(--ink)}.message-meta dd{margin:0;overflow-wrap:anywhere}",
        ".reader-meta{margin-top:.8rem}",
        ".protected-trust-strip{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin:0 0 1rem;padding:1rem;border:1px solid var(--ok-line);border-left:6px solid var(--ok);border-radius:8px;background:var(--ok-bg);color:var(--ok-ink)}",
        ".protected-trust-strip strong{display:block;font-size:1.05rem;margin-bottom:.2rem}",
        ".protected-trust-strip p{margin:0;color:var(--ok-ink)}",
        ".trust-strip-badges,.reader-badge-list{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap}",
        ".protected-reading-pane{display:grid;grid-template-columns:minmax(0,1fr);gap:1rem}.protected-reading-pane>*{min-width:0}",
        ".reader-section-heading{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:.5rem}",
        ".reader-section-heading h2{margin:0}",
        ".reader-boundary-note{margin:.35rem 0 .85rem}",
        ".body-panel [data-protected-body-panel='true']{border-color:var(--line)}",
        ".openpgp-reader-states{padding:1rem;border:1px solid var(--warn-line);border-left:6px solid var(--warn-line);border-radius:8px;background:var(--warn-bg);color:var(--warn-ink)}",
        ".openpgp-reader-states strong{display:block;font-size:1.05rem;margin-bottom:.2rem}",
        ".openpgp-reader-states p{margin:.25rem 0;color:var(--warn-ink)}",
        ".openpgp-state-list{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.35rem .75rem;margin:.75rem 0 0}",
        ".openpgp-state-list dt{font-weight:750;color:var(--warn-ink)}",
        ".openpgp-state-list dd{margin:0;overflow-wrap:anywhere}",
        ".openpgp-boundary-note{margin-top:.75rem}",
        ".openpgp-compose-controls{margin:1rem 0;border-color:var(--warn-line);border-left:6px solid var(--warn-line);background:var(--warn-bg);color:var(--warn-ink)}",
        ".openpgp-compose-controls h2{margin:0 0 .55rem}",
        ".openpgp-compose-controls p{margin:.25rem 0;color:var(--warn-ink)}",
        ".openpgp-compose-option-list{display:grid;gap:.45rem;margin:.75rem 0;padding:.75rem;border:1px dashed var(--warn-line);border-radius:8px;background:var(--panel)}",
        ".openpgp-compose-option-list label{display:flex;align-items:center;gap:.35rem;font-weight:700;color:var(--warn-ink)}",
        ".openpgp-compose-option-list input{margin:0;width:auto}",
        ".openpgp-compose-boundary-note{margin-top:.75rem}",
        ".account-security-panel{margin:1rem 0;border-color:var(--line)}",
        ".openpgp-account-security{display:grid;gap:.75rem;margin-top:.75rem;padding:1rem;border:1px solid var(--warn-line);border-left:6px solid var(--warn-line);border-radius:8px;background:var(--warn-bg);color:var(--warn-ink)}",
        ".openpgp-account-security p{margin:.25rem 0;color:var(--warn-ink)}",
        ".openpgp-account-badges{display:flex;gap:.45rem;flex-wrap:wrap}",
        ".openpgp-account-control-set{display:grid;gap:.45rem;margin:.5rem 0 0;padding:.75rem;border:1px dashed var(--warn-line);border-radius:8px;background:var(--panel)}",
        ".openpgp-account-control-set label{display:flex;align-items:center;gap:.35rem;font-weight:700;color:var(--warn-ink)}",
        ".openpgp-account-control-set input{margin:0;width:auto}",
        ".openpgp-account-boundary-note{margin-top:.5rem}",
        ".action-stack{display:grid;gap:.75rem;margin-top:1rem}",
        ".body-panel{padding:1rem;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:auto}",
        ".attachment-list{list-style:none;padding:0;margin:.5rem 0 0;display:grid;gap:.5rem}",
        ".attachment-item{min-width:0;overflow-wrap:anywhere;border:1px solid var(--line);border-radius:8px;padding:.65rem;background:var(--panel-soft)}",
        ".message-html{overflow-wrap:anywhere}",
        ".message-html p,.message-html ul,.message-html ol,.message-html blockquote,.message-html pre,.message-html table{margin:.75rem 0}",
        ".message-html pre,pre{white-space:pre-wrap;overflow-wrap:anywhere}",
        ".message-html a{word-break:break-word}",
        ".message-html a[href]::after{content:\" (\" attr(href) \")\";font-size:.86em;color:var(--muted);overflow-wrap:anywhere}",
        "@media (prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}",
        "@media (max-width:40rem){.message-list-table th,.message-list-table td{padding:.5rem}.toolbar,.badge-list{align-items:stretch;flex-direction:column}.button-link,button{width:100%}}",
        "@media (max-width:56rem){.page-shell{padding:.75rem}.topbar,.section-header{align-items:stretch;flex-direction:column}.mail-shell,.mail-shell-three{grid-template-columns:1fr}.search-row{grid-template-columns:1fr}.login-card{padding:1.25rem}.login-title{font-size:2.35rem}.login-shield{width:3.8rem;height:3.8rem}.security-grid{grid-template-columns:1fr}.login-decor{display:none}}",
        ":root{--rail-width:4.75rem;--topbar-height:4.25rem}",
        "body:has(.rail-disclosure[open]){--rail-width:13rem}",
        ".sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}",
        ".shell-icon{display:block;width:1.35rem;height:1.35rem;flex:0 0 auto;color:currentColor}",
        ".app-rail{position:fixed;inset:0 auto 0 0;width:var(--rail-width);z-index:20;display:flex;flex-direction:column;gap:1rem;padding:.8rem .6rem;background:var(--panel);border-right:1px solid var(--line);overflow-y:auto;overflow-x:hidden}",
        ".rail-disclosure summary{display:flex;align-items:center;justify-content:center;min-height:2.65rem;width:2.65rem;cursor:pointer;border:1px solid transparent;border-radius:.6rem;list-style:none;color:var(--muted)}",
        ".rail-disclosure summary::-webkit-details-marker{display:none}",
        ".rail-disclosure summary:hover{background:var(--panel-soft);color:var(--ink)}",
        ".rail-collapse-label{display:none}.rail-disclosure[open] .rail-collapse-label{display:block}.rail-disclosure[open] .rail-expand-label{display:none}",
        ".rail-links{display:grid;gap:.5rem}.rail-link{display:flex;align-items:center;justify-content:center;gap:.85rem;min-height:2.9rem;padding:.65rem;border:1px solid transparent;border-radius:.65rem;color:var(--muted);font-weight:650}",
        ".rail-link:hover{background:var(--panel-soft);color:var(--ink);text-decoration:none}.rail-link[aria-current=page]{background:var(--selected);color:var(--link);border-color:var(--line-strong)}",
        ".rail-label{display:none}.rail-disclosure[open]~.rail-links .rail-label{display:block}.rail-disclosure[open]~.rail-links .rail-link{justify-content:flex-start}",
        ".rail-compose{background:var(--accent);color:var(--on-accent);margin-bottom:.45rem}.rail-compose:hover,.rail-compose[aria-current=page]{background:var(--accent-strong);color:var(--on-accent)}",
        ".topbar{position:relative;margin:0 0 0 var(--rail-width);min-height:var(--topbar-height);padding:.75rem 1.5rem;border:0;border-bottom:1px solid var(--line);border-radius:0;flex-direction:row;align-items:center;flex-wrap:wrap}",
        ".brand{color:var(--ink);font-size:1.15rem;flex:0 0 auto}.brand:hover{text-decoration:none}.brand-mark{background:var(--selected);color:var(--link);border:0;width:2.1rem;height:2.1rem}.brand-icon,.brand-icon .shell-icon{display:block;width:1.4rem;height:1.4rem}",
        ".page-shell{width:calc(100% - var(--rail-width));margin-left:var(--rail-width);min-height:calc(100vh - var(--topbar-height));padding:1.5rem}",
        ".auth-status{min-width:0;flex-wrap:nowrap;gap:.8rem}.account-menu{position:relative;min-width:0}.account-menu summary{display:flex;align-items:center;gap:.5rem;min-height:2.65rem;padding:.35rem .5rem;cursor:pointer;list-style:none;border:1px solid transparent;border-radius:.5rem}.account-menu summary::-webkit-details-marker{display:none}.account-menu summary:hover,.account-menu[open] summary{background:var(--panel-soft);border-color:var(--line-strong)}",
        ".account-name{display:block;max-width:min(30vw,26rem);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.9rem;font-weight:650}.account-menu summary .shell-icon{width:1rem;height:1rem}",
        ".account-menu-panel{position:absolute;right:0;top:calc(100% + .5rem);z-index:30;width:min(21rem,calc(100vw - var(--rail-width) - 1.5rem));padding:1rem;background:var(--panel);border:1px solid var(--line-strong);border-radius:.65rem;box-shadow:0 12px 30px var(--shadow);overflow-wrap:anywhere}",
        ".account-menu-panel p{font-size:.85rem;padding-bottom:.65rem;border-bottom:1px solid var(--line)}.account-menu-panel a{display:block;padding:.6rem;border-radius:.35rem}.account-menu-panel a:hover{background:var(--panel-soft)}.account-menu-panel .logout-form{display:block;margin-top:.5rem;padding-top:.7rem;border-top:1px solid var(--line)}.account-menu-panel .logout-button{width:100%}",
        "@media(max-width:56rem){.topbar{padding:.65rem .8rem;gap:.5rem}.page-shell{padding:.85rem}.auth-status{gap:.35rem}.account-name{max-width:23vw}}",
        "@media(max-width:40rem){:root{--rail-width:3.5rem}body:has(.rail-disclosure[open]){--rail-width:3.5rem}.app-rail{padding:.6rem .3rem;gap:.65rem}.app-rail:has(.rail-disclosure[open]){width:13rem;box-shadow:10px 0 25px var(--shadow)}.rail-link{min-height:2.8rem;padding:.5rem}.topbar{align-items:flex-start;min-height:4rem}.brand{font-size:1rem}.brand-mark{width:1.7rem;height:1.7rem}.auth-status{flex-wrap:wrap;justify-content:flex-end;max-width:65%}.shell-session-chip{font-size:.72rem;padding:.2rem .4rem}.account-name{max-width:31vw;font-size:.8rem}.account-menu summary{padding:.15rem .25rem;min-height:2rem}.page-shell{padding:.65rem}.account-menu-panel{width:min(19rem,calc(100vw - 4.5rem))}}",
        ".skip-link{z-index:50}.account-menu{position:static}.account-menu-panel{right:.75rem}",
        "@media(max-width:40rem){.openpgp-state-list,.message-meta{grid-template-columns:1fr;gap:.2rem}.openpgp-state-list dt,.message-meta dt{margin-top:.35rem}.openpgp-state-list dd,.message-meta dd{margin-bottom:.4rem}.openpgp-account-security{padding:.75rem}}",
        "@media(forced-colors:active){.rail-link[aria-current=page]{outline:2px solid Highlight;outline-offset:-3px}.rail-compose{border-color:ButtonText}.account-menu-panel{border:2px solid CanvasText}.shell-icon{forced-color-adjust:auto}}",
        ".standalone-notice{max-width:46rem;margin:clamp(1rem,7vh,5rem) auto;padding:1rem}.standalone-notice h1{font-size:1.65rem}.standalone-notice nav{margin-top:1.5rem}",
        ".page-intro{margin-bottom:1.25rem}.page-intro p{margin:.35rem 0 0;color:var(--muted);max-width:52rem}.page-intro h1{margin:0;font-size:1.8rem;line-height:1.25}",
        ".protection-menu summary{display:flex;align-items:center;gap:.4rem;min-height:2.25rem;padding:.35rem .6rem;border:1px solid var(--ok-line);border-radius:.5rem;background:var(--ok-bg);color:var(--ok-ink);cursor:pointer;list-style:none;font-size:.85rem;font-weight:650}.protection-menu summary::-webkit-details-marker{display:none}.protection-menu summary .shell-icon{width:1rem;height:1rem}.protection-menu .account-menu-panel{max-width:23rem}.protection-menu .account-menu-panel p{border:0;padding:0;margin:0}",
        ".settings-pane{max-width:80rem;margin:0 auto;padding:0;background:transparent;border:0}.settings-pane .panel{padding:1.25rem}.settings-pane .account-security-panel{margin-top:0}.settings-pane .panel h2{font-size:1.05rem;text-transform:none;letter-spacing:0}",
        ".settings-pane .openpgp-account-security{padding:0;border:0;background:transparent;color:var(--ink);gap:.7rem}.settings-pane .openpgp-account-security p{color:var(--muted)}.settings-pane .openpgp-account-badges{align-items:center}.settings-pane .openpgp-account-control-set{margin-top:1rem;background:var(--panel-soft);border-color:var(--line-strong)}",
        ".security-disclosure summary,.protected-trust-strip summary,.openpgp-reader-states summary,.openpgp-compose-controls summary{cursor:pointer;font-weight:650;min-height:2.5rem;align-content:center}.security-disclosure summary{color:var(--link)}.security-disclosure[open] summary{margin-bottom:.75rem}.security-disclosure .openpgp-state-list{grid-template-columns:10rem minmax(0,1fr)}",
        ".settings-pane .appearance-panel{margin:1rem 0}.appearance-panel form{display:flex;flex-wrap:wrap;gap:.8rem 1.5rem;align-items:flex-end;justify-content:space-between}.appearance-panel fieldset{padding:0;min-width:0}.appearance-panel legend{font-size:.85rem;color:var(--muted)}.appearance-choices{margin:0;gap:.5rem}.appearance-choice{padding:.45rem .65rem}.appearance-panel button{margin-bottom:0}",
        ".preferences-form-wrap .action-stack{grid-template-columns:1fr 1fr;align-items:stretch}.preferences-form-wrap .action-stack>div{grid-column:1/-1}.preferences-form-wrap .action-stack fieldset{min-width:0}.preferences-form-wrap .action-stack input[type=text]{max-width:none}.principles-strip{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-top:1.5rem;padding:1.15rem 1.25rem;background:var(--panel);border:1px solid var(--line);border-radius:.65rem}.principles-strip p{margin:0}.principles-list{display:flex;flex-wrap:wrap;gap:.6rem 1rem;font-size:.82rem;color:var(--muted)}",
        ".protected-trust-strip,.openpgp-reader-states{display:block;margin:0 0 .8rem;padding:.35rem .85rem;border-left-width:3px}.protected-trust-strip summary,.openpgp-reader-states summary{display:flex;align-items:center;justify-content:space-between;gap:.5rem;flex-wrap:wrap}.protected-trust-strip summary strong,.openpgp-reader-states summary strong{margin:0;font-size:.9rem}.protected-trust-strip>div,.openpgp-reader-states>div{padding:.45rem 0}.protected-trust-strip p,.openpgp-reader-states p{font-size:.86rem}",
        ".openpgp-compose-controls{padding:.4rem .85rem;margin:.75rem 0 1rem;border-left-width:3px}.openpgp-compose-controls summary{display:flex;justify-content:space-between;gap:.6rem;flex-wrap:wrap}.openpgp-compose-controls summary span{font-size:.85rem;color:var(--warn-ink)}.openpgp-compose-controls>p{font-size:.86rem}.openpgp-compose-option-list{margin-top:.6rem}",
        ".reader-layout{grid-template-columns:minmax(10rem,13rem) minmax(13rem,19rem) minmax(0,1fr)}.reader-layout>.folder-pane,.reader-layout>.message-summary-pane,.reader-layout>.reading-pane{min-width:0}.reader-layout .message-meta{grid-template-columns:1fr;gap:.1rem}.reader-layout .message-meta dd{margin-bottom:.4rem}.reader-layout .toolbar{align-items:stretch}.reader-layout .toolbar a{flex:1}.reader-layout .action-stack p{font-size:.85rem}.reader-layout .body-panel{padding:.85rem}",
        ".notice{overflow-wrap:anywhere}.content-pane p,.panel p,.reading-pane p,.message-summary-pane p{overflow-wrap:anywhere}.table-wrap{max-width:100%;min-width:0}input::placeholder,textarea::placeholder{color:var(--muted);opacity:1}",
        "@media(max-width:72rem){.reader-layout{grid-template-columns:minmax(11rem,15rem) minmax(0,1fr)}.reader-layout>.reading-pane{grid-column:1/-1}.reader-layout .message-meta{grid-template-columns:8rem minmax(0,1fr)}}",
        "@media(max-width:56rem){.preferences-form-wrap .action-stack{grid-template-columns:1fr}.reader-layout{grid-template-columns:1fr}.reader-layout>.reading-pane{grid-column:auto}.page-intro h1{font-size:1.55rem}.settings-pane .panel{padding:1rem}}",
        "@media(max-width:40rem){.protection-menu summary{font-size:.72rem;min-height:1.8rem;padding:.2rem .35rem}.protection-menu summary .shell-icon{width:.85rem;height:.85rem}.topbar{flex-wrap:nowrap}.auth-status{flex:1;max-width:none}.shell-session-chip{display:none}.security-disclosure .openpgp-state-list,.reader-layout .message-meta{grid-template-columns:1fr}.appearance-panel form{display:block}.appearance-panel button{margin-top:.85rem}.appearance-choice{padding:.4rem .55rem;font-size:.9rem}.appearance-choices{gap:.4rem}.principles-strip{padding:1rem}.settings-pane .panel{padding:.9rem}.reader-layout .protected-trust-strip summary,.reader-layout .openpgp-reader-states summary{display:block}}",
        ".table-wrap:focus-visible{outline:3px solid var(--focus);outline-offset:2px}",
        ".global-search-menu{position:static;margin-right:auto}.global-search-menu>summary{cursor:pointer;color:var(--link);font-size:.88rem;min-height:36px;align-content:center;padding:.35rem .65rem;border:1px solid var(--line-strong);border-radius:.5rem}.global-search-panel{width:min(25rem,calc(100vw - var(--rail-width) - 1.5rem))}.global-search-panel input{max-width:100%;margin:.35rem 0}.global-search-panel form{margin:0 0 .85rem}.global-search-panel button{width:100%}.global-search-panel h2{font-size:.9rem;margin:.6rem 0}.global-search-panel nav{display:grid;grid-template-columns:1fr 1fr;gap:.25rem}.global-search-panel nav h2{grid-column:1/-1}.global-search-panel nav a{font-size:.85rem;padding:.5rem;overflow-wrap:anywhere}.global-search-panel nav a:hover{background:var(--panel-soft)}",
        ".message-avatar{grid-column:1;grid-row:1/span 4;display:flex;align-items:center;justify-content:center;width:2.1rem;height:2.1rem;border-radius:50%;background:var(--selected);color:var(--link);font-size:.78rem;font-weight:700;unicode-bidi:isolate}.message-body-preview{grid-column:2/-1;grid-row:3;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:1;overflow:hidden;overflow-wrap:anywhere;font-size:.8rem;color:var(--muted);unicode-bidi:plaintext}.bulk-selection-menu{margin:.4rem 0}.bulk-selection-menu summary{color:var(--link);font-size:.85rem;cursor:pointer;min-height:36px;align-content:center}.bulk-selection-menu nav{display:flex;gap:.5rem;flex-wrap:wrap;margin:.4rem 0}.bulk-selection-menu nav a{border:1px solid var(--line-strong);border-radius:.4rem;padding:.4rem .6rem;font-size:.83rem}.bulk-selection-menu p{font-size:.8rem;margin:.4rem 0}",
        "@media(max-width:40rem){.topbar:has(.global-search-menu){flex-wrap:wrap}.topbar:has(.global-search-menu) .auth-status{flex-basis:100%;justify-content:space-between}.global-search-menu{margin:0 0 0 auto}.global-search-menu>summary{padding:.25rem .5rem}.message-avatar{width:1.8rem;height:1.8rem}.message-body-preview{grid-column:2}.global-search-panel nav{grid-template-columns:1fr}}",
        ".message-filters{gap:.35rem;font-size:.84rem}.filter-link{padding:.4rem .5rem}.list-navigation{margin:.6rem 0;gap:.4rem 1rem}.list-pagination{gap:.4rem}.list-pagination .button-link{width:auto;min-height:36px;padding:.4rem .6rem}.message-list-summary{margin:0}",
        ".compact-search{grid-template-columns:minmax(0,1fr) auto;gap:.45rem .65rem;margin:.75rem 0}.compact-search>label{grid-column:auto!important}.compact-search>button{margin:0;min-width:5rem;min-height:48px}.search-options{grid-column:1/-1}.search-options>summary{cursor:pointer;color:var(--link);min-height:36px;align-content:center;font-size:.85rem}.search-options>div{display:flex;flex-wrap:wrap;align-items:center;gap:.65rem 1rem;padding:.5rem 0}.search-options label{margin:0;max-width:100%;font-size:.85rem}.search-options select{margin:0;max-width:100%}.search-options input[type=checkbox]{width:auto;margin:0 .35rem 0 0}.search-context{display:flex;flex-wrap:wrap;gap:.3rem 1rem;font-size:.83rem;color:var(--muted);margin:.4rem 0}",
        ".message-cards{list-style:none;margin:.8rem 0 0;padding:0;display:grid;gap:.35rem}.message-card{min-width:0;padding:.85rem 1rem;border:1px solid var(--line);border-inline-start:3px solid transparent;border-radius:.55rem}.message-card[data-selected=true]{border-inline-start-color:var(--focus)}.message-card-main{display:grid;grid-template-columns:2.1rem minmax(0,1fr) auto;gap:.2rem 1rem;align-items:baseline}.message-sender{grid-column:2;grid-row:1;font-size:.9rem;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.message-unread .message-sender{font-weight:750}.message-date{grid-column:3;grid-row:1;font-size:.78rem;color:var(--muted);overflow-wrap:anywhere}.message-card .message-subject-link{grid-column:2/-1;grid-row:2;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden;min-height:1.7rem;line-height:1.5;padding:.15rem 0;color:var(--ink)}",
        ".message-card-footer{display:flex;gap:.5rem .85rem;align-items:center;margin-top:.35rem}.message-card-footer .message-state-controls{flex:1}.message-mailbox{font-size:.75rem;overflow-wrap:anywhere}.message-card .flag-control{width:auto;min-width:36px}.message-card .message-star{margin:0}.message-more{min-width:0;max-width:100%}.message-more summary,.message-sort summary,.bulk-actions>summary{cursor:pointer;min-height:36px;align-content:center;font-size:.86rem;color:var(--link)}.message-more-content{padding:.65rem;background:var(--panel-soft);border:1px solid var(--line);border-radius:.4rem}.message-more-content p{margin:.2rem 0 .65rem}.message-more-content form{margin:.5rem 0 0}.bulk-row-choice{display:flex;align-items:center;gap:.5rem;font-size:.85rem;margin:.4rem 0}.bulk-row-choice input{margin:0;width:auto}",
        ".message-card:has(>.bulk-row-choice){display:grid;grid-template-columns:1.5rem minmax(0,1fr);column-gap:.5rem}.message-card>.bulk-row-choice{grid-column:1;grid-row:1;margin:0;align-self:start;min-height:32px}.message-card>.bulk-row-choice input{width:20px;height:20px}.message-card:has(>.bulk-row-choice)>.message-card-main{grid-column:2;grid-row:1}.message-card:has(>.bulk-row-choice)>.message-card-footer{grid-column:2;grid-row:2}.message-move-controls .toolbar,.bulk-move-controls .toolbar{display:flex;flex-direction:row;flex-wrap:wrap;gap:.5rem}.message-move-controls button,.bulk-move-controls button{width:auto}.message-move-controls,.bulk-move-controls{min-width:0;max-width:100%}",
        ".message-sort{margin:.4rem 0}.message-sort nav{display:flex;flex-wrap:wrap;gap:.5rem;padding:.5rem 0}.message-sort a{padding:.4rem .6rem;border:1px solid var(--line-strong);border-radius:.4rem}.message-sort a[aria-current=true]{background:var(--selected);font-weight:750}.bulk-actions{margin:.5rem 0}.bulk-actions>p{font-size:.85rem;margin:.35rem 0}.bulk-actions .toolbar{padding:.65rem;background:var(--panel-soft);border:1px solid var(--line);border-radius:.4rem}.message-card .attachment-count{padding:.1rem .35rem;white-space:normal}.message-card .state-unavailable{font-size:.75rem}",
        "@media(max-width:40rem){.message-card{padding:.65rem}.message-card-main{grid-template-columns:1.8rem minmax(0,1fr);gap:.15rem .5rem}.message-card .message-subject-link{grid-row:2;grid-column:2}.message-date{grid-column:2;grid-row:4}.message-card-footer{gap:.35rem .5rem}.message-card-footer .message-state-controls{flex-basis:100%}.message-more{flex-basis:100%}.message-more summary{width:max-content}.message-card .flag-control{min-height:40px}.message-sort nav{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}}",
        ".coordinated-mail{display:grid;grid-template-columns:minmax(23rem,32rem) minmax(0,1fr);gap:1rem;align-items:start}.coordinated-mail>*{min-width:0}.coordinated-list{padding:1rem}.coordinated-list .list-navigation{display:block}.coordinated-list .list-window{margin:.4rem 0}.coordinated-list .message-card-main{grid-template-columns:1.8rem minmax(0,1fr);gap:.15rem .5rem}.coordinated-list .message-date{grid-column:2;grid-row:4}.coordinated-list .message-card-footer{flex-wrap:wrap}.coordinated-list .message-card{padding:.65rem}.coordinated-list .message-avatar{width:1.8rem;height:1.8rem}.reader-column,.reading-pane{min-width:0}.reader-empty{min-height:24rem;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center}.reader-navigation{display:flex;flex-wrap:wrap;gap:.6rem 1.5rem;font-size:.84rem;margin-bottom:1rem}.message-heading h2{font-size:1.5rem;margin:.4rem 0;overflow-wrap:anywhere}.message-heading p{margin:.35rem 0;overflow-wrap:anywhere}.message-heading>p:first-child{font-size:.8rem}.reader-primary-actions{margin:.85rem 0;gap:.5rem}.reader-primary-actions .message-state-controls{display:flex;flex-wrap:wrap;gap:.4rem}.reader-more-actions>summary,.reader-details>summary{min-height:36px;align-content:center;cursor:pointer;color:var(--link);font-size:.85rem}.reader-more-actions{margin:.35rem 0 .75rem}.reader-more-actions .action-stack{padding:.6rem 0}.reading-pane .reader-status{margin:.5rem 0}.reading-pane .reader-status summary{font-size:.83rem}.reading-pane .body-panel{padding:.75rem}.reading-pane .body-panel>h2{font-size:1rem;margin:0 0 .4rem}.reading-pane .reader-boundary-note{font-size:.78rem;margin:.35rem 0 .75rem}.reading-pane .body-panel pre{white-space:pre-wrap;overflow-wrap:anywhere}.reader-details{margin-top:1rem}.reader-details .message-meta{grid-template-columns:7rem minmax(0,1fr)}.reader-attachments{margin-top:1rem}.reader-attachments h2{font-size:1rem}.reader-locate{margin:0 0 .6rem;font-size:.85rem}.standalone-reader{max-width:78rem;margin:0 auto}.reading-pane:focus-visible{outline:3px solid var(--focus);outline-offset:2px}",
        "@media(max-width:72rem){.coordinated-mail{grid-template-columns:1fr}.coordinated-mail:not(.has-selection) .reader-empty{display:none}.coordinated-mail.has-selection>.coordinated-list{display:none}.coordinated-list{padding:.8rem}.message-heading h2{font-size:1.3rem}.reader-primary-actions .message-state-controls{flex-basis:100%}.reader-details .message-meta{grid-template-columns:1fr}.reading-pane .reader-status summary{display:block}.reading-pane .reader-status summary span{display:block;font-size:.8rem}}",
        ".protected-reading-pane{gap:.6rem}.reading-pane .message-heading h2{text-transform:none;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow:hidden}.reading-pane .message-from{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden}.reader-navigation{margin-bottom:0}.reader-primary-actions{flex-direction:row;align-items:center;flex-wrap:wrap;margin:.3rem 0}.reader-primary-actions>.button-link{width:auto;min-height:40px}.reader-primary-actions .flag-control{width:auto}.reader-primary-actions .message-state-controls{min-width:0}.reader-more-actions{margin:0}.reading-pane .reader-status{margin:0}",
        "@media(forced-colors:active){.message-card[data-selected=true]{border-inline-start-color:Highlight;outline:1px solid Highlight}.message-card[data-selected=true] .message-subject-link{color:LinkText}}",
        "@media(max-width:20rem){:root,body:has(.rail-disclosure[open]){--rail-width:0rem}.app-rail,.app-rail:has(.rail-disclosure[open]){position:relative;inset:auto;width:100%;padding:.4rem;gap:.4rem;border-right:0;border-bottom:1px solid var(--line);box-shadow:none;overflow:visible}.rail-links{display:none}.rail-disclosure[open]~.rail-links{display:grid}.topbar{flex-direction:column;align-items:stretch;padding:.6rem;gap:.5rem}.auth-status{align-items:stretch;flex-direction:column}.account-menu summary{justify-content:space-between}.account-name{max-width:calc(100vw - 4rem)}.account-menu-panel{right:.5rem;width:calc(100vw - 1rem)}.page-shell{padding:.5rem}.mail-shell>*{min-width:0}.content-pane,.reading-pane,.message-summary-pane,.folder-pane,.panel{padding:.65rem}h1,h2,h3,legend,.badge{overflow-wrap:anywhere}.button-link,button{min-width:0;overflow-wrap:anywhere}fieldset{min-width:0;padding:.5rem}legend{max-width:100%}.login-page{padding:1rem .5rem}.login-card{padding:.75rem}.login-brand{flex-direction:column;gap:.65rem}.login-title{font-size:2rem}.login-shield{width:3rem;height:3rem}.standalone-notice{padding:.65rem}}"
        , include_str!("http/approved.css")
    )
}

/// Builds a structured HTTP info event with the shared request fields attached.
pub(crate) fn build_http_info_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Info, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Builds a structured HTTP warning event with the shared request fields
/// attached.
pub(crate) fn build_http_warning_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Warn, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Builds a structured auth warning event with the shared request fields
/// attached.
pub(crate) fn build_auth_warning_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Warn, EventCategory::Auth, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Maps session errors into small stable labels for browser-operation logs.
pub(crate) fn session_error_label(error: &SessionError) -> &'static str {
    match error {
        SessionError::InvalidToken { .. } => "invalid_token",
        SessionError::RandomSourceFailure { .. } => "random_source_failure",
        SessionError::StoreFailure { .. } => "store_failure",
        SessionError::SessionNotFound { .. } => "session_not_found",
    }
}

/// Maps throttle-store errors into small stable labels for auth-abuse logs.
pub(crate) fn throttle_store_error_label(error: &LoginThrottleError) -> &'static str {
    match error {
        LoginThrottleError::StoreFailure { .. } => "store_failure",
    }
}

/// Maps a public reason string into a small browser-facing message.
pub(crate) fn public_reason_message(reason: &str) -> &'static str {
    match reason {
        "invalid_credentials" => "The supplied credentials were not accepted.",
        "invalid_archive_mailbox" => {
            "The selected archive mailbox does not exist for this account."
        }
        "invalid_mailbox" => "The selected mailbox does not exist for this account.",
        "invalid_message_reference" => "The selected message was not found in that mailbox.",
        "invalid_request" => "The submitted request was not valid.",
        "draft_conflict" => "This draft changed in another tab or was deleted. Your changes have not overwritten the saved version. Open the saved version separately to compare your text.",
        "draft_quota_exceeded" => "Your draft storage is full. Remove an unneeded draft, then save again. Your current text is retained here.",
        "draft_busy" => "Another draft operation is still running. Your text is retained; try saving again shortly.",
        "invalid_second_factor" => "The supplied credentials were not accepted.",
        "too_many_attempts" => "Too many login attempts were observed. Please try again later.",
        "too_many_submissions" => {
            "Too many outbound submissions were observed. Please try again later."
        }
        "too_many_message_moves" => {
            "Too many mailbox move requests were observed. Please try again later."
        }
        "not_found" => "The requested item was not found.",
        _ => "The service could not complete the request at this time.",
    }
}

/// Escapes HTML-significant characters for simple template insertion.
pub(crate) fn escape_html(value: &str) -> EscapedHtml {
    EscapedHtml::new(value)
}

/// URL-encodes a query component without bringing in an HTTP utility crate.
pub(crate) fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

/// Compares two byte slices without early exit for CSRF token validation.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }

    diff == 0
}

/// Builds a conservative attachment-style `Content-Disposition` header value.
fn build_attachment_content_disposition(filename: &str) -> String {
    format!(
        "attachment; filename=\"{}\"",
        escape_header_quoted_string(filename)
    )
}

/// Escapes a response header quoted-string without widening filename syntax.
fn escape_header_quoted_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_html_links_visually_disclose_destinations() {
        assert!(browser_css().contains(".message-html a[href]::after"));
        assert!(browser_css().contains("attr(href)"));
    }

    #[test]
    fn html_response_accepts_typed_template_output_and_escapes_title() {
        let body = TrustedHtml::from_template(format!(
            "<p>{}</p>",
            escape_html("<script>alert('body')</script>")
        ));

        let response = html_response(200, "OK", "<title>", body);
        let serialized = String::from_utf8(response.to_http_bytes()).expect("utf-8 response");

        assert!(serialized.contains("<title>&lt;title&gt;</title>"));
        assert!(serialized.contains("<p>&lt;script&gt;alert(&#39;body&#39;)&lt;/script&gt;</p>"));
        assert!(!serialized.contains("<script>alert"));
    }
}
