//! Native footer and delivery actions; saving and sending remain route-owned.
use crate::http_ui::ComposePageModel;

fn mutation_state(model: &ComposePageModel<'_>) -> &'static str {
    if model.draft_id.is_some() && model.draft_revision.is_none() {
        " disabled"
    } else {
        ""
    }
}

pub(crate) fn footer_more(model: &ComposePageModel<'_>) -> String {
    let disabled = mutation_state(model);
    format!(concat!(
        "<details class=\"compose-footer-more\" name=\"compose-delivery-menu\">",
        "<summary aria-label=\"More message actions\">More</summary>",
        "<div class=\"compose-delivery-menu\">",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"minimize\">Save and close</button>",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preview\">Preview</button>",
        "<a href=\"/contacts\" target=\"_blank\" rel=\"noopener\">Contacts<span class=\"sr-only\"> (opens in a new tab)</span></a>",
        "</div></details>"
    ), disabled = disabled)
}

pub(crate) fn send_controls(model: &ComposePageModel<'_>) -> String {
    let disabled = mutation_state(model);
    let paused = if disabled.is_empty() {
        ""
    } else {
        "<p class=\"muted\">Compare the stored version before saving or sending.</p>"
    };
    format!(concat!(
        "<div class=\"compose-send-controls\">",
        "<button class=\"primary-button\" type=\"submit\"{disabled} aria-label=\"Send Message\">Send</button>",
        "<details class=\"compose-send-options\" name=\"compose-delivery-menu\">",
        "<summary aria-label=\"Send options\" title=\"Send options\">⌄</summary>",
        "<div class=\"compose-delivery-menu\">",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preflight\">Pre-send check</button>",
        "<p class=\"muted\">Save this draft and check its readiness. No message is sent.</p>",
        "<button type=\"button\" disabled aria-describedby=\"compose-send-schedule-status\">Schedule</button>",
        "<p id=\"compose-send-schedule-status\" class=\"muted\">Scheduling is unavailable.</p>{paused}",
        "</div></details></div>"
    ), disabled = disabled, paused = paused)
}
