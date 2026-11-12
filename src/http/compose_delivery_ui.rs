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
        "<summary aria-label=\"More message actions\"><span class=\"presentation-icon presentation-icon-more\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">More</span></summary>",
        "<div class=\"compose-delivery-menu\">",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"minimize\"><span class=\"presentation-icon presentation-icon-save\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Save and close</span></button>",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preview\"><span class=\"presentation-icon presentation-icon-eye\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Preview</span></button>",
        "<a href=\"/contacts\" target=\"_blank\" rel=\"noopener\">Contacts<span class=\"sr-only\"> (opens in a new tab)</span></a>",
        "<a href=\"/outbox\" target=\"_blank\" rel=\"noopener\">Outbox<span class=\"sr-only\"> (opens in a new tab)</span></a>",
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
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preflight\" aria-describedby=\"compose-pre-send-description\"><span class=\"presentation-icon presentation-icon-shield\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Pre-send check</span></button>",
        "<span id=\"compose-pre-send-description\" class=\"sr-only\">Save this draft and check current recipients, keys and protection choices. No message is sent.</span>",
        "<div class=\"compose-send-controls\">",
        "<button class=\"primary-button\" type=\"submit\"{disabled} aria-label=\"Send Message\"><span class=\"presentation-icon presentation-icon-sent\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Send</span></button>",
        "<details class=\"compose-send-options\" name=\"compose-delivery-menu\">",
        "<summary aria-label=\"Send options\" title=\"Send options\"><span class=\"presentation-icon presentation-icon-more\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Send options</span></summary>",
        "<div class=\"compose-delivery-menu\">",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"schedule\" aria-describedby=\"compose-send-schedule-status\"><span class=\"presentation-icon presentation-icon-clock\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Schedule</span></button>",
        "<p id=\"compose-send-schedule-status\" class=\"muted\">Save this draft and choose when to send it.</p>{paused}",
        "</div></details></div>"
    ), disabled = disabled, paused = paused)
}
