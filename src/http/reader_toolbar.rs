//! Standalone icons retain the existing native identity-bound form contracts.
use super::*;
#[allow(clippy::too_many_arguments)]
pub(super) fn render(
    csrf: &str,
    message: &RenderedMessageView,
    archive: Option<&str>,
    mailboxes: &[MailboxEntry],
    back: &str,
    return_to: &str,
    neighbours: &crate::reader_neighbours::ReaderNeighbours,
    reply: &str,
    labels: &str,
    snooze: &str,
    more: &str,
) -> String {
    let icon_button = |label: &str, icon: &str, action: &str, enabled: bool| {
        format!("<button type=\"{}\" name=\"action\" value=\"{action}\" aria-label=\"{label}\" title=\"{label}\"{}>{}</button>", if enabled { "submit" } else { "button" }, if enabled { "" } else { " disabled" }, reader_icon(icon))
    };
    let fields = move_identity_fields(
        csrf,
        &message.mailbox_name,
        message.uid,
        message.metadata.as_ref(),
        return_to,
    );
    let archive_enabled = fields.is_some()
        && archive.is_some_and(|name| {
            name != message.mailbox_name && mailboxes.iter().any(|m| m.name == name)
        });
    let restore = message.mailbox_name == "Trash";
    let destination = if restore { "INBOX" } else { "Trash" };
    let moves = format!(
        "{}{}{}",
        fields.as_deref().unwrap_or(""),
        icon_button("Archive message", "archive", "archive", archive_enabled),
        icon_button(
            if restore {
                "Restore message to Inbox"
            } else {
                "Move message to Bin"
            },
            if restore { "inbox" } else { "bin" },
            if restore { "restore" } else { "bin" },
            fields.is_some() && mailboxes.iter().any(|m| m.name == destination)
        )
    );
    let moves = if fields.is_some() {
        format!("<form class=\"reader-icon-moves\" method=\"post\" action=\"/message/move\">{moves}</form>")
    } else {
        format!("<div class=\"reader-icon-moves\">{moves}</div>")
    };
    let flags = message
        .metadata
        .as_ref()
        .map(|m| {
            let seen = has_flag(&message.flags, MessageFlag::Seen.imap());
            let read = render_message_flag_form(
                csrf,
                &message.mailbox_name,
                message.uid,
                m,
                MessageFlag::Seen,
                seen,
                return_to,
            )
            .replace(
                if seen {
                    ">Mark unread</button>"
                } else {
                    ">Mark read</button>"
                },
                &format!(">{}</button>", reader_icon("read")),
            );
            let star = render_message_flag_form(
                csrf,
                &message.mailbox_name,
                message.uid,
                m,
                MessageFlag::Flagged,
                has_flag(&message.flags, MessageFlag::Flagged.imap()),
                return_to,
            );
            (read, star)
        })
        .unwrap_or_else(|| {
            (
                format!(
                    "<button disabled aria-label=\"Read state unavailable\">{}</button>",
                    reader_icon("read")
                ),
                String::new(),
            )
        });
    let reply = reply.replace(
        ">Reply to message</a>",
        &format!(
            " aria-label=\"Reply to message\" title=\"Reply to message\">{}</a>",
            reader_icon("reply")
        ),
    );
    let labels = labels.replace(
        "<summary>Labels</summary>",
        &format!(
            "<summary aria-label=\"Labels\" title=\"Labels\">{}</summary>",
            reader_icon("label")
        ),
    );
    let snooze = snooze.replace("<span aria-hidden=\"true\">◷</span>", &reader_icon("clock"));
    format!("<div class=\"reader-toolbar reader-icon-toolbar\"><a href=\"{}\" aria-label=\"Back to list\" title=\"Back to list\">{}</a>{reply}{moves}{}{snooze}{labels}{}<details class=\"reader-more-actions\"><summary aria-label=\"More message actions\" title=\"More message actions\">{}</summary><div class=\"action-stack\">{}{}{more}</div></details></div>",escape_html(back),reader_icon("back"),flags.0,neighbours.controls_html_with_policy(csrf),reader_icon("more"),neighbours.scope_html(),flags.1)
}

// Inert CSS geometry keeps message main free of SVG markup.
fn reader_icon(name: &str) -> String {
    let name = match name {
        "archive" | "inbox" | "bin" | "read" | "reply" | "label" | "clock" | "back" | "more" => {
            name
        }
        _ => "more",
    };
    format!(
        "<span class=\"reader-line-icon reader-line-{name}\" aria-hidden=\"true\"><i></i></span>"
    )
}
