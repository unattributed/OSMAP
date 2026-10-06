//! Bounded presentation derived from verified namespace and LIST facts.
use super::*;
use crate::folder_metadata::{FolderSnapshot, NamespaceKind};
#[derive(Clone)]
pub(crate) struct FolderNode {
    pub name: String,
    pub parent: Option<usize>,
    pub namespace: String,
    pub roles: String,
    pub state: &'static str,
    pub selectable: bool,
}
pub(crate) struct FolderTree {
    pub nodes: Vec<FolderNode>,
    snapshot: FolderSnapshot,
}
impl FolderTree {
    pub(crate) fn build(
        account: &str,
        snapshot: &FolderSnapshot,
        owned: &[MailboxEntry],
    ) -> Option<Self> {
        snapshot.validate_for(account).ok()?;
        if owned.len() > 1024 {
            return None;
        }
        let mut nodes: Vec<FolderNode> = Vec::new();
        for mailbox in owned {
            let entry = snapshot.folder(account, &mailbox.name).ok()?;
            let ns = snapshot
                .namespaces()
                .iter()
                .filter(|n| {
                    mailbox.name.starts_with(n.prefix())
                        || (mailbox.name.eq_ignore_ascii_case("INBOX")
                            && n.kind() == NamespaceKind::Private
                            && n.delimiter().is_some_and(|d| {
                                n.prefix().eq_ignore_ascii_case(&format!("INBOX{d}"))
                            }))
                })
                .max_by_key(|n| n.prefix().len())?;
            if entry.delimiter() != ns.delimiter() {
                return None;
            }
            let namespace = format!(
                "{} namespace{}",
                match ns.kind() {
                    NamespaceKind::Private => "Private",
                    NamespaceKind::Shared => "Shared",
                    NamespaceKind::Public => "Public",
                },
                if ns.prefix().is_empty() {
                    String::new()
                } else {
                    format!(": {}", ns.prefix())
                }
            );
            let mut names = Vec::new();
            if let Some(delimiter) = entry.delimiter() {
                for (index, ch) in mailbox.name.char_indices() {
                    if ch == delimiter && index >= ns.prefix().len() {
                        names.push(mailbox.name[..index].to_owned());
                    }
                }
            }
            names.push(mailbox.name.clone());
            if names.len() > 32 {
                return None;
            }
            let mut parent = None;
            for name in names {
                let found = nodes.iter().position(|n| n.name == name);
                let index = if let Some(i) = found {
                    if nodes[i].parent != parent || nodes[i].namespace != namespace {
                        return None;
                    }
                    i
                } else {
                    if nodes.len() >= 2048 {
                        return None;
                    }
                    let facts = snapshot.folder(account, &name).ok();
                    let listed = owned.iter().any(|m| m.name == name);
                    let actionable = super::routes_mail::mailbox_is_user_visible(&name);
                    let selectable = listed
                        && actionable
                        && facts.is_some_and(|f| {
                            !f.has_flag("\\Noselect") && !f.has_flag("\\NonExistent")
                        });
                    let state = match facts {
                        None => "Structural parent only",
                        Some(f) if f.has_flag("\\NonExistent") => "Nonexistent",
                        Some(f) if f.has_flag("\\Noselect") => "Not selectable",
                        Some(_) if !listed => "Display-only parent",
                        Some(_) if !actionable => "Not available to open here",
                        _ => "Selectable",
                    };
                    let roles = facts
                        .map(|f| f.special_use().join(", "))
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "None reported".into());
                    nodes.push(FolderNode {
                        name,
                        parent,
                        namespace: namespace.clone(),
                        roles,
                        state,
                        selectable,
                    });
                    nodes.len() - 1
                };
                parent = Some(index);
            }
        }
        Some(Self {
            nodes,
            snapshot: snapshot.clone(),
        })
    }
    pub(crate) fn can_rename(
        &self,
        account: &str,
        name: &str,
        status: &crate::mailbox_status::MailboxStatus,
    ) -> bool {
        self.selectable(name)
            && crate::folder_rename::validate_source(account, name, &self.snapshot, status).is_ok()
    }
    pub(crate) fn can_create(
        &self,
        account: &str,
        name: &str,
        status: &crate::mailbox_status::MailboxStatus,
    ) -> bool {
        self.selectable(name)
            && crate::folder_create::validate_creation_parent(account, name, &self.snapshot, status)
                .is_ok()
    }
    pub(crate) fn selectable(&self, name: &str) -> bool {
        self.nodes.iter().any(|n| n.name == name && n.selectable)
    }
    pub(crate) fn render(&self, chosen: Option<&str>) -> String {
        fn children(tree: &FolderTree, parent: Option<usize>, chosen: Option<&str>) -> String {
            let mut ids: Vec<_> = tree
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, n)| n.parent == parent)
                .collect();
            ids.sort_by(|a, b| (&a.1.namespace, &a.1.name).cmp(&(&b.1.namespace, &b.1.name)));
            let mut html = String::new();
            let mut last_namespace = String::new();
            for (i, n) in ids {
                if parent.is_none() && last_namespace != n.namespace {
                    html.push_str(&format!(
                        "<li class=\"folder-namespace\">{}</li>",
                        escape_html(&n.namespace)
                    ));
                    last_namespace = n.namespace.clone();
                }
                let child = children(tree, Some(i), chosen);
                let name = escape_html(&n.name);
                let label = if n.selectable {
                    format!("<a href=\"/settings?section=copies&amp;folder={}\"{}><span class=\"folder-line-icon\" aria-hidden=\"true\"></span>{name}</a>",url_encode(&n.name),if chosen==Some(n.name.as_str()){" aria-current=\"true\""}else{""})
                } else {
                    format!(
                        "<span class=\"folder-display-only\">{name} <small>{}</small></span>",
                        n.state
                    )
                };
                html.push_str(&format!("<li>{label}{}{} </li>",String::new(),if child.is_empty(){String::new()}else{format!("<details open><summary>Subfolders of {name}</summary><ul>{child}</ul></details>")}));
            }
            html
        }
        children(self, None, chosen)
    }
    pub(crate) fn primary(&self, name: &str) -> (String, String) {
        self.nodes
            .iter()
            .enumerate()
            .find(|(_, n)| n.name == name)
            .map(|(i, n)| {
                (
                    n.parent
                        .map(|p| escape_html(&self.nodes[p].name).to_string())
                        .unwrap_or_else(|| escape_html(&n.namespace).to_string()),
                    self.nodes
                        .iter()
                        .filter(|c| c.parent == Some(i))
                        .count()
                        .to_string(),
                )
            })
            .unwrap_or_else(|| ("Unknown".into(), "Unknown".into()))
    }
    pub(crate) fn details(&self, name: &str) -> String {
        let Some(n) = self.nodes.iter().find(|n| n.name == name) else {
            return String::new();
        };
        format!("<dl class=\"folder-hierarchy-facts\"><dt>Reported roles</dt><dd>{}</dd><dt>Folder state</dt><dd>{}</dd></dl><p class=\"copies-count-scope\">Roles describe server-reported use; they do not grant permissions or protection.</p>",escape_html(&n.roles),n.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folder_hierarchy_authority_and_ambiguous_fallback() {
        let snapshot=FolderSnapshot::parse("alice@example.com",b"* PREAUTH test\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\Noselect) \".\" INBOX\r\n* LIST (\\Sent) \".\" INBOX.Child\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n").unwrap();
        let owned = vec![MailboxEntry {
            name: "INBOX.Child".into(),
        }];
        let tree = FolderTree::build("alice@example.com", &snapshot, &owned).unwrap();
        assert!(tree.selectable("INBOX.Child"));
        assert!(!tree.selectable("INBOX"));
        assert!(tree.render(None).contains("Not selectable"));
        assert!(tree.details("INBOX.Child").contains("\\Sent"));
        assert!(FolderTree::build("bob@example.com", &snapshot, &owned).is_none());
        assert!(FolderTree::build(
            "alice@example.com",
            &snapshot,
            &[MailboxEntry {
                name: "Unknown".into()
            }]
        )
        .is_none());
    }
}
