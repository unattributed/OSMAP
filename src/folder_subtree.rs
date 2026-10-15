//! Finite, exact descendant identities for one native mailbox-container rename.
//! No recursion over files and no child copy/delete. Empty bindings preserve
//! legacy leaf requests; a non-leaf action requires every current child GUID.
use crate::{
    folder_create::Refusal, folder_metadata::FolderSnapshot, folder_rename::RenameFolderRequest,
    mailbox::MailboxBackend, mailbox_status::MailboxStatus,
};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_DESCENDANTS: usize = 8;
pub(crate) fn identities(request: &RenameFolderRequest) -> Vec<(String, String)> {
    let mut rows = vec![(String::new(), request.source_guid().to_owned())];
    rows.extend(
        request
            .descendants()
            .iter()
            .map(|child| (child.suffix.clone(), child.guid.clone())),
    );
    rows
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descendant {
    suffix: String,
    guid: String,
}

impl Descendant {
    pub(crate) fn suffix(&self) -> &str {
        &self.suffix
    }
    pub(crate) fn validate(&self, request: &RenameFolderRequest) -> Result<(), Refusal> {
        if !self.suffix.starts_with('.')
            || self.suffix.len() < 2
            || crate::folder_rename::protected_name(&format!("INBOX{}", self.suffix))
            || self.guid == request.source_guid()
            || self.guid == request.parent_guid()
            || self.guid == request.source_parent_guid()
        {
            return Err(Refusal::Invalid);
        }
        for part in self.suffix.split('.').skip(1) {
            crate::folder_create::CreateFolderRequest::new(
                request.account(),
                "INBOX",
                request.parent_guid(),
                part,
            )?;
        }
        for root in [request.source().to_owned(), request.destination()] {
            let name = format!("{root}{}", self.suffix);
            MailboxStatus::new(&name, &self.guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_bindings(request: &RenameFolderRequest) -> Result<(), Refusal> {
    if request.descendants().len() > MAX_DESCENDANTS {
        return Err(Refusal::Capacity);
    }
    if !request.descendants().is_empty() && request.reserved_recovery_bytes()? > 2048 {
        return Err(Refusal::Capacity);
    }
    let mut last = "";
    let mut guids = std::collections::BTreeSet::new();
    for child in request.descendants() {
        child.validate(request)?;
        if child.suffix.as_str() <= last || !guids.insert(&child.guid) {
            return Err(Refusal::Invalid);
        }
        let parent = child.suffix.rsplit_once('.').ok_or(Refusal::Invalid)?.0;
        if !parent.is_empty() && !request.descendants().iter().any(|c| c.suffix == parent) {
            return Err(Refusal::Invalid);
        }
        last = &child.suffix;
    }
    Ok(())
}

pub(crate) fn names(
    snapshot: &FolderSnapshot,
    account: &str,
    root: &str,
    stored: bool,
) -> Result<Vec<String>, Refusal> {
    snapshot
        .validate_for(account)
        .map_err(|_| Refusal::Unavailable)?;
    let mut names = Vec::new();
    for folder in snapshot
        .folders()
        .iter()
        .filter(|f| f.name().starts_with(&format!("{root}.")))
    {
        let name = folder.name();
        let suffix = name.strip_prefix(root).ok_or(Refusal::Invalid)?;
        crate::folder_create::validate_private_namespace(snapshot, name)?;
        if (!stored && crate::folder_rename::protected_name(name))
            || crate::folder_rename::protected_name(&format!("INBOX{suffix}"))
            || folder.delimiter() != Some('.')
            || !crate::sent_location::selectable(snapshot, account, name)
            || !folder.special_use().is_empty()
            || folder.flags().iter().any(|flag| {
                ![
                    "\\HasChildren",
                    "\\HasNoChildren",
                    "\\Subscribed",
                    "\\Marked",
                    "\\Unmarked",
                ]
                .iter()
                .any(|allowed| flag.eq_ignore_ascii_case(allowed))
            })
        {
            return Err(Refusal::Invalid);
        }
        names.push(name.to_owned());
        if names.len() > MAX_DESCENDANTS {
            return Err(Refusal::Capacity);
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
pub(crate) fn capture<B: MailboxBackend>(
    backend: &B,
    request: &RenameFolderRequest,
) -> Result<Vec<Descendant>, Refusal> {
    request.validate()?;
    let snapshot = backend
        .folder_metadata(request.account())
        .map_err(|_| Refusal::Unavailable)?;
    capture_from(&snapshot, request, |name| {
        backend
            .mailbox_status(request.account(), name)
            .map_err(|_| Refusal::Unavailable)
    })
}

pub(crate) fn capture_from(
    snapshot: &FolderSnapshot,
    request: &RenameFolderRequest,
    mut read: impl FnMut(&str) -> Result<MailboxStatus, Refusal>,
) -> Result<Vec<Descendant>, Refusal> {
    let stored = request.disposition().is_some_and(|p| p.restoring());
    let mut children = Vec::new();
    for name in names(snapshot, request.account(), request.source(), stored)? {
        let status = read(&name)?;
        status.validate(&name).map_err(|_| Refusal::Unavailable)?;
        children.push(Descendant {
            suffix: name
                .strip_prefix(request.source())
                .ok_or(Refusal::Invalid)?
                .into(),
            guid: status.guid().into(),
        });
    }
    Ok(children)
}

/// A changed tree is uncertainty after dispatch, a stale refusal before it.
/// Messages may arrive without changing these container identities.
pub(crate) fn check<B: MailboxBackend>(
    backend: &B,
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    changed: bool,
) -> Result<(), Refusal> {
    check_from(request, snapshot, changed, |name| {
        backend
            .mailbox_status(request.account(), name)
            .map_err(|_| Refusal::Unavailable)
    })
}

pub(crate) fn check_from(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    changed: bool,
    mut read: impl FnMut(&str) -> Result<MailboxStatus, Refusal>,
) -> Result<(), Refusal> {
    validate_bindings(request)?;
    let root = if changed {
        request.destination()
    } else {
        request.source().into()
    };
    let stored = request
        .disposition()
        .is_some_and(|p| p.restoring() != changed);
    let current = names(snapshot, request.account(), &root, stored)?;
    let expected: Vec<_> = request
        .descendants()
        .iter()
        .map(|c| format!("{root}{}", c.suffix))
        .collect();
    if current != expected {
        return Err(if request.descendants().is_empty() {
            Refusal::Invalid
        } else {
            Refusal::Stale
        });
    }
    for (name, child) in expected.iter().zip(request.descendants()) {
        let status = read(name)?;
        status.validate(name).map_err(|_| Refusal::Unavailable)?;
        if status.guid() != child.guid {
            return Err(Refusal::Stale);
        }
    }
    if changed
        && snapshot.folders().iter().any(|f| {
            f.name() == request.source() || f.name().starts_with(&format!("{}.", request.source()))
        })
    {
        return Err(Refusal::Stale);
    }
    Ok(())
}

pub(crate) fn relocated(request: &RenameFolderRequest, name: &str, guid: &str) -> Option<String> {
    if name == request.source() && guid == request.source_guid() {
        return Some(request.destination());
    }
    request
        .descendants()
        .iter()
        .find(|child| guid == child.guid && name == format!("{}{}", request.source(), child.suffix))
        .map(|child| format!("{}{}", request.destination(), child.suffix))
}

#[cfg(test)]
pub(crate) fn fixture_destination_guid(
    request: &RenameFolderRequest,
    name: &str,
) -> Option<String> {
    if name == request.destination() {
        return Some(request.source_guid().into());
    }
    request
        .descendants()
        .iter()
        .find(|child| name == format!("{}{}", request.destination(), child.suffix))
        .map(|child| child.guid.clone())
}
