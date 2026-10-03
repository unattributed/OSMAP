//! Bounded public threading structure; never sender verification or read authority.
use crate::mailbox::{MessageSearchResult, MessageSummary};
use crate::reading_preferences::DateOrder;
use crate::reply_thread::{
    message_id, MAX_MESSAGE_ID_BYTES, MAX_REFERENCES, MAX_THREAD_INPUT_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// JSON escaping/framing overhead is bounded separately; validated header content
// remains at most MAX_THREAD_INPUT_BYTES. The shared helper frame cap is unchanged.
pub(crate) const MAX_THREAD_WIRE_BYTES: usize = MAX_THREAD_INPUT_BYTES * 2 + 512;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadingMetadata {
    message_id: String,
    in_reply_to: Option<String>,
    references: Vec<String>,
}

impl std::fmt::Debug for ThreadingMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadingMetadata")
            .field("has_parent", &self.in_reply_to.is_some())
            .field("references", &self.references.len())
            .finish()
    }
}

impl ThreadingMetadata {
    /// Missing, unsupported, ambiguous or excessive native headers remain unknown.
    pub fn from_headers(
        id: Option<&str>,
        parent: Option<&str>,
        references: Option<&str>,
    ) -> Option<Self> {
        let id = id?;
        let total = id
            .len()
            .checked_add(parent.map_or(0, str::len))?
            .checked_add(references.map_or(0, str::len))?;
        if total > MAX_THREAD_INPUT_BYTES {
            return None;
        }
        let id = unfold(id)?;
        let parent = match parent {
            Some(value) => Some(unfold(value)?),
            None => None,
        };
        let references = match references {
            Some(value) => Some(unfold(value)?),
            None => None,
        };
        let message_id = message_id(&id).ok()?;
        let in_reply_to = parent
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(message_id_from_header)
            .transpose()
            .ok()?;
        let references = references
            .as_deref()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .map(message_id_from_header)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let result = Self {
            message_id,
            in_reply_to,
            references,
        };
        result.valid().then_some(result)
    }

    pub fn message_id(&self) -> &str {
        &self.message_id
    }
    pub fn in_reply_to(&self) -> Option<&str> {
        self.in_reply_to.as_deref()
    }
    pub fn references(&self) -> &[String] {
        &self.references
    }

    pub(crate) fn valid(&self) -> bool {
        let exact = |id: &str| {
            id.len() <= MAX_MESSAGE_ID_BYTES
                && message_id(id).is_ok_and(|normalized| normalized == id)
        };
        self.references.len() <= MAX_REFERENCES
            && exact(&self.message_id)
            && self
                .in_reply_to
                .as_deref()
                .is_none_or(|id| exact(id) && id != self.message_id)
            && self
                .references
                .iter()
                .all(|id| exact(id) && id != &self.message_id)
            && self.references.iter().collect::<BTreeSet<_>>().len() == self.references.len()
            && self
                .in_reply_to
                .as_ref()
                .is_none_or(|parent| self.references.last().is_none_or(|last| last == parent))
            && self.message_id.len()
                + self.in_reply_to.as_ref().map_or(0, String::len)
                + self.references.iter().map(|id| id.len() + 1).sum::<usize>()
                <= MAX_THREAD_INPUT_BYTES
    }
}

fn message_id_from_header(value: &str) -> Result<String, &'static str> {
    message_id(value)
}

// Fold only CRLF followed by whitespace; a new header line remains unknown.
fn unfold(value: &str) -> Option<String> {
    let mut lines = value.split("\r\n");
    let mut result = lines.next()?.to_string();
    for line in lines {
        if !line.starts_with([' ', '\t']) {
            return None;
        }
        result.push(' ');
        result.push_str(line.trim_start_matches([' ', '\t']));
    }
    (!result
        .bytes()
        .any(|byte| byte.is_ascii_control() && byte != b'\t'))
    .then_some(result)
}

pub(crate) fn order_message_summaries(rows: &mut [MessageSummary], order: DateOrder) {
    if rows.len() > crate::mailbox::DEFAULT_MAX_MESSAGES {
        return;
    }
    let order = indices(
        &rows
            .iter()
            .map(|row| Record {
                mailbox: &row.mailbox_name,
                uid: row.uid,
                date: &row.date_received,
                metadata: row.metadata.as_ref(),
            })
            .collect::<Vec<_>>(),
        order,
        crate::mailbox::DEFAULT_MAX_MESSAGES,
    );
    reorder(rows, order);
}
pub(crate) fn order_search_results(rows: &mut [MessageSearchResult], order: DateOrder) {
    if rows.len() > crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS {
        return;
    }
    let order = indices(
        &rows
            .iter()
            .map(|row| Record {
                mailbox: &row.mailbox_name,
                uid: row.uid,
                date: &row.date_received,
                metadata: row.metadata.as_ref(),
            })
            .collect::<Vec<_>>(),
        order,
        crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS,
    );
    reorder(rows, order);
}

fn reorder<T: Clone>(rows: &mut [T], indices: Vec<usize>) {
    let ordered: Vec<_> = indices
        .into_iter()
        .map(|index| rows[index].clone())
        .collect();
    rows.clone_from_slice(&ordered);
}

struct Record<'a> {
    mailbox: &'a str,
    uid: u64,
    date: &'a str,
    metadata: Option<&'a crate::message_metadata::MessageMetadata>,
}
impl Record<'_> {
    fn public_threading(&self) -> Option<&ThreadingMetadata> {
        self.metadata?
            .threading
            .as_ref()
            .filter(|thread| thread.valid())
    }
    fn identity(&self) -> (&str, u64, &str, &str) {
        (
            self.mailbox,
            self.uid,
            self.metadata
                .map_or("", |m| m.version.mailbox_guid.as_str()),
            self.metadata
                .map_or("", |m| m.version.message_guid.as_str()),
        )
    }
    fn threading(&self) -> Option<&ThreadingMetadata> {
        let metadata = self.metadata?;
        if self.uid == 0
            || self.uid > u64::from(u32::MAX)
            || crate::mailbox::MailboxEntry::new(
                crate::mailbox::MailboxListingPolicy::default(),
                self.mailbox,
            )
            .is_err()
            || crate::message_metadata::MessageVersion::new(
                metadata.version.mailbox_guid.clone(),
                metadata.version.message_guid.clone(),
            )
            .is_err()
            || crate::mailbox::parse_received_timestamp(self.date).is_none()
        {
            return None;
        }
        self.public_threading()
    }
}

fn find(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}
fn union(parents: &mut [usize], a: usize, b: usize) {
    let a = find(parents, a);
    let b = find(parents, b);
    parents[a.max(b)] = a.min(b);
}

fn indices(rows: &[Record<'_>], order: DateOrder, maximum: usize) -> Vec<usize> {
    if rows.len() > maximum {
        return (0..rows.len()).collect();
    }
    let times: Vec<_> = rows
        .iter()
        .map(|row| crate::mailbox::parse_received_timestamp(row.date))
        .collect();
    let compare = |a: usize, b: usize| {
        // Preserve the existing independent date sort: unknown times remain
        // last in either direction, and equal times retain mailbox/UID ties.
        (match (times[a], times[b]) {
            (Some(a), Some(b)) if order == DateOrder::Newest => b.cmp(&a),
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        })
        .then_with(|| rows[a].mailbox.cmp(rows[b].mailbox))
        .then_with(|| rows[b].uid.cmp(&rows[a].uid))
        .then_with(|| rows[a].identity().cmp(&rows[b].identity()))
    };
    let mut parents: Vec<_> = (0..rows.len()).collect();
    // Discover IDs before checking grouping eligibility. An invalid time or
    // identity must not conceal a duplicate public ID from its valid sibling.
    let threads: Vec<_> = rows.iter().map(Record::public_threading).collect();
    let mut ids: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut identities: BTreeMap<(&str, u64, &str, &str), Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        identities.entry(row.identity()).or_default().push(index);
        if let Some(thread) = threads[index] {
            ids.entry(thread.message_id()).or_default().push(index);
        }
    }
    let mut invalid: Vec<_> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| threads[index].is_some() && row.threading().is_none())
        .collect();
    for duplicates in ids
        .values()
        .chain(identities.values())
        .filter(|members| members.len() > 1)
    {
        for &index in duplicates {
            invalid[index] = true;
            union(&mut parents, duplicates[0], index);
        }
    }
    let mut edges = vec![Vec::new(); rows.len()];
    let mut indegree = vec![0usize; rows.len()];
    for (index, thread) in threads.iter().enumerate() {
        let Some(thread) = thread else {
            continue;
        };
        let ancestors: BTreeSet<_> = thread
            .references()
            .iter()
            .map(String::as_str)
            .chain(thread.in_reply_to())
            .collect();
        for id in ancestors {
            let Some(targets) = ids.get(id) else {
                continue;
            };
            // Duplicate IDs were already joined and quarantined. One union
            // propagates refusal without expanding each reference into N edges.
            let target = targets[0];
            union(&mut parents, index, target);
            if targets.len() == 1 {
                edges[index].push(target);
                indegree[target] += 1;
            }
        }
    }
    // Topological removal leaves cyclic ancestry; quarantine only its component.
    let mut queue: VecDeque<_> = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, &count)| (count == 0).then_some(index))
        .collect();
    while let Some(index) = queue.pop_front() {
        for &target in &edges[index] {
            indegree[target] -= 1;
            if indegree[target] == 0 {
                queue.push_back(target);
            }
        }
    }
    let invalid_components: BTreeSet<_> = (0..rows.len())
        .filter(|&index| invalid[index] || indegree[index] > 0)
        .map(|index| find(&mut parents, index))
        .collect();
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, thread) in threads.iter().enumerate() {
        let root = find(&mut parents, index);
        // Quarantined/unknown records each remain individual groups, separately
        // keyed from the bounded valid components.
        let key = if invalid_components.contains(&root) || thread.is_none() {
            rows.len() + index
        } else {
            root
        };
        groups.entry(key).or_default().push(index);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    for group in &mut groups {
        group.sort_by(|&a, &b| compare(a, b));
    }
    groups.sort_by(|a, b| compare(a[0], b[0]));
    groups.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_metadata::{MessageMetadata, MessageProtection, MessageVersion};
    fn row(uid: u64, id: Option<&str>, parent: Option<&str>) -> MessageSummary {
        MessageSummary {
            mailbox_name: "INBOX".into(),
            uid,
            flags: vec![],
            date_received: format!("2026-10-03 00:{:02}:{:02} +0000", (uid / 60) % 60, uid % 60),
            size_virtual: 10,
            subject: Some("Same subject".into()),
            from: None,
            to: None,
            metadata: Some(MessageMetadata {
                version: MessageVersion::new("a".repeat(32), format!("record-{uid}")).unwrap(),
                attachment_count: None,
                attachments: None,
                protection: MessageProtection::Unknown,
                preview: None,
                threading: ThreadingMetadata::from_headers(id, parent, parent),
            }),
        }
    }
    #[test]
    fn actual_ancestry_groups_reply_parent_without_same_subject_inference() {
        let rows = vec![
            row(1, Some("<parent@example.test>"), None),
            row(2, Some("<unrelated@example.test>"), None),
            row(
                3,
                Some("<reply@example.test>"),
                Some("<parent@example.test>"),
            ),
        ];
        for (order, expected) in [
            (DateOrder::Newest, vec![3, 1, 2]),
            (DateOrder::Oldest, vec![1, 3, 2]),
        ] {
            let mut ordered = rows.clone();
            order_message_summaries(&mut ordered, order);
            assert_eq!(
                ordered.iter().map(|row| row.uid).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn duplicate_and_cyclic_components_remain_individual_without_poisoning_valid_thread() {
        let valid = vec![
            row(1, Some("<root@example.test>"), None),
            row(2, Some("<separate@example.test>"), None),
            row(3, Some("<reply@example.test>"), Some("<root@example.test>")),
        ];
        let mut cyclic = valid.clone();
        cyclic.extend([
            row(
                4,
                Some("<cycle-a@example.test>"),
                Some("<cycle-b@example.test>"),
            ),
            row(
                5,
                Some("<cycle-b@example.test>"),
                Some("<cycle-a@example.test>"),
            ),
        ]);
        order_message_summaries(&mut cyclic, DateOrder::Newest);
        assert_eq!(
            cyclic.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![5, 4, 3, 1, 2]
        );
        let mut duplicate = valid;
        duplicate.extend([
            row(4, Some("<duplicate@example.test>"), None),
            row(5, Some("<duplicate@example.test>"), None),
            row(
                6,
                Some("<ambiguous-child@example.test>"),
                Some("<duplicate@example.test>"),
            ),
        ]);
        order_message_summaries(&mut duplicate, DateOrder::Newest);
        assert_eq!(
            duplicate.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![6, 5, 4, 3, 1, 2]
        );
    }

    #[test]
    fn ineligible_duplicate_id_quarantines_connected_siblings_not_independent_threads() {
        for invalid_time in [true, false] {
            let mut rows = vec![
                row(1, Some("<root@example.test>"), None),
                row(2, Some("<separate@example.test>"), None),
                row(3, Some("<reply@example.test>"), Some("<root@example.test>")),
                row(4, Some("<root@example.test>"), None),
                row(5, Some("<good-root@example.test>"), None),
                row(6, Some("<other@example.test>"), None),
                row(
                    7,
                    Some("<good-reply@example.test>"),
                    Some("<good-root@example.test>"),
                ),
            ];
            if invalid_time {
                rows[3].date_received = "unsupported-time".into();
            } else {
                rows[3].metadata.as_mut().unwrap().version.mailbox_guid = "invalid".into();
            }
            let expected = if invalid_time {
                vec![7, 5, 6, 3, 2, 1, 4]
            } else {
                vec![7, 5, 6, 4, 3, 2, 1]
            };
            let mut search: Vec<_> = rows
                .iter()
                .cloned()
                .map(|row| MessageSearchResult {
                    mailbox_name: row.mailbox_name,
                    uid: row.uid,
                    flags: row.flags,
                    date_received: row.date_received,
                    size_virtual: row.size_virtual,
                    subject: row.subject,
                    from: row.from,
                    metadata: row.metadata,
                })
                .collect();
            order_message_summaries(&mut rows, DateOrder::Newest);
            assert_eq!(rows.iter().map(|row| row.uid).collect::<Vec<_>>(), expected);
            order_search_results(&mut search, DateOrder::Newest);
            assert_eq!(
                search.iter().map(|row| row.uid).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn unknown_invalid_and_external_ancestry_never_infer_same_subject_membership() {
        let mut rows = vec![
            row(1, None, None),
            row(
                2,
                Some("<external-child@example.test>"),
                Some("<not-loaded@example.test>"),
            ),
            row(3, Some("<third@example.test>"), None),
        ];
        rows[2].metadata.as_mut().unwrap().threading = Some(
            serde_json::from_str(r#"{"message_id":"bad","in_reply_to":null,"references":[]}"#)
                .unwrap(),
        );
        order_message_summaries(&mut rows, DateOrder::Newest);
        assert_eq!(
            rows.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        rows[2].date_received = "unknown-time".into();
        order_message_summaries(&mut rows, DateOrder::Newest);
        assert_eq!(
            rows.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
    }

    #[test]
    fn equal_time_and_search_folder_identity_ties_are_stable_without_global_state() {
        let mut rows = vec![
            row(1, Some("<root@example.test>"), None),
            row(2, Some("<separate@example.test>"), None),
            row(3, Some("<reply@example.test>"), Some("<root@example.test>")),
        ];
        for row in &mut rows {
            row.date_received = "2026-10-03 00:00:00 +0000".into();
        }
        let mut shuffled = vec![rows[2].clone(), rows[1].clone(), rows[0].clone()];
        order_message_summaries(&mut rows, DateOrder::Newest);
        order_message_summaries(&mut shuffled, DateOrder::Newest);
        assert_eq!(rows, shuffled);
        assert_eq!(
            rows.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![3, 1, 2]
        );
        let mut search: Vec<_> = shuffled
            .into_iter()
            .map(|row| MessageSearchResult {
                mailbox_name: row.mailbox_name,
                uid: row.uid,
                flags: row.flags,
                date_received: row.date_received,
                size_virtual: row.size_virtual,
                subject: row.subject,
                from: row.from,
                metadata: row.metadata,
            })
            .collect();
        search
            .iter_mut()
            .find(|row| row.uid == 3)
            .unwrap()
            .mailbox_name = "Sent".into();
        let original = search.clone();
        order_search_results(&mut search, DateOrder::Oldest);
        assert_eq!(
            search
                .iter()
                .map(|row| (&*row.mailbox_name, row.uid))
                .collect::<Vec<_>>(),
            vec![("INBOX", 2), ("INBOX", 1), ("Sent", 3)]
        );
        assert!(search.iter().all(|row| original.contains(row)));
        let mut other = vec![
            row(3, Some("<reply@example.test>"), Some("<root@example.test>")),
            row(2, Some("<separate@example.test>"), None),
        ];
        order_message_summaries(&mut other, DateOrder::Oldest);
        assert_eq!(
            other.iter().map(|row| row.uid).collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn oversized_snapshots_are_not_silently_truncated_or_grouped() {
        let original = vec![
            row(1, Some("<root@example.test>"), None);
            crate::mailbox::DEFAULT_MAX_MESSAGES + 1
        ];
        let mut rows = original.clone();
        order_message_summaries(&mut rows, DateOrder::Newest);
        assert_eq!(rows, original);
    }

    #[test]
    fn missing_and_unknown_threading_preserve_legacy_equal_time_order_in_both_directions() {
        for missing in [false, true] {
            for time_profile in 0..3 {
                let mut original = vec![
                    row(1, None, None),
                    row(4, None, None),
                    row(2, None, None),
                    row(3, None, None),
                ];
                for row in &mut original {
                    row.date_received = "2026-10-03 00:00:00 +0000".into();
                    if missing {
                        row.metadata = None;
                    }
                }
                original[3].mailbox_name = "Sent".into();
                if time_profile == 1 {
                    original[1].date_received = "unknown-time".into();
                    original[2].date_received = "2026-10-03 00:01:00 +0000".into();
                    original[3].date_received = "unknown-time".into();
                } else if time_profile == 2 {
                    for row in &mut original {
                        row.date_received = "unknown-time".into();
                    }
                }
                for order in [DateOrder::Newest, DateOrder::Oldest] {
                    let sort = Some(crate::mailbox::MessageSort {
                        column: crate::mailbox::MessageSortColumn::Received,
                        direction: if order == DateOrder::Newest {
                            crate::mailbox::MessageSortDirection::Desc
                        } else {
                            crate::mailbox::MessageSortDirection::Asc
                        },
                    });
                    let mut legacy = original.clone();
                    crate::mailbox::sort_message_summaries(&mut legacy, sort);
                    let mut actual = original.clone();
                    order_message_summaries(&mut actual, order);
                    assert_eq!(actual, legacy);
                    if time_profile != 1 {
                        assert_eq!(
                            actual.iter().map(|row| row.uid).collect::<Vec<_>>(),
                            vec![4, 2, 1, 3]
                        );
                    }
                    let mut search: Vec<_> = original
                        .clone()
                        .into_iter()
                        .map(|row| MessageSearchResult {
                            mailbox_name: row.mailbox_name,
                            uid: row.uid,
                            flags: row.flags,
                            date_received: row.date_received,
                            size_virtual: row.size_virtual,
                            subject: row.subject,
                            from: row.from,
                            metadata: row.metadata,
                        })
                        .collect();
                    let mut legacy = search.clone();
                    crate::mailbox::sort_message_search_results(&mut legacy, sort);
                    order_search_results(&mut search, order);
                    assert_eq!(search, legacy);
                }
            }
        }
    }
    #[test]
    fn native_thread_header_profile_is_bounded_and_unknown_on_ambiguity() {
        let valid = ThreadingMetadata::from_headers(
            Some("<child@example.test>"),
            Some("<parent@example.test>"),
            Some("<root@example.test> <parent@example.test>"),
        )
        .unwrap();
        assert_eq!(valid.message_id(), "<child@example.test>");
        let folded = ThreadingMetadata::from_headers(
            Some("<child@example.test>"),
            Some("<parent@example.test>"),
            Some("<root@example.test>\r\n\t<parent@example.test>"),
        )
        .unwrap();
        assert_eq!(folded, valid);
        for (id, parent, refs) in [
            (None, None, None),
            (Some("bad"), None, None),
            (
                Some("<child@example.test>"),
                Some("<a@example.test> <b@example.test>"),
                None,
            ),
            (
                Some("<child@example.test>"),
                Some("<parent@example.test>"),
                Some("<other@example.test>"),
            ),
            (Some("<child@example.test>\r\nX: injected"), None, None),
            (
                Some("<child@example.test>"),
                None,
                Some("<root@example.test> <root@example.test>"),
            ),
        ] {
            assert!(ThreadingMetadata::from_headers(id, parent, refs).is_none());
        }
        let excess = (0..21)
            .map(|i| format!("<parent{i}@example.test>"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            ThreadingMetadata::from_headers(Some("<child@example.test>"), None, Some(&excess))
                .is_none()
        );
    }
}
