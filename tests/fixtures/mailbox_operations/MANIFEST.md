# V8 Mailbox Operation Fixtures

These fixtures support V8 Slice 3. They are synthetic and intentionally small.

| Fixture | Regression objective |
|---|---|
| `mailboxes.txt` | Stable mailbox listing inventory, including nested mailbox names |
| `messages.tsv` | Message listing and sorting over UID, subject, sender, received time, flags, and size |
| `search_results.tsv` | Search result sorting and all-mailbox result retention |
| `message_view.eml` | Single-message retrieval fixture metadata |
| `move_operations.tsv` | One-message move success and rejected move request shapes |
