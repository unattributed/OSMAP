# OSMAP Hostile Mail Corpus

This corpus contains synthetic hostile or malformed mail fixtures used only for
containment assurance. It does not contain real user mail, credentials, or
private attachment content.

Each `.eml` fixture has a sibling `.json` metadata file with:

- `fixture_identifier`
- `category`
- `expected_outcome`
- `security_objective`
- `release_coverage_mapping`

The release gate treats this corpus as mandatory evidence for V4 hostile-content
containment. Fixture additions must update `MANIFEST.json` and preserve the
required category coverage.
