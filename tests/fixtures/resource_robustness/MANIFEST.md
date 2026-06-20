# V8 Resource Robustness Fixtures

These fixtures support V8 Slice 5. They are synthetic and intentionally small.

| Fixture | Regression objective |
|---|---|
| `limits.env` | Bounded limit cases used by the Rust matrix |
| `sort_matrix.tsv` | Deterministic sorting expectations for larger synthetic message sets |
| `rejection_matrix.tsv` | Fail-closed request and output rejection expectations |
