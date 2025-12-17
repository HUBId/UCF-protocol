# Protocol Versioning

The UCF core schema is versioned via the `schema_id` and `schema_version` pairs
used when computing digests and embedding references in envelopes. For milestone
1 the package namespace is `ucf.v1` and the schema identifiers used in fixtures
are:

| Schema                | Identifier                | Version |
| --------------------- | ------------------------- | ------- |
| CanonicalIntent       | `ucf.v1.CanonicalIntent`  | `1`     |
| PolicyDecision        | `ucf.v1.PolicyDecision`   | `1`     |
| PVGSReceipt           | `ucf.v1.PVGSReceipt`      | `1`     |

Future revisions MUST bump `schema_version` (e.g., to `2`) while retaining the
schema identifier string, and digest derivation MUST include the updated
version. Backward-incompatible changes require a new package name (e.g.,
`ucf.v2`).
