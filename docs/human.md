# Human approvals and recovery

The `human.proto` package models human governance artifacts for approvals,
stops, and recovery.

* `ApprovalArtifactPackage` bundles the session, intent/action references,
  charter/policy/profile digests, requested operation/risk summary, proposed
  constraints, alternatives, evidence, expiry, and two-person requirements.
* `ApprovalDecision` captures a bounded decision (including optional constraint
  modifications), reason codes, signatures, expiry, and an optional proof
  receipt reference.
* `StopEvent` records a scoped stop action with attestation details, while
  `RecoveryCase` tracks recovery state, required/completed checks, related
  triggers, and optional proof receipts.

Alternatives support either a `CostClass` or bucketed estimate via a `oneof` for
stable encoding. All enums reserve an `UNSPECIFIED` value, and fixtures in
`testvectors/` validate deterministic encoding and digest computation for both
approval package and decision shapes.
