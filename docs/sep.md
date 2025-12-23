# Session Event Path (SEP)

The `sep.proto` definitions track session-level event chains, seals, and
completeness reports.

* `SepEvent` captures a typed event with object reference, reason codes,
  timestamps, chain digests (previous/current), attestation signature, and
  epoch linkage.
* `SessionSeal` finalizes a session with the terminal event/record digests and an
  optional proof receipt reference.
* `CompletenessReport` summarizes session completeness, including missing nodes
  or edges and associated reason codes.

Enums include explicit `UNSPECIFIED` values for deterministic prost output. The
fixtures encode a three-event chain plus a terminal seal and a failure-mode
completeness report to exercise digest stability.
