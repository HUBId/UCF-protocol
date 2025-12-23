# Determinism Rules

These rules describe how canonical encodings and digests MUST be created for UCF
messages.

## Canonical encoding

* Protobuf serialization MUST use deterministic ordering. No `map<>` fields are
  present in the v1 core schema; repeated fields that conceptually represent
  sets (for example `ReasonCodes.codes`) MUST be sorted lexicographically before
  serialization. Such set-like lists SHOULD also be bounded by the caller to
  prevent unbounded growth when forming digests.
* `ExperienceRecord.related_refs` is ordered and MUST be produced in a stable
  order by upstream systems. The producer is responsible for pinning an order
  (for example sorted by label or URI) before serialization.
* Reason codes that are carried directly (for example `ReasonCodes.codes`) or
  wrapped (for example `TopReasonCodes.reason_codes`) MUST be sorted
  lexicographically before computing canonical bytes or digests.
* Canonical bytes are the deterministic protobuf encoding of the fully prepared
  message. The `canonical_bytes` helper in this crate performs the encoding; the
  caller is responsible for ordering any set-like repeated fields before
  encoding. Tests exercise `prost`'s deterministic encoder path by re-encoding
  fixtures and asserting byte-for-byte stability.

## Digest construction

Digests are `BLAKE3-256` over the concatenation of:

```
DOMAIN || schema_id || schema_version || canonical_bytes
```

where each component is UTF-8 encoded and concatenated without separators.

The `digest32` helper implements this rule and returns a fixed 32-byte array.

Some schemas define their own domain separators. For example,
`MicrocircuitConfigEvidence` digests are computed with the
`UCF:HASH:MC_CONFIG` domain instead of the `ucf-core` domain used by the core
fixtures.

## Fixture expectations

* Re-running canonical encoding on fixture messages MUST yield identical bytes.
* Recomputing digests using `digest32` MUST exactly match the stored golden
  digests in `testvectors/*.digest`.
