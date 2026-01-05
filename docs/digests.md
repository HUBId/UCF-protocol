# Digest Rules

This document defines digest derivations for proposal, activation, and trace
schemas. All digest fields in the v1 schema are `Digest32` values whose `value`
MUST contain exactly 32 bytes.

## Proposal digests

```
proposal_digest = blake3("UCF:PROPOSAL_EVIDENCE" || proposal_bytes_without_digest_field)
```

`proposal_bytes_without_digest_field` is the deterministic protobuf encoding of
`ProposalEvidence` after setting `proposal_digest` to 32 zero bytes.

Proposal payloads use a dedicated domain separator:

```
payload_digest = blake3("UCF:PROPOSAL_PAYLOAD" || payload_bytes)
```

## Activation digests

```
activation_digest = blake3("UCF:ACTIVATION_EVIDENCE" || activation_bytes_without_digest_field)
```

`activation_bytes_without_digest_field` is the deterministic protobuf encoding
of `ProposalActivationEvidence` after setting `activation_digest` to 32 zero
bytes.

## Trace digests

```
trace_digest = blake3("UCF:TRACE_RUN_EVIDENCE" || trace_bytes_without_digest_field)
```

`trace_bytes_without_digest_field` is the deterministic protobuf encoding of
`TraceRunEvidence` after setting `trace_digest` to 32 zero bytes.
