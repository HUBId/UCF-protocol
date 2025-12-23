# Microcircuit configuration evidence

Microcircuit configuration evidence packages a signed, digest-addressed summary of
microcircuit configuration state for LC, SN, and other micro-modules. It allows
chips and orchestration layers to prove which configuration was active at the
moment a decision or action was taken.

## Purpose

* Bind a microcircuit configuration to a stable `Digest32` so it can be referenced
  elsewhere in the protocol.
* Provide a chainable history via `prev_config_digest` so chips can detect
  rollbacks or unexpected configuration swaps.
* Capture optional attestations that affirm the configuration digest and version.

## How chips use it

* Chips emit `MicrocircuitConfigEvidence` alongside configuration rollouts or
  during periodic state snapshots.
* Consumers verify the digest against their local config material using the
  `UCF:HASH:MC_CONFIG` domain and validate any provided attestation signature
  under `UCF:SIGN:MC_CONFIG`.
* When `prev_config_digest` is present, chips ensure the new configuration forms
  a contiguous chain, rejecting unexpected jumps unless explicitly permitted.

## Boundedness rules

* The `MicrocircuitConfigEvidence` message contains no repeated fields.
* References (`proof_receipt_ref`) MUST be kept to a single entry and MUST point
  to a bounded receipt payload elsewhere in the system.
* Producers SHOULD rotate `attestation_sig` material rather than embedding large
  data blobs; only cryptographic summaries belong in this message.
