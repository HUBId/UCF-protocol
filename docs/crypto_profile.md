# Cryptographic Profile

This repository fixes a minimal cryptographic profile for milestone 1 fixtures:

* **Digest**: `BLAKE3-256` with domain separation `ucf-core`. Digests are formed
  over `DOMAIN || schema_id || schema_version || canonical_bytes` and encoded as
  32 raw bytes. Hex strings in fixtures are lowercase and unprefixed.
* **Signatures**: The protobuf schema is algorithm-agnostic and carries a
  lowercase algorithm label alongside the raw `signer` and `signature` byte
  strings. Fixtures demonstrate Ed25519-encoded bytes but no specific algorithm
  is mandated by the schema.
* **Randomness**: Nonces in envelopes are treated as opaque bytes. When
  constructing fixtures, 16-byte nonces derived from a CSPRNG SHOULD be used to
  avoid collisions.

Future profile revisions may standardize key formats, hashing contexts, and
signature verification procedures; those changes must bump the schema version as
covered in `protocol_versioning.md`.
