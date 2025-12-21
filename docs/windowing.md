# Windowing and Epochs

Milestone 1 uses a simple epoch-based windowing model suitable for deterministic
fixtures:

* **Epoch identifiers**: Envelopes carry an `epoch_id` string that binds a batch
  of intent processing to a logical window (for example `2024-Q1` or a rolling
  checkpoint label). The identifier is opaque to the schema and compared as an
  exact string.
* **Nonces**: Each envelope includes a nonce to guarantee uniqueness within an
  epoch. Producers SHOULD ensure nonces are collision-resistant (at least 128
  bits of entropy) and avoid reuse across epochs.
* **Ordering**: Within an epoch, consumers MUST preserve the ordering encoded in
  the enclosing transport. The protobuf schema itself does not encode an
  ordering field; ordering guarantees are delegated to the higher-level channel.
* **Expiration**: Epoch lifetimes and expiry checks are implementation details
  left to the transport. When an epoch is considered expired, envelopes bound to
  that epoch SHOULD be rejected or re-issued under a fresh epoch identifier.

These rules are intentionally minimal and are meant to be compatible with
streaming or batch channels as described in `canonical.proto`.
