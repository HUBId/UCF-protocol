# Assets

Assets describe deterministic, digest-addressed configuration bundles that chips
reference when binding morphology, channel parameters, synapse parameters, and
connectivity graphs to protocol events.

## Stored data

* **`AssetDigest`** captures the asset kind, version, digest, and creation time.
  Optional fields allow linking to a previous digest (for chaining) and a proof
  receipt reference.
* **`AssetManifest`** binds a set of four `AssetDigest` entries (morphology,
  channel parameters, synapse parameters, connectivity) together with its own
  manifest digest and creation time.

## Digest formation

Chips compute digests over canonical protobuf bytes using the standard
`DOMAIN || schema_id || schema_version || bytes` input to BLAKE3-256.
The domain strings are:

* `UCF:ASSET:MORPH`
* `UCF:ASSET:CHANNEL_PARAMS`
* `UCF:ASSET:SYN_PARAMS`
* `UCF:ASSET:CONNECTIVITY`
* `UCF:ASSET:MANIFEST`

The canonical bytes are generated using deterministic protobuf encoding with
any repeated fields pre-sorted when they represent sets.

## Boundedness and update policy

* `AssetDigest` and `AssetManifest` are bounded: no unbounded repeated fields
  are present, and optional references must point to externally stored proofs.
* `prev_digest` (when provided) should create a linear history for a given
  asset kind. Producers SHOULD only advance the chain with a strictly newer
  asset version to prevent rollback.
* `AssetManifest` updates should only occur when one or more component digests
  change; consumers should validate that all component asset versions remain
  compatible with the manifest version they accept.
