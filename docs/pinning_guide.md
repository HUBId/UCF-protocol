# Pinning Guide for Chip2/3/4

Consumers must pin to immutable references to guarantee deterministic behavior and reproducible rollouts.

- **Pin by git tag:** use release tags such as `protocol-v1.x.y`.
- **Pin by commit hash:** for pre-release testing or hotfix validation, use a specific commit SHA.
- **Never depend on `main`:** rolling dependencies on the default branch are disallowed to avoid silent schema drift.

## How to Pin
- Update your dependency declarations to reference the desired tag or commit hash in Cargo, Bazel, or your chosen build tool.
- Mirror the pinned reference in downstream lock files where applicable.

## Release Coordination
- When a new tag is published, update chip2, chip3, and chip4 to the matching tag or commit.
- Verify CI remains green after pin updates to confirm deterministic encode/decode behavior.
