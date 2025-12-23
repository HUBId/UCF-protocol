# Release Process

1. Bump the crate/protocol version according to semantic versioning (MAJOR for breaking schema changes, MINOR for additive schema changes).
2. Update `CHANGELOG.md` with the new version entry and notable changes.
3. Run the full test suite (`cargo fmt`, `cargo build`, `cargo clippy`, `cargo test`) to ensure CI will be green.
4. Tag the release as `protocol-v1.x.y` once tests pass.
5. Update chip2, chip3, and chip4 to pin to the new tag (or commit hash if hotfixing).
6. Verify downstream CI remains green after the pins update.
