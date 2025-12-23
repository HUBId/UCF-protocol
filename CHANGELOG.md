# Changelog

## v1.1.0
### Added
- Documented pinning, compatibility expectations, breaking-change policy, and release process to guide chip integrations.
- Added fixture coverage registry ensuring deterministic encode/decode and digest validation for every protocol definition.
- Introduced CI guardrails checking protobuf compilations, generated bindings presence, enum zero values, and map-field bans.

### Changed
- Clarified versioning guidance: additive schema changes are treated as MINOR bumps, while breaking changes require MAJOR releases.

### Fixed
- Ensured every .proto file has at least one deterministic test fixture with expected digests.

## v1.0.0
### Added
- Initial release of the UCF protocol definitions and deterministic encoding helpers.
- Baseline determinism fixtures and tests for core schemas.

### Changed
- N/A

### Fixed
- N/A
