# Tooling Profiles

The `tooling.proto` package captures how external tools are profiled and onboarded
into UCF.

* `ToolActionProfile` records the action metadata (action type, scope, schemas),
  default constraints (timeouts, rate limits, size bounds), retry/simulation/cost
  models, attestation/logging requirements, and optional data-class conditions or
  expected side-effect indicators. All repeated fields are explicitly ordered in
  fixtures for deterministic encoding.
* `ToolRegistryContainer` aggregates the profiled tool actions with registry
  metadata and attestation material, while `ToolOnboardingEvent` documents staged
  onboarding progress for a specific tool action.
* `ToolAdapterMapEntry` links a tool action to an adapter endpoint alongside
  payload and destination class limits.

Enumerations all include an `UNSPECIFIED` zero value and avoid maps to ensure
stable prost code generation. Fixtures in `testvectors/` cover a read-style
profile, registry container, onboarding event, and adapter constraints to enforce
deterministic round-trips.
