# Experience Stream

`ExperienceRecord` instances form the durable stream for runtime activity. Each
record references the frames and finalization metadata that describe how the
runtime processed a step.

## Record types and required references

* `RECORD_TYPE_RT_PERCEPTION`: requires `core_frame_ref` and
  `metabolic_frame_ref` that point to the perception inputs and metabolic state.
* `RECORD_TYPE_RT_ACTION_EXEC`: requires `core_frame_ref`, `metabolic_frame_ref`,
  and `governance_frame_ref`. Governance should include `pvgs_receipt_ref` when
  a gate is applied. Include related refs such as policy query/decision and
  ruleset digests.
* `RECORD_TYPE_RT_OUTPUT`: requires `core_frame_ref`, `metabolic_frame_ref`, and
  `governance_frame_ref` with non-empty `dlp_refs`. Related refs typically
  include the output artifact and the DLP scan refs used in the governance
  frame.
* `RECORD_TYPE_RT_DECISION`: requires `governance_frame_ref` with non-empty
  `policy_decision_refs`. `metabolic_frame_ref` is optional when no metabolic
  sampling occurred.
* `RECORD_TYPE_RT_REPLAY`: `related_refs` MUST include the replay plan digest
  ref (client label `replay_plan`).
* `RECORD_TYPE_RT_CONSOLIDATION`: `related_refs` include milestone digests
  summarizing the consolidation scope.

`related_refs` is ordered: producing systems MUST output a stable ordering (for
example sorting by URI) so downstream encoders remain deterministic.
