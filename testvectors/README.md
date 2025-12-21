# Test Vectors

Each fixture consists of two files:

* `<name>.hex`: canonical deterministic protobuf bytes for the message encoded
  as lowercase hex.
* `<name>.digest`: expected BLAKE3-256 digest in lowercase hex for
  `DOMAIN || schema_id || schema_version || <name>.hex` (the decoded bytes).

The fixtures currently included are:

| Name                   | Domain       | Schema                   | Version |
| ---------------------- | ------------ | ------------------------ | ------- |
| canonical_intent_query | `ucf-core`   | `ucf.v1.CanonicalIntent` | `1`     |
| policy_decision        | `ucf-core`   | `ucf.v1.PolicyDecision`  | `1`     |
| pvgs_receipt           | `ucf-core`   | `ucf.v1.PVGSReceipt`     | `1`     |
| signal_frame_short_window | `ucf-core` | `ucf.v1.SignalFrame`     | `1`     |
| control_frame_m1_overlays_on | `ucf-core` | `ucf.v1.ControlFrame` | `1`     |
| experience_rt_perception | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| experience_rt_action_exec | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| experience_rt_output | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| macro_milestone_chain | `ucf-core` | `ucf.v1.MacroMilestone` | `1`     |
| replay_plan_triggered | `ucf-core` | `ucf.v1.ReplayPlan` | `1`     |
| consistency_feedback_low | `ucf-core` | `ucf.v1.ConsistencyFeedback` | `1`     |
| consistency_feedback_high | `ucf-core` | `ucf.v1.ConsistencyFeedback` | `1`     |
| tool_registry_container | `ucf-core` | `ucf.v1.ToolRegistryContainer` | `1`     |
| tool_onboarding_event | `ucf-core` | `ucf.v1.ToolOnboardingEvent` | `1`     |
| aap_with_recovery | `ucf-core` | `ucf.v1.AAP` | `1`     |
| sep_event_chain | `ucf-core` | `ucf.v1.SepEvent` | `1`     |
| session_seal | `ucf-core` | `ucf.v1.SessionSeal` | `1`     |
| completeness_report | `ucf-core` | `ucf.v1.CompletenessReport` | `1`     |

All repeated fields that represent sets are pre-sorted in the encoded bytes so
that recomputation via the library helpers yields identical outputs.
