# Test Vectors

Each fixture consists of two files:

* `<name>.hex`: canonical deterministic protobuf bytes for the message encoded
  as lowercase hex.
* `<name>.digest`: expected BLAKE3-256 digest in lowercase hex for
  `DOMAIN || schema_id || schema_version || <name>.hex` (the decoded bytes).

The fixtures currently included are:

| Name                   | Domain       | Schema                   | Version |
| ---------------------- | ------------ | ------------------------ | ------- |
| asset_digest_morphology_v1 | `UCF:ASSET:MORPH` | `ucf.v1.AssetDigest` | `1` |
| asset_manifest_v1 | `UCF:ASSET:MANIFEST` | `ucf.v1.AssetManifest` | `1` |
| biophys_channel_params_set_v1 | `UCF:ASSET:CHANNEL_PARAMS` | `ucf.v1.ChannelParamsSetPayload` | `1` |
| biophys_connectivity_graph_v1 | `UCF:ASSET:CONNECTIVITY` | `ucf.v1.ConnectivityGraphPayload` | `1` |
| biophys_morphology_set_v1 | `UCF:ASSET:MORPH` | `ucf.v1.MorphologySetPayload` | `1` |
| biophys_synapse_params_set_v1 | `UCF:ASSET:SYN_PARAMS` | `ucf.v1.SynapseParamsSetPayload` | `1` |
| canonical_intent_query | `ucf-core`   | `ucf.v1.CanonicalIntent` | `1`     |
| policy_decision        | `ucf-core`   | `ucf.v1.PolicyDecision`  | `1`     |
| pvgs_receipt           | `ucf-core`   | `ucf.v1.PVGSReceipt`     | `1`     |
| signal_frame_short_window | `ucf-core` | `ucf.v1.SignalFrame`     | `1`     |
| control_frame_m1_overlays_on | `ucf-core` | `ucf.v1.ControlFrame` | `1`     |
| experience_rt_perception | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| experience_rt_action_exec | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| experience_rt_output | `ucf-core` | `ucf.v1.ExperienceRecord` | `1`     |
| micro_milestone_sealed | `ucf-core` | `ucf.v1.MicroMilestone` | `1`     |
| microcircuit_config_lc_v1 | `UCF:HASH:MC_CONFIG` | `ucf.v1.MicrocircuitConfigEvidence` | `1` |
| microcircuit_config_sn_v1 | `UCF:HASH:MC_CONFIG` | `ucf.v1.MicrocircuitConfigEvidence` | `1` |
| microcircuit_config_hpa_v1 | `UCF:HASH:MC_CONFIG` | `ucf.v1.MicrocircuitConfigEvidence` | `1` |
| meso_milestone_stable | `ucf-core` | `ucf.v1.MesoMilestone` | `1`     |
| macro_milestone_finalized | `ucf-core` | `ucf.v1.MacroMilestone` | `1`     |
| replay_plan_high_fidelity | `ucf-core` | `ucf.v1.ReplayPlan` | `1`     |
| replay_plan_asset_manifest_ref | `ucf-core` | `ucf.v1.ReplayPlan` | `1`     |
| replay_run_evidence | `ucf-core` | `ucf.v1.ReplayRunEvidence` | `1`     |
| consistency_feedback_low_flags | `ucf-core` | `ucf.v1.ConsistencyFeedback` | `1`     |
| tool_registry_container | `ucf-core` | `ucf.v1.ToolRegistryContainer` | `1`     |
| tool_onboarding_event | `ucf-core` | `ucf.v1.ToolOnboardingEvent` | `1`     |
| approval_artifact_package | `ucf-core` | `ucf.v1.ApprovalArtifactPackage` | `1`     |
| approval_decision | `ucf-core` | `ucf.v1.ApprovalDecision` | `1`     |
| sep_event_chain_1 | `ucf-core` | `ucf.v1.SepEvent` | `1`     |
| sep_event_chain_2 | `ucf-core` | `ucf.v1.SepEvent` | `1`     |
| sep_event_chain_3 | `ucf-core` | `ucf.v1.SepEvent` | `1`     |
| session_seal | `ucf-core` | `ucf.v1.SessionSeal` | `1`     |
| completeness_report | `ucf-core` | `ucf.v1.CompletenessReport` | `1`     |

All repeated fields that represent sets are pre-sorted in the encoded bytes so
that recomputation via the library helpers yields identical outputs.
