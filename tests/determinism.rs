#![forbid(unsafe_code)]

use std::fs;

use anyhow::{Context, Result};
use prost::Message;
use ucf_protocol::ucf::v1::canonical_intent::Params as CanonicalIntentParams;
use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

const DOMAIN: &str = "ucf-core";
const INTENT_SCHEMA: &str = "ucf.v1.CanonicalIntent";
const POLICY_SCHEMA: &str = "ucf.v1.PolicyDecision";
const PVGS_SCHEMA: &str = "ucf.v1.PVGSReceipt";
const SIGNAL_FRAME_SCHEMA: &str = "ucf.v1.SignalFrame";
const CONTROL_FRAME_SCHEMA: &str = "ucf.v1.ControlFrame";
const EXPERIENCE_SCHEMA: &str = "ucf.v1.ExperienceRecord";
const MACRO_MILESTONE_SCHEMA: &str = "ucf.v1.MacroMilestone";
const REPLAY_PLAN_SCHEMA: &str = "ucf.v1.ReplayPlan";
const CONSISTENCY_FEEDBACK_SCHEMA: &str = "ucf.v1.ConsistencyFeedback";
const VERSION: &str = "1";

fn load_fixture(name: &str) -> Result<(Vec<u8>, [u8; 32])> {
    let hex_bytes = fs::read_to_string(format!("testvectors/{name}.hex"))
        .with_context(|| format!("reading {name}.hex"))?;
    let bytes = hex::decode(hex_bytes.trim()).context("decoding fixture hex bytes")?;
    let digest_hex = fs::read_to_string(format!("testvectors/{name}.digest"))
        .with_context(|| format!("reading {name}.digest"))?;
    let digest_vec = hex::decode(digest_hex.trim()).context("decoding digest hex")?;
    let digest: [u8; 32] =
        digest_vec.try_into().map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?;
    Ok((bytes, digest))
}

fn verify_roundtrip<M>(name: &str, schema: &str, expected: M) -> Result<()>
where
    M: Message + Default + Clone,
{
    let (fixture_bytes, fixture_digest) = load_fixture(name)?;

    let decoded = M::decode(fixture_bytes.as_slice())?;
    let encoded = canonical_bytes(&decoded);
    assert_eq!(fixture_bytes, encoded, "canonical bytes should be stable");

    let digest = digest32(DOMAIN, schema, VERSION, &encoded);
    assert_eq!(fixture_digest, digest, "digest should match stored fixture");

    // Regenerate bytes from an explicitly constructed message to ensure parity.
    let constructed_bytes = canonical_bytes(&expected);
    assert_eq!(encoded, constructed_bytes, "constructed and fixture differ");

    Ok(())
}

#[test]
fn canonical_intent_fixture_roundtrip() -> Result<()> {
    let expected = CanonicalIntent {
        intent_id: "intent-123".to_string(),
        channel: Channel::Realtime as i32,
        risk_level: RiskLevel::Low as i32,
        data_class: DataClass::Public as i32,
        subject: Some(Ref { uri: "did:example:subject".to_string(), label: "primary".to_string() }),
        reason_codes: Some(ReasonCodes {
            codes: vec!["baseline".to_string(), "query".to_string()],
        }),
        params: Some(CanonicalIntentParams::Query(QueryParams {
            query: "select * from controls".to_string(),
            selectors: vec!["bar".to_string(), "foo".to_string()],
        })),
    };

    verify_roundtrip("canonical_intent_query", INTENT_SCHEMA, expected)
}

#[test]
fn policy_decision_fixture_roundtrip() -> Result<()> {
    let expected = PolicyDecision {
        decision: DecisionForm::RequireApproval as i32,
        reason_codes: Some(ReasonCodes {
            codes: vec!["missing-proof".to_string(), "scope-limited".to_string()],
        }),
        constraints: Some(ConstraintsDelta {
            constraints_added: vec!["geo-fence".to_string(), "mfa-required".to_string()],
            constraints_removed: vec!["legacy-exception".to_string()],
        }),
    };

    verify_roundtrip("policy_decision", POLICY_SCHEMA, expected)
}

#[test]
fn pvgs_receipt_fixture_roundtrip() -> Result<()> {
    let expected = PvgsReceipt {
        status: ReceiptStatus::Accepted as i32,
        program_digest: Some(Digest32 { value: (0u8..32).collect() }),
        proof_digest: Some(Digest32 { value: vec![0xAA; 32] }),
        signer: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x01, 0x02, 0x03, 0x04],
            signature: vec![0x05, 0x06, 0x07, 0x08],
        }),
    };

    verify_roundtrip("pvgs_receipt", PVGS_SCHEMA, expected)
}

#[test]
fn signal_frame_fixture_roundtrip() -> Result<()> {
    let expected = SignalFrame {
        window: "window-5m".to_string(),
        policy_stats: Some(PolicyStats { evaluated: 15, allowed: 12, denied: 2, deferred: 1 }),
        dlp_stats: Some(DlpStats { scanned: 8, flagged: 2, blocked: 1 }),
        exec_stats: Some(ExecStats {
            runs_started: 5,
            runs_completed: 4,
            runs_failed: 1,
            tokens_consumed: 4096,
        }),
        budget_stats: Some(BudgetStats {
            consumed_tokens: 4096,
            remaining_tokens: 8192,
            overage_tokens: 0,
        }),
        receipt_stats: Some(ReceiptStats { accepted: 10, rejected: 1, errored: 1 }),
        human_stats: Some(HumanStats {
            approvals_requested: 2,
            approvals_granted: 1,
            escalations: 1,
            overrides: 0,
        }),
    };

    verify_roundtrip("signal_frame_short_window", SIGNAL_FRAME_SCHEMA, expected)
}

#[test]
fn control_frame_fixture_roundtrip() -> Result<()> {
    let expected = ControlFrame {
        profile: "M1".to_string(),
        overlays: Some(OverlayControls {
            state: OverlayState::Enabled as i32,
            watermark_enabled: true,
            audit_trail_enabled: true,
        }),
        toolclass_masks: vec![
            ToolClassMask { tool_class: ToolClass::Model as i32, action: MaskAction::Allow as i32 },
            ToolClassMask {
                tool_class: ToolClass::Executor as i32,
                action: MaskAction::RequireHuman as i32,
            },
        ],
        threshold_modifiers: Some(ThresholdModifiers {
            safety: ThresholdBehavior::Stricter as i32,
            privacy: ThresholdBehavior::Unchanged as i32,
            budget: ThresholdBehavior::Relaxed as i32,
        }),
    };

    verify_roundtrip("control_frame_m1_overlays_on", CONTROL_FRAME_SCHEMA, expected)
}

#[test]
fn experience_record_rt_perception_roundtrip() -> Result<()> {
    let expected = ExperienceRecord {
        record_type: RuntimeRecordType::RtPerception as i32,
        core: Some(CoreFrame {
            intent_id: "intent-rt".to_string(),
            session_id: "session-42".to_string(),
            step_id: "perception-1".to_string(),
            actor: "sensor-bridge".to_string(),
            description: "ingest perception stream".to_string(),
        }),
        metabolic: Some(MetabolicFrame {
            prompt_tokens: 128,
            completion_tokens: 0,
            latency_ms: 25,
            cache_hit: false,
        }),
        governance: Some(GovernanceFrame {
            decision: DecisionForm::Allow as i32,
            reason_codes: Some(ReasonCodes { codes: vec!["perception-baseline".to_string()] }),
            constraints_applied: vec!["sanitized-inputs".to_string()],
        }),
        finalization: Some(FinalizationHeader {
            epoch_id: 17,
            charter_digest: "charter:v1".to_string(),
            profile_digest: Some(Digest32 { value: vec![0x10; 32] }),
            prev_record_digest: Some(Digest32 { value: vec![0x00; 32] }),
            record_digest: Some(Digest32 { value: vec![0x01; 32] }),
            vrf_proof: Some(Signature {
                algorithm: "TEMPORARY_VRF".to_string(),
                signer: vec![0xAA, 0xBB, 0xCC, 0xDD],
                signature: vec![0x01, 0x23, 0x45, 0x67, 0x89],
            }),
        }),
    };

    verify_roundtrip("experience_rt_perception", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn experience_record_rt_action_exec_roundtrip() -> Result<()> {
    let mut constraints = vec!["rate-limit".to_string(), "humans-in-loop".to_string()];
    constraints.sort();
    let mut reason_codes = vec!["approval-required".to_string(), "safety-review".to_string()];
    reason_codes.sort();

    let expected = ExperienceRecord {
        record_type: RuntimeRecordType::RtActionExec as i32,
        core: Some(CoreFrame {
            intent_id: "intent-rt".to_string(),
            session_id: "session-42".to_string(),
            step_id: "action-2".to_string(),
            actor: "agent-core".to_string(),
            description: "execute action plan".to_string(),
        }),
        metabolic: Some(MetabolicFrame {
            prompt_tokens: 256,
            completion_tokens: 128,
            latency_ms: 40,
            cache_hit: true,
        }),
        governance: Some(GovernanceFrame {
            decision: DecisionForm::RequireApproval as i32,
            reason_codes: Some(ReasonCodes { codes: reason_codes }),
            constraints_applied: constraints,
        }),
        finalization: Some(FinalizationHeader {
            epoch_id: 17,
            charter_digest: "charter:v1".to_string(),
            profile_digest: Some(Digest32 { value: vec![0x20; 32] }),
            prev_record_digest: Some(Digest32 { value: vec![0x01; 32] }),
            record_digest: Some(Digest32 { value: vec![0x02; 32] }),
            vrf_proof: Some(Signature {
                algorithm: "TEMPORARY_VRF".to_string(),
                signer: vec![0xAA, 0xBB, 0xCC, 0xDD],
                signature: vec![0x02, 0x24, 0x46, 0x68, 0x8A],
            }),
        }),
    };

    verify_roundtrip("experience_rt_action_exec", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn experience_record_rt_output_roundtrip() -> Result<()> {
    let mut constraints = vec!["output-audited".to_string(), "watermark-applied".to_string()];
    constraints.sort();
    let mut reason_codes = vec!["output-ready".to_string()];
    reason_codes.sort();

    let expected = ExperienceRecord {
        record_type: RuntimeRecordType::RtOutput as i32,
        core: Some(CoreFrame {
            intent_id: "intent-rt".to_string(),
            session_id: "session-42".to_string(),
            step_id: "output-3".to_string(),
            actor: "renderer".to_string(),
            description: "deliver output to user".to_string(),
        }),
        metabolic: Some(MetabolicFrame {
            prompt_tokens: 64,
            completion_tokens: 512,
            latency_ms: 30,
            cache_hit: false,
        }),
        governance: Some(GovernanceFrame {
            decision: DecisionForm::Allow as i32,
            reason_codes: Some(ReasonCodes { codes: reason_codes }),
            constraints_applied: constraints,
        }),
        finalization: Some(FinalizationHeader {
            epoch_id: 17,
            charter_digest: "charter:v1".to_string(),
            profile_digest: Some(Digest32 { value: vec![0x30; 32] }),
            prev_record_digest: Some(Digest32 { value: vec![0x02; 32] }),
            record_digest: Some(Digest32 { value: vec![0x03; 32] }),
            vrf_proof: Some(Signature {
                algorithm: "TEMPORARY_VRF".to_string(),
                signer: vec![0xAA, 0xBB, 0xCC, 0xDD],
                signature: vec![0x03, 0x25, 0x47, 0x69, 0x8B],
            }),
        }),
    };

    verify_roundtrip("experience_rt_output", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn macro_milestone_chain_roundtrip() -> Result<()> {
    let expected = MacroMilestone {
        id: "macro-frontier".to_string(),
        objective: "Expand frontier safely".to_string(),
        meso_milestones: vec![MesoMilestone {
            id: "meso-staging".to_string(),
            objective: "Stage corridor expansion".to_string(),
            micro_milestones: vec![
                MicroMilestone {
                    id: "micro-calibrate".to_string(),
                    objective: "Calibrate edge sensors".to_string(),
                    deliverables: vec!["calibration-report".to_string(), "sensor-map".to_string()],
                    owner: "scout".to_string(),
                },
                MicroMilestone {
                    id: "micro-scout".to_string(),
                    objective: "Scout safe corridor".to_string(),
                    deliverables: vec!["intel-brief".to_string(), "route-plan".to_string()],
                    owner: "scout".to_string(),
                },
            ],
            steward: "orchestrator".to_string(),
        }],
        sponsor: "mission-control".to_string(),
    };

    verify_roundtrip("macro_milestone_chain", MACRO_MILESTONE_SCHEMA, expected)
}

#[test]
fn replay_plan_triggered_roundtrip() -> Result<()> {
    let mut actions = vec!["recompute-digest".to_string(), "replay-signature".to_string()];
    actions.sort();
    let mut reason_codes = vec!["epoch-mismatch".to_string(), "vrf-replay".to_string()];
    reason_codes.sort();

    let expected = ReplayPlan {
        plan_id: "replay-epoch-17".to_string(),
        trigger: "finalization-drift".to_string(),
        reason_codes: Some(ReasonCodes { codes: reason_codes }),
        actions,
    };

    verify_roundtrip("replay_plan_triggered", REPLAY_PLAN_SCHEMA, expected)
}

#[test]
fn consistency_feedback_low_roundtrip() -> Result<()> {
    let expected = ConsistencyFeedback {
        level: ConsistencyLevel::Low as i32,
        reason_codes: Some(ReasonCodes { codes: vec!["state-divergence".to_string()] }),
        summary: "Observed drift from baseline state".to_string(),
    };

    verify_roundtrip("consistency_feedback_low", CONSISTENCY_FEEDBACK_SCHEMA, expected)
}

#[test]
fn consistency_feedback_high_roundtrip() -> Result<()> {
    let mut reason_codes = vec!["multi-hop-consistency".to_string(), "self-check".to_string()];
    reason_codes.sort();

    let expected = ConsistencyFeedback {
        level: ConsistencyLevel::High as i32,
        reason_codes: Some(ReasonCodes { codes: reason_codes }),
        summary: "High alignment across recursive states".to_string(),
    };

    verify_roundtrip("consistency_feedback_high", CONSISTENCY_FEEDBACK_SCHEMA, expected)
}
