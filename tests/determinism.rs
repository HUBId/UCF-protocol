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
const TOOL_REGISTRY_SCHEMA: &str = "ucf.v1.ToolRegistryContainer";
const TOOL_ONBOARDING_SCHEMA: &str = "ucf.v1.ToolOnboardingEvent";
const AAP_SCHEMA: &str = "ucf.v1.AAP";
const SEP_EVENT_SCHEMA: &str = "ucf.v1.SepEvent";
const SESSION_SEAL_SCHEMA: &str = "ucf.v1.SessionSeal";
const COMPLETENESS_REPORT_SCHEMA: &str = "ucf.v1.CompletenessReport";
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
    let mut aggregate_reason_codes =
        vec!["budget-tight".to_string(), "policy-deny".to_string(), "receipt-missing".to_string()];
    aggregate_reason_codes.sort();

    let mut policy_reason_codes = vec!["deny".to_string(), "require-approval".to_string()];
    policy_reason_codes.sort();

    let mut dlp_reason_codes = vec!["dlp-block".to_string(), "dlp-redact".to_string()];
    dlp_reason_codes.sort();

    let mut exec_reason_codes =
        vec!["executor-timeout".to_string(), "tool-unavailable".to_string()];
    exec_reason_codes.sort();

    let mut budget_reason_codes = vec!["chain-limit".to_string(), "near-exhaustion".to_string()];
    budget_reason_codes.sort();

    let mut receipt_reason_codes = vec!["missing".to_string(), "signature-invalid".to_string()];
    receipt_reason_codes.sort();

    let expected = SignalFrame {
        signal_frame_id: "sig-short-001".to_string(),
        signal_frame_digest: Some(Digest32 { value: vec![0x11; 32] }),
        epoch_id: 42,
        timestamp_ms: 1_700_000_500,
        window: Some(WindowRef {
            window_id: "window-short-1".to_string(),
            window_kind: WindowKind::Short as i32,
            epoch_id: 42,
            digest: Some(Digest32 { value: vec![0xAA; 32] }),
        }),
        integrity_state: IntegrityState::Ok as i32,
        policy_stats: Some(PolicyStats {
            deny_count: 3,
            allow_count: 7,
            require_approval_count: 2,
            require_simulation_count: 1,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes { codes: policy_reason_codes }),
            }),
        }),
        dlp_stats: Some(DlpStats {
            dlp_block_count: 2,
            dlp_redact_count: 1,
            classify_upgrade_count: 1,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes { codes: dlp_reason_codes }),
            }),
        }),
        exec_stats: Some(ExecStats {
            timeout_count: 1,
            partial_failure_count: 1,
            tool_unavailable_count: 2,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes { codes: exec_reason_codes }),
            }),
        }),
        budget_stats: Some(BudgetStats {
            near_exhaustion_count: 1,
            chain_limit_hits: 1,
            concurrency_limit_hits: 0,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes { codes: budget_reason_codes }),
            }),
        }),
        human_stats: Some(HumanStats {
            approval_denied_count: 1,
            stop_invoked_flag: false,
            recovery_stage: "pilot".to_string(),
        }),
        receipt_stats: Some(ReceiptStats {
            receipt_missing_count: 1,
            receipt_invalid_count: 1,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes { codes: receipt_reason_codes }),
            }),
        }),
        reason_codes: Some(ReasonCodes { codes: aggregate_reason_codes }),
    };

    verify_roundtrip("signal_frame_short_window", SIGNAL_FRAME_SCHEMA, expected)
}

#[test]
fn control_frame_fixture_roundtrip() -> Result<()> {
    let mut profile_reason_codes = vec!["ml-ops".to_string(), "safety".to_string()];
    profile_reason_codes.sort();

    let expected = ControlFrame {
        control_frame_id: "ctrl-m1-001".to_string(),
        control_frame_digest: Some(Digest32 { value: vec![0x22; 32] }),
        epoch_id: 42,
        timestamp_ms: 1_700_000_750,
        active_profile: ProfileState::M1 as i32,
        profile_reason_codes: Some(ReasonCodes { codes: profile_reason_codes }),
        overlays: Some(OverlaySet {
            ovl_simulate_first: true,
            ovl_export_lock: true,
            ovl_novelty_lock: true,
        }),
        threshold_modifiers: Some(ThresholdModifiers {
            approval_mode: ApprovalMode::Strict as i32,
            novelty_tightening: LevelClass::High as i32,
            chain_tightening: LevelClass::Med as i32,
            export_strictness_tightening: LevelClass::Med as i32,
            cooldown_class: CooldownClass::Longer as i32,
        }),
        toolclass_mask: Some(ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: false,
            enable_write: false,
            enable_execute: false,
        }),
        deescalation_lock: true,
        charter_version_digest: "charter:v2".to_string(),
        character_epoch_digest: Some(Digest32 { value: vec![0x33; 32] }),
        prev_control_frame_digest: Some(Digest32 { value: vec![0x44; 32] }),
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

#[test]
fn tool_registry_container_roundtrip() -> Result<()> {
    let mut classify_inputs = vec!["image/png".to_string(), "text/plain".to_string()];
    classify_inputs.sort();
    let classify_action = ToolActionProfile {
        action_id: "tool-classify".to_string(),
        display_name: "Classifier".to_string(),
        tool_class: ToolClass::Model as i32,
        input_types: classify_inputs,
        output_type: "application/json".to_string(),
        requires_approval: true,
    };

    let mut storage_inputs = vec!["application/json".to_string()];
    storage_inputs.sort();
    let storage_action = ToolActionProfile {
        action_id: "tool-store".to_string(),
        display_name: "Storage writer".to_string(),
        tool_class: ToolClass::Storage as i32,
        input_types: storage_inputs,
        output_type: "application/octet-stream".to_string(),
        requires_approval: false,
    };

    let mut actions = vec![classify_action.clone(), storage_action.clone()];
    actions.sort_by(|a, b| a.action_id.cmp(&b.action_id));

    let mut adapters = vec![
        AdapterMapEntry {
            adapter: "http-adapter".to_string(),
            tool_id: "tool-classify".to_string(),
            version: "v1.2.3".to_string(),
        },
        AdapterMapEntry {
            adapter: "s3-adapter".to_string(),
            tool_id: "tool-store".to_string(),
            version: "v2.0".to_string(),
        },
    ];
    adapters.sort_by(|a, b| a.adapter.cmp(&b.adapter));

    let expected = ToolRegistryContainer {
        actions,
        adapters,
        steward: "registry-admin".to_string(),
        updated_at: 1_700_000_000,
    };

    verify_roundtrip("tool_registry_container", TOOL_REGISTRY_SCHEMA, expected)
}

#[test]
fn tool_onboarding_event_roundtrip() -> Result<()> {
    let mut classify_inputs = vec!["image/png".to_string(), "text/plain".to_string()];
    classify_inputs.sort();
    let classify_action = ToolActionProfile {
        action_id: "tool-classify".to_string(),
        display_name: "Classifier".to_string(),
        tool_class: ToolClass::Model as i32,
        input_types: classify_inputs,
        output_type: "application/json".to_string(),
        requires_approval: true,
    };

    let expected = ToolOnboardingEvent {
        tool_id: "tool-classify".to_string(),
        submitted_by: "ops-team".to_string(),
        profile: Some(classify_action),
        review_status: "accepted".to_string(),
    };

    verify_roundtrip("tool_onboarding_event", TOOL_ONBOARDING_SCHEMA, expected)
}

#[test]
fn aap_with_recovery_roundtrip() -> Result<()> {
    let mut objectives = vec!["capture approvals".to_string(), "ensure auditability".to_string()];
    objectives.sort();

    let mut approval_reasons = vec!["policy-aligned".to_string(), "risk-low".to_string()];
    approval_reasons.sort();
    let approval = ApprovalDecision {
        approver: "lead-operator".to_string(),
        decision: DecisionForm::Allow as i32,
        reason_codes: Some(ReasonCodes { codes: approval_reasons }),
        summary: "Approved for pilot".to_string(),
    };

    let mut recovery_steps = vec!["notify-owner".to_string(), "reset-plan".to_string()];
    recovery_steps.sort();
    let recovery = RecoveryCase {
        trigger: "missing-approval".to_string(),
        steps: recovery_steps,
        owner: "duty-officer".to_string(),
    };

    let expected = Aap {
        plan_id: "aap-42".to_string(),
        session_id: "session-9000".to_string(),
        objectives,
        approvals: vec![approval],
        recoveries: vec![recovery],
        stop_event: Some(StopEvent {
            reason: "completed".to_string(),
            actor: "supervisor".to_string(),
            timestamp: 1_700_001_234,
            summary: "Plan concluded".to_string(),
        }),
    };

    verify_roundtrip("aap_with_recovery", AAP_SCHEMA, expected)
}

#[test]
fn sep_event_chain_roundtrip() -> Result<()> {
    let mut parent_events = vec!["evt-boot".to_string(), "evt-root".to_string()];
    parent_events.sort();

    let expected = SepEvent {
        session_id: "session-9000".to_string(),
        event_id: "evt-1".to_string(),
        phase: "plan".to_string(),
        parents: parent_events,
        payload: "kickoff".to_string(),
        timestamp: 1_700_002_000,
        summary: Some("Initial planning event".to_string()),
    };

    verify_roundtrip("sep_event_chain", SEP_EVENT_SCHEMA, expected)
}

#[test]
fn session_seal_roundtrip() -> Result<()> {
    let expected = SessionSeal {
        session_id: "session-9000".to_string(),
        record_digest: Some(Digest32 { value: vec![0xAB; 32] }),
        signer: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA, 0xBB, 0xCC],
            signature: vec![0x01, 0x02, 0x03, 0x04],
        }),
        sealed_at: 1_700_002_500,
        summary: Some("Session closed".to_string()),
    };

    verify_roundtrip("session_seal", SESSION_SEAL_SCHEMA, expected)
}

#[test]
fn completeness_report_roundtrip() -> Result<()> {
    let expected = CompletenessReport {
        session_id: "session-9000".to_string(),
        observed_events: 3,
        expected_events: 3,
        terminal: true,
        summary: Some("All planned events observed".to_string()),
    };

    verify_roundtrip("completeness_report", COMPLETENESS_REPORT_SCHEMA, expected)
}
