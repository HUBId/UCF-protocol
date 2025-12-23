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
const MICRO_MILESTONE_SCHEMA: &str = "ucf.v1.MicroMilestone";
const MESO_MILESTONE_SCHEMA: &str = "ucf.v1.MesoMilestone";
const MACRO_MILESTONE_SCHEMA: &str = "ucf.v1.MacroMilestone";
const REPLAY_PLAN_SCHEMA: &str = "ucf.v1.ReplayPlan";
const CONSISTENCY_FEEDBACK_SCHEMA: &str = "ucf.v1.ConsistencyFeedback";
const TOOL_REGISTRY_SCHEMA: &str = "ucf.v1.ToolRegistryContainer";
const TOOL_ONBOARDING_SCHEMA: &str = "ucf.v1.ToolOnboardingEvent";
const APPROVAL_ARTIFACT_PACKAGE_SCHEMA: &str = "ucf.v1.ApprovalArtifactPackage";
const APPROVAL_DECISION_SCHEMA: &str = "ucf.v1.ApprovalDecision";
const SEP_EVENT_SCHEMA: &str = "ucf.v1.SepEvent";
const SESSION_SEAL_SCHEMA: &str = "ucf.v1.SessionSeal";
const COMPLETENESS_REPORT_SCHEMA: &str = "ucf.v1.CompletenessReport";
const VERSION: &str = "1";

fn sorted_strings(items: &[&str]) -> Vec<String> {
    let mut values: Vec<String> = items.iter().map(|item| item.to_string()).collect();
    values.sort();
    values
}

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
    let input_packet_refs = vec![
        Ref { uri: "packet://ingest/0001".to_string(), label: "input-0001".to_string() },
        Ref { uri: "packet://ingest/0002".to_string(), label: "input-0002".to_string() },
    ];

    let intent_refs = vec![
        Ref { uri: "intent://primary/42".to_string(), label: "primary".to_string() },
        Ref { uri: "intent://safety/42".to_string(), label: "safety".to_string() },
    ];

    let candidate_refs =
        vec![Ref { uri: "candidate://lm/alpha".to_string(), label: "lm-alpha".to_string() }];

    let expected = ExperienceRecord {
        record_type: RecordType::RtPerception as i32,
        core_frame_ref: Some(Ref {
            uri: "core://perception/001".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://perception/001".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: None,
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_001,
            timestamp_ms: 1_700_010_000,
            prev_record_digest: Some(Digest32 { value: vec![0xAA; 32] }),
            record_digest: Some(Digest32 { value: vec![0xBB; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/a".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs: vec![],
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-perception-001".to_string(),
        session_id: "session-42".to_string(),
        step_id: "perception-1".to_string(),
        input_packet_refs,
        self_state_ref: Some(Ref {
            uri: "state://self/42".to_string(),
            label: "baseline".to_string(),
        }),
        intent_refs,
        candidate_refs,
        workspace_mode: WorkMode::WmSimulate as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x01; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["ingest", "perception"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-perception-001".to_string(),
        profile_state: ProfileState::M1 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/17".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Low as i32,
        threat_class: LevelClass::Low as i32,
        stability_class: LevelClass::High as i32,
        progress_class: LevelClass::Med as i32,
        noise_class: NoiseClass::Low as i32,
        priority_class: PriorityClass::Low as i32,
        hpa_baseline_ref: Some(Ref {
            uri: "hpa://baseline/seed".to_string(),
            label: "hpa".to_string(),
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-baseline"]) }),
    };

    verify_roundtrip("experience_rt_perception", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn experience_record_rt_action_exec_roundtrip() -> Result<()> {
    let related_refs = vec![
        Ref { uri: "policy://query/001".to_string(), label: "policy_query".to_string() },
        Ref { uri: "policy://decision/001".to_string(), label: "policy_decision".to_string() },
        Ref { uri: "policy://ruleset/alpha".to_string(), label: "ruleset".to_string() },
    ];

    let policy_decision_refs = vec![
        Ref { uri: "policy://decision/001".to_string(), label: "decision-primary".to_string() },
        Ref { uri: "policy://decision/002".to_string(), label: "decision-secondary".to_string() },
    ];

    let grant_refs = vec![
        Ref { uri: "grant://budget/2024-01".to_string(), label: "budget-grant".to_string() },
        Ref { uri: "grant://safety/alpha".to_string(), label: "safety-grant".to_string() },
    ];

    let expected = ExperienceRecord {
        record_type: RecordType::RtActionExec as i32,
        core_frame_ref: Some(Ref {
            uri: "core://action/002".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://action/002".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: Some(Ref {
            uri: "governance://action/002".to_string(),
            label: "governance-frame".to_string(),
        }),
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_002,
            timestamp_ms: 1_700_010_250,
            prev_record_digest: Some(Digest32 { value: vec![0xBB; 32] }),
            record_digest: Some(Digest32 { value: vec![0xCC; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/b".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs,
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-action-002".to_string(),
        session_id: "session-42".to_string(),
        step_id: "action-2".to_string(),
        input_packet_refs: vec![Ref {
            uri: "packet://bridge/030".to_string(),
            label: "primary".to_string(),
        }],
        self_state_ref: Some(Ref {
            uri: "state://self/42".to_string(),
            label: "baseline".to_string(),
        }),
        intent_refs: vec![Ref {
            uri: "intent://primary/42".to_string(),
            label: "primary".to_string(),
        }],
        candidate_refs: vec![Ref {
            uri: "candidate://lm/beta".to_string(),
            label: "lm-beta".to_string(),
        }],
        workspace_mode: WorkMode::WmExecPlan as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x02; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["action", "execute"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-action-002".to_string(),
        profile_state: ProfileState::M2 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/18".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Med as i32,
        threat_class: LevelClass::Med as i32,
        stability_class: LevelClass::Med as i32,
        progress_class: LevelClass::High as i32,
        noise_class: NoiseClass::Med as i32,
        priority_class: PriorityClass::High as i32,
        hpa_baseline_ref: None,
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-action"]) }),
    };

    let mut dlp_refs =
        vec![Ref { uri: "dlp://scan/alpha".to_string(), label: "pre-exec".to_string() }];
    dlp_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let _governance_frame = GovernanceFrame {
        governance_frame_id: "governance-action-002".to_string(),
        policy_decision_refs,
        grant_refs,
        dlp_refs,
        budget_snapshot_ref: Some(Ref {
            uri: "budget://snap/2024-01".to_string(),
            label: "budget".to_string(),
        }),
        pvgs_receipt_ref: Some(Ref {
            uri: "pvgs://receipt/alpha".to_string(),
            label: "pvgs".to_string(),
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["policy-check", "pvgs-gate"]) }),
    };

    verify_roundtrip("experience_rt_action_exec", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn experience_record_rt_output_roundtrip() -> Result<()> {
    let related_refs = vec![
        Ref { uri: "artifact://output/777".to_string(), label: "output_artifact".to_string() },
        Ref { uri: "dlp://scan/final".to_string(), label: "dlp-scan".to_string() },
    ];

    let dlp_refs = vec![
        Ref { uri: "dlp://scan/final".to_string(), label: "dlp-scan".to_string() },
        Ref { uri: "dlp://audit/summary".to_string(), label: "dlp-audit".to_string() },
    ];

    let expected = ExperienceRecord {
        record_type: RecordType::RtOutput as i32,
        core_frame_ref: Some(Ref {
            uri: "core://output/003".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://output/003".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: Some(Ref {
            uri: "governance://output/003".to_string(),
            label: "governance-frame".to_string(),
        }),
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_003,
            timestamp_ms: 1_700_010_500,
            prev_record_digest: Some(Digest32 { value: vec![0xCC; 32] }),
            record_digest: Some(Digest32 { value: vec![0xDD; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/c".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs,
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-output-003".to_string(),
        session_id: "session-42".to_string(),
        step_id: "output-3".to_string(),
        input_packet_refs: vec![Ref {
            uri: "packet://bridge/045".to_string(),
            label: "primary".to_string(),
        }],
        self_state_ref: None,
        intent_refs: vec![Ref {
            uri: "intent://primary/42".to_string(),
            label: "primary".to_string(),
        }],
        candidate_refs: vec![Ref {
            uri: "candidate://lm/gamma".to_string(),
            label: "lm-gamma".to_string(),
        }],
        workspace_mode: WorkMode::WmReport as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x03; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["output", "ready"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-output-003".to_string(),
        profile_state: ProfileState::M2 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/19".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Low as i32,
        threat_class: LevelClass::Low as i32,
        stability_class: LevelClass::High as i32,
        progress_class: LevelClass::High as i32,
        noise_class: NoiseClass::Low as i32,
        priority_class: PriorityClass::Med as i32,
        hpa_baseline_ref: None,
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-output"]) }),
    };

    let mut policy_decision_refs =
        vec![Ref { uri: "policy://decision/003".to_string(), label: "decision".to_string() }];
    policy_decision_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let mut grant_refs =
        vec![Ref { uri: "grant://dlp/export".to_string(), label: "export-grant".to_string() }];
    grant_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let _governance_frame = GovernanceFrame {
        governance_frame_id: "governance-output-003".to_string(),
        policy_decision_refs,
        grant_refs,
        dlp_refs,
        budget_snapshot_ref: Some(Ref {
            uri: "budget://snap/2024-02".to_string(),
            label: "budget".to_string(),
        }),
        pvgs_receipt_ref: None,
        reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["dlp-approved", "output-ready"]),
        }),
    };

    verify_roundtrip("experience_rt_output", EXPERIENCE_SCHEMA, expected)
}

#[test]
fn micro_milestone_sealed_roundtrip() -> Result<()> {
    let mut theme_tags = vec!["alignment".to_string(), "staging".to_string()];
    theme_tags.sort();
    let mut reason_codes = vec!["checkpoint".to_string(), "sealed".to_string()];
    reason_codes.sort();

    let expected = MicroMilestone {
        micro_id: "micro-001".to_string(),
        micro_digest: Some(Digest32 { value: vec![0x11; 32] }),
        state: MilestoneState::Sealed as i32,
        experience_range: Some(ExperienceRange {
            start_experience_id: 1_000,
            end_experience_id: 1_024,
            head_record_digest: Some(Digest32 { value: vec![0xAA; 32] }),
        }),
        summary_digest: Some(Digest32 { value: vec![0xBB; 32] }),
        hormone_profile: Some(HormoneProfileSummary {
            arousal: LevelClass::Low as i32,
            threat: LevelClass::Med as i32,
            stability: LevelClass::High as i32,
            progress: LevelClass::Med as i32,
            allostatic_load: Some(LevelClass::Low as i32),
        }),
        priority_class: PriorityClass::High as i32,
        vrf_digest_ref: Some(Ref { uri: "vrf://micro/seed".to_string(), label: "vrf".to_string() }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://micro/receipt".to_string(),
            label: "proof".to_string(),
        }),
        theme_tags,
        reason_codes: Some(ReasonCodes { codes: reason_codes }),
    };

    verify_roundtrip("micro_milestone_sealed", MICRO_MILESTONE_SCHEMA, expected)
}

#[test]
fn meso_milestone_stable_roundtrip() -> Result<()> {
    let mut theme_tags = vec!["consolidation".to_string(), "stability".to_string()];
    theme_tags.sort();
    let mut micro_refs = vec![
        Ref { uri: "ucf://micro/001".to_string(), label: "micro-a".to_string() },
        Ref { uri: "ucf://micro/002".to_string(), label: "micro-b".to_string() },
    ];
    micro_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let expected = MesoMilestone {
        meso_id: "meso-bridge".to_string(),
        meso_digest: Some(Digest32 { value: vec![0x22; 32] }),
        state: MilestoneState::Stable as i32,
        micro_refs,
        theme_tags,
        hormone_profile: Some(HormoneProfileSummary {
            arousal: LevelClass::Med as i32,
            threat: LevelClass::Low as i32,
            stability: LevelClass::High as i32,
            progress: LevelClass::High as i32,
            allostatic_load: Some(LevelClass::Med as i32),
        }),
        stability_class: LevelClass::High as i32,
        vrf_digest_ref: None,
        proof_receipt_ref: Some(Ref {
            uri: "proof://meso/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_roundtrip("meso_milestone_stable", MESO_MILESTONE_SCHEMA, expected)
}

#[test]
fn macro_milestone_finalized_roundtrip() -> Result<()> {
    let mut meso_refs =
        vec![Ref { uri: "ucf://meso/bridge".to_string(), label: "meso-bridge".to_string() }];
    meso_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut justification_refs = vec![
        Ref { uri: "just://policy/alpha".to_string(), label: "policy".to_string() },
        Ref { uri: "just://audit/2024".to_string(), label: "audit".to_string() },
    ];
    justification_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let trait_updates = vec![
        TraitUpdate {
            trait_name: "novelty-threshold".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: LevelClass::High as i32,
            justification_refs: justification_refs.clone(),
        },
        TraitUpdate {
            trait_name: "export-guardrails".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: LevelClass::Med as i32,
            justification_refs,
        },
    ];

    let expected = MacroMilestone {
        macro_id: "macro-root".to_string(),
        macro_digest: Some(Digest32 { value: vec![0x33; 32] }),
        state: MilestoneState::Finalized as i32,
        meso_refs,
        trait_updates,
        identity_anchor_flag: true,
        consistency_class: ConsistencyClass::ConsistencyHigh as i32,
        vrf_digest_ref: Some(Ref { uri: "vrf://macro/seed".to_string(), label: "vrf".to_string() }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://macro/receipt".to_string(),
            label: "proof".to_string(),
        }),
        policy_ecology_ref: Some(Ref {
            uri: "pev://digest/v1".to_string(),
            label: "policy-ecology".to_string(),
        }),
    };

    verify_roundtrip("macro_milestone_finalized", MACRO_MILESTONE_SCHEMA, expected)
}

#[test]
fn replay_plan_high_fidelity_roundtrip() -> Result<()> {
    let mut target_refs = vec![
        Ref { uri: "ucf://macro/root".to_string(), label: "macro-root".to_string() },
        Ref { uri: "ucf://meso/bridge".to_string(), label: "meso-bridge".to_string() },
    ];
    target_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut trigger_reason_codes =
        vec!["consistency-low".to_string(), "operator-trigger".to_string()];
    trigger_reason_codes.sort();

    let expected = ReplayPlan {
        replay_id: "replay-stability-check".to_string(),
        replay_digest: Some(Digest32 { value: vec![0x44; 32] }),
        trigger_reason_codes: Some(ReasonCodes { codes: trigger_reason_codes }),
        target_refs,
        fidelity: ReplayFidelity::ReplayHigh as i32,
        inject_mode: ReplayInjectMode::InjectCenExecPlan as i32,
        stop_conditions: Some(replay_plan::StopConditions {
            max_steps_class: 4,
            max_budget_class: 2,
            stop_on_dlp_flag: true,
        }),
        vrf_digest_ref: Some(Ref {
            uri: "vrf://replay/seed".to_string(),
            label: "vrf".to_string(),
        }),
        proof_receipt_ref: None,
    };

    verify_roundtrip("replay_plan_high_fidelity", REPLAY_PLAN_SCHEMA, expected)
}

#[test]
fn consistency_feedback_low_flags_roundtrip() -> Result<()> {
    let mut ism_refs = vec![
        Ref { uri: "ucf://macro/root".to_string(), label: "macro-anchor".to_string() },
        Ref { uri: "ucf://ism/123".to_string(), label: "ism".to_string() },
    ];
    ism_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut trigger_reason_codes =
        vec!["drift-detected".to_string(), "replay-recommended".to_string()];
    trigger_reason_codes.sort();

    let flags = vec![ConsistencyFlag::BehaviorDrift as i32, ConsistencyFlag::RiskDrift as i32];

    let expected = ConsistencyFeedback {
        cf_id: "cf-low-001".to_string(),
        cf_digest: Some(Digest32 { value: vec![0x55; 32] }),
        rss_ref: Some(Ref {
            uri: "rss://baseline/1".to_string(),
            label: "baseline-rss".to_string(),
        }),
        ism_refs,
        pev_ref: Some(Ref {
            uri: "pev://digest/v2".to_string(),
            label: "policy-ecology".to_string(),
        }),
        consistency_class: ConsistencyClass::ConsistencyLow as i32,
        flags,
        recommended_noise_class: NoiseClass::Med as i32,
        consolidation_eligibility: ConsolidationEligibility::Allow as i32,
        replay_trigger_hint: true,
        trigger_reason_codes: Some(ReasonCodes { codes: trigger_reason_codes }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://consistency/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_roundtrip("consistency_feedback_low_flags", CONSISTENCY_FEEDBACK_SCHEMA, expected)
}

#[test]
fn tool_registry_container_roundtrip() -> Result<()> {
    let default_constraints = ToolConstraintsDefaults {
        max_bytes_out_class: SizeClass::SizeSmall as i32,
        max_items_out_class: SizeClass::SizeMed as i32,
        timeout_class: TimeoutClass::TimeoutShort as i32,
        rate_limit_class: RateLimitClass::RateMed as i32,
        allow_unbounded_query: false,
    };

    let data_class_conditions = vec![DataClassCondition {
        param_name: "query".to_string(),
        op: "eq".to_string(),
        value: "latest".to_string(),
        result_data_class: DataClass::Public as i32,
    }];

    let tool_action = ToolActionProfile {
        tool_id: "sensor-service".to_string(),
        action_id: "read-latest".to_string(),
        profile_version: "1.0.0".to_string(),
        profile_digest: Some(Digest32 { value: vec![0x10; 32] }),
        action_type: ToolActionType::Read as i32,
        reversibility: Reversibility::Reversible as i32,
        side_effect_class: SideEffectClass::None as i32,
        scope_shape: ScopeShape::Single as i32,
        max_data_class_out: DataClass::Confidential as i32,
        input_schema: Some(TypedSchema {
            schema_id: "ucf.v1.ReadInput".to_string(),
            schema_digest: Some(Digest32 { value: vec![0xA1; 32] }),
            max_fields: 4,
        }),
        output_schema: Some(TypedSchema {
            schema_id: "ucf.v1.ReadOutput".to_string(),
            schema_digest: Some(Digest32 { value: vec![0xB2; 32] }),
            max_fields: 6,
        }),
        default_constraints: Some(default_constraints),
        retry_policy: Some(RetryPolicy {
            retry_allowed: true,
            retry_class: RetryClass::RetryLow as i32,
        }),
        simulation_mode: Some(SimulationMode {
            simulatable: true,
            sim_tool_id: "sim-sensor".to_string(),
            sim_action_id: "simulate-read".to_string(),
            sim_fidelity_class: SimulationFidelity::Med as i32,
        }),
        cost_model: Some(CostModel {
            base_cost_class: CostClass::CostLow as i32,
            scope_multiplier_class: CostClass::CostMed as i32,
            data_multiplier_class: CostClass::CostMed as i32,
            irreversibility_multiplier_class: CostClass::CostLow as i32,
        }),
        attestation_requirements: Some(AttestationRequirements {
            artifact_digest_required: true,
            allowed_artifact_digests: vec![
                Digest32 { value: vec![0x01; 32] },
                Digest32 { value: vec![0x02; 32] },
            ],
        }),
        logging_requirements: Some(LoggingRequirements {
            require_outcome_digest: true,
            require_tool_version_digest: true,
            require_side_effect_indicators: false,
        }),
        data_class_conditions,
        expected_side_effect_indicators: vec!["cache-read".to_string(), "trace".to_string()],
        known_failure_modes: vec!["timeout".to_string(), "unreachable".to_string()],
    };

    let mut tool_actions = vec![tool_action];
    tool_actions.sort_by(|a, b| a.action_id.cmp(&b.action_id));

    let expected = ToolRegistryContainer {
        registry_id: "registry-alpha".to_string(),
        registry_version: "2024-01".to_string(),
        registry_digest: Some(Digest32 { value: vec![0xCC; 32] }),
        tool_actions,
        created_at_ms: 1_700_003_000,
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Accepted as i32,
            receipt_digest: Some(Digest32 { value: vec![0xAA; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0x01, 0x02],
                signature: vec![0x03, 0x04],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x10; 32] }),
        }),
        attestation_sig: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x10, 0x11, 0x12],
            signature: vec![0x21, 0x22, 0x23],
        }),
    };

    verify_roundtrip("tool_registry_container", TOOL_REGISTRY_SCHEMA, expected)
}

#[test]
fn tool_onboarding_event_roundtrip() -> Result<()> {
    let expected = ToolOnboardingEvent {
        event_id: "onboard-evt-01".to_string(),
        event_digest: Some(Digest32 { value: vec![0x0A; 32] }),
        tool_id: "sensor-service".to_string(),
        action_id: "read-latest".to_string(),
        stage: OnboardingStage::To6Suspended as i32,
        stage_reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["missing-attestation", "risk-review"]),
        }),
        required_artifact_digests: vec![Digest32 { value: vec![0x05; 32] }],
        test_evidence_refs: vec![Ref {
            uri: "evidence://test/report".to_string(),
            label: "report".to_string(),
        }],
        signatures: vec![Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA, 0xBB],
            signature: vec![0xCC, 0xDD],
        }],
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Pending as i32,
            receipt_digest: Some(Digest32 { value: vec![0x09; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0xFE],
                signature: vec![0xEE],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x0F; 32] }),
        }),
    };

    verify_roundtrip("tool_onboarding_event", TOOL_ONBOARDING_SCHEMA, expected)
}

#[test]
fn approval_artifact_package_roundtrip() -> Result<()> {
    let alternatives = vec![
        Alternative {
            alt_type: AlternativeType::SimulateFirst as i32,
            expected_cost: Some(alternative::ExpectedCost::ExpectedCostClass(
                CostClass::CostMed as i32,
            )),
            pros_cons_digest: Some(Digest32 { value: vec![0xAB; 32] }),
        },
        Alternative {
            alt_type: AlternativeType::NarrowScope as i32,
            expected_cost: Some(alternative::ExpectedCost::ExpectedCostBucket(2)),
            pros_cons_digest: Some(Digest32 { value: vec![0xBC; 32] }),
        },
    ];

    let evidence_refs = vec![
        Ref { uri: "evidence://logs/primary".to_string(), label: "logs".to_string() },
        Ref { uri: "evidence://report/risk".to_string(), label: "risk".to_string() },
    ];

    let expected = ApprovalArtifactPackage {
        aap_id: "aap-42".to_string(),
        aap_digest: Some(Digest32 { value: vec![0x44; 32] }),
        session_id: "session-9000".to_string(),
        intent_ref: Some(Ref {
            uri: "intent://primary/42".to_string(),
            label: "intent".to_string(),
        }),
        action_spec_ref: Some(Ref {
            uri: "action://spec/read".to_string(),
            label: "action-spec".to_string(),
        }),
        decision_ref: Some(Ref {
            uri: "decision://placeholder".to_string(),
            label: "decision".to_string(),
        }),
        charter_version_digest: "charter:v5".to_string(),
        policy_version_digest: "policy:v7".to_string(),
        profile_digest: Some(Digest32 { value: vec![0x45; 32] }),
        requested_operation: RequestedOperation::OpWrite as i32,
        risk_level: RiskLevel::Medium as i32,
        requested_data_class: DataClass::Restricted as i32,
        constraints_proposal: Some(ConstraintsDelta {
            constraints_added: sorted_strings(&["approval-required", "scope-narrowing"]),
            constraints_removed: vec!["legacy-exception".to_string()],
        }),
        alternatives,
        evidence_refs,
        expires_at_ms: 1_700_020_000,
        two_person_requirement: TwoPersonRequirement::Two as i32,
    };

    verify_roundtrip("approval_artifact_package", APPROVAL_ARTIFACT_PACKAGE_SCHEMA, expected)
}

#[test]
fn approval_decision_roundtrip() -> Result<()> {
    let expected = ApprovalDecision {
        approval_id: "approval-01".to_string(),
        approval_digest: Some(Digest32 { value: vec![0x55; 32] }),
        aap_digest: Some(Digest32 { value: vec![0x44; 32] }),
        decision: ApprovalDecisionType::ApproveWithModifications as i32,
        modifications: Some(ConstraintsDelta {
            constraints_added: vec!["cooldown-required".to_string()],
            constraints_removed: vec![],
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["two-person", "risk-review"]) }),
        signatures: vec![Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA],
            signature: vec![0xBB],
        }],
        expires_at_ms: 1_700_030_000,
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Accepted as i32,
            receipt_digest: Some(Digest32 { value: vec![0x46; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0x0A, 0x0B],
                signature: vec![0x0C, 0x0D],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x0E; 32] }),
        }),
    };

    verify_roundtrip("approval_decision", APPROVAL_DECISION_SCHEMA, expected)
}

#[test]
fn sep_event_chain_roundtrip() -> Result<()> {
    let events = vec![
        (
            "sep_event_chain_1",
            SepEvent {
                event_id: "evt-1".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvIntent as i32,
                object_ref: Some(Ref {
                    uri: "intent://primary/42".to_string(),
                    label: "intent".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["init".to_string()] }),
                timestamp_ms: 1_700_002_000,
                prev_event_digest: Some(Digest32 { value: vec![0x00; 32] }),
                event_digest: Some(Digest32 { value: vec![0x10; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x01],
                    signature: vec![0x02],
                }),
                epoch_id: 100,
            },
        ),
        (
            "sep_event_chain_2",
            SepEvent {
                event_id: "evt-2".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvDecision as i32,
                object_ref: Some(Ref {
                    uri: "decision://approval".to_string(),
                    label: "decision".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["policy".to_string()] }),
                timestamp_ms: 1_700_002_500,
                prev_event_digest: Some(Digest32 { value: vec![0x10; 32] }),
                event_digest: Some(Digest32 { value: vec![0x20; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x03],
                    signature: vec![0x04],
                }),
                epoch_id: 100,
            },
        ),
        (
            "sep_event_chain_3",
            SepEvent {
                event_id: "evt-3".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvOutcome as i32,
                object_ref: Some(Ref {
                    uri: "outcome://result".to_string(),
                    label: "outcome".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["success".to_string()] }),
                timestamp_ms: 1_700_003_000,
                prev_event_digest: Some(Digest32 { value: vec![0x20; 32] }),
                event_digest: Some(Digest32 { value: vec![0x30; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x05],
                    signature: vec![0x06],
                }),
                epoch_id: 101,
            },
        ),
    ];

    for (name, expected) in events {
        verify_roundtrip(name, SEP_EVENT_SCHEMA, expected.clone())?;
    }

    Ok(())
}

#[test]
fn session_seal_roundtrip() -> Result<()> {
    let expected = SessionSeal {
        seal_id: "seal-9000".to_string(),
        seal_digest: Some(Digest32 { value: vec![0xAB; 32] }),
        session_id: "session-9000".to_string(),
        final_event_digest: Some(Digest32 { value: vec![0x30; 32] }),
        final_record_digest: Some(Digest32 { value: vec![0xCD; 32] }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://session/receipt".to_string(),
            label: "proof".to_string(),
        }),
        created_at_ms: 1_700_003_500,
    };

    verify_roundtrip("session_seal", SESSION_SEAL_SCHEMA, expected)
}

#[test]
fn completeness_report_roundtrip() -> Result<()> {
    let expected = CompletenessReport {
        report_id: "comp-01".to_string(),
        report_digest: Some(Digest32 { value: vec![0xEF; 32] }),
        session_id: "session-9000".to_string(),
        status: CompletenessStatus::CompFail as i32,
        missing_nodes: vec![Ref {
            uri: "sep://evt/missing".to_string(),
            label: "missing".to_string(),
        }],
        missing_edges: vec!["evt-2->evt-4".to_string(), "evt-1->evt-3".to_string()],
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["edge-gap", "missing-node"]) }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://completeness/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_roundtrip("completeness_report", COMPLETENESS_REPORT_SCHEMA, expected)
}
