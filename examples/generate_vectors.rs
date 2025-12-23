use std::fs;
use std::path::Path;

use prost::Message;
use ucf_protocol::ucf::v1::canonical_intent::Params as CanonicalIntentParams;
use ucf_protocol::ucf::v1::replay_plan::StopConditions;
use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

fn sorted_strings(items: &[&str]) -> Vec<String> {
    let mut values: Vec<String> = items.iter().map(|item| item.to_string()).collect();
    values.sort();
    values
}

fn write_fixture(name: &str, schema: &str, bytes: &[u8], domain: &str) -> anyhow::Result<()> {
    let digest = digest32(domain, schema, "1", bytes);
    let hex_path = Path::new("testvectors").join(format!("{name}.hex"));
    let digest_path = Path::new("testvectors").join(format!("{name}.digest"));
    let mut hex_body = hex::encode(bytes);
    hex_body.push('\n');
    let mut digest_body = hex::encode(digest);
    digest_body.push('\n');
    fs::write(&hex_path, hex_body)?;
    fs::write(&digest_path, digest_body)?;
    Ok(())
}

fn emit_fixture<M: Message>(
    name: &str,
    schema: &str,
    message: &M,
    domain: &str,
) -> anyhow::Result<()> {
    let bytes = canonical_bytes(message);
    write_fixture(name, schema, &bytes, domain)
}

fn main() -> anyhow::Result<()> {
    fs::create_dir_all("testvectors")?;
    let domain = "ucf-core";

    let canonical_intent = CanonicalIntent {
        intent_id: "intent-123".to_string(),
        channel: Channel::Realtime as i32,
        risk_level: RiskLevel::Low as i32,
        data_class: DataClass::Public as i32,
        subject: Some(Ref { uri: "did:example:subject".to_string(), label: "primary".to_string() }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["baseline", "query"]) }),
        params: Some(CanonicalIntentParams::Query(QueryParams {
            query: "select * from controls".to_string(),
            selectors: sorted_strings(&["foo", "bar"]),
        })),
    };

    let policy_decision = PolicyDecision {
        decision: DecisionForm::RequireApproval as i32,
        reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["missing-proof", "scope-limited"]),
        }),
        constraints: Some(ConstraintsDelta {
            constraints_added: sorted_strings(&["mfa-required", "geo-fence"]),
            constraints_removed: sorted_strings(&["legacy-exception"]),
        }),
    };

    let pvgs_receipt = PvgsReceipt {
        status: ReceiptStatus::Accepted as i32,
        program_digest: Some(Digest32 { value: (0u8..32).collect() }),
        proof_digest: Some(Digest32 { value: vec![0xAA; 32] }),
        signer: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x01, 0x02, 0x03, 0x04],
            signature: vec![0x05, 0x06, 0x07, 0x08],
        }),
    };

    let signal_frame = SignalFrame {
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
                reason_codes: Some(ReasonCodes {
                    codes: sorted_strings(&["deny", "require-approval"]),
                }),
            }),
        }),
        dlp_stats: Some(DlpStats {
            dlp_block_count: 2,
            dlp_redact_count: 1,
            classify_upgrade_count: 1,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes {
                    codes: sorted_strings(&["dlp-block", "dlp-redact"]),
                }),
            }),
        }),
        exec_stats: Some(ExecStats {
            timeout_count: 1,
            partial_failure_count: 1,
            tool_unavailable_count: 2,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes {
                    codes: sorted_strings(&["executor-timeout", "tool-unavailable"]),
                }),
            }),
        }),
        budget_stats: Some(BudgetStats {
            near_exhaustion_count: 1,
            chain_limit_hits: 1,
            concurrency_limit_hits: 0,
            top_reason_codes: Some(TopReasonCodes {
                reason_codes: Some(ReasonCodes {
                    codes: sorted_strings(&["chain-limit", "near-exhaustion"]),
                }),
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
                reason_codes: Some(ReasonCodes {
                    codes: sorted_strings(&["missing", "signature-invalid"]),
                }),
            }),
        }),
        reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["budget-tight", "policy-deny", "receipt-missing"]),
        }),
    };

    let control_frame = ControlFrame {
        control_frame_id: "ctrl-m1-001".to_string(),
        control_frame_digest: Some(Digest32 { value: vec![0x22; 32] }),
        epoch_id: 42,
        timestamp_ms: 1_700_000_750,
        active_profile: ProfileState::M1 as i32,
        profile_reason_codes: Some(ReasonCodes { codes: sorted_strings(&["ml-ops", "safety"]) }),
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

    let experience_rt_perception = ExperienceRecord {
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

    let experience_rt_action_exec = ExperienceRecord {
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
        related_refs: vec![
            Ref { uri: "policy://query/001".to_string(), label: "policy_query".to_string() },
            Ref { uri: "policy://decision/001".to_string(), label: "policy_decision".to_string() },
            Ref { uri: "policy://ruleset/alpha".to_string(), label: "ruleset".to_string() },
        ],
    };

    let experience_rt_output = ExperienceRecord {
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
        related_refs: vec![
            Ref { uri: "artifact://output/777".to_string(), label: "output_artifact".to_string() },
            Ref { uri: "dlp://scan/final".to_string(), label: "dlp-scan".to_string() },
        ],
    };

    let micro_milestone = MicroMilestone {
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
        theme_tags: sorted_strings(&["alignment", "staging"]),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["checkpoint", "sealed"]) }),
    };

    let meso_milestone = MesoMilestone {
        meso_id: "meso-bridge".to_string(),
        meso_digest: Some(Digest32 { value: vec![0x22; 32] }),
        state: MilestoneState::Stable as i32,
        micro_refs: {
            let mut refs = vec![
                Ref { uri: "ucf://micro/001".to_string(), label: "micro-a".to_string() },
                Ref { uri: "ucf://micro/002".to_string(), label: "micro-b".to_string() },
            ];
            refs.sort_by(|a, b| a.uri.cmp(&b.uri));
            refs
        },
        theme_tags: sorted_strings(&["consolidation", "stability"]),
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

    let macro_milestone = MacroMilestone {
        macro_id: "macro-root".to_string(),
        macro_digest: Some(Digest32 { value: vec![0x33; 32] }),
        state: MilestoneState::Finalized as i32,
        meso_refs: {
            let mut refs = vec![Ref {
                uri: "ucf://meso/bridge".to_string(),
                label: "meso-bridge".to_string(),
            }];
            refs.sort_by(|a, b| a.uri.cmp(&b.uri));
            refs
        },
        trait_updates: {
            let mut justification_refs = vec![
                Ref { uri: "just://audit/2024".to_string(), label: "audit".to_string() },
                Ref { uri: "just://policy/alpha".to_string(), label: "policy".to_string() },
            ];
            justification_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
            vec![
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
            ]
        },
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

    let replay_plan = ReplayPlan {
        replay_id: "replay-stability-check".to_string(),
        replay_digest: Some(Digest32 { value: vec![0x44; 32] }),
        trigger_reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["consistency-low", "operator-trigger"]),
        }),
        target_refs: {
            let mut refs = vec![
                Ref { uri: "ucf://macro/root".to_string(), label: "macro-root".to_string() },
                Ref { uri: "ucf://meso/bridge".to_string(), label: "meso-bridge".to_string() },
            ];
            refs.sort_by(|a, b| a.uri.cmp(&b.uri));
            refs
        },
        fidelity: ReplayFidelity::ReplayHigh as i32,
        inject_mode: ReplayInjectMode::InjectCenExecPlan as i32,
        stop_conditions: Some(StopConditions {
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

    let consistency_feedback = ConsistencyFeedback {
        cf_id: "cf-low-001".to_string(),
        cf_digest: Some(Digest32 { value: vec![0x55; 32] }),
        rss_ref: Some(Ref {
            uri: "rss://baseline/1".to_string(),
            label: "baseline-rss".to_string(),
        }),
        ism_refs: {
            let mut refs = vec![
                Ref { uri: "ucf://macro/root".to_string(), label: "macro-anchor".to_string() },
                Ref { uri: "ucf://ism/123".to_string(), label: "ism".to_string() },
            ];
            refs.sort_by(|a, b| a.uri.cmp(&b.uri));
            refs
        },
        pev_ref: Some(Ref {
            uri: "pev://digest/v2".to_string(),
            label: "policy-ecology".to_string(),
        }),
        consistency_class: ConsistencyClass::ConsistencyLow as i32,
        flags: vec![ConsistencyFlag::BehaviorDrift as i32, ConsistencyFlag::RiskDrift as i32],
        recommended_noise_class: NoiseClass::Med as i32,
        consolidation_eligibility: ConsolidationEligibility::Allow as i32,
        replay_trigger_hint: true,
        trigger_reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["drift-detected", "replay-recommended"]),
        }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://consistency/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    let classify_inputs = sorted_strings(&["text/plain", "image/png"]);
    let classify_action = ToolActionProfile {
        action_id: "tool-classify".to_string(),
        display_name: "Classifier".to_string(),
        tool_class: ToolClass::Model as i32,
        input_types: classify_inputs,
        output_type: "application/json".to_string(),
        requires_approval: true,
    };

    let storage_inputs = sorted_strings(&["application/json"]);
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

    let registry_container = ToolRegistryContainer {
        actions,
        adapters,
        steward: "registry-admin".to_string(),
        updated_at: 1_700_000_000,
    };

    let onboarding_event = ToolOnboardingEvent {
        tool_id: "tool-classify".to_string(),
        submitted_by: "ops-team".to_string(),
        profile: Some(classify_action.clone()),
        review_status: "accepted".to_string(),
    };

    let aap = {
        let objectives = sorted_strings(&["capture approvals", "ensure auditability"]);
        let approval_reasons = sorted_strings(&["policy-aligned", "risk-low"]);
        let approval = ApprovalDecision {
            approver: "lead-operator".to_string(),
            decision: DecisionForm::Allow as i32,
            reason_codes: Some(ReasonCodes { codes: approval_reasons }),
            summary: "Approved for pilot".to_string(),
        };

        let recovery_steps = sorted_strings(&["notify-owner", "reset-plan"]);
        let recovery = RecoveryCase {
            trigger: "missing-approval".to_string(),
            steps: recovery_steps,
            owner: "duty-officer".to_string(),
        };

        let stop_event = StopEvent {
            reason: "completed".to_string(),
            actor: "supervisor".to_string(),
            timestamp: 1_700_001_234,
            summary: "Plan concluded".to_string(),
        };

        Aap {
            plan_id: "aap-42".to_string(),
            session_id: "session-9000".to_string(),
            objectives,
            approvals: vec![approval],
            recoveries: vec![recovery],
            stop_event: Some(stop_event),
        }
    };

    let sep_event = {
        let mut parent_events = vec!["evt-root".to_string(), "evt-boot".to_string()];
        parent_events.sort();
        SepEvent {
            session_id: "session-9000".to_string(),
            event_id: "evt-1".to_string(),
            phase: "plan".to_string(),
            parents: parent_events,
            payload: "kickoff".to_string(),
            timestamp: 1_700_002_000,
            summary: Some("Initial planning event".to_string()),
        }
    };

    let session_seal = SessionSeal {
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

    let completeness_report = CompletenessReport {
        session_id: "session-9000".to_string(),
        observed_events: 3,
        expected_events: 3,
        terminal: true,
        summary: Some("All planned events observed".to_string()),
    };

    emit_fixture("canonical_intent_query", "ucf.v1.CanonicalIntent", &canonical_intent, domain)?;
    emit_fixture("policy_decision", "ucf.v1.PolicyDecision", &policy_decision, domain)?;
    emit_fixture("pvgs_receipt", "ucf.v1.PVGSReceipt", &pvgs_receipt, domain)?;
    emit_fixture("signal_frame_short_window", "ucf.v1.SignalFrame", &signal_frame, domain)?;
    emit_fixture("control_frame_m1_overlays_on", "ucf.v1.ControlFrame", &control_frame, domain)?;
    emit_fixture(
        "experience_rt_perception",
        "ucf.v1.ExperienceRecord",
        &experience_rt_perception,
        domain,
    )?;
    emit_fixture(
        "experience_rt_action_exec",
        "ucf.v1.ExperienceRecord",
        &experience_rt_action_exec,
        domain,
    )?;
    emit_fixture("experience_rt_output", "ucf.v1.ExperienceRecord", &experience_rt_output, domain)?;
    emit_fixture("micro_milestone_sealed", "ucf.v1.MicroMilestone", &micro_milestone, domain)?;
    emit_fixture("meso_milestone_stable", "ucf.v1.MesoMilestone", &meso_milestone, domain)?;
    emit_fixture("macro_milestone_finalized", "ucf.v1.MacroMilestone", &macro_milestone, domain)?;
    emit_fixture("replay_plan_high_fidelity", "ucf.v1.ReplayPlan", &replay_plan, domain)?;
    emit_fixture(
        "consistency_feedback_low_flags",
        "ucf.v1.ConsistencyFeedback",
        &consistency_feedback,
        domain,
    )?;
    emit_fixture(
        "tool_registry_container",
        "ucf.v1.ToolRegistryContainer",
        &registry_container,
        domain,
    )?;
    emit_fixture("tool_onboarding_event", "ucf.v1.ToolOnboardingEvent", &onboarding_event, domain)?;
    emit_fixture("aap_with_recovery", "ucf.v1.AAP", &aap, domain)?;
    emit_fixture("sep_event_chain", "ucf.v1.SepEvent", &sep_event, domain)?;
    emit_fixture("session_seal", "ucf.v1.SessionSeal", &session_seal, domain)?;
    emit_fixture("completeness_report", "ucf.v1.CompletenessReport", &completeness_report, domain)?;

    Ok(())
}
