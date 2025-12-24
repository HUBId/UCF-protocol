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

fn write_bin_fixture(name: &str, schema: &str, bytes: &[u8], domain: &str) -> anyhow::Result<()> {
    let digest = digest32(domain, schema, "1", bytes);
    let bin_path = Path::new("testvectors").join(format!("{name}.bin"));
    let digest_path = Path::new("testvectors").join(format!("{name}.digest"));
    let mut digest_body = hex::encode(digest);
    digest_body.push('\n');
    fs::write(&bin_path, bytes)?;
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

fn emit_bin_fixture<M: Message>(
    name: &str,
    schema: &str,
    message: &M,
    domain: &str,
) -> anyhow::Result<()> {
    let bytes = canonical_bytes(message);
    write_bin_fixture(name, schema, &bytes, domain)
}

fn main() -> anyhow::Result<()> {
    fs::create_dir_all("testvectors")?;
    let domain = "ucf-core";
    let microcircuit_domain = "UCF:HASH:MC_CONFIG";

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

    let registry_container = ToolRegistryContainer {
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

    let onboarding_event = ToolOnboardingEvent {
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

    let approval_artifact_package = ApprovalArtifactPackage {
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

    let approval_decision = ApprovalDecision {
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

    let sep_event_1 = SepEvent {
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
    };

    let sep_event_2 = SepEvent {
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
    };

    let sep_event_3 = SepEvent {
        event_id: "evt-3".to_string(),
        session_id: "session-9000".to_string(),
        event_type: SepEventType::EvOutcome as i32,
        object_ref: Some(Ref { uri: "outcome://result".to_string(), label: "outcome".to_string() }),
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
    };

    let session_seal = SessionSeal {
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

    let completeness_report = CompletenessReport {
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

    let microcircuit_config_lc = MicrocircuitConfigEvidence {
        module: MicroModule::Lc as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x10; 32] }),
        created_at_ms: 1_700_123_456,
        prev_config_digest: None,
        proof_receipt_ref: Some(Ref {
            uri: "proof://microcircuit/config/receipt-1".to_string(),
            label: "receipt".to_string(),
        }),
        attestation_sig: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x01, 0x02, 0x03, 0x04],
            signature: vec![0x05, 0x06, 0x07, 0x08],
        }),
        attestation_key_id: Some("attest-key-1".to_string()),
    };

    emit_fixture(
        "microcircuit_config_lc_v1",
        "ucf.v1.MicrocircuitConfigEvidence",
        &microcircuit_config_lc,
        microcircuit_domain,
    )?;

    let microcircuit_config_sn = MicrocircuitConfigEvidence {
        module: MicroModule::Sn as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x22; 32] }),
        created_at_ms: 1_700_123_999,
        prev_config_digest: Some(Digest32 { value: vec![0x11; 32] }),
        proof_receipt_ref: None,
        attestation_sig: None,
        attestation_key_id: None,
    };

    emit_fixture(
        "microcircuit_config_sn_v1",
        "ucf.v1.MicrocircuitConfigEvidence",
        &microcircuit_config_sn,
        microcircuit_domain,
    )?;

    let microcircuit_config_hpa = MicrocircuitConfigEvidence {
        module: MicroModule::Hpa as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x33; 32] }),
        created_at_ms: 1_700_124_111,
        prev_config_digest: Some(Digest32 { value: vec![0x22; 32] }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://microcircuit/config/receipt-hpa-1".to_string(),
            label: "receipt".to_string(),
        }),
        attestation_sig: None,
        attestation_key_id: Some("attest-key-hpa-1".to_string()),
    };

    emit_fixture(
        "microcircuit_config_hpa_v1",
        "ucf.v1.MicrocircuitConfigEvidence",
        &microcircuit_config_hpa,
        microcircuit_domain,
    )?;

    let microcircuit_config_hpa_bin = MicrocircuitConfigEvidence {
        module: MicroModule::Hpa as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x44; 32] }),
        created_at_ms: 1_700_125_555,
        prev_config_digest: None,
        proof_receipt_ref: None,
        attestation_sig: None,
        attestation_key_id: None,
    };

    emit_bin_fixture(
        "mc_cfg_hpa",
        "ucf.v1.MicrocircuitConfigEvidence",
        &microcircuit_config_hpa_bin,
        microcircuit_domain,
    )?;
    emit_fixture(
        "tool_registry_container",
        "ucf.v1.ToolRegistryContainer",
        &registry_container,
        domain,
    )?;
    emit_fixture("tool_onboarding_event", "ucf.v1.ToolOnboardingEvent", &onboarding_event, domain)?;
    emit_fixture(
        "approval_artifact_package",
        "ucf.v1.ApprovalArtifactPackage",
        &approval_artifact_package,
        domain,
    )?;
    emit_fixture("approval_decision", "ucf.v1.ApprovalDecision", &approval_decision, domain)?;
    emit_fixture("sep_event_chain_1", "ucf.v1.SepEvent", &sep_event_1, domain)?;
    emit_fixture("sep_event_chain_2", "ucf.v1.SepEvent", &sep_event_2, domain)?;
    emit_fixture("sep_event_chain_3", "ucf.v1.SepEvent", &sep_event_3, domain)?;
    emit_fixture("session_seal", "ucf.v1.SessionSeal", &session_seal, domain)?;
    emit_fixture("completeness_report", "ucf.v1.CompletenessReport", &completeness_report, domain)?;

    Ok(())
}
