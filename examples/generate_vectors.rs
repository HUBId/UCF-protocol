use std::fs;
use std::path::Path;

use ucf_protocol::ucf::v1::canonical_intent::Params as CanonicalIntentParams;
use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

fn ensure_sorted(values: &mut [String]) {
    values.sort();
}

fn write_fixture(name: &str, bytes: &[u8], digest: [u8; 32]) -> anyhow::Result<()> {
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

fn main() -> anyhow::Result<()> {
    fs::create_dir_all("testvectors")?;

    let domain = "ucf-core";

    let mut macro_actions = vec!["recompute-digest".to_string(), "replay-signature".to_string()];
    ensure_sorted(&mut macro_actions);
    let mut replay_reason_codes = vec!["epoch-mismatch".to_string(), "vrf-replay".to_string()];
    ensure_sorted(&mut replay_reason_codes);

    let micro_align = MicroMilestone {
        id: "micro-calibrate".to_string(),
        objective: "Calibrate edge sensors".to_string(),
        deliverables: vec!["calibration-report".to_string(), "sensor-map".to_string()],
        owner: "scout".to_string(),
    };
    let micro_scout = MicroMilestone {
        id: "micro-scout".to_string(),
        objective: "Scout safe corridor".to_string(),
        deliverables: vec!["intel-brief".to_string(), "route-plan".to_string()],
        owner: "scout".to_string(),
    };
    let meso_path = MesoMilestone {
        id: "meso-staging".to_string(),
        objective: "Stage corridor expansion".to_string(),
        micro_milestones: vec![micro_align.clone(), micro_scout.clone()],
        steward: "orchestrator".to_string(),
    };
    let macro_frontier = MacroMilestone {
        id: "macro-frontier".to_string(),
        objective: "Expand frontier safely".to_string(),
        meso_milestones: vec![meso_path.clone()],
        sponsor: "mission-control".to_string(),
    };

    let replay_plan = ReplayPlan {
        plan_id: "replay-epoch-17".to_string(),
        trigger: "finalization-drift".to_string(),
        reason_codes: Some(ReasonCodes { codes: replay_reason_codes }),
        actions: macro_actions,
    };

    let consistency_feedback_low = ConsistencyFeedback {
        level: ConsistencyLevel::Low as i32,
        reason_codes: Some(ReasonCodes { codes: vec!["state-divergence".to_string()] }),
        summary: "Observed drift from baseline state".to_string(),
    };

    let mut high_reasons = vec!["multi-hop-consistency".to_string(), "self-check".to_string()];
    ensure_sorted(&mut high_reasons);
    let consistency_feedback_high = ConsistencyFeedback {
        level: ConsistencyLevel::High as i32,
        reason_codes: Some(ReasonCodes { codes: high_reasons }),
        summary: "High alignment across recursive states".to_string(),
    };

    let mut query_selectors = vec!["foo".to_string(), "bar".to_string()];
    ensure_sorted(&mut query_selectors);
    let mut ci_reason_codes = vec!["baseline".to_string(), "query".to_string()];
    ensure_sorted(&mut ci_reason_codes);

    let canonical_intent = CanonicalIntent {
        intent_id: "intent-123".to_string(),
        channel: Channel::Realtime as i32,
        risk_level: RiskLevel::Low as i32,
        data_class: DataClass::Public as i32,
        subject: Some(Ref { uri: "did:example:subject".to_string(), label: "primary".to_string() }),
        reason_codes: Some(ReasonCodes { codes: ci_reason_codes }),
        params: Some(CanonicalIntentParams::Query(QueryParams {
            query: "select * from controls".to_string(),
            selectors: query_selectors,
        })),
    };

    let ci_bytes = canonical_bytes(&canonical_intent);
    let ci_digest = digest32(domain, "ucf.v1.CanonicalIntent", "1", &ci_bytes);
    write_fixture("canonical_intent_query", &ci_bytes, ci_digest)?;

    let mut pd_reason_codes = vec!["missing-proof".to_string(), "scope-limited".to_string()];
    ensure_sorted(&mut pd_reason_codes);
    let mut constraints_added = vec!["mfa-required".to_string(), "geo-fence".to_string()];
    ensure_sorted(&mut constraints_added);
    let mut constraints_removed = vec!["legacy-exception".to_string()];
    ensure_sorted(&mut constraints_removed);

    let policy_decision = PolicyDecision {
        decision: DecisionForm::RequireApproval as i32,
        reason_codes: Some(ReasonCodes { codes: pd_reason_codes }),
        constraints: Some(ConstraintsDelta { constraints_added, constraints_removed }),
    };

    let pd_bytes = canonical_bytes(&policy_decision);
    let pd_digest = digest32(domain, "ucf.v1.PolicyDecision", "1", &pd_bytes);
    write_fixture("policy_decision", &pd_bytes, pd_digest)?;

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

    let pvgs_bytes = canonical_bytes(&pvgs_receipt);
    let pvgs_digest = digest32(domain, "ucf.v1.PVGSReceipt", "1", &pvgs_bytes);
    write_fixture("pvgs_receipt", &pvgs_bytes, pvgs_digest)?;

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

    for (name, record) in [
        ("experience_rt_perception", experience_rt_perception),
        ("experience_rt_action_exec", experience_rt_action_exec),
        ("experience_rt_output", experience_rt_output),
    ] {
        let bytes = canonical_bytes(&record);
        let digest = digest32(domain, "ucf.v1.ExperienceRecord", "1", &bytes);
        write_fixture(name, &bytes, digest)?;
    }

    let macro_bytes = canonical_bytes(&macro_frontier);
    let macro_digest = digest32(domain, "ucf.v1.MacroMilestone", "1", &macro_bytes);
    write_fixture("macro_milestone_chain", &macro_bytes, macro_digest)?;

    let replay_bytes = canonical_bytes(&replay_plan);
    let replay_digest = digest32(domain, "ucf.v1.ReplayPlan", "1", &replay_bytes);
    write_fixture("replay_plan_triggered", &replay_bytes, replay_digest)?;

    for (name, feedback) in [
        ("consistency_feedback_low", consistency_feedback_low),
        ("consistency_feedback_high", consistency_feedback_high),
    ] {
        let bytes = canonical_bytes(&feedback);
        let digest = digest32(domain, "ucf.v1.ConsistencyFeedback", "1", &bytes);
        write_fixture(name, &bytes, digest)?;
    }

    let mut classify_inputs = vec!["text/plain".to_string(), "image/png".to_string()];
    ensure_sorted(&mut classify_inputs);
    let classify_action = ToolActionProfile {
        action_id: "tool-classify".to_string(),
        display_name: "Classifier".to_string(),
        tool_class: ToolClass::Model as i32,
        input_types: classify_inputs,
        output_type: "application/json".to_string(),
        requires_approval: true,
    };

    let mut storage_inputs = vec!["application/json".to_string()];
    ensure_sorted(&mut storage_inputs);
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

    let registry_bytes = canonical_bytes(&registry_container);
    let registry_digest = digest32(domain, "ucf.v1.ToolRegistryContainer", "1", &registry_bytes);
    write_fixture("tool_registry_container", &registry_bytes, registry_digest)?;

    let onboarding_bytes = canonical_bytes(&onboarding_event);
    let onboarding_digest = digest32(domain, "ucf.v1.ToolOnboardingEvent", "1", &onboarding_bytes);
    write_fixture("tool_onboarding_event", &onboarding_bytes, onboarding_digest)?;

    let mut objectives = vec!["capture approvals".to_string(), "ensure auditability".to_string()];
    ensure_sorted(&mut objectives);

    let mut approval_reasons = vec!["policy-aligned".to_string(), "risk-low".to_string()];
    ensure_sorted(&mut approval_reasons);
    let approval = ApprovalDecision {
        approver: "lead-operator".to_string(),
        decision: DecisionForm::Allow as i32,
        reason_codes: Some(ReasonCodes { codes: approval_reasons }),
        summary: "Approved for pilot".to_string(),
    };

    let mut recovery_steps = vec!["notify-owner".to_string(), "reset-plan".to_string()];
    ensure_sorted(&mut recovery_steps);
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

    let aap = Aap {
        plan_id: "aap-42".to_string(),
        session_id: "session-9000".to_string(),
        objectives,
        approvals: vec![approval],
        recoveries: vec![recovery],
        stop_event: Some(stop_event),
    };

    let aap_bytes = canonical_bytes(&aap);
    let aap_digest = digest32(domain, "ucf.v1.AAP", "1", &aap_bytes);
    write_fixture("aap_with_recovery", &aap_bytes, aap_digest)?;

    let mut parent_events = vec!["evt-root".to_string(), "evt-boot".to_string()];
    ensure_sorted(&mut parent_events);
    let sep_event = SepEvent {
        session_id: "session-9000".to_string(),
        event_id: "evt-1".to_string(),
        phase: "plan".to_string(),
        parents: parent_events,
        payload: "kickoff".to_string(),
        timestamp: 1_700_002_000,
        summary: Some("Initial planning event".to_string()),
    };

    let sep_bytes = canonical_bytes(&sep_event);
    let sep_digest = digest32(domain, "ucf.v1.SepEvent", "1", &sep_bytes);
    write_fixture("sep_event_chain", &sep_bytes, sep_digest)?;

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

    let seal_bytes = canonical_bytes(&session_seal);
    let seal_digest = digest32(domain, "ucf.v1.SessionSeal", "1", &seal_bytes);
    write_fixture("session_seal", &seal_bytes, seal_digest)?;

    let completeness_report = CompletenessReport {
        session_id: "session-9000".to_string(),
        observed_events: 3,
        expected_events: 3,
        terminal: true,
        summary: Some("All planned events observed".to_string()),
    };

    let completeness_bytes = canonical_bytes(&completeness_report);
    let completeness_digest =
        digest32(domain, "ucf.v1.CompletenessReport", "1", &completeness_bytes);
    write_fixture("completeness_report", &completeness_bytes, completeness_digest)?;

    println!("Fixtures written to testvectors/");
    Ok(())
}
