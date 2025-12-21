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

    let mut action_constraints = vec!["rate-limit".to_string(), "humans-in-loop".to_string()];
    ensure_sorted(&mut action_constraints);
    let mut action_reason_codes =
        vec!["approval-required".to_string(), "safety-review".to_string()];
    ensure_sorted(&mut action_reason_codes);

    let mut output_constraints =
        vec!["output-audited".to_string(), "watermark-applied".to_string()];
    ensure_sorted(&mut output_constraints);
    let mut output_reason_codes = vec!["output-ready".to_string()];
    ensure_sorted(&mut output_reason_codes);

    let experience_rt_perception = ExperienceRecord {
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

    let experience_rt_action_exec = ExperienceRecord {
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
            reason_codes: Some(ReasonCodes { codes: action_reason_codes }),
            constraints_applied: action_constraints,
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

    let experience_rt_output = ExperienceRecord {
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
            reason_codes: Some(ReasonCodes { codes: output_reason_codes }),
            constraints_applied: output_constraints,
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
        summary: "Initial planning event".to_string(),
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
        summary: "Session closed".to_string(),
    };

    let seal_bytes = canonical_bytes(&session_seal);
    let seal_digest = digest32(domain, "ucf.v1.SessionSeal", "1", &seal_bytes);
    write_fixture("session_seal", &seal_bytes, seal_digest)?;

    let completeness_report = CompletenessReport {
        session_id: "session-9000".to_string(),
        observed_events: 3,
        expected_events: 3,
        terminal: true,
        summary: "All planned events observed".to_string(),
    };

    let completeness_bytes = canonical_bytes(&completeness_report);
    let completeness_digest =
        digest32(domain, "ucf.v1.CompletenessReport", "1", &completeness_bytes);
    write_fixture("completeness_report", &completeness_bytes, completeness_digest)?;

    println!("Fixtures written to testvectors/");
    Ok(())
}
