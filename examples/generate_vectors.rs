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

    println!("Fixtures written to testvectors/");
    Ok(())
}
