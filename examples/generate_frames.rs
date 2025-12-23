use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

fn emit_fixture<M: prost::Message>(name: &str, schema: &str, message: M) {
    let bytes = canonical_bytes(&message);
    let digest = digest32("ucf-core", schema, "1", &bytes);
    let hex_bytes = hex::encode(&bytes);
    let hex_digest = hex::encode(digest);

    println!("{} hex: {}", name, hex_bytes);
    println!("{} digest: {}", name, hex_digest);

    std::fs::write(format!("testvectors/{name}.hex"), format!("{}\n", hex_bytes))
        .expect("write hex fixture");
    std::fs::write(format!("testvectors/{name}.digest"), format!("{}\n", hex_digest))
        .expect("write digest fixture");
}

fn main() {
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

    let mut profile_reason_codes = vec!["ml-ops".to_string(), "safety".to_string()];
    profile_reason_codes.sort();

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

    let control_frame = ControlFrame {
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

    emit_fixture("signal_frame_short_window", "ucf.v1.SignalFrame", signal_frame);
    emit_fixture("control_frame_m1_overlays_on", "ucf.v1.ControlFrame", control_frame);
}
