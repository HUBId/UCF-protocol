use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

fn print_fixture<M: prost::Message>(name: &str, schema: &str, message: M) {
    let bytes = canonical_bytes(&message);
    let digest = digest32("ucf-core", schema, "1", &bytes);
    println!("{} hex: {}", name, hex::encode(&bytes));
    println!("{} digest: {}", name, hex::encode(digest));
}

fn main() {
    let signal_frame = SignalFrame {
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

    let control_frame = ControlFrame {
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

    print_fixture("signal_frame_short_window", "ucf.v1.SignalFrame", signal_frame);
    print_fixture("control_frame_m1_overlays_on", "ucf.v1.ControlFrame", control_frame);
}
