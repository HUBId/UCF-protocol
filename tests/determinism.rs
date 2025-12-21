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
        policy_stats: Some(PolicyStats {
            evaluated: 15,
            allowed: 12,
            denied: 2,
            deferred: 1,
        }),
        dlp_stats: Some(DlpStats {
            scanned: 8,
            flagged: 2,
            blocked: 1,
        }),
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
        receipt_stats: Some(ReceiptStats {
            accepted: 10,
            rejected: 1,
            errored: 1,
        }),
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
            ToolClassMask {
                tool_class: ToolClass::Model as i32,
                action: MaskAction::Allow as i32,
            },
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
