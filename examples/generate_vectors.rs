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
    fs::write(&hex_path, hex::encode(bytes))?;
    fs::write(&digest_path, hex::encode(digest))?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    fs::create_dir_all("testvectors")?;

    let domain = "ucf-core";

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

    println!("Fixtures written to testvectors/");
    Ok(())
}
