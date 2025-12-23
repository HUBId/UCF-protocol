use std::fs;

use hex::encode as hex_encode;
use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

const DOMAIN: &str = "ucf-core";
const VERSION: &str = "1";

fn write_fixture<M: prost::Message>(name: &str, schema: &str, message: &M) -> std::io::Result<()> {
    let bytes = canonical_bytes(message);
    let digest = digest32(DOMAIN, schema, VERSION, &bytes);

    fs::write(format!("testvectors/{name}.hex"), format!("{}\n", hex_encode(bytes)))?;
    fs::write(format!("testvectors/{name}.digest"), format!("{}\n", hex_encode(digest)))?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    let reason_codes =
        ReasonCodes { codes: vec!["deterministic".to_string(), "coverage".to_string()] };
    write_fixture("reason_codes_basic", "ucf.v1.ReasonCodes", &reason_codes)?;

    let envelope = UcfEnvelope {
        epoch_id: "epoch-1".to_string(),
        nonce: vec![0x01, 0x02, 0x03, 0x04],
        signature: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA, 0xBB, 0xCC],
            signature: vec![0x11, 0x22, 0x33, 0x44],
        }),
        payload_digest: Some(Digest32 { value: vec![0x10; 32] }),
        msg_type: MsgType::PolicyDecision as i32,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    write_fixture("ucf_envelope_policy_decision", "ucf.v1.UcfEnvelope", &envelope)?;

    Ok(())
}
