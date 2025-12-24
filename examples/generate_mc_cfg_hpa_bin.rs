use std::fs;
use std::path::Path;

use ucf_protocol::ucf::v1::*;
use ucf_protocol::{canonical_bytes, digest32};

fn main() -> anyhow::Result<()> {
    let message = MicrocircuitConfigEvidence {
        module: MicroModule::Hpa as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x44; 32] }),
        created_at_ms: 1_700_125_000,
        prev_config_digest: None,
        proof_receipt_ref: None,
        attestation_sig: None,
        attestation_key_id: None,
    };

    fs::create_dir_all("testvectors")?;

    let bytes = canonical_bytes(&message);
    let bin_path = Path::new("testvectors").join("mc_cfg_hpa.bin");
    fs::write(&bin_path, &bytes)?;

    let digest = digest32("UCF:HASH:MC_CONFIG", "ucf.v1.MicrocircuitConfigEvidence", "1", &bytes);
    let digest_path = Path::new("testvectors").join("mc_cfg_hpa.digest");
    let mut digest_body = hex::encode(digest);
    digest_body.push('\n');
    fs::write(&digest_path, digest_body)?;

    Ok(())
}
