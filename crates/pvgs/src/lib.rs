//! PVGS receipt issuance helpers.

use blake3::Hasher;
use ucf_protocol::ucf::v1::{Digest32, ProofReceipt, ReceiptStatus, Signature};
use ucf_vrf::VrfEngine;

/// Internal announcement format for PVGS key epochs.
#[derive(Clone, Debug)]
pub struct PvgsKeyEpoch {
    pub epoch_id: u64,
    pub attestation_key_id: String,
    pub attestation_public_key: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct ProofReceiptIssuer {
    vrf_engine: VrfEngine,
}

#[derive(Clone, Debug)]
pub struct ProofReceiptInputs {
    pub status: ReceiptStatus,
    pub receipt_digest: [u8; 32],
    pub verified_fields_digest: [u8; 32],
    pub prev_record_digest: [u8; 32],
    pub charter_digest: String,
    pub profile_digest: [u8; 32],
    pub commit_id: Vec<u8>,
    pub epoch_id: u64,
    pub validator: Signature,
}

impl ProofReceiptIssuer {
    pub fn new(vrf_engine: VrfEngine) -> Self {
        Self { vrf_engine }
    }

    pub fn vrf_public_key(&self) -> &[u8] {
        self.vrf_engine.vrf_public_key()
    }

    pub fn issue_proof_receipt(&self, inputs: ProofReceiptInputs) -> ProofReceipt {
        let record_digest = record_digest_from_components(
            inputs.verified_fields_digest,
            inputs.prev_record_digest,
            &inputs.commit_id,
        );
        let vrf_digest = self.vrf_engine.eval_record_vrf(
            inputs.prev_record_digest,
            record_digest,
            &inputs.charter_digest,
            inputs.profile_digest,
            inputs.epoch_id,
        );

        ProofReceipt {
            status: inputs.status as i32,
            receipt_digest: Some(Digest32 {
                value: inputs.receipt_digest.to_vec(),
            }),
            validator: Some(inputs.validator),
            vrf_digest: Some(Digest32 {
                value: vrf_digest.to_vec(),
            }),
        }
    }
}

pub fn record_digest_from_components(
    verified_fields_digest: [u8; 32],
    prev_record_digest: [u8; 32],
    commit_id: &[u8],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&verified_fields_digest);
    hasher.update(&prev_record_digest);
    hasher.update(commit_id);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signature() -> Signature {
        Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA; 32],
            signature: vec![0xBB; 64],
        }
    }

    #[test]
    fn proof_receipt_carries_vrf_digest() {
        let vrf_engine = VrfEngine::new_dev(5);
        let issuer = ProofReceiptIssuer::new(vrf_engine.clone());

        let receipt = issuer.issue_proof_receipt(ProofReceiptInputs {
            status: ReceiptStatus::Accepted,
            receipt_digest: [9u8; 32],
            verified_fields_digest: [3u8; 32],
            prev_record_digest: [0u8; 32],
            charter_digest: "charter-digest".to_string(),
            profile_digest: [2u8; 32],
            commit_id: b"commit-abc123".to_vec(),
            epoch_id: vrf_engine.current_epoch(),
            validator: sample_signature(),
        });

        let vrf_digest = receipt
            .vrf_digest
            .as_ref()
            .expect("vrf digest should be set")
            .value
            .clone();

        assert!(
            vrf_digest.iter().any(|b| *b != 0),
            "VRF digest should not be all zeros"
        );

        let expected = vrf_engine.eval_record_vrf(
            [0u8; 32],
            record_digest_from_components([3u8; 32], [0u8; 32], b"commit-abc123"),
            "charter-digest",
            [2u8; 32],
            vrf_engine.current_epoch(),
        );

        assert_eq!(
            vrf_digest,
            expected.to_vec(),
            "VRF digest should be deterministic"
        );
    }
}
