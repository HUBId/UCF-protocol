//! Temporary VRF engine for Chip 4 using deterministic Ed25519 signatures.
//!
//! This is **not** a production-grade ECVRF. It derives a digest by hashing a
//! deterministic Ed25519 signature and then compressing it with BLAKE3. The
//! design is intentionally marked as `TEMPORARY_VRF` so it can be replaced by a
//! standards-compliant ECVRF-ED25519-SHA512-TAI implementation later.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha512};

const VRF_DOMAIN: &[u8] = b"UCF:VRF:EXPERIENCE_RECORD";
const TEMPORARY_VRF_LABEL: &str = "TEMPORARY_VRF";

/// Key material for the VRF engine.
#[derive(Clone, Debug)]
pub struct VrfKeypair {
    pub key_id: String,
    pub epoch_id: u64,
    pub vrf_pk: Vec<u8>,
    pub vrf_sk: Vec<u8>,
}

/// VRF engine that evaluates digests for experience records.
///
/// This implementation is a temporary stand-in: it signs the preimage with
/// Ed25519, hashes the signature with SHA-512, and then compresses it with
/// BLAKE3-256 to produce a 32-byte digest. It should be replaced by a true
/// ECVRF-ED25519-SHA512-TAI implementation when available.
#[derive(Clone)]
pub struct VrfEngine {
    signing_key: SigningKey,
    pub current: VrfKeypair,
}

impl VrfEngine {
    /// Create a deterministic dev/test keypair for the provided epoch.
    pub fn new_dev(epoch_id: u64) -> Self {
        let mut seed_hasher = Hasher::new();
        seed_hasher.update(b"UCF:VRF:DEV");
        seed_hasher.update(&epoch_id.to_le_bytes());
        let seed = seed_hasher.finalize();

        let signing_key = SigningKey::from_bytes(seed.as_bytes());
        let verifying_key = signing_key.verifying_key();
        let key_id = format!(
            "{TEMPORARY_VRF_LABEL}:{}",
            hex::encode(&verifying_key.to_bytes()[..8])
        );
        let current = VrfKeypair {
            key_id,
            epoch_id,
            vrf_pk: verifying_key.to_bytes().to_vec(),
            vrf_sk: signing_key.to_bytes().to_vec(),
        };

        Self {
            signing_key,
            current,
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current.epoch_id
    }

    pub fn vrf_public_key(&self) -> &[u8] {
        &self.current.vrf_pk
    }

    /// Evaluate the VRF digest for an experience record commitment.
    pub fn eval_record_vrf(
        &self,
        prev_record_digest: [u8; 32],
        record_digest: [u8; 32],
        charter_digest: &str,
        profile_digest: [u8; 32],
        epoch_id: u64,
    ) -> [u8; 32] {
        let message = self.build_message(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );
        let signature = self.signing_key.sign(&message);
        digest_signature(&signature)
    }

    fn build_message(
        &self,
        prev_record_digest: [u8; 32],
        record_digest: [u8; 32],
        charter_digest: &str,
        profile_digest: [u8; 32],
        epoch_id: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            VRF_DOMAIN.len()
                + prev_record_digest.len()
                + record_digest.len()
                + charter_digest.len()
                + profile_digest.len()
                + std::mem::size_of::<u64>(),
        );
        msg.extend_from_slice(VRF_DOMAIN);
        msg.extend_from_slice(&prev_record_digest);
        msg.extend_from_slice(&record_digest);
        msg.extend_from_slice(charter_digest.as_bytes());
        msg.extend_from_slice(&profile_digest);
        msg.extend_from_slice(&epoch_id.to_le_bytes());
        msg
    }
}

fn digest_signature(signature: &Signature) -> [u8; 32] {
    let sig_hash = Sha512::digest(signature.to_bytes());
    let mut hasher = Hasher::new();
    hasher.update(&sig_hash);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ([u8; 32], [u8; 32], &'static str, [u8; 32], u64) {
        ([0u8; 32], [1u8; 32], "charter-digest", [2u8; 32], 42)
    }

    #[test]
    fn vrf_digest_is_deterministic() {
        let engine = VrfEngine::new_dev(7);
        let (prev_record_digest, record_digest, charter_digest, profile_digest, epoch_id) =
            sample_inputs();

        let digest1 = engine.eval_record_vrf(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );
        let digest2 = engine.eval_record_vrf(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );

        assert_eq!(digest1, digest2, "VRF digest should be deterministic");
    }

    #[test]
    fn vrf_digest_changes_with_record_digest() {
        let engine = VrfEngine::new_dev(7);
        let (prev_record_digest, record_digest, charter_digest, profile_digest, epoch_id) =
            sample_inputs();
        let mut tweaked_record_digest = record_digest;
        tweaked_record_digest[0] ^= 0xFF;

        let digest1 = engine.eval_record_vrf(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );
        let digest2 = engine.eval_record_vrf(
            prev_record_digest,
            tweaked_record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );

        assert_ne!(
            digest1, digest2,
            "VRF digest should change when record digest changes"
        );
    }

    #[test]
    fn temporary_verify_recomputes_digest_from_signature() {
        let engine = VrfEngine::new_dev(9);
        let (prev_record_digest, record_digest, charter_digest, profile_digest, epoch_id) =
            sample_inputs();

        let message = engine.build_message(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );
        let signature = engine.signing_key.sign(&message);
        let digest = engine.eval_record_vrf(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );

        let recomputed = digest_signature(&signature);
        assert_eq!(
            digest, recomputed,
            "TEMPORARY_VRF digest should match recomputed hash of signature"
        );
    }
}
