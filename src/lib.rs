#![forbid(unsafe_code)]

//! UCF protocol core types and deterministic helpers.
use blake3::Hasher;
use prost::Message;

pub mod ucf {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/ucf.v1.rs"));
    }
}

pub use ucf::v1::{
    AssetDigest, AssetKind, AssetManifest, ChannelParams, ChannelParamsSetPayload, Compartment,
    CompartmentKind, ConnEdge, ConnectivityGraphPayload, LabelKv, ModChannel, MorphNeuron,
    MorphologySetPayload, SynKind, SynType, SynapseParams, SynapseParamsSetPayload,
};

/// Canonically encode a protobuf message using deterministic field ordering.
///
/// The caller is responsible for ordering any repeated fields that should be
/// treated as sets before invoking this function.
pub fn canonical_bytes<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// Compute a 32-byte digest using BLAKE3 over DOMAIN || schema_id || schema_version || bytes.
pub fn digest32(domain: &str, schema_id: &str, schema_version: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(schema_id.as_bytes());
    hasher.update(schema_version.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
