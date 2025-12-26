#![forbid(unsafe_code)]

use std::collections::HashSet;
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
const EXPERIENCE_SCHEMA: &str = "ucf.v1.ExperienceRecord";
const MICRO_MILESTONE_SCHEMA: &str = "ucf.v1.MicroMilestone";
const MESO_MILESTONE_SCHEMA: &str = "ucf.v1.MesoMilestone";
const MACRO_MILESTONE_SCHEMA: &str = "ucf.v1.MacroMilestone";
const REPLAY_PLAN_SCHEMA: &str = "ucf.v1.ReplayPlan";
const REPLAY_RUN_SCHEMA: &str = "ucf.v1.ReplayRunEvidence";
const CONSISTENCY_FEEDBACK_SCHEMA: &str = "ucf.v1.ConsistencyFeedback";
const TOOL_REGISTRY_SCHEMA: &str = "ucf.v1.ToolRegistryContainer";
const TOOL_ONBOARDING_SCHEMA: &str = "ucf.v1.ToolOnboardingEvent";
const APPROVAL_ARTIFACT_PACKAGE_SCHEMA: &str = "ucf.v1.ApprovalArtifactPackage";
const APPROVAL_DECISION_SCHEMA: &str = "ucf.v1.ApprovalDecision";
const SEP_EVENT_SCHEMA: &str = "ucf.v1.SepEvent";
const SESSION_SEAL_SCHEMA: &str = "ucf.v1.SessionSeal";
const COMPLETENESS_REPORT_SCHEMA: &str = "ucf.v1.CompletenessReport";
const UCF_ENVELOPE_SCHEMA: &str = "ucf.v1.UcfEnvelope";
const REASON_CODES_SCHEMA: &str = "ucf.v1.ReasonCodes";
const MICRO_CIRCUIT_SCHEMA: &str = "ucf.v1.MicrocircuitConfigEvidence";
const ASSET_DIGEST_SCHEMA: &str = "ucf.v1.AssetDigest";
const ASSET_MANIFEST_SCHEMA: &str = "ucf.v1.AssetManifest";
const MORPHOLOGY_SET_SCHEMA: &str = "ucf.v1.MorphologySetPayload";
const CHANNEL_PARAMS_SET_SCHEMA: &str = "ucf.v1.ChannelParamsSetPayload";
const SYNAPSE_PARAMS_SET_SCHEMA: &str = "ucf.v1.SynapseParamsSetPayload";
const CONNECTIVITY_GRAPH_SCHEMA: &str = "ucf.v1.ConnectivityGraphPayload";
const VERSION: &str = "1";
const MICRO_CIRCUIT_DOMAIN: &str = "UCF:HASH:MC_CONFIG";
const ASSET_MORPHOLOGY_DOMAIN: &str = "UCF:ASSET:MORPH";
const ASSET_CHANNEL_PARAMS_DOMAIN: &str = "UCF:ASSET:CHANNEL_PARAMS";
const ASSET_SYN_PARAMS_DOMAIN: &str = "UCF:ASSET:SYN_PARAMS";
const ASSET_CONNECTIVITY_DOMAIN: &str = "UCF:ASSET:CONNECTIVITY";
const ASSET_MANIFEST_DOMAIN: &str = "UCF:ASSET:MANIFEST";

struct FixtureCase {
    name: &'static str,
    schema: &'static str,
    proto_files: &'static [&'static str],
    verify: fn() -> Result<()>,
}

const PROTO_FILES: &[&str] = &[
    "proto/ucf/v1/common.proto",
    "proto/ucf/v1/envelope.proto",
    "proto/ucf/v1/canonical.proto",
    "proto/ucf/v1/tooling.proto",
    "proto/ucf/v1/human.proto",
    "proto/ucf/v1/policy.proto",
    "proto/ucf/v1/pvgs.proto",
    "proto/ucf/v1/assets.proto",
    "proto/ucf/v1/biophys_assets.proto",
    "proto/ucf/v1/frames.proto",
    "proto/ucf/v1/experience.proto",
    "proto/ucf/v1/milestones.proto",
    "proto/ucf/v1/geist.proto",
    "proto/ucf/v1/sep.proto",
    "proto/ucf/v1/microcircuit.proto",
    "proto/ucf/v1/replay_run.proto",
];

fn sorted_strings(items: &[&str]) -> Vec<String> {
    let mut values: Vec<String> = items.iter().map(|item| item.to_string()).collect();
    values.sort();
    values
}

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

fn load_binary_fixture(name: &str) -> Result<(Vec<u8>, [u8; 32])> {
    let bytes = fs::read(format!("testvectors/{name}.bin"))
        .with_context(|| format!("reading {name}.bin"))?;
    let digest_hex = fs::read_to_string(format!("testvectors/{name}.digest"))
        .with_context(|| format!("reading {name}.digest"))?;
    let digest_vec = hex::decode(digest_hex.trim()).context("decoding digest hex")?;
    let digest: [u8; 32] =
        digest_vec.try_into().map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?;
    Ok((bytes, digest))
}

fn verify_case<M>(name: &str, schema: &str, expected: M) -> Result<()>
where
    M: Message + Default + Clone,
{
    verify_case_with_domain(name, schema, DOMAIN, expected)
}

fn verify_case_with_domain<M>(name: &str, schema: &str, domain: &str, expected: M) -> Result<()>
where
    M: Message + Default + Clone,
{
    let (fixture_bytes, fixture_digest) = load_fixture(name)?;

    let decoded = M::decode(fixture_bytes.as_slice())?;
    let encoded = canonical_bytes(&decoded);
    assert_eq!(fixture_bytes, encoded, "canonical bytes should be stable");

    let digest = digest32(domain, schema, VERSION, &encoded);
    assert_eq!(fixture_digest, digest, "digest should match stored fixture");

    // Regenerate bytes from an explicitly constructed message to ensure parity.
    let constructed_bytes = canonical_bytes(&expected);
    assert_eq!(encoded, constructed_bytes, "constructed and fixture differ");

    Ok(())
}

fn reason_codes_basic_case() -> Result<()> {
    let expected = ReasonCodes { codes: vec!["deterministic".to_string(), "coverage".to_string()] };

    verify_case("reason_codes_basic", REASON_CODES_SCHEMA, expected)
}

fn ucf_envelope_policy_decision_case() -> Result<()> {
    let expected = UcfEnvelope {
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

    verify_case("ucf_envelope_policy_decision", UCF_ENVELOPE_SCHEMA, expected)
}

fn canonical_intent_fixture_case() -> Result<()> {
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

    verify_case("canonical_intent_query", INTENT_SCHEMA, expected)
}

fn policy_decision_fixture_case() -> Result<()> {
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

    verify_case("policy_decision", POLICY_SCHEMA, expected)
}

fn pvgs_receipt_fixture_case() -> Result<()> {
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

    verify_case("pvgs_receipt", PVGS_SCHEMA, expected)
}

fn asset_digest_morphology_case() -> Result<()> {
    let expected = AssetDigest {
        kind: AssetKind::MorphologySet as i32,
        version: 1,
        digest: Some(Digest32 { value: vec![0x10; 32] }),
        created_at_ms: 1_700_100_123,
        prev_digest: Some(Digest32 { value: vec![0x20; 32] }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://assets/morphology/receipt-1".to_string(),
            label: "morphology-proof".to_string(),
        }),
    };

    verify_case_with_domain(
        "asset_digest_morphology_v1",
        ASSET_DIGEST_SCHEMA,
        ASSET_MORPHOLOGY_DOMAIN,
        expected,
    )
}

fn asset_manifest_case() -> Result<()> {
    let morphology = AssetDigest {
        kind: AssetKind::MorphologySet as i32,
        version: 1,
        digest: Some(Digest32 { value: vec![0x01; 32] }),
        created_at_ms: 1_700_100_500,
        prev_digest: None,
        proof_receipt_ref: None,
    };
    let channel_params = AssetDigest {
        kind: AssetKind::ChannelParamsSet as i32,
        version: 2,
        digest: Some(Digest32 { value: vec![0x02; 32] }),
        created_at_ms: 1_700_100_600,
        prev_digest: Some(Digest32 { value: vec![0x12; 32] }),
        proof_receipt_ref: None,
    };
    let synapse_params = AssetDigest {
        kind: AssetKind::SynapseParamsSet as i32,
        version: 3,
        digest: Some(Digest32 { value: vec![0x03; 32] }),
        created_at_ms: 1_700_100_700,
        prev_digest: None,
        proof_receipt_ref: Some(Ref {
            uri: "proof://assets/synapse/receipt-9".to_string(),
            label: "synapse-proof".to_string(),
        }),
    };
    let connectivity = AssetDigest {
        kind: AssetKind::ConnectivityGraph as i32,
        version: 4,
        digest: Some(Digest32 { value: vec![0x04; 32] }),
        created_at_ms: 1_700_100_800,
        prev_digest: Some(Digest32 { value: vec![0x14; 32] }),
        proof_receipt_ref: None,
    };
    let expected = AssetManifest {
        manifest_version: 1,
        manifest_digest: Some(Digest32 { value: vec![0x99; 32] }),
        morphology: Some(morphology),
        channel_params: Some(channel_params),
        synapse_params: Some(synapse_params),
        connectivity: Some(connectivity),
        created_at_ms: 1_700_100_900,
        proof_receipt_ref: Some(Ref {
            uri: "proof://assets/manifest/receipt-1".to_string(),
            label: "manifest-proof".to_string(),
        }),
    };

    verify_case_with_domain(
        "asset_manifest_v1",
        ASSET_MANIFEST_SCHEMA,
        ASSET_MANIFEST_DOMAIN,
        expected,
    )
}

fn biophys_morphology_set_case() -> Result<()> {
    let neuron_one = MorphNeuron {
        neuron_id: 1,
        compartments: vec![
            Compartment {
                comp_id: 1,
                parent: None,
                kind: CompartmentKind::Soma as i32,
                length_um: 20,
                diameter_um: 15,
            },
            Compartment {
                comp_id: 2,
                parent: Some(compartment::Parent::ParentCompId(1)),
                kind: CompartmentKind::Dendrite as i32,
                length_um: 120,
                diameter_um: 4,
            },
        ],
        labels: vec![
            LabelKv { k: "pool".to_string(), v: "alpha".to_string() },
            LabelKv { k: "type".to_string(), v: "pyramidal".to_string() },
        ],
    };

    let neuron_two = MorphNeuron {
        neuron_id: 2,
        compartments: vec![
            Compartment {
                comp_id: 1,
                parent: None,
                kind: CompartmentKind::Soma as i32,
                length_um: 18,
                diameter_um: 12,
            },
            Compartment {
                comp_id: 3,
                parent: Some(compartment::Parent::ParentCompId(1)),
                kind: CompartmentKind::Axon as i32,
                length_um: 200,
                diameter_um: 2,
            },
        ],
        labels: vec![LabelKv { k: "pool".to_string(), v: "beta".to_string() }],
    };

    let expected = MorphologySetPayload {
        version: 1,
        neurons: vec![neuron_one, neuron_two],
        payload_digest: Some(Digest32 { value: vec![0xAB; 32] }),
    };

    verify_case_with_domain(
        "biophys_morphology_set_v1",
        MORPHOLOGY_SET_SCHEMA,
        ASSET_MORPHOLOGY_DOMAIN,
        expected,
    )
}

fn biophys_channel_params_set_case() -> Result<()> {
    let expected = ChannelParamsSetPayload {
        version: 1,
        params: vec![
            ChannelParams {
                neuron_id: 1,
                comp_id: 1,
                leak_g: 1000,
                na_g: 2000,
                k_g: 1500,
                ca_g: Some(800),
                e_rev_leak: Some(-65),
            },
            ChannelParams {
                neuron_id: 2,
                comp_id: 1,
                leak_g: 900,
                na_g: 1800,
                k_g: 1400,
                ca_g: None,
                e_rev_leak: None,
            },
        ],
        payload_digest: Some(Digest32 { value: vec![0xBC; 32] }),
    };

    verify_case_with_domain(
        "biophys_channel_params_set_v1",
        CHANNEL_PARAMS_SET_SCHEMA,
        ASSET_CHANNEL_PARAMS_DOMAIN,
        expected,
    )
}

fn biophys_synapse_params_set_case() -> Result<()> {
    let expected = SynapseParamsSetPayload {
        version: 1,
        params: vec![
            SynapseParams {
                syn_param_id: 10,
                syn_type: SynType::Exc as i32,
                syn_kind: SynKind::Ampa as i32,
                g_max_q: 65_536,
                e_rev_mv: 0,
                tau_decay_steps: 50,
                stp_u_q: 32_768,
                tau_rec_steps: 200,
                tau_fac_steps: 100,
                mod_channel: ModChannel::Na as i32,
            },
            SynapseParams {
                syn_param_id: 11,
                syn_type: SynType::Inh as i32,
                syn_kind: SynKind::Gaba as i32,
                g_max_q: 32_768,
                e_rev_mv: -70,
                tau_decay_steps: 60,
                stp_u_q: 16_384,
                tau_rec_steps: 150,
                tau_fac_steps: 80,
                mod_channel: ModChannel::None as i32,
            },
        ],
        payload_digest: Some(Digest32 { value: vec![0xCD; 32] }),
    };

    verify_case_with_domain(
        "biophys_synapse_params_set_v1",
        SYNAPSE_PARAMS_SET_SCHEMA,
        ASSET_SYN_PARAMS_DOMAIN,
        expected,
    )
}

fn biophys_connectivity_graph_case() -> Result<()> {
    let expected = ConnectivityGraphPayload {
        version: 1,
        edges: vec![
            ConnEdge { pre: 1, post: 2, post_compartment: 1, syn_param_id: 10, delay_steps: 2 },
            ConnEdge { pre: 1, post: 3, post_compartment: 1, syn_param_id: 11, delay_steps: 3 },
        ],
        payload_digest: Some(Digest32 { value: vec![0xDE; 32] }),
    };

    verify_case_with_domain(
        "biophys_connectivity_graph_v1",
        CONNECTIVITY_GRAPH_SCHEMA,
        ASSET_CONNECTIVITY_DOMAIN,
        expected,
    )
}

fn signal_frame_fixture_case() -> Result<()> {
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

    let expected = SignalFrame {
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

    verify_case("signal_frame_short_window", SIGNAL_FRAME_SCHEMA, expected)
}

fn control_frame_fixture_case() -> Result<()> {
    let mut profile_reason_codes = vec!["ml-ops".to_string(), "safety".to_string()];
    profile_reason_codes.sort();

    let expected = ControlFrame {
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

    verify_case("control_frame_m1_overlays_on", CONTROL_FRAME_SCHEMA, expected)
}

fn experience_record_rt_perception_case() -> Result<()> {
    let input_packet_refs = vec![
        Ref { uri: "packet://ingest/0001".to_string(), label: "input-0001".to_string() },
        Ref { uri: "packet://ingest/0002".to_string(), label: "input-0002".to_string() },
    ];

    let intent_refs = vec![
        Ref { uri: "intent://primary/42".to_string(), label: "primary".to_string() },
        Ref { uri: "intent://safety/42".to_string(), label: "safety".to_string() },
    ];

    let candidate_refs =
        vec![Ref { uri: "candidate://lm/alpha".to_string(), label: "lm-alpha".to_string() }];

    let expected = ExperienceRecord {
        record_type: RecordType::RtPerception as i32,
        core_frame_ref: Some(Ref {
            uri: "core://perception/001".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://perception/001".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: None,
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_001,
            timestamp_ms: 1_700_010_000,
            prev_record_digest: Some(Digest32 { value: vec![0xAA; 32] }),
            record_digest: Some(Digest32 { value: vec![0xBB; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/a".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs: vec![],
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-perception-001".to_string(),
        session_id: "session-42".to_string(),
        step_id: "perception-1".to_string(),
        input_packet_refs,
        self_state_ref: Some(Ref {
            uri: "state://self/42".to_string(),
            label: "baseline".to_string(),
        }),
        intent_refs,
        candidate_refs,
        workspace_mode: WorkMode::WmSimulate as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x01; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["ingest", "perception"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-perception-001".to_string(),
        profile_state: ProfileState::M1 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/17".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Low as i32,
        threat_class: LevelClass::Low as i32,
        stability_class: LevelClass::High as i32,
        progress_class: LevelClass::Med as i32,
        noise_class: NoiseClass::Low as i32,
        priority_class: PriorityClass::Low as i32,
        hpa_baseline_ref: Some(Ref {
            uri: "hpa://baseline/seed".to_string(),
            label: "hpa".to_string(),
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-baseline"]) }),
    };

    verify_case("experience_rt_perception", EXPERIENCE_SCHEMA, expected)
}

fn experience_record_rt_action_exec_case() -> Result<()> {
    let related_refs = vec![
        Ref { uri: "policy://query/001".to_string(), label: "policy_query".to_string() },
        Ref { uri: "policy://decision/001".to_string(), label: "policy_decision".to_string() },
        Ref { uri: "policy://ruleset/alpha".to_string(), label: "ruleset".to_string() },
    ];

    let policy_decision_refs = vec![
        Ref { uri: "policy://decision/001".to_string(), label: "decision-primary".to_string() },
        Ref { uri: "policy://decision/002".to_string(), label: "decision-secondary".to_string() },
    ];

    let grant_refs = vec![
        Ref { uri: "grant://budget/2024-01".to_string(), label: "budget-grant".to_string() },
        Ref { uri: "grant://safety/alpha".to_string(), label: "safety-grant".to_string() },
    ];

    let expected = ExperienceRecord {
        record_type: RecordType::RtActionExec as i32,
        core_frame_ref: Some(Ref {
            uri: "core://action/002".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://action/002".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: Some(Ref {
            uri: "governance://action/002".to_string(),
            label: "governance-frame".to_string(),
        }),
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_002,
            timestamp_ms: 1_700_010_250,
            prev_record_digest: Some(Digest32 { value: vec![0xBB; 32] }),
            record_digest: Some(Digest32 { value: vec![0xCC; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/b".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs,
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-action-002".to_string(),
        session_id: "session-42".to_string(),
        step_id: "action-2".to_string(),
        input_packet_refs: vec![Ref {
            uri: "packet://bridge/030".to_string(),
            label: "primary".to_string(),
        }],
        self_state_ref: Some(Ref {
            uri: "state://self/42".to_string(),
            label: "baseline".to_string(),
        }),
        intent_refs: vec![Ref {
            uri: "intent://primary/42".to_string(),
            label: "primary".to_string(),
        }],
        candidate_refs: vec![Ref {
            uri: "candidate://lm/beta".to_string(),
            label: "lm-beta".to_string(),
        }],
        workspace_mode: WorkMode::WmExecPlan as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x02; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["action", "execute"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-action-002".to_string(),
        profile_state: ProfileState::M2 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/18".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Med as i32,
        threat_class: LevelClass::Med as i32,
        stability_class: LevelClass::Med as i32,
        progress_class: LevelClass::High as i32,
        noise_class: NoiseClass::Med as i32,
        priority_class: PriorityClass::High as i32,
        hpa_baseline_ref: None,
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-action"]) }),
    };

    let mut dlp_refs =
        vec![Ref { uri: "dlp://scan/alpha".to_string(), label: "pre-exec".to_string() }];
    dlp_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let _governance_frame = GovernanceFrame {
        governance_frame_id: "governance-action-002".to_string(),
        policy_decision_refs,
        grant_refs,
        dlp_refs,
        budget_snapshot_ref: Some(Ref {
            uri: "budget://snap/2024-01".to_string(),
            label: "budget".to_string(),
        }),
        pvgs_receipt_ref: Some(Ref {
            uri: "pvgs://receipt/alpha".to_string(),
            label: "pvgs".to_string(),
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["policy-check", "pvgs-gate"]) }),
    };

    verify_case("experience_rt_action_exec", EXPERIENCE_SCHEMA, expected)
}

fn experience_record_rt_output_case() -> Result<()> {
    let related_refs = vec![
        Ref { uri: "artifact://output/777".to_string(), label: "output_artifact".to_string() },
        Ref { uri: "dlp://scan/final".to_string(), label: "dlp-scan".to_string() },
    ];

    let dlp_refs = vec![
        Ref { uri: "dlp://scan/final".to_string(), label: "dlp-scan".to_string() },
        Ref { uri: "dlp://audit/summary".to_string(), label: "dlp-audit".to_string() },
    ];

    let expected = ExperienceRecord {
        record_type: RecordType::RtOutput as i32,
        core_frame_ref: Some(Ref {
            uri: "core://output/003".to_string(),
            label: "core-frame".to_string(),
        }),
        metabolic_frame_ref: Some(Ref {
            uri: "metabolic://output/003".to_string(),
            label: "metabolic-frame".to_string(),
        }),
        governance_frame_ref: Some(Ref {
            uri: "governance://output/003".to_string(),
            label: "governance-frame".to_string(),
        }),
        finalization_header: Some(FinalizationHeader {
            experience_id: 1_003,
            timestamp_ms: 1_700_010_500,
            prev_record_digest: Some(Digest32 { value: vec![0xCC; 32] }),
            record_digest: Some(Digest32 { value: vec![0xDD; 32] }),
            vrf_digest_ref: Some(Ref {
                uri: "vrf://digest/seed".to_string(),
                label: "vrf".to_string(),
            }),
            proof_receipt_ref: Some(Ref {
                uri: "proof://receipt/c".to_string(),
                label: "proof".to_string(),
            }),
            charter_version_digest: "charter:v3".to_string(),
            policy_version_digest: "policy:v5".to_string(),
            key_epoch_id: 17,
        }),
        related_refs,
    };

    let _core_frame = CoreFrame {
        core_frame_id: "core-output-003".to_string(),
        session_id: "session-42".to_string(),
        step_id: "output-3".to_string(),
        input_packet_refs: vec![Ref {
            uri: "packet://bridge/045".to_string(),
            label: "primary".to_string(),
        }],
        self_state_ref: None,
        intent_refs: vec![Ref {
            uri: "intent://primary/42".to_string(),
            label: "primary".to_string(),
        }],
        candidate_refs: vec![Ref {
            uri: "candidate://lm/gamma".to_string(),
            label: "lm-gamma".to_string(),
        }],
        workspace_mode: WorkMode::WmReport as i32,
        core_embedding_digest: Some(Digest32 { value: vec![0x03; 32] }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["output", "ready"]) }),
    };

    let _metabolic_frame = MetabolicFrame {
        metabolic_frame_id: "metabolic-output-003".to_string(),
        profile_state: ProfileState::M2 as i32,
        control_frame_ref: Some(Ref {
            uri: "control://frame/19".to_string(),
            label: "control".to_string(),
        }),
        arousal_class: LevelClass::Low as i32,
        threat_class: LevelClass::Low as i32,
        stability_class: LevelClass::High as i32,
        progress_class: LevelClass::High as i32,
        noise_class: NoiseClass::Low as i32,
        priority_class: PriorityClass::Med as i32,
        hpa_baseline_ref: None,
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["metabolic-output"]) }),
    };

    let mut policy_decision_refs =
        vec![Ref { uri: "policy://decision/003".to_string(), label: "decision".to_string() }];
    policy_decision_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let mut grant_refs =
        vec![Ref { uri: "grant://dlp/export".to_string(), label: "export-grant".to_string() }];
    grant_refs.sort_by(|a, b| a.uri.cmp(&b.uri));
    let _governance_frame = GovernanceFrame {
        governance_frame_id: "governance-output-003".to_string(),
        policy_decision_refs,
        grant_refs,
        dlp_refs,
        budget_snapshot_ref: Some(Ref {
            uri: "budget://snap/2024-02".to_string(),
            label: "budget".to_string(),
        }),
        pvgs_receipt_ref: None,
        reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["dlp-approved", "output-ready"]),
        }),
    };

    verify_case("experience_rt_output", EXPERIENCE_SCHEMA, expected)
}

fn micro_milestone_sealed_case() -> Result<()> {
    let mut theme_tags = vec!["alignment".to_string(), "staging".to_string()];
    theme_tags.sort();
    let mut reason_codes = vec!["checkpoint".to_string(), "sealed".to_string()];
    reason_codes.sort();

    let expected = MicroMilestone {
        micro_id: "micro-001".to_string(),
        micro_digest: Some(Digest32 { value: vec![0x11; 32] }),
        state: MilestoneState::Sealed as i32,
        experience_range: Some(ExperienceRange {
            start_experience_id: 1_000,
            end_experience_id: 1_024,
            head_record_digest: Some(Digest32 { value: vec![0xAA; 32] }),
        }),
        summary_digest: Some(Digest32 { value: vec![0xBB; 32] }),
        hormone_profile: Some(HormoneProfileSummary {
            arousal: LevelClass::Low as i32,
            threat: LevelClass::Med as i32,
            stability: LevelClass::High as i32,
            progress: LevelClass::Med as i32,
            allostatic_load: Some(LevelClass::Low as i32),
        }),
        priority_class: PriorityClass::High as i32,
        vrf_digest_ref: Some(Ref { uri: "vrf://micro/seed".to_string(), label: "vrf".to_string() }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://micro/receipt".to_string(),
            label: "proof".to_string(),
        }),
        theme_tags,
        reason_codes: Some(ReasonCodes { codes: reason_codes }),
    };

    verify_case("micro_milestone_sealed", MICRO_MILESTONE_SCHEMA, expected)
}

fn microcircuit_config_lc_case() -> Result<()> {
    let expected = MicrocircuitConfigEvidence {
        module: MicroModule::Lc as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x10; 32] }),
        created_at_ms: 1_700_123_456,
        prev_config_digest: None,
        proof_receipt_ref: Some(Ref {
            uri: "proof://microcircuit/config/receipt-1".to_string(),
            label: "receipt".to_string(),
        }),
        attestation_sig: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x01, 0x02, 0x03, 0x04],
            signature: vec![0x05, 0x06, 0x07, 0x08],
        }),
        attestation_key_id: Some("attest-key-1".to_string()),
    };

    verify_case_with_domain(
        "microcircuit_config_lc_v1",
        MICRO_CIRCUIT_SCHEMA,
        MICRO_CIRCUIT_DOMAIN,
        expected,
    )
}

fn microcircuit_config_sn_case() -> Result<()> {
    let expected = MicrocircuitConfigEvidence {
        module: MicroModule::Sn as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x22; 32] }),
        created_at_ms: 1_700_123_999,
        prev_config_digest: Some(Digest32 { value: vec![0x11; 32] }),
        proof_receipt_ref: None,
        attestation_sig: None,
        attestation_key_id: None,
    };

    verify_case_with_domain(
        "microcircuit_config_sn_v1",
        MICRO_CIRCUIT_SCHEMA,
        MICRO_CIRCUIT_DOMAIN,
        expected,
    )
}

fn microcircuit_config_hpa_case() -> Result<()> {
    let expected = MicrocircuitConfigEvidence {
        module: MicroModule::Hpa as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x33; 32] }),
        created_at_ms: 1_700_124_111,
        prev_config_digest: Some(Digest32 { value: vec![0x22; 32] }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://microcircuit/config/receipt-hpa-1".to_string(),
            label: "receipt".to_string(),
        }),
        attestation_sig: None,
        attestation_key_id: Some("attest-key-hpa-1".to_string()),
    };

    verify_case_with_domain(
        "microcircuit_config_hpa_v1",
        MICRO_CIRCUIT_SCHEMA,
        MICRO_CIRCUIT_DOMAIN,
        expected,
    )
}

#[test]
fn microcircuit_config_hpa_bin_case() -> Result<()> {
    let (fixture_bytes, fixture_digest) = load_binary_fixture("mc_cfg_hpa")?;

    let decoded = MicrocircuitConfigEvidence::decode(fixture_bytes.as_slice())?;
    let encoded = canonical_bytes(&decoded);
    assert_eq!(fixture_bytes, encoded, "canonical bytes should be stable");

    let digest = digest32(MICRO_CIRCUIT_DOMAIN, MICRO_CIRCUIT_SCHEMA, VERSION, &encoded);
    assert_eq!(fixture_digest, digest, "digest should match stored fixture");

    let expected = MicrocircuitConfigEvidence {
        module: MicroModule::Hpa as i32,
        config_version: 1,
        config_digest: Some(Digest32 { value: vec![0x44; 32] }),
        created_at_ms: 1_700_125_000,
        prev_config_digest: None,
        proof_receipt_ref: None,
        attestation_sig: None,
        attestation_key_id: None,
    };

    let expected_bytes = canonical_bytes(&expected);
    assert_eq!(encoded, expected_bytes, "constructed and fixture differ");

    Ok(())
}

fn meso_milestone_stable_case() -> Result<()> {
    let mut theme_tags = vec!["consolidation".to_string(), "stability".to_string()];
    theme_tags.sort();
    let mut micro_refs = vec![
        Ref { uri: "ucf://micro/001".to_string(), label: "micro-a".to_string() },
        Ref { uri: "ucf://micro/002".to_string(), label: "micro-b".to_string() },
    ];
    micro_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let expected = MesoMilestone {
        meso_id: "meso-bridge".to_string(),
        meso_digest: Some(Digest32 { value: vec![0x22; 32] }),
        state: MilestoneState::Stable as i32,
        micro_refs,
        theme_tags,
        hormone_profile: Some(HormoneProfileSummary {
            arousal: LevelClass::Med as i32,
            threat: LevelClass::Low as i32,
            stability: LevelClass::High as i32,
            progress: LevelClass::High as i32,
            allostatic_load: Some(LevelClass::Med as i32),
        }),
        stability_class: LevelClass::High as i32,
        vrf_digest_ref: None,
        proof_receipt_ref: Some(Ref {
            uri: "proof://meso/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_case("meso_milestone_stable", MESO_MILESTONE_SCHEMA, expected)
}

fn macro_milestone_finalized_case() -> Result<()> {
    let mut meso_refs =
        vec![Ref { uri: "ucf://meso/bridge".to_string(), label: "meso-bridge".to_string() }];
    meso_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut justification_refs = vec![
        Ref { uri: "just://policy/alpha".to_string(), label: "policy".to_string() },
        Ref { uri: "just://audit/2024".to_string(), label: "audit".to_string() },
    ];
    justification_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let trait_updates = vec![
        TraitUpdate {
            trait_name: "novelty-threshold".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: LevelClass::High as i32,
            justification_refs: justification_refs.clone(),
        },
        TraitUpdate {
            trait_name: "export-guardrails".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: LevelClass::Med as i32,
            justification_refs,
        },
    ];

    let expected = MacroMilestone {
        macro_id: "macro-root".to_string(),
        macro_digest: Some(Digest32 { value: vec![0x33; 32] }),
        state: MilestoneState::Finalized as i32,
        meso_refs,
        trait_updates,
        identity_anchor_flag: true,
        consistency_class: ConsistencyClass::ConsistencyHigh as i32,
        vrf_digest_ref: Some(Ref { uri: "vrf://macro/seed".to_string(), label: "vrf".to_string() }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://macro/receipt".to_string(),
            label: "proof".to_string(),
        }),
        policy_ecology_ref: Some(Ref {
            uri: "pev://digest/v1".to_string(),
            label: "policy-ecology".to_string(),
        }),
    };

    verify_case("macro_milestone_finalized", MACRO_MILESTONE_SCHEMA, expected)
}

fn replay_plan_high_fidelity_case() -> Result<()> {
    let mut target_refs = vec![
        Ref { uri: "ucf://macro/root".to_string(), label: "macro-root".to_string() },
        Ref { uri: "ucf://meso/bridge".to_string(), label: "meso-bridge".to_string() },
    ];
    target_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut trigger_reason_codes =
        vec!["consistency-low".to_string(), "operator-trigger".to_string()];
    trigger_reason_codes.sort();

    let expected = ReplayPlan {
        replay_id: "replay-stability-check".to_string(),
        replay_digest: Some(Digest32 { value: vec![0x44; 32] }),
        trigger_reason_codes: Some(ReasonCodes { codes: trigger_reason_codes }),
        target_refs,
        fidelity: ReplayFidelity::ReplayHigh as i32,
        inject_mode: ReplayInjectMode::InjectCenExecPlan as i32,
        stop_conditions: Some(replay_plan::StopConditions {
            max_steps_class: 4,
            max_budget_class: 2,
            stop_on_dlp_flag: true,
        }),
        vrf_digest_ref: Some(Ref {
            uri: "vrf://replay/seed".to_string(),
            label: "vrf".to_string(),
        }),
        proof_receipt_ref: None,
        asset_manifest_ref: None,
    };

    verify_case("replay_plan_high_fidelity", REPLAY_PLAN_SCHEMA, expected)
}

fn replay_plan_asset_manifest_ref_case() -> Result<()> {
    let mut target_refs = vec![Ref {
        uri: "ucf://macro/asset-refresh".to_string(),
        label: "macro-asset-refresh".to_string(),
    }];
    target_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut trigger_reason_codes = vec!["asset-refresh".to_string()];
    trigger_reason_codes.sort();

    let expected = ReplayPlan {
        replay_id: "replay-asset-manifest".to_string(),
        replay_digest: Some(Digest32 { value: vec![0x45; 32] }),
        trigger_reason_codes: Some(ReasonCodes { codes: trigger_reason_codes }),
        target_refs,
        fidelity: ReplayFidelity::ReplayMed as i32,
        inject_mode: ReplayInjectMode::InjectReportOnly as i32,
        stop_conditions: Some(replay_plan::StopConditions {
            max_steps_class: 2,
            max_budget_class: 1,
            stop_on_dlp_flag: false,
        }),
        vrf_digest_ref: None,
        proof_receipt_ref: None,
        asset_manifest_ref: Some(Ref {
            uri: "asset_manifest".to_string(),
            label: "manifest-digest".to_string(),
        }),
    };

    verify_case("replay_plan_asset_manifest_ref", REPLAY_PLAN_SCHEMA, expected)
}

fn replay_run_evidence_case() -> Result<()> {
    let micro_configs = vec![
        MicrocircuitConfigEvidence {
            module: MicroModule::Lc as i32,
            config_version: 2,
            config_digest: Some(Digest32 { value: vec![0x11; 32] }),
            created_at_ms: 1_700_101_100,
            prev_config_digest: None,
            proof_receipt_ref: Some(Ref {
                uri: "proof://micro/lc/receipt".to_string(),
                label: "lc-proof".to_string(),
            }),
            attestation_sig: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0x10, 0x20, 0x30],
                signature: vec![0x40, 0x50, 0x60],
            }),
            attestation_key_id: Some("key-lc-1".to_string()),
        },
        MicrocircuitConfigEvidence {
            module: MicroModule::Sn as i32,
            config_version: 3,
            config_digest: Some(Digest32 { value: vec![0x22; 32] }),
            created_at_ms: 1_700_101_200,
            prev_config_digest: Some(Digest32 { value: vec![0x33; 32] }),
            proof_receipt_ref: None,
            attestation_sig: None,
            attestation_key_id: None,
        },
    ];

    let expected = ReplayRunEvidence {
        run_id: "run-889".to_string(),
        run_digest: Some(Digest32 { value: vec![0xAA; 32] }),
        replay_plan_ref: Some(Ref {
            uri: "ucf://replay/plan-889".to_string(),
            label: "replay-plan".to_string(),
        }),
        asset_manifest_ref: Some(Ref {
            uri: "ucf://assets/manifest-21".to_string(),
            label: "asset-manifest".to_string(),
        }),
        micro_configs,
        steps: 42,
        dt_us: 25,
        substeps_per_tick: 4,
        summary_profile_seq_digest: Some(Digest32 { value: vec![0x55; 32] }),
        summary_dwm_seq_digest: Some(Digest32 { value: vec![0x66; 32] }),
        created_at_ms: 1_700_200_321,
        proof_receipt_ref: Some(Ref {
            uri: "proof://replay/run/receipt".to_string(),
            label: "replay-proof".to_string(),
        }),
        attestation_sig: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x05, 0x06],
        }),
    };

    verify_case("replay_run_evidence", REPLAY_RUN_SCHEMA, expected)
}

fn consistency_feedback_low_flags_case() -> Result<()> {
    let mut ism_refs = vec![
        Ref { uri: "ucf://macro/root".to_string(), label: "macro-anchor".to_string() },
        Ref { uri: "ucf://ism/123".to_string(), label: "ism".to_string() },
    ];
    ism_refs.sort_by(|a, b| a.uri.cmp(&b.uri));

    let mut trigger_reason_codes =
        vec!["drift-detected".to_string(), "replay-recommended".to_string()];
    trigger_reason_codes.sort();

    let flags = vec![ConsistencyFlag::BehaviorDrift as i32, ConsistencyFlag::RiskDrift as i32];

    let expected = ConsistencyFeedback {
        cf_id: "cf-low-001".to_string(),
        cf_digest: Some(Digest32 { value: vec![0x55; 32] }),
        rss_ref: Some(Ref {
            uri: "rss://baseline/1".to_string(),
            label: "baseline-rss".to_string(),
        }),
        ism_refs,
        pev_ref: Some(Ref {
            uri: "pev://digest/v2".to_string(),
            label: "policy-ecology".to_string(),
        }),
        consistency_class: ConsistencyClass::ConsistencyLow as i32,
        flags,
        recommended_noise_class: NoiseClass::Med as i32,
        consolidation_eligibility: ConsolidationEligibility::Allow as i32,
        replay_trigger_hint: true,
        trigger_reason_codes: Some(ReasonCodes { codes: trigger_reason_codes }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://consistency/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_case("consistency_feedback_low_flags", CONSISTENCY_FEEDBACK_SCHEMA, expected)
}

fn tool_registry_container_case() -> Result<()> {
    let default_constraints = ToolConstraintsDefaults {
        max_bytes_out_class: SizeClass::SizeSmall as i32,
        max_items_out_class: SizeClass::SizeMed as i32,
        timeout_class: TimeoutClass::TimeoutShort as i32,
        rate_limit_class: RateLimitClass::RateMed as i32,
        allow_unbounded_query: false,
    };

    let data_class_conditions = vec![DataClassCondition {
        param_name: "query".to_string(),
        op: "eq".to_string(),
        value: "latest".to_string(),
        result_data_class: DataClass::Public as i32,
    }];

    let tool_action = ToolActionProfile {
        tool_id: "sensor-service".to_string(),
        action_id: "read-latest".to_string(),
        profile_version: "1.0.0".to_string(),
        profile_digest: Some(Digest32 { value: vec![0x10; 32] }),
        action_type: ToolActionType::Read as i32,
        reversibility: Reversibility::Reversible as i32,
        side_effect_class: SideEffectClass::None as i32,
        scope_shape: ScopeShape::Single as i32,
        max_data_class_out: DataClass::Confidential as i32,
        input_schema: Some(TypedSchema {
            schema_id: "ucf.v1.ReadInput".to_string(),
            schema_digest: Some(Digest32 { value: vec![0xA1; 32] }),
            max_fields: 4,
        }),
        output_schema: Some(TypedSchema {
            schema_id: "ucf.v1.ReadOutput".to_string(),
            schema_digest: Some(Digest32 { value: vec![0xB2; 32] }),
            max_fields: 6,
        }),
        default_constraints: Some(default_constraints),
        retry_policy: Some(RetryPolicy {
            retry_allowed: true,
            retry_class: RetryClass::RetryLow as i32,
        }),
        simulation_mode: Some(SimulationMode {
            simulatable: true,
            sim_tool_id: "sim-sensor".to_string(),
            sim_action_id: "simulate-read".to_string(),
            sim_fidelity_class: SimulationFidelity::Med as i32,
        }),
        cost_model: Some(CostModel {
            base_cost_class: CostClass::CostLow as i32,
            scope_multiplier_class: CostClass::CostMed as i32,
            data_multiplier_class: CostClass::CostMed as i32,
            irreversibility_multiplier_class: CostClass::CostLow as i32,
        }),
        attestation_requirements: Some(AttestationRequirements {
            artifact_digest_required: true,
            allowed_artifact_digests: vec![
                Digest32 { value: vec![0x01; 32] },
                Digest32 { value: vec![0x02; 32] },
            ],
        }),
        logging_requirements: Some(LoggingRequirements {
            require_outcome_digest: true,
            require_tool_version_digest: true,
            require_side_effect_indicators: false,
        }),
        data_class_conditions,
        expected_side_effect_indicators: vec!["cache-read".to_string(), "trace".to_string()],
        known_failure_modes: vec!["timeout".to_string(), "unreachable".to_string()],
    };

    let mut tool_actions = vec![tool_action];
    tool_actions.sort_by(|a, b| a.action_id.cmp(&b.action_id));

    let expected = ToolRegistryContainer {
        registry_id: "registry-alpha".to_string(),
        registry_version: "2024-01".to_string(),
        registry_digest: Some(Digest32 { value: vec![0xCC; 32] }),
        tool_actions,
        created_at_ms: 1_700_003_000,
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Accepted as i32,
            receipt_digest: Some(Digest32 { value: vec![0xAA; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0x01, 0x02],
                signature: vec![0x03, 0x04],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x10; 32] }),
        }),
        attestation_sig: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0x10, 0x11, 0x12],
            signature: vec![0x21, 0x22, 0x23],
        }),
    };

    verify_case("tool_registry_container", TOOL_REGISTRY_SCHEMA, expected)
}

fn tool_onboarding_event_case() -> Result<()> {
    let expected = ToolOnboardingEvent {
        event_id: "onboard-evt-01".to_string(),
        event_digest: Some(Digest32 { value: vec![0x0A; 32] }),
        tool_id: "sensor-service".to_string(),
        action_id: "read-latest".to_string(),
        stage: OnboardingStage::To6Suspended as i32,
        stage_reason_codes: Some(ReasonCodes {
            codes: sorted_strings(&["missing-attestation", "risk-review"]),
        }),
        required_artifact_digests: vec![Digest32 { value: vec![0x05; 32] }],
        test_evidence_refs: vec![Ref {
            uri: "evidence://test/report".to_string(),
            label: "report".to_string(),
        }],
        signatures: vec![Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA, 0xBB],
            signature: vec![0xCC, 0xDD],
        }],
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Pending as i32,
            receipt_digest: Some(Digest32 { value: vec![0x09; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0xFE],
                signature: vec![0xEE],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x0F; 32] }),
        }),
    };

    verify_case("tool_onboarding_event", TOOL_ONBOARDING_SCHEMA, expected)
}

fn approval_artifact_package_case() -> Result<()> {
    let alternatives = vec![
        Alternative {
            alt_type: AlternativeType::SimulateFirst as i32,
            expected_cost: Some(alternative::ExpectedCost::ExpectedCostClass(
                CostClass::CostMed as i32,
            )),
            pros_cons_digest: Some(Digest32 { value: vec![0xAB; 32] }),
        },
        Alternative {
            alt_type: AlternativeType::NarrowScope as i32,
            expected_cost: Some(alternative::ExpectedCost::ExpectedCostBucket(2)),
            pros_cons_digest: Some(Digest32 { value: vec![0xBC; 32] }),
        },
    ];

    let evidence_refs = vec![
        Ref { uri: "evidence://logs/primary".to_string(), label: "logs".to_string() },
        Ref { uri: "evidence://report/risk".to_string(), label: "risk".to_string() },
    ];

    let expected = ApprovalArtifactPackage {
        aap_id: "aap-42".to_string(),
        aap_digest: Some(Digest32 { value: vec![0x44; 32] }),
        session_id: "session-9000".to_string(),
        intent_ref: Some(Ref {
            uri: "intent://primary/42".to_string(),
            label: "intent".to_string(),
        }),
        action_spec_ref: Some(Ref {
            uri: "action://spec/read".to_string(),
            label: "action-spec".to_string(),
        }),
        decision_ref: Some(Ref {
            uri: "decision://placeholder".to_string(),
            label: "decision".to_string(),
        }),
        charter_version_digest: "charter:v5".to_string(),
        policy_version_digest: "policy:v7".to_string(),
        profile_digest: Some(Digest32 { value: vec![0x45; 32] }),
        requested_operation: RequestedOperation::OpWrite as i32,
        risk_level: RiskLevel::Medium as i32,
        requested_data_class: DataClass::Restricted as i32,
        constraints_proposal: Some(ConstraintsDelta {
            constraints_added: sorted_strings(&["approval-required", "scope-narrowing"]),
            constraints_removed: vec!["legacy-exception".to_string()],
        }),
        alternatives,
        evidence_refs,
        expires_at_ms: 1_700_020_000,
        two_person_requirement: TwoPersonRequirement::Two as i32,
    };

    verify_case("approval_artifact_package", APPROVAL_ARTIFACT_PACKAGE_SCHEMA, expected)
}

fn approval_decision_case() -> Result<()> {
    let expected = ApprovalDecision {
        approval_id: "approval-01".to_string(),
        approval_digest: Some(Digest32 { value: vec![0x55; 32] }),
        aap_digest: Some(Digest32 { value: vec![0x44; 32] }),
        decision: ApprovalDecisionType::ApproveWithModifications as i32,
        modifications: Some(ConstraintsDelta {
            constraints_added: vec!["cooldown-required".to_string()],
            constraints_removed: vec![],
        }),
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["two-person", "risk-review"]) }),
        signatures: vec![Signature {
            algorithm: "ed25519".to_string(),
            signer: vec![0xAA],
            signature: vec![0xBB],
        }],
        expires_at_ms: 1_700_030_000,
        proof_receipt_ref: Some(ProofReceipt {
            status: ReceiptStatus::Accepted as i32,
            receipt_digest: Some(Digest32 { value: vec![0x46; 32] }),
            validator: Some(Signature {
                algorithm: "ed25519".to_string(),
                signer: vec![0x0A, 0x0B],
                signature: vec![0x0C, 0x0D],
            }),
            vrf_digest: Some(Digest32 { value: vec![0x0E; 32] }),
        }),
    };

    verify_case("approval_decision", APPROVAL_DECISION_SCHEMA, expected)
}

fn sep_event_chain_case() -> Result<()> {
    let events = vec![
        (
            "sep_event_chain_1",
            SepEvent {
                event_id: "evt-1".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvIntent as i32,
                object_ref: Some(Ref {
                    uri: "intent://primary/42".to_string(),
                    label: "intent".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["init".to_string()] }),
                timestamp_ms: 1_700_002_000,
                prev_event_digest: Some(Digest32 { value: vec![0x00; 32] }),
                event_digest: Some(Digest32 { value: vec![0x10; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x01],
                    signature: vec![0x02],
                }),
                epoch_id: 100,
            },
        ),
        (
            "sep_event_chain_2",
            SepEvent {
                event_id: "evt-2".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvDecision as i32,
                object_ref: Some(Ref {
                    uri: "decision://approval".to_string(),
                    label: "decision".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["policy".to_string()] }),
                timestamp_ms: 1_700_002_500,
                prev_event_digest: Some(Digest32 { value: vec![0x10; 32] }),
                event_digest: Some(Digest32 { value: vec![0x20; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x03],
                    signature: vec![0x04],
                }),
                epoch_id: 100,
            },
        ),
        (
            "sep_event_chain_3",
            SepEvent {
                event_id: "evt-3".to_string(),
                session_id: "session-9000".to_string(),
                event_type: SepEventType::EvOutcome as i32,
                object_ref: Some(Ref {
                    uri: "outcome://result".to_string(),
                    label: "outcome".to_string(),
                }),
                reason_codes: Some(ReasonCodes { codes: vec!["success".to_string()] }),
                timestamp_ms: 1_700_003_000,
                prev_event_digest: Some(Digest32 { value: vec![0x20; 32] }),
                event_digest: Some(Digest32 { value: vec![0x30; 32] }),
                attestation_sig: Some(Signature {
                    algorithm: "ed25519".to_string(),
                    signer: vec![0x05],
                    signature: vec![0x06],
                }),
                epoch_id: 101,
            },
        ),
    ];

    for (name, expected) in events {
        verify_case(name, SEP_EVENT_SCHEMA, expected.clone())?;
    }

    Ok(())
}

fn session_seal_case() -> Result<()> {
    let expected = SessionSeal {
        seal_id: "seal-9000".to_string(),
        seal_digest: Some(Digest32 { value: vec![0xAB; 32] }),
        session_id: "session-9000".to_string(),
        final_event_digest: Some(Digest32 { value: vec![0x30; 32] }),
        final_record_digest: Some(Digest32 { value: vec![0xCD; 32] }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://session/receipt".to_string(),
            label: "proof".to_string(),
        }),
        created_at_ms: 1_700_003_500,
    };

    verify_case("session_seal", SESSION_SEAL_SCHEMA, expected)
}

fn completeness_report_case() -> Result<()> {
    let expected = CompletenessReport {
        report_id: "comp-01".to_string(),
        report_digest: Some(Digest32 { value: vec![0xEF; 32] }),
        session_id: "session-9000".to_string(),
        status: CompletenessStatus::CompFail as i32,
        missing_nodes: vec![Ref {
            uri: "sep://evt/missing".to_string(),
            label: "missing".to_string(),
        }],
        missing_edges: vec!["evt-2->evt-4".to_string(), "evt-1->evt-3".to_string()],
        reason_codes: Some(ReasonCodes { codes: sorted_strings(&["edge-gap", "missing-node"]) }),
        proof_receipt_ref: Some(Ref {
            uri: "proof://completeness/receipt".to_string(),
            label: "proof".to_string(),
        }),
    };

    verify_case("completeness_report", COMPLETENESS_REPORT_SCHEMA, expected)
}

const FIXTURE_CASES: &[FixtureCase] = &[
    FixtureCase {
        name: "approval_artifact_package",
        schema: APPROVAL_ARTIFACT_PACKAGE_SCHEMA,
        proto_files: &["proto/ucf/v1/human.proto", "proto/ucf/v1/common.proto"],
        verify: approval_artifact_package_case,
    },
    FixtureCase {
        name: "approval_decision",
        schema: APPROVAL_DECISION_SCHEMA,
        proto_files: &["proto/ucf/v1/human.proto", "proto/ucf/v1/common.proto"],
        verify: approval_decision_case,
    },
    FixtureCase {
        name: "asset_digest_morphology_v1",
        schema: ASSET_DIGEST_SCHEMA,
        proto_files: &["proto/ucf/v1/assets.proto", "proto/ucf/v1/common.proto"],
        verify: asset_digest_morphology_case,
    },
    FixtureCase {
        name: "asset_manifest_v1",
        schema: ASSET_MANIFEST_SCHEMA,
        proto_files: &["proto/ucf/v1/assets.proto", "proto/ucf/v1/common.proto"],
        verify: asset_manifest_case,
    },
    FixtureCase {
        name: "biophys_channel_params_set_v1",
        schema: CHANNEL_PARAMS_SET_SCHEMA,
        proto_files: &["proto/ucf/v1/biophys_assets.proto", "proto/ucf/v1/common.proto"],
        verify: biophys_channel_params_set_case,
    },
    FixtureCase {
        name: "biophys_connectivity_graph_v1",
        schema: CONNECTIVITY_GRAPH_SCHEMA,
        proto_files: &["proto/ucf/v1/biophys_assets.proto", "proto/ucf/v1/common.proto"],
        verify: biophys_connectivity_graph_case,
    },
    FixtureCase {
        name: "biophys_morphology_set_v1",
        schema: MORPHOLOGY_SET_SCHEMA,
        proto_files: &["proto/ucf/v1/biophys_assets.proto", "proto/ucf/v1/common.proto"],
        verify: biophys_morphology_set_case,
    },
    FixtureCase {
        name: "biophys_synapse_params_set_v1",
        schema: SYNAPSE_PARAMS_SET_SCHEMA,
        proto_files: &["proto/ucf/v1/biophys_assets.proto", "proto/ucf/v1/common.proto"],
        verify: biophys_synapse_params_set_case,
    },
    FixtureCase {
        name: "canonical_intent_query",
        schema: INTENT_SCHEMA,
        proto_files: &["proto/ucf/v1/canonical.proto", "proto/ucf/v1/common.proto"],
        verify: canonical_intent_fixture_case,
    },
    FixtureCase {
        name: "completeness_report",
        schema: COMPLETENESS_REPORT_SCHEMA,
        proto_files: &["proto/ucf/v1/sep.proto", "proto/ucf/v1/common.proto"],
        verify: completeness_report_case,
    },
    FixtureCase {
        name: "consistency_feedback_low_flags",
        schema: CONSISTENCY_FEEDBACK_SCHEMA,
        proto_files: &["proto/ucf/v1/geist.proto", "proto/ucf/v1/common.proto"],
        verify: consistency_feedback_low_flags_case,
    },
    FixtureCase {
        name: "control_frame_m1_overlays_on",
        schema: CONTROL_FRAME_SCHEMA,
        proto_files: &["proto/ucf/v1/frames.proto", "proto/ucf/v1/common.proto"],
        verify: control_frame_fixture_case,
    },
    FixtureCase {
        name: "experience_rt_action_exec",
        schema: EXPERIENCE_SCHEMA,
        proto_files: &["proto/ucf/v1/experience.proto", "proto/ucf/v1/common.proto"],
        verify: experience_record_rt_action_exec_case,
    },
    FixtureCase {
        name: "experience_rt_output",
        schema: EXPERIENCE_SCHEMA,
        proto_files: &["proto/ucf/v1/experience.proto", "proto/ucf/v1/common.proto"],
        verify: experience_record_rt_output_case,
    },
    FixtureCase {
        name: "experience_rt_perception",
        schema: EXPERIENCE_SCHEMA,
        proto_files: &["proto/ucf/v1/experience.proto", "proto/ucf/v1/common.proto"],
        verify: experience_record_rt_perception_case,
    },
    FixtureCase {
        name: "macro_milestone_finalized",
        schema: MACRO_MILESTONE_SCHEMA,
        proto_files: &["proto/ucf/v1/milestones.proto", "proto/ucf/v1/common.proto"],
        verify: macro_milestone_finalized_case,
    },
    FixtureCase {
        name: "meso_milestone_stable",
        schema: MESO_MILESTONE_SCHEMA,
        proto_files: &["proto/ucf/v1/milestones.proto", "proto/ucf/v1/common.proto"],
        verify: meso_milestone_stable_case,
    },
    FixtureCase {
        name: "micro_milestone_sealed",
        schema: MICRO_MILESTONE_SCHEMA,
        proto_files: &["proto/ucf/v1/milestones.proto", "proto/ucf/v1/common.proto"],
        verify: micro_milestone_sealed_case,
    },
    FixtureCase {
        name: "microcircuit_config_hpa_v1",
        schema: MICRO_CIRCUIT_SCHEMA,
        proto_files: &["proto/ucf/v1/microcircuit.proto", "proto/ucf/v1/common.proto"],
        verify: microcircuit_config_hpa_case,
    },
    FixtureCase {
        name: "microcircuit_config_lc_v1",
        schema: MICRO_CIRCUIT_SCHEMA,
        proto_files: &["proto/ucf/v1/microcircuit.proto", "proto/ucf/v1/common.proto"],
        verify: microcircuit_config_lc_case,
    },
    FixtureCase {
        name: "microcircuit_config_sn_v1",
        schema: MICRO_CIRCUIT_SCHEMA,
        proto_files: &["proto/ucf/v1/microcircuit.proto", "proto/ucf/v1/common.proto"],
        verify: microcircuit_config_sn_case,
    },
    FixtureCase {
        name: "policy_decision",
        schema: POLICY_SCHEMA,
        proto_files: &["proto/ucf/v1/policy.proto", "proto/ucf/v1/common.proto"],
        verify: policy_decision_fixture_case,
    },
    FixtureCase {
        name: "pvgs_receipt",
        schema: PVGS_SCHEMA,
        proto_files: &["proto/ucf/v1/pvgs.proto", "proto/ucf/v1/common.proto"],
        verify: pvgs_receipt_fixture_case,
    },
    FixtureCase {
        name: "reason_codes_basic",
        schema: REASON_CODES_SCHEMA,
        proto_files: &["proto/ucf/v1/common.proto"],
        verify: reason_codes_basic_case,
    },
    FixtureCase {
        name: "replay_plan_asset_manifest_ref",
        schema: REPLAY_PLAN_SCHEMA,
        proto_files: &["proto/ucf/v1/milestones.proto", "proto/ucf/v1/common.proto"],
        verify: replay_plan_asset_manifest_ref_case,
    },
    FixtureCase {
        name: "replay_plan_high_fidelity",
        schema: REPLAY_PLAN_SCHEMA,
        proto_files: &["proto/ucf/v1/milestones.proto", "proto/ucf/v1/common.proto"],
        verify: replay_plan_high_fidelity_case,
    },
    FixtureCase {
        name: "replay_run_evidence",
        schema: REPLAY_RUN_SCHEMA,
        proto_files: &["proto/ucf/v1/replay_run.proto", "proto/ucf/v1/common.proto"],
        verify: replay_run_evidence_case,
    },
    FixtureCase {
        name: "sep_event_chain_1",
        schema: SEP_EVENT_SCHEMA,
        proto_files: &["proto/ucf/v1/sep.proto", "proto/ucf/v1/common.proto"],
        verify: sep_event_chain_case,
    },
    FixtureCase {
        name: "session_seal",
        schema: SESSION_SEAL_SCHEMA,
        proto_files: &["proto/ucf/v1/sep.proto", "proto/ucf/v1/common.proto"],
        verify: session_seal_case,
    },
    FixtureCase {
        name: "signal_frame_short_window",
        schema: SIGNAL_FRAME_SCHEMA,
        proto_files: &["proto/ucf/v1/frames.proto", "proto/ucf/v1/common.proto"],
        verify: signal_frame_fixture_case,
    },
    FixtureCase {
        name: "tool_onboarding_event",
        schema: TOOL_ONBOARDING_SCHEMA,
        proto_files: &["proto/ucf/v1/tooling.proto", "proto/ucf/v1/common.proto"],
        verify: tool_onboarding_event_case,
    },
    FixtureCase {
        name: "tool_registry_container",
        schema: TOOL_REGISTRY_SCHEMA,
        proto_files: &["proto/ucf/v1/tooling.proto", "proto/ucf/v1/common.proto"],
        verify: tool_registry_container_case,
    },
    FixtureCase {
        name: "ucf_envelope_policy_decision",
        schema: UCF_ENVELOPE_SCHEMA,
        proto_files: &["proto/ucf/v1/envelope.proto", "proto/ucf/v1/common.proto"],
        verify: ucf_envelope_policy_decision_case,
    },
];

#[test]
fn fixture_registry_is_complete() -> Result<()> {
    let names: Vec<&str> = FIXTURE_CASES.iter().map(|case| case.name).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "fixture registry should be sorted by name");

    let mut covered_protos: HashSet<&str> = HashSet::new();
    for case in FIXTURE_CASES {
        assert!(!case.schema.is_empty(), "schema identifier must be set for {}", case.name);
        (case.verify)()?;
        for proto in case.proto_files {
            covered_protos.insert(*proto);
        }
    }

    for proto in PROTO_FILES {
        assert!(covered_protos.contains(proto), "missing fixture coverage for {proto}");
    }

    Ok(())
}
