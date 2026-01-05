use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    let protos = [
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
        "proto/ucf/v1/proposal.proto",
        "proto/ucf/v1/activation.proto",
        "proto/ucf/v1/trace.proto",
    ];

    println!("cargo:rerun-if-changed=proto");

    let mut config = prost_build::Config::new();
    config.out_dir(PathBuf::from(std::env::var("OUT_DIR").unwrap()));
    config.compile_protos(&protos, &[proto_dir])?;
    Ok(())
}
