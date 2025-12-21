use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    let protos = [
        "proto/ucf/v1/common.proto",
        "proto/ucf/v1/envelope.proto",
        "proto/ucf/v1/canonical.proto",
        "proto/ucf/v1/policy.proto",
        "proto/ucf/v1/pvgs.proto",
        "proto/ucf/v1/frames.proto",
    ];

    println!("cargo:rerun-if-changed=proto");

    let mut config = prost_build::Config::new();
    config.out_dir(PathBuf::from(std::env::var("OUT_DIR").unwrap()));
    config.compile_protos(&protos, &[proto_dir])?;
    Ok(())
}
