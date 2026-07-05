//! Compiles `proto/fleet.proto` with tonic-build. Uses a vendored `protoc`
//! so the build does not depend on a system protobuf compiler.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    // SAFETY: single-threaded build script; setting PROTOC before codegen runs.
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/fleet.proto"], &["proto"])
        .expect("compile fleet.proto");

    println!("cargo:rerun-if-changed=proto/fleet.proto");
}
