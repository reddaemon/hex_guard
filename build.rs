fn main() {
    let protoc_path = protoc_bin_vendored::protoc_bin_path().unwrap();
    let protoc_exe = protoc_path.to_str().unwrap();
    unsafe {
        std::env::set_var("PROTOC", protoc_exe);
    }
    tonic_build::configure()
        .compile_protos(&["proto/hex_guard.proto"], &["proto"])
        .unwrap_or_else(|e| panic!("Failed to compile proto: {}", e));
}
