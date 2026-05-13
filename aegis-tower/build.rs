fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/aegis.proto");
    tonic_build::compile_protos("../proto/aegis.proto")?;
    Ok(())
}
