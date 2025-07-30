use std::path::PathBuf;

fn main() {
    let target_dir = "target/release";
    let elf_path = PathBuf::from(target_dir).join("mermin-ebpf");
    println!(
        "cargo:rustc-env=EBPF_PROGRAM_PATH={}",
        elf_path.to_str().unwrap()
    );
    println!("cargo:rerun-if-changed={}", elf_path.to_str().unwrap());
}
