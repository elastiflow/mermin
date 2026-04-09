//! Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
//! better expressed by [artifact-dependencies][bindeps] but issues such as
//! https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
//!
//! This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
//! mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
//! $PATH ahead of the one used as the cache key still exists. Solving this in the general case
//! would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
//! which would likely mean far too much cache invalidation.
//!
//! [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies

fn main() {
    let bpf_linker = std::env::var_os("PATH")
        .and_then(|path_var| {
            std::env::split_paths(&path_var)
                .map(|dir| dir.join("bpf-linker"))
                .find(|p| is_executable(p))
        })
        .expect("bpf-linker not found in PATH");

    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}

fn is_executable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}
