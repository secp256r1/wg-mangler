//! Build script for wg-mangler.
//!
//! With `--features kernel` on Linux, the eBPF program must be produced and
//! copied into `$OUT_DIR/wg_mangler_ebpf` for `include_bytes_aligned!`.
//!
//! Two strategies, in order:
//!
//! 1. **Prebuilt artifact** (fast path): if
//!    `target/bpfel-unknown-none/release/wg_mangler_ebpf` exists in the
//!    workspace and is newer than the eBPF sources, it is copied as-is. This
//!    is how `cross` builds and CI work: the host builds the (architecture
//!    independent) BPF ELF once with the nightly toolchain, and the cross /
//!    CI containers — which have no rustup/nightly/bpf-linker — reuse it.
//! 2. **aya-build** (fallback): invokes `aya_build::build_ebpf` to compile
//!    `wg-mangler-ebpf` for `bpfel-unknown-none` via `rustup run nightly`
//!    with `-Z build-std=core` (requires nightly + rust-src + bpf-linker on
//!    the host). Used by native Linux builds without a prebuilt artifact.
//!
//! Without the `kernel` feature (or on non-Linux hosts) this script is a
//! no-op, so default builds are completely unchanged.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Workspace-relative location of the prebuilt eBPF ELF.
#[allow(dead_code)] // used only with feature "kernel" on Linux
fn prebuilt_ebpf_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/bpfel-unknown-none/release/wg_mangler_ebpf")
}

/// Returns the prebuilt artifact path if it is present and not older than
/// the eBPF sources (a stale artifact would silently embed an old program).
#[allow(dead_code)] // used only with feature "kernel" on Linux
fn prebuilt_ebpf() -> Option<PathBuf> {
    let artifact = prebuilt_ebpf_path();
    let meta = std::fs::metadata(&artifact).ok()?;
    let artifact_mtime = meta.modified().unwrap_or(UNIX_EPOCH);

    let sources = [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("wg-mangler-ebpf/src/main.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("wg-mangler-ebpf/Cargo.toml"),
    ];
    for src in &sources {
        // source is newer than the artifact -> rebuild needed
        if let Ok(sm) = std::fs::metadata(src)
            && sm.modified().unwrap_or(UNIX_EPOCH) > artifact_mtime
        {
            return None;
        }
    }
    Some(artifact)
}

#[cfg(all(feature = "kernel", target_os = "linux"))]
mod kernel_build {
    use super::prebuilt_ebpf;
    use std::path::Path;

    pub fn run() {
        // 1. prebuilt artifact (cross-container/CI; arch-independent)
        if let Some(artifact) = prebuilt_ebpf() {
            println!(
                "cargo:warning=using prebuilt eBPF object {} (rebuild it after \
                 editing wg-mangler-ebpf/src/main.rs)",
                artifact.display()
            );
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let out = Path::new(&out_dir).join("wg_mangler_ebpf");
            std::fs::copy(&artifact, &out).expect("failed to copy prebuilt eBPF object");
            println!("cargo:rerun-if-changed={}", artifact.display());
            println!("cargo:rerun-if-changed=wg-mangler-ebpf/src/main.rs");
            println!("cargo:rerun-if-changed=wg-mangler-ebpf/Cargo.toml");
            return;
        }

        // 2. local aya-build (native Linux development)
        let metadata = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .expect("failed to run `cargo metadata`; is this really a cargo workspace?");
        let pkg = metadata
            .packages
            .iter()
            .find(|p| p.name == "wg-mangler-ebpf")
            .expect("workspace member `wg-mangler-ebpf` not found");
        let root_dir = pkg
            .manifest_path
            .parent()
            .expect("no parent for ebpf manifest")
            .as_std_path()
            .to_string_lossy()
            .into_owned();

        let package = aya_build::Package {
            name: "wg-mangler-ebpf",
            root_dir: &root_dir,
            ..Default::default()
        };

        aya_build::build_ebpf([package], aya_build::Toolchain::default()).expect(
            "failed to build eBPF program; install the nightly toolchain, rust-src and \
             bpf-linker:\n  \
             rustup toolchain install nightly --profile minimal --component rust-src\n  \
             cargo install bpf-linker --locked\n\
             (or, when cross-compiling with `cross`, first build the eBPF program on the \
             host: `cargo +nightly build -p wg-mangler-ebpf --bins --release \
             --target bpfel-unknown-none -Z build-std=core`)",
        );

        println!("cargo:rerun-if-changed=wg-mangler-ebpf/src/main.rs");
        println!("cargo:rerun-if-changed=wg-mangler-ebpf/Cargo.toml");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    kernel_build::run();
}