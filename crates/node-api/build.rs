//! The UI is embedded from `frontend/dist`. Rust builds work without it, and the node then serves
//! a page explaining how to build it.

use std::path::Path;

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frontend/dist");
    if let Err(error) = std::fs::create_dir_all(&dist) {
        println!("cargo::warning=cannot create {}: {error}", dist.display());
    }
    println!("cargo::rerun-if-changed=../../frontend/dist");
    println!("cargo::rerun-if-changed=build.rs");
}
