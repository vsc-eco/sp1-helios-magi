#[allow(unused_imports)]
use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs {
            docker: true,
            // MED-40 / MED-131 (Z-PR-M3, M58-2P-M1): pin the SP1 builder image by
            // immutable digest, not the mutable `v6.1.0` tag. sp1-build's
            // get_docker_image() does format!("{image_base}:{tag}") with no
            // sanitization, so the `tag:...@sha256:...` form yields a
            // digest-authoritative ref. An upstream re-push of `v6.8.1` can no
            // longer change the ELF. Override still possible via SP1_DOCKER_IMAGE.
            // Digest = the ghcr.io/succinctlabs/sp1:v6.8.1 image index (2026-10-21).
            tag: "v6.8.1@sha256:e672d7160039916f40a6a4c2ea4cb0c8cd3dab120fdb24d08560d386ad8f59c2".to_string(),
            output_directory: Some("../elf".to_string()),
            ..Default::default()
        },
    );
}
