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
            // digest-authoritative ref. An upstream re-push of `v6.1.0` can no
            // longer change the ELF. Override still possible via SP1_DOCKER_IMAGE.
            tag: "v6.1.0@sha256:484abccef8b457bfce8159f53364e93e0c78be6e5187a17e04c09856a7861576".to_string(),
            output_directory: Some("../elf".to_string()),
            ..Default::default()
        },
    );
}
