#!/usr/bin/env bash
# Inspect an SP1 ELF binary and report build provenance from embedded metadata.
#
# What this catches:
#   - Local non-Docker builds (cargo paths reveal the builder's home directory)
#   - SP1 toolchain version mismatches
#   - ELF format problems
#
# What this does NOT do:
#   - Compute the vkey hash (use `cargo run --bin vkey` for that)
#   - Verify reproducibility (the CI workflow does that by rebuilding via Docker)
#
# Usage:
#   scripts/inspect-elf.sh elf/light_client
#   scripts/inspect-elf.sh elf/light_client elf/storage    # compare multiple

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <elf-path> [<elf-path>...]" >&2
    exit 2
fi

for elf in "$@"; do
    if [[ ! -f "$elf" ]]; then
        echo "error: $elf not found" >&2
        exit 1
    fi

    echo "================================================================"
    echo "  $elf"
    echo "================================================================"

    echo ""
    echo "── File ──"
    printf "  size:    %d bytes\n" "$(wc -c < "$elf")"
    printf "  sha256:  %s\n" "$(sha256sum "$elf" | cut -d' ' -f1)"
    printf "  format:  %s\n" "$(file -b "$elf")"

    # Cache strings output — it's slow on large binaries and we grep it many times.
    strings_out=$(strings -n 8 "$elf")

    echo ""
    echo "── SP1 zkvm version ──"
    sp1_versions=$(echo "$strings_out" | grep -oE 'sp1-zkvm-[0-9]+\.[0-9]+\.[0-9]+' | sort -u || true)
    if [[ -z "$sp1_versions" ]]; then
        echo "  (no sp1-zkvm version markers found)"
    else
        echo "$sp1_versions" | sed 's/^/  /'
    fi

    echo ""
    echo "── Pinned dependency markers ──"
    deps=$(echo "$strings_out" | grep -oE '/(checkouts|registry/[^/]+)/(helios|alloy[a-z_-]*|sp1[a-z_-]*|tree_hash|ssz[a-z_-]*|gnark[a-z_-]*)[a-z_-]*-([0-9a-f]{7,}|[0-9.]+)' | sort -u | head -15 || true)
    if [[ -z "$deps" ]]; then
        echo "  (no dependency markers found)"
    else
        echo "$deps" | sed 's/^/  /'
    fi

    echo ""
    echo "── Cargo paths owned by build environment ──"
    echo "  (the discriminator: /root/ = Docker, /home/<user>/ = that user's local build)"
    cargo_homes=$(echo "$strings_out" | grep -oE '/(home/[^/]+|root)/\.cargo/(registry|git)/' | grep -oE '/(home/[^/]+|root)/' | sort -u || true)
    if [[ -z "$cargo_homes" ]]; then
        echo "  (no .cargo paths found — binary may be stripped)"
    else
        echo "$cargo_homes" | sed 's/^/  /'
    fi

    echo ""
    echo "── Build environment guess ──"
    has_root=$(echo "$cargo_homes" | grep -c '^/root/$' || true)
    non_docker_users=$(echo "$cargo_homes" | grep -E '^/home/' | grep -vE '^/home/(ubuntu|runner)/$' || true)

    if [[ "$has_root" -gt 0 && -z "$non_docker_users" ]]; then
        echo "  ✓ Likely Docker build (cargo paths under /root/, no foreign user homes)"
    elif [[ -n "$non_docker_users" ]]; then
        echo "  ✗ Likely LOCAL non-Docker build by:"
        echo "$non_docker_users" | sed 's/^/      /'
        echo "    If this ELF is committed to the repo, it is NOT reproducible."
        echo "    Rebuild with docker enabled in script/build.rs."
    else
        echo "  ? Unable to determine — no recognizable cargo paths"
    fi

    echo ""
done
