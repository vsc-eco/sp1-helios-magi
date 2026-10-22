//! Execute a recorded post-Gloas Sepolia update and check what the Magi light client commits.

use alloy::sol_types::SolType;
use alloy_primitives::{b256, B256, U256};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const LIGHT_CLIENT_ELF: &[u8] = include_bytes!("../../elf/light_client");
/// Recorded 2026-10-22 with gen_fixture (see fixtures/sepolia_sources.json).
const FIXTURE: &[u8] = include_bytes!("fixtures/sepolia_gloas.cbor");
/// Sepolia's GLOAS_FORK_EPOCH (eth-clients/sepolia config) x 32.
const SEPOLIA_GLOAS_SLOT: u64 = 353024 * 32;
/// Sepolia's genesis_validators_root.
const SEPOLIA_GENESIS_ROOT: B256 =
    b256!("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");

#[tokio::test]
async fn sepolia_gloas_update_commits_the_magi_outputs() {
    let inputs: ProofInputs = serde_cbor::from_slice(FIXTURE).unwrap();
    let start = inputs.store.finalized_header.beacon().slot;
    let target = inputs.finality_update.finalized_header().beacon().slot;
    assert!(start >= SEPOLIA_GLOAS_SLOT, "the fixture must start after Sepolia's Gloas fork");
    assert_eq!(inputs.genesis_root, SEPOLIA_GENESIS_ROOT, "not a Sepolia fixture");
    let header = inputs
        .execution_header
        .as_ref()
        .expect("a Gloas update carries the execution header witness");

    let client = ProverClient::builder().cpu().build().await;
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(FIXTURE);
    let (values, report) = client
        .execute(Elf::Static(LIGHT_CLIENT_ELF), stdin)
        .await
        .unwrap();
    assert_eq!(report.exit_code, 0);
    let out = ProofOutputs::abi_decode(values.as_slice()).unwrap();

    assert_eq!(out.prevHead, U256::from(start));
    assert_eq!(out.newHead, U256::from(target));
    assert_eq!(out.executionBlockHash, header.hash_slow());
    assert_eq!(out.executionStateRoot, header.state_root);
    assert_eq!(out.executionBlockNumber, U256::from(header.number));
    assert_eq!(out.genesisRoot, SEPOLIA_GENESIS_ROOT);
    assert_ne!(out.nextSyncCommitteeHash, B256::ZERO);
}
