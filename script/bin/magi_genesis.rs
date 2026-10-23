//! Prints the Magi zk-header-verifier `init` payload for a fresh deploy, and
//! the ELF hash for its first `setExpectedElfHash`.
//!
//! Everything comes from one beacon light-client bootstrap at a finalized
//! checkpoint (the latest, or `--slot`): `initial_head` is its slot,
//! `initial_sync_committee_hash` the hash of its current sync committee (the
//! committee the first proof must start from, RV-4), `genesis_root` the
//! chain's genesis validators root, and the anchor (`initial_height`,
//! `initial_block_hash`) the execution block that checkpoint finalizes, checked
//! against the beacon header before it is printed. `sp1_vkey_hash` is the
//! committed light-client ELF's vkey; `groth16_vk` and `vk_root` are SP1
//! 6.8.1's own (sp1-verifier), never taken from a proof.
//!
//! The consensus RPC must serve `light_client/bootstrap` for that checkpoint.
//! Nothing is sent anywhere: the owner reviews the output and calls `init`.

use anyhow::{ensure, Context, Result};
use clap::Parser;
use helios_consensus_core::types::LightClientHeader;
use sha2::{Digest, Sha256};
use sp1_helios_primitives::execution::verified_execution_fields;
use sp1_helios_script::execution::ExecutionRpc;
use sp1_helios_script::get_client;
use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};
use tree_hash::TreeHash;

const LIGHT_CLIENT_ELF: &[u8] = include_bytes!("../../elf/light_client");

#[derive(Parser, Debug)]
#[command(about = "Print the zk-header-verifier init payload from a finalized beacon checkpoint.")]
struct Args {
    /// The chain ID of the source chain (1 mainnet, 11155111 Sepolia).
    #[arg(long)]
    source_chain_id: u64,
    /// The source chain's consensus (beacon) RPC, with light-client endpoints.
    #[arg(long)]
    source_consensus_rpc: String,
    /// The source chain's execution RPC.
    #[arg(long)]
    source_execution_rpc: String,
    /// The checkpoint slot to bootstrap at (a multiple of 32); default: the
    /// latest finalized checkpoint.
    #[arg(long)]
    slot: Option<u64>,
    /// Header retention in L1 blocks (0: the verifier's default, 7 days).
    #[arg(long, default_value_t = 0)]
    max_retention: u64,
    /// Mark the verifier a testnet instance (enables clearTestnetState).
    #[arg(long)]
    is_testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let client = get_client(args.slot, &args.source_consensus_rpc, args.source_chain_id)
        .await
        .context("bootstrap the light client")?;
    let head = client.store.finalized_header.clone().beacon().slot;
    ensure!(head > 0 && head % 32 == 0, "bootstrap slot {head} is not a checkpoint slot");
    if let Some(slot) = args.slot {
        ensure!(head == slot, "bootstrapped at slot {head}, not the requested {slot}");
    }
    let sync_committee_hash = client.store.current_sync_committee.clone().tree_hash_root();
    let genesis_root = client.config.chain.genesis_root;

    let execution_rpc = ExecutionRpc::new(&args.source_execution_rpc)?;
    execution_rpc
        .check_chain_id(args.source_chain_id)
        .await
        .context("the execution RPC is on another chain")?;
    let execution_header = match &client.store.finalized_header {
        LightClientHeader::Gloas(header) => Some(
            execution_rpc
                .header_by_hash(header.execution_block_hash)
                .await
                .context("fetch the finalized execution header")?,
        ),
        _ => None,
    };
    let execution = verified_execution_fields(&client.store.finalized_header, execution_header.as_ref())
        .context("the execution header does not match the beacon header")?;

    let prover = ProverClient::builder().cpu().build().await;
    let vkey = prover
        .setup(LIGHT_CLIENT_ELF.into())
        .await
        .context("set up the light client program")?
        .verifying_key()
        .bytes32();

    let init = serde_json::json!({
        "groth16_vk": hex::encode(*sp1_verifier::GROTH16_VK_BYTES),
        "vk_root": hex::encode(*sp1_verifier::VK_ROOT_BYTES),
        "sp1_vkey_hash": vkey,
        "max_retention": args.max_retention,
        "initial_height": execution.block_number,
        "initial_block_hash": format!("0x{:x}", execution.block_hash),
        "expected_chain_id": args.source_chain_id,
        "genesis_root": format!("0x{genesis_root:x}"),
        "initial_sync_committee_hash": format!("0x{sync_committee_hash:x}"),
        "initial_head": head,
        "is_testnet": args.is_testnet,
    });
    eprintln!("bootstrap slot {head}, period {}, execution block {} {:#x}", head / 8192, execution.block_number, execution.block_hash);
    eprintln!("setExpectedElfHash (first pin): {}", hex::encode(Sha256::digest(LIGHT_CLIENT_ELF)));
    println!("{}", serde_json::to_string_pretty(&init)?);
    Ok(())
}
