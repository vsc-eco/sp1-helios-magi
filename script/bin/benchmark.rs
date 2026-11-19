use anyhow::Result;
use clap::Parser;
use sp1_helios_script::get_client;
use tree_hash::TreeHash;
use sp1_helios_script::magi_prover::{prover_settings_from_env, MagiZkProver};
use std::time::Instant;
#[derive(Parser)]
struct Args {
    #[arg(
        long,
        default_value = "https://ethereum-sepolia-beacon-api.publicnode.com"
    )]
    consensus_rpc: String,
    /// Execution RPC of the same chain (the post-Gloas execution header witness).
    #[arg(long)]
    execution_rpc: String,
    #[arg(long, default_value = "11155111")]
    chain_id: u64,
}
#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    // Offline benchmark: never submits on-chain, so the HIGH #22 ELF pin
    // check is intentionally skipped (None). A live prover MUST pass Some(..).
    let prover = MagiZkProver::new(args.chain_id, None, &args.execution_rpc, prover_settings_from_env().await?).await?;
    let current_slot = {
        let c = get_client(None, &args.consensus_rpc, args.chain_id).await?;
        c.store.finalized_header.beacon().slot
    };
    let bootstrap_slot = current_slot.saturating_sub(64);
    eprintln!("current: {} bootstrap: {}", current_slot, bootstrap_slot);
    let client = get_client(Some(bootstrap_slot), &args.consensus_rpc, args.chain_id).await?;
    let t = Instant::now();
    // Prove from the bootstrap itself: its slot is the head and its current
    // committee the trusted one (there is no verifier to read them from).
    let head = client.store.finalized_header.clone().beacon().slot;
    let committee = client.store.current_sync_committee.clone().tree_hash_root();
    let paid = std::sync::atomic::AtomicU64::new(0);
    let proof = prover.prove_header_update(&client, head, committee, &paid).await?;
    if let Some(p) = proof {
        eprintln!(
            "TIME: {:.1}s PROOF: {}B PV: {}B",
            t.elapsed().as_secs_f64(),
            p.bytes().len(),
            p.public_values.as_slice().len()
        );
        std::fs::write("/tmp/proof.bin", p.bytes())?;
        std::fs::write("/tmp/public_values.bin", p.public_values.as_slice())?;
    } else {
        eprintln!("No proof generated");
    }
    Ok(())
}
