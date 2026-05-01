use anyhow::Result;
use clap::Parser;
use magi_zk_oracle_script::{operator::MagiZkProver, get_client};
use std::time::Instant;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "https://ethereum-sepolia-beacon-api.publicnode.com")]
    consensus_rpc: String,
    #[arg(long, default_value = "11155111")]
    chain_id: u64,
}
#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let prover = MagiZkProver::new().await;
    let current_slot = {
        let c = get_client(None, &args.consensus_rpc, args.chain_id).await?;
        c.store.finalized_header.beacon().slot
    };
    let bootstrap_slot = current_slot.saturating_sub(64);
    eprintln!("current: {} bootstrap: {}", current_slot, bootstrap_slot);
    let client = get_client(Some(bootstrap_slot), &args.consensus_rpc, args.chain_id).await?;
    let t = Instant::now();
    let proof = prover.prove_header_update(&client, 0).await?;
    if let Some(p) = proof {
        eprintln!("TIME: {:.1}s PROOF: {}B PV: {}B", t.elapsed().as_secs_f64(), p.bytes().len(), p.public_values.as_slice().len());
        std::fs::write("/tmp/proof.bin", p.bytes())?;
        std::fs::write("/tmp/public_values.bin", p.public_values.as_slice())?;
    } else { eprintln!("No proof generated"); }
    Ok(())
}
