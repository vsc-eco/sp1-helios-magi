//! RV-5: runs the Magi operator loop (see `sp1_helios_script::magi_operator`).
//!
//! Prover Network settings come from the environment as for the upstream
//! operator (`.env.example`; the proof mode is always Groth16). The Magi
//! signing key is read from `MAGI_OPERATOR_PRIVATE_KEY` (secp256k1 hex), never
//! argv, and handed to the `zk-tx-signer` sidecar the same way; the sidecar
//! must be on PATH. Its did:pkh identity needs HBD for RC: a proof with 5
//! headers costs ~13k RC and each backfilled header ~2.6k.

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;
use sp1_helios_script::execution::ExecutionRpc;
use sp1_helios_script::magi_operator::{MagiOperator, Step};
use sp1_helios_script::magi_prover::{prover_settings_from_env, ElfPinConfig, MagiZkProver};
use sp1_helios_script::magi_submitter::MagiSubmitterConfig;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug, Clone)]
#[command(about = "Prove Ethereum finality into Magi's zk-header-verifier and backfill its headers.")]
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
    /// Magi GraphQL endpoint(s), comma separated.
    #[arg(long, value_delimiter = ',')]
    magi_graphql: Vec<String>,
    /// The zk-header-verifier contract id on Magi.
    #[arg(long)]
    verifier_contract: String,
    /// Magi network id (vsc-mainnet, vsc-testnet, vsc-devnet).
    #[arg(long)]
    net_id: String,
    /// RC limit per call.
    #[arg(long, default_value_t = 50_000)]
    rc_limit: u64,
    /// Minutes to wait when there is nothing new to prove.
    #[arg(long, default_value_t = 1)]
    loop_delay_mins: u64,
    /// Minutes a submitted call may take to show in the verifier state.
    #[arg(long, default_value_t = 3)]
    land_timeout_mins: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .try_init()
        .expect("Failed to initialize tracing");
    let args = Args::parse();

    let key = std::env::var("MAGI_OPERATOR_PRIVATE_KEY").context("MAGI_OPERATOR_PRIVATE_KEY is not set")?;
    let key = key.trim().trim_start_matches("0x").to_string();
    let signer: PrivateKeySigner = key.parse().context("MAGI_OPERATOR_PRIVATE_KEY is not a secp256k1 key")?;
    let did = format!("did:pkh:eip155:1:{}", signer.address().to_checksum(None));
    info!("Magi operator identity {did}");

    let submitter = MagiSubmitterConfig {
        graphql_urls: args.magi_graphql.clone(),
        contract_id: args.verifier_contract.clone(),
        net_id: args.net_id.clone(),
        private_key_hex: key,
        did,
        rc_limit: args.rc_limit,
    };
    let elf_pin = ElfPinConfig {
        graphql_urls: args.magi_graphql.clone(),
        contract_id: args.verifier_contract.clone(),
    };
    let prover = MagiZkProver::new(
        args.source_chain_id,
        Some(elf_pin),
        &args.source_execution_rpc,
        prover_settings_from_env().await?,
    )
    .await?;
    let operator = MagiOperator {
        prover,
        execution_rpc: ExecutionRpc::new(&args.source_execution_rpc)?,
        consensus_rpc: args.source_consensus_rpc.clone(),
        chain_id: args.source_chain_id,
        submitter,
        land_timeout: Duration::from_secs(args.land_timeout_mins * 60),
    };

    let idle = Duration::from_secs(args.loop_delay_mins * 60);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Stopping");
                return Ok(());
            }
            step = operator.run_once() => match step {
                // Backfill right after a proof: no new proof lands while a gap is open.
                Ok(Step::Proved) | Ok(Step::Backfilled) => continue,
                Ok(Step::Idle) => tokio::time::sleep(idle).await,
                Err(e) => {
                    error!("operator step failed: {e:#}");
                    tokio::time::sleep(idle).await;
                }
            },
        }
    }
}
