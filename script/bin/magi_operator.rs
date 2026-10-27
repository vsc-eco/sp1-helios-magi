//! RV-5: runs the Magi operator loop (see `sp1_helios_script::magi_operator`).
//!
//! Prover Network settings come from the environment as for the upstream
//! operator (`.env.example`; the proof mode is always Groth16). The Magi
//! signing key is read from `MAGI_OPERATOR_PRIVATE_KEY` (secp256k1 hex), never
//! argv, and handed to the `zk-tx-signer` sidecar the same way; the sidecar
//! must be on PATH. Its did:pkh identity needs HBD for RC: a proof with its one
//! header costs a few k RC; nothing is backfilled (RP-9).
//!
//! Prover Network limits (RP-2) come from SP1_MAX_PRICE_PER_PGU (PROVE wei per
//! PGU, default 0.3 PROVE per billion), SP1_PROOF_TIMEOUT_SECS (1800) and
//! SP1_AUCTION_TIMEOUT_SECS (120); the pending request id is kept in
//! MAGI_PROOF_REQUEST_FILE (RP-10, default magi-proof-request.json).

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;
use sp1_helios_script::execution::ExecutionRpc;
use sp1_helios_script::magi_operator::{backoff, MagiOperator, Step};
use sp1_helios_script::magi_prover::{network_limits_from_env, prover_settings_from_env, ElfPinConfig, MagiZkProver};
use sp1_helios_script::magi_submitter::MagiSubmitterConfig;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug, Clone)]
#[command(about = "Prove Ethereum finality into Magi's zk-header-verifier, on demand.")]
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
    /// Stop after this many proofs have been paid for on the Prover Network
    /// (landed or not). Unset: no limit.
    #[arg(long)]
    max_proofs: Option<u64>,
    /// RP-9: the bot's NEEDS_FILE. Set: prove only while the bot wants a proof.
    /// Unset: prove every new checkpoint.
    #[arg(long)]
    needs_file: Option<std::path::PathBuf>,
    /// Minutes a wanted proof waits, so one proof covers what arrives meanwhile.
    #[arg(long, default_value_t = 10)]
    batch_window_mins: u64,
    /// Minutes without a needs-file update after which the bot is taken as down.
    #[arg(long, default_value_t = 15)]
    needs_stale_mins: u64,
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
    let mut prover = MagiZkProver::new(
        args.source_chain_id,
        Some(elf_pin),
        &args.source_execution_rpc,
        prover_settings_from_env().await?,
    )
    .await?;
    prover.limits = network_limits_from_env()?;
    if prover.limits.request_file.is_none() {
        prover.limits.request_file = Some("magi-proof-request.json".into());
    }
    info!(
        "Prover Network limits: max {} PROVE wei/PGU, deadline {:?}, auction {:?}, request file {:?}",
        prover.limits.max_price_per_pgu, prover.limits.proof_timeout, prover.limits.auction_timeout, prover.limits.request_file
    );
    let operator = MagiOperator {
        prover,
        execution_rpc: ExecutionRpc::new(&args.source_execution_rpc)?,
        consensus_rpc: args.source_consensus_rpc.clone(),
        chain_id: args.source_chain_id,
        submitter,
        land_timeout: Duration::from_secs(args.land_timeout_mins * 60),
        proofs_paid: std::sync::atomic::AtomicU64::new(0),
        needs_file: args.needs_file.clone(),
        batch_window: Duration::from_secs(args.batch_window_mins * 60),
        needs_stale_after: Duration::from_secs(args.needs_stale_mins * 60),
    };
    match &args.needs_file {
        Some(p) => info!("on demand: proving only while {} wants a proof (batch window {} min)", p.display(), args.batch_window_mins),
        None => info!("no --needs-file: proving every new checkpoint"),
    }

    let idle = Duration::from_secs(args.loop_delay_mins * 60);
    let mut failures = 0u32;
    let mut landed = 0u64;
    if let Some(max) = args.max_proofs {
        info!("proof budget: {max} paid proof(s), then stop");
    }
    loop {
        let paid = operator.proofs_paid.load(std::sync::atomic::Ordering::SeqCst);
        let may_prove = args.max_proofs.map_or(true, |max| paid < max);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Stopping");
                return Ok(());
            }
            step = operator.run_once(may_prove) => match step {
                Ok(Step::Proved) => {
                    failures = 0;
                    landed += 1;
                    info!("{landed} proof(s) landed");
                }
                Ok(Step::BudgetSpent) => {
                    info!("proof budget spent ({paid} paid, {landed} landed); stopping");
                    return Ok(());
                }
                Ok(Step::Idle) => {
                    failures = 0;
                    tokio::time::sleep(idle).await;
                }
                Err(e) => {
                    failures += 1;
                    let wait = backoff(idle, failures);
                    error!("operator step failed ({failures} in a row), next try in {wait:?}: {e:#}");
                    tokio::time::sleep(wait).await;
                }
            },
        }
    }
}
