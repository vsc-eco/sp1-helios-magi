use alloy_primitives::B256;
use helios_consensus_core::{
    calc_sync_period,
    consensus_spec::MainnetConsensusSpec,
    types::{BeaconBlock, Update},
};
use helios_ethereum::rpc::ConsensusRpc;
use helios_ethereum::{
    config::{checkpoints, networks::Network, Config},
    consensus::Inner,
    rpc::http_rpc::HttpRpc,
};

use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::{mpsc::channel, watch};
use tree_hash::TreeHash;

pub mod magi_submitter;
pub mod operator;

pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u8 = 128;

/// Fetch updates for client.
///
/// review6 closure (Z-PR-H3): propagate the RPC error via Result instead
/// of `.unwrap()`-panicking. The prior panic killed the entire submitter
/// process on any transient consensus-RPC hiccup. Callers can now retry
/// at their own cadence.
pub async fn get_updates(
    client: &Inner<MainnetConsensusSpec, HttpRpc>,
) -> Result<Vec<Update<MainnetConsensusSpec>>> {
    let period =
        calc_sync_period::<MainnetConsensusSpec>(client.store.finalized_header.beacon().slot);

    let updates = client
        .rpc
        .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .map_err(|e| anyhow!("get_updates RPC failed: {}", e.to_string()))?;

    Ok(updates.clone())
}

/// Fetch latest checkpoint from chain to bootstrap client to the latest state.
pub async fn get_latest_checkpoint(chain_id: u64) -> Result<B256> {
    let cf = checkpoints::CheckpointFallback::new()
        .build()
        .await
        .map_err(|e| anyhow!("error building checkpoint fallback: {}", e.to_string()))?;

    // review6 closure (Z-PR-L4): convert the panic on unknown chain_id
    // into a typed error so a misconfigured submitter doesn't crash —
    // instead it returns a clear "unknown network" error the operator
    // can map to a config fix.
    let network = Network::from_chain_id(chain_id)
        .map_err(|_| anyhow!("get_latest_checkpoint: unknown network chain_id={}", chain_id))?;

    cf.fetch_latest_checkpoint(&network)
        .await
        .map_err(|e| anyhow!("error fetching latest checkpoint: {}", e.to_string()))
}

/// Setup a client from a checkpoint slot.
///
/// This method will also bootstrap the client to the given slot, or the latest checkpoint if no slot is provided.
pub async fn get_client(
    slot: Option<u64>,
    consensus_rpc: &str,
    chain_id: u64,
) -> Result<Inner<MainnetConsensusSpec, HttpRpc>> {
    // review6 closure (Z-PR-H3): convert `.unwrap()` panic into a typed
    // error. Same rationale as get_latest_checkpoint above.
    let network = Network::from_chain_id(chain_id)
        .map_err(|_| anyhow!("get_client: unknown network chain_id={}", chain_id))?;
    let base_config = network.to_base_config();

    let config = Config {
        consensus_rpc: consensus_rpc.parse()?,
        execution_rpc: None,
        chain: base_config.chain,
        forks: base_config.forks,
        strict_checkpoint_age: false,
        ..Default::default()
    };

    let (block_send, _) = channel(256);
    let (finalized_block_send, _) = watch::channel(None);
    let (channel_send, _) = watch::channel(None);

    let mut client = Inner::<MainnetConsensusSpec, HttpRpc>::new(
        consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    );

    let root = match slot {
        Some(slot) => {
            let block: BeaconBlock<MainnetConsensusSpec> = client
                .rpc
                .get_block(slot)
                .await
                .map_err(|e| anyhow!("error getting block: {}", e.to_string()))?;

            block.tree_hash_root()
        }
        None => get_latest_checkpoint(chain_id).await?,
    };

    client
        .bootstrap(root)
        .await
        .map_err(|e| anyhow!("error bootstrapping client: {}", e.to_string()))?;

    Ok(client)
}
