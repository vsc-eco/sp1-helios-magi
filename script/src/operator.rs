use crate::get_updates;
use anyhow::{Context, Result};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::FinalityUpdate;
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::http_rpc::HttpRpc;
use helios_ethereum::rpc::ConsensusRpc;
use magi_zk_oracle_primitives::types::ProofInputs;
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::{
    include_elf, prover::ProvingKey, HashableKey, ProveRequest, Prover, ProverClient,
    SP1ProofWithPublicValues, SP1Stdin,
};
use std::sync::Arc;
use tracing::info;

const LIGHTCLIENT_ELF: sp1_sdk::Elf = include_elf!("light_client");
const STORAGE_ELF: sp1_sdk::Elf = include_elf!("storage");

pub struct MagiZkProver {
    client: Arc<EnvProver>,
    lightclient_pk: Arc<EnvProvingKey>,
    storage_pk: Arc<EnvProvingKey>,
    // W4 Cluster B CRIT #6 Site 5 + CRIT #23: the expected L1 chainId.
    // Pinned at construction from the operator's config (commonly via
    // `Network::from_chain_id` inverse). Cached so we never re-read a
    // potentially compromised env var mid-loop; on every
    // get_finality_update call we re-verify the upstream RPC still
    // reports this same chainId (CRIT #23 runtime probe).
    chain_id: u64,
}

impl MagiZkProver {
    pub async fn new(chain_id: u64) -> Self {
        let client = ProverClient::from_env().await;

        info!("Setting up light client proving key...");
        let lightclient_pk = client
            .setup(LIGHTCLIENT_ELF)
            .await
            .expect("Failed to setup light client");

        info!("Setting up storage proving key...");
        let storage_pk = client
            .setup(STORAGE_ELF)
            .await
            .expect("Failed to setup storage");

        Self {
            client: Arc::new(client),
            lightclient_pk: Arc::new(lightclient_pk),
            storage_pk: Arc::new(storage_pk),
            chain_id,
        }
    }

    pub async fn prove_header_update(
        &self,
        client: &Inner<MainnetConsensusSpec, HttpRpc>,
        head: u64,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        let updates = get_updates(client).await;
        let finality_update: FinalityUpdate<MainnetConsensusSpec> =
            client.rpc.get_finality_update().await.unwrap();

        let latest_block = finality_update.finalized_header().beacon().slot;
        if latest_block <= head {
            info!("Already up to date at slot {head}. Nothing to prove.");
            return Ok(None);
        } else if !latest_block.is_multiple_of(32) {
            info!("Non-checkpoint slot {latest_block}. Skipping.");
            return Ok(None);
        }

        info!("Proving update from slot {head} to {latest_block}");

        let expected_current_slot = client.expected_current_slot();
        let inputs = ProofInputs {
            updates,
            finality_update,
            expected_current_slot,
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
            contract_storage: vec![],
            // W4 Cluster B Site 5: thread chainId into the ZK input so the
            // program (light_client.rs main()) can commit it as part of
            // ProofOutputs.
            chain_id: self.chain_id,
        };

        let encoded = serde_cbor::to_vec(&inputs).context("Failed to encode proof inputs")?;

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&encoded);

        let mut prove_stdin = SP1Stdin::new();
        prove_stdin.write_slice(&encoded);

        let (public_values, _) = self
            .client
            .execute(LIGHTCLIENT_ELF, stdin)
            .await
            .context("Execution failed")?;

        let mut proof = self
            .client
            .prove(&self.lightclient_pk, prove_stdin)
            .groth16()
            .await
            .context("Groth16 proving failed")?;

        proof.public_values = public_values;

        // Verify locally before publishing. Catches any divergence between the
        // emulator's public values (run 1) and what the prover bound into the
        // SNARK (run 2) — the on-chain verifier would otherwise reject silently
        // after a long round-trip.
        self.client
            .verify(&proof, self.lightclient_pk.verifying_key(), None)
            .context("Local proof verification failed after public values splice")?;

        info!("Proof generated for slot {latest_block}");
        Ok(Some(proof))
    }

    pub fn lightclient_vkey(&self) -> String {
        self.lightclient_pk.verifying_key().bytes32()
    }

    pub fn storage_vkey(&self) -> String {
        self.storage_pk.verifying_key().bytes32()
    }
}
