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
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};

const LIGHTCLIENT_ELF: sp1_sdk::Elf = include_elf!("light_client");
const STORAGE_ELF: sp1_sdk::Elf = include_elf!("storage");

// W4 Cluster B HIGH #22 — ELF hash pinning, prover-side consumer.
//
// The zk-header-verifier contract stores the SHA-256 of the SP1 ELF binary
// the prover is authorized to use under state key `KeyExpectedElfHash`
// (string literal "elfhash", see zk-header-verifier/contract/main.go). The
// `setExpectedElfHash` admin handler writes the 64-char lowercase-or-mixed
// hex form (0x prefix stripped) via `sdk.StateSetObject("elfhash", h)`,
// which stores the RAW UTF-8 bytes of that hex string.
//
// This consumer reads that key at prover startup, recomputes the SHA-256 of
// the LOCAL `light_client` ELF the prover actually proves against, and
// fatal-exits on mismatch. Without it the on-chain handler is hollow: a
// malicious operator could swap the ELF and rotate the vkey to match,
// defeating binary authenticity. This is the missing half of HIGH #22.
pub const KEY_EXPECTED_ELF_HASH: &str = "elfhash";

/// Configuration required to read the on-chain expected-ELF-hash for the
/// HIGH #22 startup pin. Populated from the operator's Magi config (same
/// GraphQL endpoints + verifier contract id used by the submitter).
#[derive(Clone)]
pub struct ElfPinConfig {
    /// Magi GraphQL endpoint(s), e.g. "https://api.vsc.eco/api/v1/graphql".
    pub graphql_urls: Vec<String>,
    /// zk-header-verifier contract id on Magi.
    pub contract_id: String,
}

/// GraphQL response wrapper for `getStateByKeys`. We request WITHOUT the
/// `hex` encoding so the contract value is returned as the plain UTF-8
/// string the contract stored (the 64-char hex), avoiding any double-hex
/// ambiguity. Unset keys come back as JSON `null`.
#[derive(serde::Deserialize)]
struct StateResponse {
    data: Option<StateData>,
    errors: Option<Vec<GqlError>>,
}

#[derive(serde::Deserialize)]
struct StateData {
    #[serde(rename = "getStateByKeys")]
    state: Option<std::collections::HashMap<String, Option<String>>>,
}

#[derive(serde::Deserialize)]
struct GqlError {
    message: String,
}

/// Read the on-chain expected ELF hash from the zk-header-verifier contract
/// state via `getStateByKeys`. Returns:
///   - `Ok(Some(hash))` when the key is set (normalized: lowercase, no 0x),
///   - `Ok(None)` when the key is unset (grace window before first
///     `setExpectedElfHash`),
///   - `Err(_)` on transport/GraphQL failure (treated as fatal by the
///     caller — we must not start unpinned because a node is unreachable).
async fn fetch_expected_elf_hash(cfg: &ElfPinConfig) -> Result<Option<String>> {
    let graphql_url = cfg
        .graphql_urls
        .first()
        .ok_or_else(|| anyhow::anyhow!("HIGH #22: no GraphQL URL configured for ELF-hash pin"))?;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "query": "query($contractId: String!, $keys: [String!]!) { getStateByKeys(contractId: $contractId, keys: $keys) }",
        "variables": {
            "contractId": cfg.contract_id,
            "keys": [KEY_EXPECTED_ELF_HASH],
        }
    });

    let resp: StateResponse = client
        .post(graphql_url)
        .json(&body)
        .send()
        .await
        .context("HIGH #22: getStateByKeys request failed")?
        .json()
        .await
        .context("HIGH #22: getStateByKeys response was not valid JSON")?;

    if let Some(errors) = resp.errors {
        if let Some(first) = errors.first() {
            anyhow::bail!("HIGH #22: getStateByKeys GraphQL error: {}", first.message);
        }
    }

    let raw = resp
        .data
        .and_then(|d| d.state)
        .and_then(|m| m.get(KEY_EXPECTED_ELF_HASH).cloned())
        .flatten();

    // Normalize: strip optional 0x prefix, lowercase. Empty string == unset.
    let normalized = raw.and_then(|h| {
        let trimmed = h.trim();
        let no_prefix = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let lowered = no_prefix.to_ascii_lowercase();
        if lowered.is_empty() {
            None
        } else {
            Some(lowered)
        }
    });

    Ok(normalized)
}

/// HIGH #22 startup consumer: compute the SHA-256 of the local light_client
/// ELF and compare it against the on-chain pinned hash. Fatal-exits the
/// process on mismatch. Logs a WARNING and allows startup when the on-chain
/// hash is unset (deploy-then-pin grace window). Any failure to READ the
/// on-chain hash is fatal — refusing to start unpinned on a transient node
/// error is the safe default for a fund-affecting bridge.
async fn verify_elf_hash(cfg: &ElfPinConfig) {
    // Hash the SAME bytes the prover proves against. `LIGHTCLIENT_ELF` is the
    // compile-time `include_elf!("light_client")` artifact; `.as_ref()`
    // exposes its raw bytes. sp1-build (build.rs) writes that artifact to
    // `elf/light_client`, which is exactly what the operator runbook hashes
    // via `sha256sum elf/light_client` (scripts/inspect-elf.sh) to feed
    // `setExpectedElfHash`. The two are byte-identical by construction.
    let elf_bytes: &[u8] = LIGHTCLIENT_ELF.as_ref();
    let local_hash = hex::encode(Sha256::digest(elf_bytes));
    info!("HIGH #22: local light_client ELF sha256 = {local_hash}");

    let expected = match fetch_expected_elf_hash(cfg).await {
        Ok(v) => v,
        Err(e) => {
            // Cannot read the pin -> cannot prove we are running the
            // authorized binary. Fatal: do not start a fund-affecting prover
            // in an unverifiable state.
            eprintln!("FATAL HIGH #22: unable to read on-chain expected ELF hash: {e:#}");
            std::process::exit(1);
        }
    };

    match expected {
        None => {
            // Grace window: operator has not yet run setExpectedElfHash. This
            // is the documented deploy-then-pin sequence (W0 P5 ramp-up). Allow
            // startup but make the unpinned state loud and auditable.
            warn!(
                "HIGH #22: on-chain expected ELF hash is UNSET (key '{}' on contract {}). \
                 Prover starting UNPINNED — this is only safe during the deploy-then-pin \
                 grace window. Operator MUST call setExpectedElfHash with {} to close it.",
                KEY_EXPECTED_ELF_HASH, cfg.contract_id, local_hash
            );
        }
        Some(on_chain) if on_chain == local_hash => {
            info!("HIGH #22: local ELF hash matches on-chain pin — binary authenticity OK");
        }
        Some(on_chain) => {
            eprintln!(
                "FATAL HIGH #22: ELF hash mismatch. on-chain expected={on_chain} \
                 local light_client={local_hash}. The running prover binary does NOT \
                 match the hash pinned on contract {}. Refusing to produce proofs — \
                 a swapped ELF + rotated vkey would otherwise forge authoritative L1 state.",
                cfg.contract_id
            );
            std::process::exit(1);
        }
    }
}

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
    /// Construct the prover.
    ///
    /// `elf_pin` carries the GraphQL endpoints + verifier contract id needed
    /// to enforce the HIGH #22 ELF-hash pin. When `Some`, the startup check
    /// runs BEFORE any proving key setup and fatal-exits on mismatch (or on
    /// inability to read the on-chain pin). `None` is reserved for offline
    /// tooling (e.g. the `benchmark` bin) that never submits proofs on-chain;
    /// the real operator MUST pass `Some(..)`.
    pub async fn new(chain_id: u64, elf_pin: Option<ElfPinConfig>) -> Self {
        // W4 Cluster B HIGH #22: enforce ELF-hash pin at startup, before the
        // prover does any work. This is the consumer half of the on-chain
        // setExpectedElfHash handler — without it that handler is hollow.
        if let Some(cfg) = elf_pin.as_ref() {
            verify_elf_hash(cfg).await;
        } else {
            warn!(
                "HIGH #22: ELF-hash pin check SKIPPED (no ElfPinConfig provided). \
                 This path is for offline tooling only and must NOT be used by a \
                 prover that submits proofs on-chain."
            );
        }

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
        // W4 Cluster B CRIT #23: on every finality-update fetch, re-verify
        // the upstream consensus RPC is still serving the same chainId we
        // bootstrapped against. Mid-flight RPC pivots (e.g. operator swap
        // of `CONSENSUS_RPC` to a sepolia node) would otherwise produce
        // valid finality updates against the WRONG chain and the prover
        // would happily commit them with the configured chain_id —
        // silently siloed because the consensus RPC has no chainId, but
        // its `chain.chain_id` config field is read at client setup and
        // baked into `client.config.chain.chain_id`. Compare here.
        if client.config.chain.chain_id != self.chain_id {
            anyhow::bail!(
                "CRIT #23: consensus client chain_id ({}) does not match prover's expected chain_id ({}) — refusing to fetch finality update against wrong chain",
                client.config.chain.chain_id,
                self.chain_id,
            );
        }
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
