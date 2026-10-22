//! Magi prover: proves SP1-Helios light-client updates (Groth16, the proof the
//! zk-header-verifier contract checks) for submission to Magi by
//! `magi_submitter`. Built on the upstream operator's input collection, so
//! post-Gloas updates carry the execution header witness.

use crate::execution::ExecutionRpc;
use crate::get_updates;
use crate::operator::{collect_update_inputs, network_mode_for, ProverSettings};
use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::SolType;
use anyhow::{Context, Result};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::FinalityUpdate;
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::http_rpc::HttpRpc;
use helios_ethereum::rpc::ConsensusRpc;
use sha2::{Digest, Sha256};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, NetworkProver, ProveRequest, Prover, ProverClient,
    ProvingKey, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Z-PR-M4 (MED #41): bound the ELF-pin GraphQL call.
///
/// `reqwest::Client::new()` builds a client with NO overall request timeout
/// and NO connect timeout, so a hung Magi GraphQL endpoint can pin the
/// startup ELF-pin check forever. Because a read failure here is FATAL
/// (the prover refuses to start unpinned), an unbounded hang would deadlock
/// startup rather than fail loud. Both a connect timeout and an overall
/// request timeout are required: connect-only does not bound a peer that
/// completes the handshake then trickles bytes.
const ELF_PIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ELF_PIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// The committed ELF the prover proves against (same file the operator runbook
// hashes with `sha256sum elf/light_client` for setExpectedElfHash).
const LIGHT_CLIENT_ELF: &[u8] = include_bytes!("../../elf/light_client");

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
/// Reads `keys` from a contract's state over Magi GraphQL (`getStateByKeys`).
/// A key Magi does not hold maps to `None` or `Some("")`.
pub async fn fetch_contract_state(
    graphql_urls: &[String],
    contract_id: &str,
    keys: &[&str],
) -> Result<HashMap<String, Option<String>>> {
    let graphql_url = graphql_urls
        .first()
        .ok_or_else(|| anyhow::anyhow!("no GraphQL URL configured"))?;

    let client = reqwest::Client::builder()
        .connect_timeout(ELF_PIN_CONNECT_TIMEOUT)
        .timeout(ELF_PIN_REQUEST_TIMEOUT)
        .build()
        .context("failed to build HTTP client for getStateByKeys")?;
    let body = serde_json::json!({
        "query": "query($contractId: String!, $keys: [String!]!) { getStateByKeys(contractId: $contractId, keys: $keys) }",
        "variables": {
            "contractId": contract_id,
            "keys": keys,
        }
    });

    let resp: StateResponse = client
        .post(graphql_url)
        .json(&body)
        .send()
        .await
        .context("getStateByKeys request failed")?
        .json()
        .await
        .context("getStateByKeys response was not valid JSON")?;

    if let Some(errors) = resp.errors {
        if let Some(first) = errors.first() {
            anyhow::bail!("getStateByKeys GraphQL error: {}", first.message);
        }
    }

    Ok(resp.data.and_then(|d| d.state).unwrap_or_default())
}

async fn fetch_expected_elf_hash(cfg: &ElfPinConfig) -> Result<Option<String>> {
    let state = fetch_contract_state(&cfg.graphql_urls, &cfg.contract_id, &[KEY_EXPECTED_ELF_HASH])
        .await
        .context("HIGH #22: reading the ELF-hash pin")?;
    let raw = state.get(KEY_EXPECTED_ELF_HASH).cloned().flatten();

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
    // Hash the SAME bytes the prover proves against: `LIGHT_CLIENT_ELF` is the
    // committed `elf/light_client`, which is exactly what the operator runbook
    // hashes via `sha256sum elf/light_client` (scripts/inspect-elf.sh) to feed
    // `setExpectedElfHash`.
    let elf_bytes: &[u8] = LIGHT_CLIENT_ELF;
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
    client: Arc<NetworkProver>,
    lightclient_pk: Arc<SP1ProvingKey>,
    source_execution_rpc: ExecutionRpc,
    fulfillment_strategy: FulfillmentStrategy,
    // W4 Cluster B CRIT #6 Site 5 + CRIT #23: the expected L1 chainId, pinned
    // at construction; every finality fetch re-checks the consensus client
    // still reports it (CRIT #23 runtime probe).
    chain_id: u64,
}

impl MagiZkProver {
    /// Construct the prover.
    ///
    /// `elf_pin` carries the GraphQL endpoints + verifier contract id needed to
    /// enforce the HIGH #22 ELF-hash pin; when `Some`, the check runs before any
    /// proving-key setup and fatal-exits on mismatch (or on failure to read the
    /// pin). `None` is for offline tooling (the `benchmark` bin) only.
    /// `execution_rpc` is the source chain's execution RPC (same chain as the
    /// consensus RPC): post-Gloas updates need the finalized execution header.
    pub async fn new(
        chain_id: u64,
        elf_pin: Option<ElfPinConfig>,
        execution_rpc: &str,
        settings: ProverSettings,
    ) -> Result<Self> {
        if let Some(cfg) = elf_pin.as_ref() {
            verify_elf_hash(cfg).await;
        } else {
            warn!(
                "HIGH #22: ELF-hash pin check SKIPPED (no ElfPinConfig provided). \
                 This path is for offline tooling only and must NOT be used by a \
                 prover that submits proofs on-chain."
            );
        }
        let source_execution_rpc = ExecutionRpc::new(execution_rpc)?;
        source_execution_rpc
            .check_chain_id(chain_id)
            .await
            .context("source execution RPC is on a different chain")?;
        let client = ProverClient::builder()
            .network_for(network_mode_for(settings.fulfillment_strategy))
            .signer(settings.network_signer)
            .build()
            .await;
        info!("Setting up light client proving key...");
        let lightclient_pk = client
            .setup(LIGHT_CLIENT_ELF.into())
            .await
            .context("Failed to setup light client")?;
        Ok(Self {
            client: Arc::new(client),
            lightclient_pk: Arc::new(lightclient_pk),
            source_execution_rpc,
            fulfillment_strategy: settings.fulfillment_strategy,
            chain_id,
        })
    }

    /// Prove the light-client update from `head` (the verifier's last proven
    /// beacon slot) to the latest finalized checkpoint. `None` when there is
    /// nothing new to prove.
    pub async fn prove_header_update(
        &self,
        client: &Inner<MainnetConsensusSpec, HttpRpc>,
        head: u64,
    ) -> Result<Option<SP1ProofWithPublicValues>> {
        let updates = get_updates(client).await?;
        // CRIT #23: the client must be configured for this prover's chain id.
        // magi_operator builds both from --source-chain-id, so there this only
        // guards a client built for another chain. A consensus RPC serving
        // another chain is caught in-circuit (the committee signatures are
        // checked under the configured genesis root and fork domain, so the free
        // local execute fails before any proof is paid for) and by the
        // verifier's genesis-root and committee anchoring.
        if client.config.chain.chain_id != self.chain_id {
            anyhow::bail!(
                "CRIT #23: consensus client chain_id ({}) does not match prover's expected chain_id ({}); refusing to fetch finality update against wrong chain",
                client.config.chain.chain_id,
                self.chain_id,
            );
        }
        // CC-2 (MED round-4): an RPC failure is returned, not a panic.
        let finality_update: FinalityUpdate<MainnetConsensusSpec> = client
            .rpc
            .get_finality_update()
            .await
            .map_err(|e| anyhow::anyhow!("get_finality_update failed: {e}"))?;

        let latest_block = finality_update.finalized_header().beacon().slot;
        if latest_block <= head {
            info!("Already up to date at slot {head}. Nothing to prove.");
            return Ok(None);
        } else if !latest_block.is_multiple_of(32) {
            info!("Non-checkpoint slot {latest_block}. Skipping.");
            return Ok(None);
        }
        // The verifier only takes a proof that starts at its beacon head (RV-4).
        // A consensus RPC that bootstrapped from another checkpoint would make
        // every paid proof a reject, so check before paying.
        let store_slot = client.store.finalized_header.beacon().slot;
        if store_slot != head {
            anyhow::bail!(
                "bootstrapped store is at slot {store_slot}, not the verifier's beacon head {head}; not proving"
            );
        }
        info!("Proving update from slot {head} to {latest_block}");

        let mut inputs = ProofInputs {
            updates,
            finality_update,
            expected_current_slot: client.expected_current_slot(),
            store: client.store.clone(),
            genesis_root: client.config.chain.genesis_root,
            forks: client.config.forks.clone(),
            contract_storage: vec![],
            execution_header: None,
        };
        // Fills the execution header witness (required from Gloas on, checked
        // in-circuit against the committed block hash). No storage slots.
        let no_storage: Mutex<HashMap<Address, HashSet<B256>>> = Mutex::new(HashMap::new());
        collect_update_inputs(&mut inputs, &self.source_execution_rpc, &no_storage).await?;

        let encoded = serde_cbor::to_vec(&inputs).context("Failed to encode proof inputs")?;
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&encoded);
        let mut prove_stdin = SP1Stdin::new();
        prove_stdin.write_slice(&encoded);

        let (public_values, _) = self
            .client
            .execute(LIGHT_CLIENT_ELF.into(), stdin)
            .await
            .context("Execution failed")?;
        // The executed outputs are what the proof will commit: check them
        // against what the verifier requires before paying for the proof.
        check_outputs(public_values.as_slice(), head, latest_block, client.config.chain.genesis_root)?;
        let mut proof = self
            .client
            .prove(&self.lightclient_pk, prove_stdin)
            .mode(SP1ProofMode::Groth16)
            .strategy(self.fulfillment_strategy)
            .await
            .context("Groth16 proving failed")?;
        proof.public_values = public_values;
        // Verify locally before publishing: catches any divergence between the
        // executed public values and what the prover bound into the SNARK.
        self.client
            .verify(&proof, self.lightclient_pk.verifying_key(), None)
            .context("Local proof verification failed after public values splice")?;

        info!("Proof generated for slot {latest_block}");
        Ok(Some(proof))
    }

    pub fn lightclient_vkey(&self) -> String {
        self.lightclient_pk.verifying_key().bytes32()
    }
}

/// The executed public values must continue the verifier: start at its beacon
/// head, end at the finalized slot being proven, under its genesis root. A
/// proof that does not is refused on chain, so it must not be paid for.
pub fn check_outputs(public_values: &[u8], head: u64, latest_block: u64, genesis_root: B256) -> Result<()> {
    let outputs =
        ProofOutputs::abi_decode(public_values).context("executed public values are not ProofOutputs")?;
    if outputs.prevHead != U256::from(head)
        || outputs.newHead != U256::from(latest_block)
        || outputs.genesisRoot != genesis_root
    {
        anyhow::bail!(
            "executed outputs do not continue the verifier (prevHead {}, newHead {}, genesisRoot {}; want {head}, {latest_block}, {genesis_root}); not proving",
            outputs.prevHead,
            outputs.newHead,
            outputs.genesisRoot,
        );
    }
    Ok(())
}

/// Prover Network settings from the environment, as the upstream operator reads
/// them (`.env.example`): `NETWORK_PRIVATE_KEY` (an AWS KMS key ARN when
/// `USE_KMS_REQUESTER=true`) and `SP1_HELIOS_FULFILLMENT_STRATEGY` (auction,
/// hosted, reserved). The proof mode is always Groth16, the only proof the Magi
/// zk-header-verifier checks; `SP1_HELIOS_PROOF_MODE` set to anything else is
/// refused rather than ignored.
pub async fn prover_settings_from_env() -> Result<ProverSettings> {
    use crate::operator::{parse_fulfillment_strategy, parse_proof_mode};
    use sp1_sdk::network::signer::NetworkSigner;
    let env_or = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    if parse_proof_mode(&env_or("SP1_HELIOS_PROOF_MODE", "groth16"))? != SP1ProofMode::Groth16 {
        anyhow::bail!("SP1_HELIOS_PROOF_MODE must be groth16: the Magi verifier checks Groth16 proofs only");
    }
    let fulfillment_strategy = parse_fulfillment_strategy(&env_or("SP1_HELIOS_FULFILLMENT_STRATEGY", "auction"))?;
    let key = std::env::var("NETWORK_PRIVATE_KEY").context("NETWORK_PRIVATE_KEY is not set")?;
    let use_kms = env_or("USE_KMS_REQUESTER", "false")
        .parse::<bool>()
        .context("USE_KMS_REQUESTER must be true or false")?;
    let network_signer = if use_kms {
        NetworkSigner::aws_kms(&key).await.context("failed to create AWS KMS Prover Network signer")?
    } else {
        NetworkSigner::local(&key).context("failed to create local Prover Network signer")?
    };
    Ok(ProverSettings { network_signer, fulfillment_strategy, proof_mode: SP1ProofMode::Groth16 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolValue;

    fn pv(prev: u64, new: u64, genesis: B256) -> Vec<u8> {
        ProofOutputs {
            prevHeader: B256::ZERO,
            prevHead: U256::from(prev),
            prevSyncCommitteeHash: B256::ZERO,
            newHead: U256::from(new),
            newHeader: B256::ZERO,
            executionStateRoot: B256::ZERO,
            executionBlockHash: B256::ZERO,
            executionBlockNumber: U256::ZERO,
            syncCommitteeHash: B256::ZERO,
            nextSyncCommitteeHash: B256::repeat_byte(0xff),
            genesisRoot: genesis,
            storageSlots: vec![],
        }
        .abi_encode()
    }

    #[test]
    fn pays_only_for_outputs_that_continue_the_verifier() {
        let g = B256::repeat_byte(0xd8);
        assert!(check_outputs(&pv(8192, 8224, g), 8192, 8224, g).is_ok());
        assert!(check_outputs(&pv(8160, 8224, g), 8192, 8224, g).is_err()); // starts elsewhere
        assert!(check_outputs(&pv(8192, 8256, g), 8192, 8224, g).is_err()); // ends elsewhere
        assert!(check_outputs(&pv(8192, 8224, B256::ZERO), 8192, 8224, g).is_err()); // other chain
        assert!(check_outputs(&[0u8; 31], 8192, 8224, g).is_err()); // not ProofOutputs
    }
}
