//! Magi L2 transaction submission for the ZK prover operator.
//!
//! Submits SP1-Helios proofs to the ZK header verifier contract on Magi.
//! Follows the same CBOR + EIP-712 signing protocol as the evm-mapping-bot
//! and the Altera passkey signer.
//!
//! This module is a SKELETON for the Magi submission path.
//! The actual CBOR encoding and EIP-712 signing requires porting the
//! go-vsc-node `transactionpool.TransactionCrafter` logic to Rust.
//!
//! For initial testing, proof submission can be done via a Go sidecar
//! (a small Go binary that wraps callContractL2) called from Rust via exec.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Z-PR-M4 (MED #41): bound every GraphQL HTTP call made by this module.
///
/// `reqwest::Client::new()` builds a client with NO overall request timeout
/// and NO connect timeout. A slow or hung Magi GraphQL endpoint would
/// otherwise pin the calling tokio task forever (a slow-loris upstream
/// stalls the whole proof-submission pipeline). Both a connect timeout and
/// an overall request timeout are required: connect-only does not bound a
/// peer that completes the TCP handshake then trickles bytes.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a reqwest client with bounded connect + overall request timeouts.
/// Used for all Magi GraphQL calls in this module so no single hung endpoint
/// can stall the submitter indefinitely.
fn magi_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))
}

/// Configuration for the Magi submitter.
#[derive(Clone)]
pub struct MagiSubmitterConfig {
    /// Magi GraphQL endpoint(s), e.g. "https://api.vsc.eco/api/v1/graphql"
    pub graphql_urls: Vec<String>,
    /// Verifier contract ID on Magi
    pub contract_id: String,
    /// Network ID, e.g. "vsc-mainnet" or "vsc-testnet"
    pub net_id: String,
    /// secp256k1 private key hex for signing (same format as BOT_ETH_PRIVKEY)
    pub private_key_hex: String,
    /// DID derived from the private key
    pub did: String,
    /// RC limit per transaction
    pub rc_limit: u64,
}

/// Payload for the verifier contract's submitProof action.
#[derive(Serialize)]
pub struct SubmitProofPayload {
    pub proof: String,
    pub public_values: String,
    pub headers: Vec<SubmittedHeader>,
}

/// One header as the verifier reads it: the RLP alone (bare hex). Every
/// stored field is parsed from it and bound by its keccak, so nothing else is
/// sent; each extra byte costs header room under the 8192-byte payload cap.
#[derive(Serialize)]
pub struct SubmittedHeader {
    pub rlp_hex: String,
}

/// GraphQL response from submitTransactionV1.
#[derive(Deserialize)]
struct SubmitTxResponse {
    data: Option<SubmitTxData>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Deserialize)]
struct SubmitTxData {
    #[serde(rename = "submitTransactionV1")]
    submit: Option<TxId>,
}

#[derive(Deserialize)]
struct TxId {
    id: Option<String>,
}

#[derive(Deserialize)]
struct GraphQLError {
    message: String,
}

/// Nonce response from getAccountNonce.
#[derive(Deserialize)]
struct NonceResponse {
    data: Option<NonceData>,
}

#[derive(Deserialize)]
struct NonceData {
    #[serde(rename = "getAccountNonce")]
    nonce_result: Option<NonceResult>,
}

#[derive(Deserialize)]
struct NonceResult {
    nonce: u64,
}

/// Fetch the account nonce from Magi GraphQL.
pub async fn fetch_nonce(graphql_url: &str, did: &str) -> Result<u64> {
    let client = magi_http_client()?;
    let body = serde_json::json!({
        "query": "query($account: String!) { getAccountNonce(account: $account) { nonce } }",
        "variables": { "account": did }
    });

    let resp: NonceResponse = client
        .post(graphql_url)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    // review6 closure (Z-PR-H2): fail loud when the GraphQL response does
    // not contain a usable nonce. Pre-fix `.unwrap_or(0)` defaulted to
    // nonce=0 on any parse/missing-field failure, causing the submitter
    // to sign a tx the chain immediately rejects (or worse, collide with
    // init). An explicit error gives the operator the right signal.
    resp.data
        .and_then(|d| d.nonce_result)
        .map(|n| n.nonce)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "fetch_nonce: GraphQL response missing getAccountNonce.nonce — refusing to default to 0"
            )
        })
}

/// Submit a signed transaction to Magi GraphQL.
pub async fn submit_transaction(graphql_url: &str, tx_b64: &str, sig_b64: &str) -> Result<String> {
    let client = magi_http_client()?;
    let body = serde_json::json!({
        "query": "query($tx: String!, $sig: String!) { submitTransactionV1(tx: $tx, sig: $sig) { id } }",
        "variables": { "tx": tx_b64, "sig": sig_b64 }
    });

    let resp: SubmitTxResponse = client
        .post(graphql_url)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    if let Some(errors) = resp.errors {
        if let Some(first) = errors.first() {
            return Err(anyhow::anyhow!("GraphQL error: {}", first.message));
        }
    }

    resp.data
        .and_then(|d| d.submit)
        .and_then(|s| s.id)
        .ok_or_else(|| anyhow::anyhow!("submitTransactionV1 returned no ID"))
}

/// Build and submit a proof to the Magi verifier contract.
///
/// Z-PR-M5 (MED #42): this path is NOT a pure-Rust submitter. The CBOR +
/// EIP-712 signing is delegated to the external `zk-tx-signer` Go binary
/// (go-vsc-node/cmd/zk-tx-signer), invoked by `call_go_sidecar`. That binary
/// MUST be present on PATH and the operator key is handed to it via the
/// `ZK_TX_SIGNER_PRIVKEY` env var (NOT argv — review6 H4 / sidecar review2
/// #122). Do NOT hand-roll a replacement signer: a bespoke shim that passes
/// the key on the command line would re-open the Z-PR-H1 argv key-leak. The
/// in-process Rust port of the signing path (steps 1-4 below) is the eventual
/// goal; until it lands, this entry point depends on that external sidecar.
///
/// NOTE: This is a PLACEHOLDER. The full implementation requires:
/// 1. CBOR encoding of VscContractCall (matching Go's SerializeVSC)
/// 2. EIP-712 typed data hashing of the transaction container
/// 3. secp256k1 signing of the typed data hash
/// 4. DAG-JOSE encoding of the signature container
///
/// For initial deployment, use the Go sidecar approach:
/// compile a small Go binary from go-vsc-node that accepts
/// (contractId, action, payloadJSON, privateKeyHex) and outputs
/// (txB64, sigB64). Call it from Rust via std::process::Command.
///
/// The Go sidecar reuses the existing TransactionCrafter code directly,
/// avoiding any serialization format mismatches.
pub async fn submit_proof(
    config: &MagiSubmitterConfig,
    proof_hex: &str,
    public_values_hex: &str,
    headers: Vec<SubmittedHeader>,
) -> Result<String> {
    let payload = SubmitProofPayload {
        proof: proof_hex.to_string(),
        public_values: public_values_hex.to_string(),
        headers,
    };
    let payload_json = serde_json::to_string(&payload)?;
    submit_call(config, "submitProof", &payload_json).await
}

/// Signs `action(payload_json)` on the verifier contract with the
/// zk-tx-signer sidecar and submits it; returns the L2 tx id.
pub async fn submit_call(config: &MagiSubmitterConfig, action: &str, payload_json: &str) -> Result<String> {
    // Delegate to the Go sidecar for CBOR+EIP712 signing.
    let tx_result = call_go_sidecar(config, action, payload_json).await?;

    let graphql_url = config
        .graphql_urls
        .first()
        .ok_or_else(|| anyhow::anyhow!("No GraphQL URL configured"))?;

    submit_transaction(graphql_url, &tx_result.tx_b64, &tx_result.sig_b64).await
}

struct SignedTx {
    tx_b64: String,
    sig_b64: String,
}

/// Call the Go sidecar binary for transaction signing.
///
/// The sidecar binary is built from go-vsc-node/cmd/zk-tx-signer/
/// and wraps TransactionCrafter.SignFinal.
///
/// Args: contractId action payloadJSON netId rcLimit nonce privateKeyHex
/// Output: JSON {"tx_b64":"...","sig_b64":"..."}
async fn call_go_sidecar(
    config: &MagiSubmitterConfig,
    action: &str,
    payload_json: &str,
) -> Result<SignedTx> {
    let graphql_url = config
        .graphql_urls
        .first()
        .ok_or_else(|| anyhow::anyhow!("No GraphQL URL configured"))?;

    let nonce = fetch_nonce(graphql_url, &config.did).await?;

    // review6 H4: pass the private key via env var instead of CLI argv.
    // argv is world-readable via /proc/<pid>/cmdline and `ps aux`, exposing
    // the operator key to any user/process on the box for the lifetime of
    // the subprocess. Env vars are visible only to the parent's UID via
    // /proc/<pid>/environ (mode 0400). zk-tx-signer already supports the
    // ZK_TX_SIGNER_PRIVKEY env-var path via the review2 #122 fix; this
    // closes the caller side that still pinned the legacy argv form.
    let output = tokio::process::Command::new("zk-tx-signer")
        .env("ZK_TX_SIGNER_PRIVKEY", &config.private_key_hex)
        .args([
            &config.contract_id,
            action,
            payload_json,
            &config.net_id,
            &config.rc_limit.to_string(),
            &nonce.to_string(),
            // private key intentionally NOT on argv — read from
            // ZK_TX_SIGNER_PRIVKEY in the signer.
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("zk-tx-signer failed: {}", stderr));
    }

    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    // Z-PR-M5 (MED #42): fail loud when the sidecar response is missing or
    // empty. The pre-fix `.unwrap_or("")` silently substituted an empty
    // string for an absent/empty `tx_b64`/`sig_b64`, which would then be
    // submitted to `submitTransactionV1` as a malformed transaction — a
    // skeleton-path footgun that wastes a proof and produces a confusing
    // chain-side rejection instead of a clear operator-facing error. Demand
    // both fields be present and non-empty.
    let tx_b64 = result["tx_b64"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("zk-tx-signer returned no/empty tx_b64 — refusing to submit an empty transaction")
        })?
        .to_string();
    let sig_b64 = result["sig_b64"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("zk-tx-signer returned no/empty sig_b64 — refusing to submit an unsigned transaction")
        })?
        .to_string();

    Ok(SignedTx { tx_b64, sig_b64 })
}
