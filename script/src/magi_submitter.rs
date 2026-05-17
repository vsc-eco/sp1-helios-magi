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

#[derive(Serialize)]
pub struct SubmittedHeader {
    pub rlp_hex: String,
    pub block_number: u64,
    pub transactions_root: String,
    pub receipts_root: String,
    pub base_fee_per_gas: u64,
    pub gas_limit: u64,
    pub timestamp: u64,
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
    let client = reqwest::Client::new();
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

    Ok(resp
        .data
        .and_then(|d| d.nonce_result)
        .map(|n| n.nonce)
        .unwrap_or(0))
}

/// Submit a signed transaction to Magi GraphQL.
pub async fn submit_transaction(graphql_url: &str, tx_b64: &str, sig_b64: &str) -> Result<String> {
    let client = reqwest::Client::new();
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

    // For now: delegate to Go sidecar for CBOR+EIP712 signing
    let tx_result = call_go_sidecar(config, "submitProof", &payload_json).await?;

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

    // review2 #122: pass the signing key via env, not argv. Process
    // arguments are world-readable (/proc/<pid>/cmdline, `ps`), so a
    // positional CLI key leaks the secp256k1 key to any local process.
    let output = tokio::process::Command::new("zk-tx-signer")
        .args([
            &config.contract_id,
            action,
            payload_json,
            &config.net_id,
            &config.rc_limit.to_string(),
            &nonce.to_string(),
        ])
        .env("ZK_TX_SIGNER_PRIVKEY", &config.private_key_hex)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("zk-tx-signer failed: {}", stderr));
    }

    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    Ok(SignedTx {
        tx_b64: result["tx_b64"].as_str().unwrap_or("").to_string(),
        sig_b64: result["sig_b64"].as_str().unwrap_or("").to_string(),
    })
}
