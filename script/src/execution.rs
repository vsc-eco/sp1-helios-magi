//! Fetch source execution data for the exact header finalized by the SP1 input sequence.

use std::time::Duration;

use alloy::rpc::client::RpcClient;
use alloy::rpc::types::EIP1186AccountProofResponse;
use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use anyhow::{ensure, Context, Result};
use helios_consensus_core::{
    apply_finality_update, apply_update, types::LightClientHeader, verify_finality_update,
    verify_update,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sp1_helios_primitives::{
    execution::{verified_execution_fields, ExecutionFields},
    types::{ContractStorage, ProofInputs, StorageSlotWithProof},
    verify_storage_slot_proofs,
};

/// HTTP/2 health checks on the execution RPC's pooled connection (I-35,
/// testnet 11-05 ~01:22-01:38: an established HTTP/2 connection to the RPC went
/// silent, no RST or FIN, while new connections worked; without pings every
/// request was multiplexed onto it and waited out its timeout until TCP gave up,
/// ~16 minutes). A connection with nothing received for HTTP2_PING_EVERY is
/// pinged and closed if the ping is not answered within HTTP2_PING_WAIT.
const HTTP2_PING_EVERY: Duration = Duration::from_secs(15);
const HTTP2_PING_WAIT: Duration = Duration::from_secs(10);

fn http2_health(b: reqwest::ClientBuilder, every: Duration, wait: Duration) -> reqwest::ClientBuilder {
    b.http2_keep_alive_interval(every)
        .http2_keep_alive_timeout(wait)
        .http2_keep_alive_while_idle(true)
}

/// Read-only execution RPC for the source chain.
pub struct ExecutionRpc {
    client: RpcClient,
}

impl ExecutionRpc {
    /// Construct a source RPC client with bounded requests.
    pub fn new(url: &str) -> Result<Self> {
        let url = url.parse().context("Invalid source execution RPC URL")?;
        let client = http2_health(
            reqwest::Client::builder()
                .user_agent("sp1-helios")
                .timeout(Duration::from_secs(30)),
            HTTP2_PING_EVERY,
            HTTP2_PING_WAIT,
        )
        .build()?;
        Ok(Self {
            client: RpcClient::new_http_with_client(client, url),
        })
    }

    async fn request<T>(&self, method: &str, params: Value) -> Result<T>
    where
        T: DeserializeOwned + std::fmt::Debug + Send + Sync + Unpin + 'static,
    {
        self.client
            .request::<_, Option<T>>(method.to_owned(), params)
            .await
            .with_context(|| format!("Source execution RPC {method} failed"))?
            .with_context(|| format!("Source execution RPC {method} returned no data"))
    }

    /// Reject a source endpoint configured for another chain.
    pub async fn check_chain_id(&self, expected: u64) -> Result<()> {
        let value: String = self.request("eth_chainId", json!([])).await?;
        let actual = u64::from_str_radix(value.trim_start_matches("0x"), 16)?;
        ensure!(
            actual == expected,
            "Source chain ID mismatch: expected {expected}, got {actual}"
        );
        Ok(())
    }

    /// Fetch a full header and authenticate its canonical RLP hash.
    pub async fn header_by_hash(&self, hash: B256) -> Result<Header> {
        let header: Header = self
            .request("eth_getBlockByHash", json!([hash, false]))
            .await?;
        ensure!(
            header.hash_slow() == hash,
            "Source execution header does not match requested hash {hash}"
        );
        Ok(header)
    }

    /// Fetch a header for a standalone storage-proof request.
    pub async fn header_by_number(&self, number: u64) -> Result<Header> {
        let header: Header = self
            .request(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        ensure!(
            header.number == number,
            "Execution block number mismatch: expected {number}, got {}",
            header.number
        );
        Ok(header)
    }

    /// Fetch account/storage proofs and verify them against the selected source state root.
    pub async fn storage_proof(
        &self,
        state_root: B256,
        block_number: u64,
        address: Address,
        keys: Vec<B256>,
    ) -> Result<ContractStorage> {
        let proof: EIP1186AccountProofResponse = self
            .request(
                "eth_getProof",
                json!([address, keys, format!("0x{block_number:x}")]),
            )
            .await?;
        ensure!(proof.address == address, "Storage proof address mismatch");
        ensure!(
            proof.storage_proof.len() == keys.len(),
            "Storage proof omitted requested slots"
        );
        for key in &keys {
            ensure!(
                proof.storage_proof.iter().any(|p| p.key.as_b256() == *key),
                "Storage proof omitted requested slot {key}"
            );
        }
        let contract_storage = ContractStorage {
            address: proof.address,
            value: alloy_trie::TrieAccount {
                nonce: proof.nonce,
                balance: proof.balance,
                storage_root: proof.storage_hash,
                code_hash: proof.code_hash,
            },
            mpt_proof: proof.account_proof,
            storage_slots: proof
                .storage_proof
                .into_iter()
                .map(|p| StorageSlotWithProof {
                    key: p.key.as_b256(),
                    value: p.value,
                    mpt_proof: p.proof,
                })
                .collect(),
        };
        verify_storage_slot_proofs(state_root, &contract_storage)
            .with_context(|| format!("Invalid source storage proof for {address}"))?;
        Ok(contract_storage)
    }
}

/// Preview the guest's update sequence without modifying its anchored starting store.
pub fn preview_finalized_header(inputs: &ProofInputs) -> Result<LightClientHeader> {
    let mut store = inputs.store.clone();
    store.next_sync_committee = None;
    for update in &inputs.updates {
        verify_update(
            update,
            inputs.expected_current_slot,
            &store,
            inputs.genesis_root,
            &inputs.forks,
        )
        .map_err(|e| anyhow::anyhow!("Invalid update: {e}"))?;
        apply_update(&mut store, update);
    }
    verify_finality_update(
        &inputs.finality_update,
        inputs.expected_current_slot,
        &store,
        inputs.genesis_root,
        &inputs.forks,
    )
    .map_err(|e| anyhow::anyhow!("Invalid finality update: {e}"))?;
    apply_finality_update(&mut store, &inputs.finality_update);
    let slot = store.finalized_header.beacon().slot;
    ensure!(
        slot > inputs.store.finalized_header.beacon().slot,
        "Updates do not advance finalized head"
    );
    ensure!(
        slot.is_multiple_of(32),
        "Finalized head is not a checkpoint slot"
    );
    Ok(store.finalized_header)
}

/// Attach a Gloas witness for the actual finalized store, then return authenticated fields.
pub async fn fill_execution_header(
    inputs: &mut ProofInputs,
    rpc: &ExecutionRpc,
) -> Result<(u64, ExecutionFields)> {
    let finalized = preview_finalized_header(inputs)?;
    inputs.execution_header = match &finalized {
        LightClientHeader::Gloas(header) => {
            Some(rpc.header_by_hash(header.execution_block_hash).await?)
        }
        _ => None,
    };
    Ok((
        finalized.beacon().slot,
        verified_execution_fields(&finalized, inputs.execution_header.as_ref())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    /// I-35: a relay in front of an HTTP/2 server freezes the live connection
    /// (bytes in are dropped, none come out, it is never closed), as a NAT
    /// that forgot it does; new connections pass. With the health checks the
    /// client drops the silent connection and the next call is served on a new
    /// one within a few ping periods.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn i35_a_silent_http2_connection_is_replaced() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // h2c server answering every request with a JSON-RPC result.
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = srv.accept().await.unwrap();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                            bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#),
                        )))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        // The relay; freeze() silences every connection open now.
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let frozen: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::new(Mutex::new(vec![]));
        let fz = frozen.clone();
        tokio::spawn(async move {
            loop {
                let (c, _) = relay.accept().await.unwrap();
                let u = TcpStream::connect(srv_addr).await.unwrap();
                let flag = Arc::new(AtomicBool::new(false));
                fz.lock().unwrap().push(flag.clone());
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = u.into_split();
                let f1 = flag.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 << 10];
                    while let Ok(n) = cr.read(&mut buf).await {
                        if n == 0 { break; }
                        if !f1.load(Ordering::SeqCst) && uw.write_all(&buf[..n]).await.is_err() { break; }
                    }
                });
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 << 10];
                    while let Ok(n) = ur.read(&mut buf).await {
                        if n == 0 { break; }
                        if !flag.load(Ordering::SeqCst) && cw.write_all(&buf[..n]).await.is_err() { break; }
                    }
                });
            }
        });

        let client = http2_health(
            reqwest::Client::builder().timeout(Duration::from_secs(1)).http2_prior_knowledge(),
            Duration::from_millis(300),
            Duration::from_millis(300),
        )
        .build()
        .unwrap();
        let url = format!("http://{relay_addr}/");
        let post = || async {
            let r = client.post(&url).body("{}").send().await?;
            assert_eq!(r.version(), reqwest::Version::HTTP_2, "the test needs HTTP/2");
            r.bytes().await.map(|_| ())
        };
        post().await.expect("first call");
        for f in frozen.lock().unwrap().iter() {
            f.store(true, Ordering::SeqCst);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let mut fails = 0;
        loop {
            if post().await.is_ok() {
                break;
            }
            fails += 1;
            assert!(
                std::time::Instant::now() < deadline,
                "calls still fail 6 s after the connection went silent ({fails} failures): the dead HTTP/2 connection is kept"
            );
        }
    }

    #[test]
    fn preview_preserves_the_anchored_store_and_drops_untrusted_committee() {
        let mut inputs: ProofInputs =
            serde_cbor::from_slice(include_bytes!("../tests/fixtures/proof_inputs.cbor")).unwrap();
        let original_slot = inputs.store.finalized_header.beacon().slot;
        let original_root = inputs.store.finalized_header.beacon().tree_hash_root();
        let finalized = preview_finalized_header(&inputs).unwrap();
        assert!(finalized.beacon().slot > original_slot);
        assert_eq!(
            inputs.store.finalized_header.beacon().tree_hash_root(),
            original_root
        );
        assert_eq!(inputs.store.finalized_header.beacon().slot, original_slot);

        inputs.store.next_sync_committee = Some(inputs.store.current_sync_committee.clone());
        let poisoned_preview = preview_finalized_header(&inputs).unwrap();
        assert_eq!(poisoned_preview, finalized);
        assert!(inputs.store.next_sync_committee.is_some());
        verified_execution_fields(&finalized, None).unwrap();
    }
}
