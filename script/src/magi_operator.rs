//! RV-5: the Magi operator loop.
//!
//! Each step does one thing and waits for it to land on Magi:
//! - a header gap is open (E5): backfill the newest blocks below it with
//!   `submitHeaders`;
//! - otherwise: prove the latest finalized checkpoint from the verifier's
//!   beacon head and `submitProof` it with as many of the newest headers as fit.
//!
//! A call's payload is capped at go-vsc-node's `MAX_CONTRACT_PAYLOAD_SIZE`
//! (8192 bytes), which with Prague headers (~620 bytes of RLP, hex-encoded)
//! is about 5 headers next to a proof and 6 in a backfill, under the
//! verifier's own 12. Checkpoints are ~32 blocks apart, so every proof opens a
//! gap the following steps close. Every header is checked locally against the
//! hash the verifier wants before it is sent, so a wrong-chain RPC fails here
//! rather than burning RC on a call the contract refuses.
//!
//! Run one operator per verifier: two would submit the same step, and the
//! second call fails on chain (harmless, but it costs RC).

use crate::execution::ExecutionRpc;
use crate::get_client;
use crate::magi_prover::MagiZkProver;
use crate::magi_submitter::{submit_call, MagiSubmitterConfig, SubmittedHeader};
use alloy::sol_types::SolType;
use alloy_consensus::Header;
use alloy_primitives::B256;
use anyhow::{bail, ensure, Context, Result};
use sp1_helios_primitives::types::ProofOutputs;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::info;

/// go-vsc-node `params.MAX_CONTRACT_PAYLOAD_SIZE`: a contract call's payload.
pub const MAX_CONTRACT_PAYLOAD: usize = 8192;
/// zk-header-verifier `MaxHeadersPerTx`.
pub const MAX_HEADERS_PER_CALL: usize = 12;

/// The verifier state the loop steers by (zk-header-verifier state keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierState {
    /// "bh": the last proven beacon slot.
    pub beacon_head: u64,
    /// "h": the last proven execution block.
    pub last_height: u64,
    /// "lbh": hash of the newest stored header.
    pub last_hash: B256,
    pub gap: Option<Gap>,
    /// "sp1vk": the light-client program vkey the verifier accepts proofs for.
    pub program_vkey: Option<String>,
}

/// An open header gap (E5): "gapw", "gapl", "gapb", "gapa".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// Hash the next backfilled header must have (the parent of `low`).
    pub want: B256,
    /// Lowest stored header above the gap.
    pub low: u64,
    /// The stored chain's tip below the gap.
    pub base: u64,
    /// Hash of `base`, which the backfill must link to.
    pub anchor: B256,
}

fn get<'a>(state: &'a HashMap<String, Option<String>>, key: &str) -> Option<&'a str> {
    state.get(key).and_then(|v| v.as_deref()).filter(|v| !v.is_empty())
}

fn num(state: &HashMap<String, Option<String>>, key: &str) -> Result<u64> {
    let v = get(state, key).with_context(|| format!("verifier state {key} is unset"))?;
    v.parse().with_context(|| format!("verifier state {key}={v:?} is not a number"))
}

fn hash(state: &HashMap<String, Option<String>>, key: &str) -> Result<B256> {
    let v = get(state, key).with_context(|| format!("verifier state {key} is unset"))?;
    v.parse().with_context(|| format!("verifier state {key}={v:?} is not a 32-byte hash"))
}

/// The keys `parse_verifier_state` reads.
pub const STATE_KEYS: [&str; 8] = ["bh", "h", "lbh", "gapw", "gapl", "gapb", "gapa", "sp1vk"];

/// Whether the verifier's program vkey is the one this prover proves with. A
/// proof for another vkey is refused on chain, so it must not be paid for.
/// The value is read as the node reads it for sp1_verify_groth16 (an optional
/// lowercase "0x", then 32 bytes of hex), so a value the node cannot use
/// never matches.
pub fn vkey_matches(on_chain: Option<&str>, local: &str) -> bool {
    let bytes = |s: &str| hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok().filter(|b| b.len() == 32);
    match (on_chain.and_then(bytes), bytes(local)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// How long to wait after `failures` failed steps in a row: `idle` doubled per
/// failure, at most 64 x idle and one hour. A step that keeps failing (a
/// misconfigured net id, contract or RC) must not re-prove every minute.
pub fn backoff(idle: Duration, failures: u32) -> Duration {
    let factor = 1u32 << failures.saturating_sub(1).min(6);
    idle.saturating_mul(factor).min(Duration::from_secs(3600))
}

/// Parses the verifier state read with `STATE_KEYS`. A missing key reads as
/// null or "" on Magi; the gap is open iff "gapw" is set.
pub fn parse_verifier_state(state: &HashMap<String, Option<String>>) -> Result<VerifierState> {
    let gap = match get(state, "gapw") {
        None => None,
        Some(_) => Some(Gap {
            want: hash(state, "gapw")?,
            low: num(state, "gapl")?,
            base: num(state, "gapb")?,
            anchor: hash(state, "gapa")?,
        }),
    };
    Ok(VerifierState {
        beacon_head: num(state, "bh")?,
        last_height: num(state, "h")?,
        last_hash: hash(state, "lbh")?,
        gap,
        program_vkey: get(state, "sp1vk").map(str::to_string),
    })
}

fn headers_json(rlps: &[Vec<u8>]) -> Vec<SubmittedHeader> {
    rlps.iter().map(|r| SubmittedHeader { rlp_hex: hex::encode(r) }).collect()
}

/// The submitProof payload (bare hex, as the verifier decodes it).
pub fn proof_payload(proof: &[u8], public_values: &[u8], rlps: &[Vec<u8>]) -> String {
    serde_json::json!({
        "proof": hex::encode(proof),
        "public_values": hex::encode(public_values),
        "headers": headers_json(rlps),
    })
    .to_string()
}

/// The submitHeaders payload.
pub fn headers_payload(rlps: &[Vec<u8>]) -> String {
    serde_json::json!({ "headers": headers_json(rlps) }).to_string()
}

/// The most of the newest headers in `rlps` (oldest first) that one call can
/// carry: at most `MAX_HEADERS_PER_CALL`, and `payload` of them within
/// `MAX_CONTRACT_PAYLOAD` bytes. 0 if not even the newest fits.
pub fn fit_newest(rlps: &[Vec<u8>], payload: impl Fn(&[Vec<u8>]) -> String) -> usize {
    let mut k = rlps.len().min(MAX_HEADERS_PER_CALL);
    while k > 0 && payload(&rlps[rlps.len() - k..]).len() > MAX_CONTRACT_PAYLOAD {
        k -= 1;
    }
    k
}

/// The blocks a backfill fetches: the newest `MAX_HEADERS_PER_CALL` below the
/// gap's lowest stored header, never into the stored chain. The verifier only
/// opens a gap with at least one block missing; any other reading (a node
/// serving bad state) is an error rather than an empty range to unwrap.
pub fn backfill_range(gap: &Gap) -> Result<(u64, u64)> {
    ensure!(
        gap.low > gap.base.saturating_add(1),
        "verifier gap is empty or inverted (low {}, base {})",
        gap.low,
        gap.base
    );
    let top = gap.low - 1;
    Ok(((gap.base + 1).max(top.saturating_sub(MAX_HEADERS_PER_CALL as u64 - 1)), top))
}

/// Headers `lo..=hi` from the execution RPC, oldest first, checked to chain
/// by parent hash.
async fn fetch_chain(rpc: &ExecutionRpc, lo: u64, hi: u64) -> Result<Vec<Header>> {
    let mut out = Vec::with_capacity((hi - lo + 1) as usize);
    for n in lo..=hi {
        out.push(rpc.header_by_number(n).await?);
    }
    for w in out.windows(2) {
        ensure!(
            w[1].parent_hash == w[0].hash_slow(),
            "execution RPC headers {} and {} do not chain",
            w[0].number,
            w[1].number
        );
    }
    Ok(out)
}

/// What one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A proof landed.
    Proved,
    /// A backfill batch landed.
    Backfilled,
    /// Nothing new to prove.
    Idle,
}

pub struct MagiOperator {
    pub prover: MagiZkProver,
    pub execution_rpc: ExecutionRpc,
    pub consensus_rpc: String,
    pub chain_id: u64,
    pub submitter: MagiSubmitterConfig,
    /// How long a submitted call may take to show in the verifier state.
    pub land_timeout: Duration,
}

impl MagiOperator {
    pub async fn state(&self) -> Result<VerifierState> {
        let raw = crate::magi_prover::fetch_contract_state(
            &self.submitter.graphql_urls,
            &self.submitter.contract_id,
            &STATE_KEYS,
        )
        .await?;
        parse_verifier_state(&raw)
    }

    /// Polls the verifier state until `done` holds or `land_timeout` passes.
    async fn wait_for(&self, what: &str, done: impl Fn(&VerifierState) -> bool) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Ok(st) = self.state().await {
                if done(&st) {
                    return Ok(());
                }
            }
            if start.elapsed() > self.land_timeout {
                bail!("{what} did not land within {:?}", self.land_timeout);
            }
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
    }

    /// One step: backfill if a gap is open, else prove and submit.
    pub async fn run_once(&self) -> Result<Step> {
        let st = self.state().await?;
        match st.gap.clone() {
            Some(gap) => self.backfill(&gap).await.map(|_| Step::Backfilled),
            None => self.prove(&st).await,
        }
    }

    async fn backfill(&self, gap: &Gap) -> Result<()> {
        let (lo, top) = backfill_range(gap)?;
        let headers = fetch_chain(&self.execution_rpc, lo, top).await?;
        ensure!(
            headers.last().unwrap().hash_slow() == gap.want,
            "execution RPC block {top} is not the parent of the verifier's lowest stored header (want {})",
            gap.want
        );
        let rlps: Vec<Vec<u8>> = headers.iter().map(alloy_rlp::encode).collect();
        let k = fit_newest(&rlps, headers_payload);
        ensure!(k > 0, "one header does not fit a {MAX_CONTRACT_PAYLOAD}-byte payload");
        let batch = &headers[headers.len() - k..];
        let first = batch[0].number;
        if first == gap.base + 1 {
            ensure!(
                batch[0].parent_hash == gap.anchor,
                "backfill reaches the stored chain at {first} but does not link to it (stored tip {})",
                gap.anchor
            );
        }
        info!("submitHeaders {first}..={top} ({k} headers)");
        let tx = submit_call(&self.submitter, "submitHeaders", &headers_payload(&rlps[rlps.len() - k..])).await?;
        info!("submitHeaders tx {tx}");
        let low = gap.low;
        self.wait_for("submitHeaders", |st| st.gap.as_ref().map_or(true, |g| g.low < low))
            .await
    }

    async fn prove(&self, st: &VerifierState) -> Result<Step> {
        let local = self.prover.lightclient_vkey();
        if !vkey_matches(st.program_vkey.as_deref(), &local) {
            bail!(
                "the verifier's program vkey ({}) is not this prover's ({local}); not proving (rotate the verifier's vkey or run the matching ELF)",
                st.program_vkey.as_deref().unwrap_or("unset")
            );
        }
        let client = get_client(Some(st.beacon_head), &self.consensus_rpc, self.chain_id).await?;
        let Some(proof) = self.prover.prove_header_update(&client, st.beacon_head).await? else {
            return Ok(Step::Idle);
        };
        let pv = proof.public_values.to_vec();
        let po = ProofOutputs::abi_decode(&pv).context("public values are not ProofOutputs")?;
        let tip: u64 = po.executionBlockNumber.try_into().context("execution block number")?;
        let new_head: u64 = po.newHead.try_into().context("beacon head")?;
        ensure!(tip > st.last_height, "proven block {tip} is not above the stored tip {}", st.last_height);

        let lo = (st.last_height + 1).max(tip.saturating_sub(MAX_HEADERS_PER_CALL as u64 - 1));
        let headers = fetch_chain(&self.execution_rpc, lo, tip).await?;
        ensure!(
            headers.last().unwrap().hash_slow() == po.executionBlockHash,
            "execution RPC block {tip} is not the proven block {}",
            po.executionBlockHash
        );
        if lo == st.last_height + 1 {
            ensure!(
                headers[0].parent_hash == st.last_hash,
                "execution RPC block {lo} does not link to the verifier's stored tip {}",
                st.last_hash
            );
        }
        let rlps: Vec<Vec<u8>> = headers.iter().map(alloy_rlp::encode).collect();
        let proof_bytes = proof.bytes();
        let k = fit_newest(&rlps, |h| proof_payload(&proof_bytes, &pv, h));
        ensure!(k > 0, "the proof and one header do not fit a {MAX_CONTRACT_PAYLOAD}-byte payload");
        let first = tip - k as u64 + 1;
        info!("submitProof slot {} -> {new_head}, blocks {first}..={tip} ({k} headers)", st.beacon_head);
        let payload = proof_payload(&proof_bytes, &pv, &rlps[rlps.len() - k..]);
        let tx = submit_call(&self.submitter, "submitProof", &payload).await?;
        info!("submitProof tx {tx}");
        // >=: another operator's proof may land past this one.
        self.wait_for("submitProof", |s| s.beacon_head >= new_head).await?;
        Ok(Step::Proved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(kv: &[(&str, &str)]) -> HashMap<String, Option<String>> {
        let mut m: HashMap<String, Option<String>> = STATE_KEYS.iter().map(|k| (k.to_string(), None)).collect();
        for (k, v) in kv {
            m.insert(k.to_string(), Some(v.to_string()));
        }
        m
    }

    const H1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn reads_the_gap_only_when_open() {
        let base = [("bh", "8224"), ("h", "140"), ("lbh", H1)];
        let st = parse_verifier_state(&state(&base)).unwrap();
        assert_eq!(st.gap, None);
        assert_eq!((st.beacon_head, st.last_height), (8224, 140));
        // A deleted key reads as "" on Magi.
        let st = parse_verifier_state(&state(&[base[0], base[1], base[2], ("gapw", "")])).unwrap();
        assert_eq!(st.gap, None);

        let bare = &H1[2..];
        let open = [base[0], base[1], base[2], ("gapw", bare), ("gapl", "129"), ("gapb", "100"), ("gapa", bare)];
        let gap = parse_verifier_state(&state(&open)).unwrap().gap.unwrap();
        assert_eq!((gap.low, gap.base), (129, 100));
        assert_eq!(gap.want, H1.parse::<B256>().unwrap());
        // An open gap missing a field is an error, not a closed gap.
        assert!(parse_verifier_state(&state(&open[..5])).is_err());
    }

    #[test]
    fn proves_only_for_the_verifiers_vkey() {
        let local = "0x0065cd93b7f8b0a1e99c0c7cf7de78be52c7a3fc7cb605fcc05273b1d029af2c";
        assert!(vkey_matches(Some(local), local));
        // Hex digits in either case and no prefix decode as the node decodes them.
        assert!(vkey_matches(Some("0x0065CD93B7F8B0A1E99C0C7CF7DE78BE52C7A3FC7CB605FCC05273B1D029AF2C"), local));
        assert!(vkey_matches(Some(&local[2..]), local));
        // "0X" is not stripped by the node, so it cannot verify anything.
        assert!(!vkey_matches(Some("0X0065CD93B7F8B0A1E99C0C7CF7DE78BE52C7A3FC7CB605FCC05273B1D029AF2C"), local));
        assert!(!vkey_matches(Some("0x00aa"), local));
        assert!(!vkey_matches(Some(""), local));
        assert!(!vkey_matches(None, local));
        let st = parse_verifier_state(&state(&[("bh", "8224"), ("h", "140"), ("lbh", H1), ("sp1vk", local)])).unwrap();
        assert_eq!(st.program_vkey.as_deref(), Some(local));
    }

    #[test]
    fn backfill_stays_between_the_stored_chain_and_the_gap() {
        let gap = |low, base| Gap { want: B256::ZERO, low, base, anchor: B256::ZERO };
        assert_eq!(backfill_range(&gap(129, 100)).unwrap(), (117, 128));
        assert_eq!(backfill_range(&gap(105, 100)).unwrap(), (101, 104));
        assert_eq!(backfill_range(&gap(102, 100)).unwrap(), (101, 101));
        assert!(backfill_range(&gap(101, 100)).is_err()); // nothing missing
        assert!(backfill_range(&gap(50, 100)).is_err()); // inverted
        assert!(backfill_range(&gap(0, 0)).is_err());
        assert!(backfill_range(&gap(u64::MAX, u64::MAX)).is_err());
    }

    #[test]
    fn backs_off_doubling_up_to_an_hour() {
        let m = Duration::from_secs(60);
        assert_eq!(backoff(m, 1), m);
        assert_eq!(backoff(m, 2), 2 * m);
        assert_eq!(backoff(m, 4), 8 * m);
        assert_eq!(backoff(m, 7), Duration::from_secs(3600));
        assert_eq!(backoff(m, 1000), Duration::from_secs(3600));
        assert_eq!(backoff(Duration::from_secs(10), 7), Duration::from_secs(640));
        assert_eq!(backoff(Duration::MAX, 3), Duration::from_secs(3600));
    }

    #[test]
    fn payloads_are_the_verifier_shape() {
        let rlps = vec![vec![0xf9, 0x02], vec![0xab]];
        let p: serde_json::Value = serde_json::from_str(&proof_payload(&[1, 2], &[3], &rlps)).unwrap();
        assert_eq!(p["proof"], "0102");
        assert_eq!(p["public_values"], "03");
        assert_eq!(p["headers"][0]["rlp_hex"], "f902");
        assert_eq!(p["headers"][1]["rlp_hex"], "ab");
        assert_eq!(p["headers"][0].as_object().unwrap().len(), 1);
        let h: serde_json::Value = serde_json::from_str(&headers_payload(&rlps)).unwrap();
        assert_eq!(h.as_object().unwrap().len(), 1);
        assert_eq!(h["headers"][1]["rlp_hex"], "ab");
    }

    #[test]
    fn fits_the_payload_cap_and_the_header_cap() {
        // ~620-byte Prague headers: 5 next to a Groth16 proof and its public values.
        let rlps = vec![vec![0u8; 620]; 12];
        let (proof, pv) = (vec![0u8; 356], vec![0u8; 448]);
        let k = fit_newest(&rlps, |h| proof_payload(&proof, &pv, h));
        assert_eq!(k, 5);
        assert!(proof_payload(&proof, &pv, &rlps[12 - k..]).len() <= MAX_CONTRACT_PAYLOAD);
        assert!(proof_payload(&proof, &pv, &rlps[12 - k - 1..]).len() > MAX_CONTRACT_PAYLOAD);
        assert_eq!(fit_newest(&rlps, headers_payload), 6);
        // Small headers stop at the verifier's 12.
        assert_eq!(fit_newest(&vec![vec![0u8; 10]; 20], headers_payload), MAX_HEADERS_PER_CALL);
        // Nothing fits.
        assert_eq!(fit_newest(&[vec![0u8; 5000]], headers_payload), 0);
    }
}
