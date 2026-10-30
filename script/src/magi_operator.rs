//! RV-5: the Magi operator loop.
//!
//! Each step proves the latest finalized checkpoint from the verifier's beacon
//! head and `submitProof`s it with the proven block's header, then waits for it
//! to land on Magi. RP-9: the verifier stores headers on demand, so a proof
//! carries only its own block's header and nothing is backfilled; the bot
//! stores the other headers the bridge needs (attestHeaders).
//!
//! On demand (RP-9, owner 10-27): with a needs file (the bot's NEEDS_FILE) the
//! operator proves only while the bot wants a proof, once the request has
//! waited the batch window (default 10 min) so one proof covers what arrives
//! meanwhile; idle otherwise, so an idle bridge costs nothing. Without one it
//! proves every new checkpoint, as before. Even with nothing wanted, it proves
//! when the verifier's beacon head is older than `max_head_age` (default 5
//! days), so the light client never continues from a stale start.
//!
//! The proven header is checked locally against the proven block hash before
//! it is sent, so a wrong-chain RPC fails here rather than burning RC on a call
//! the contract refuses.
//!
//! Run one operator per verifier: two would submit the same step, and the
//! second call fails on chain (harmless, but it costs RC).

use crate::execution::ExecutionRpc;
use crate::get_client;
use crate::magi_prover::MagiZkProver;
use crate::magi_submitter::{submit_call, MagiSubmitterConfig, SubmittedHeader};
use alloy::sol_types::SolType;
use alloy_primitives::B256;
use anyhow::{bail, ensure, Context, Result};
use sp1_helios_primitives::types::ProofOutputs;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// go-vsc-node `params.MAX_CONTRACT_PAYLOAD_SIZE`: a contract call's payload.
pub const MAX_CONTRACT_PAYLOAD: usize = 8192;

/// A payload's size as the node counts it against MAX_CONTRACT_PAYLOAD: the
/// node keeps the payload as the JSON string literal decoded from the call's
/// CBOR (DecodeTxCbor -> json.RawMessage), two quotes and one backslash per
/// quote or backslash more than the raw text (LINK-PAYLOAD-1).
pub fn node_payload_size(payload: &str) -> usize {
    serde_json::to_string(payload).map(|s| s.len()).unwrap_or(payload.len())
}

/// Beacon slots per sync committee period (the verifier's SlotsPerSyncPeriod).
pub const SLOTS_PER_SYNC_PERIOD: u64 = 8192;
/// zk-header-verifier `MaxHeadersPerTx`.
pub const MAX_HEADERS_PER_CALL: usize = 12;

/// The verifier state the loop steers by (zk-header-verifier state keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierState {
    /// "bh": the last proven beacon slot.
    pub beacon_head: u64,
    /// "h": the last proven execution block.
    pub last_height: u64,
    /// "sp1vk": the light-client program vkey the verifier accepts proofs for.
    pub program_vkey: Option<String>,
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
pub const STATE_KEYS: [&str; 3] = ["bh", "h", "sp1vk"];

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

/// A10: the window --max-proofs-per-day counts paid proofs over.
pub const BUDGET_WINDOW_SECS: u64 = 86_400;

/// A10: when each proof of the last day was paid (unix seconds), kept in a
/// file so a restart does not reset the daily budget. Anyone who can make the
/// bot want proofs spends PROVE; the budget bounds what a day can cost, and the
/// bot's want-proof alarm reports the wait it causes.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofLedger {
    pub paid: Vec<u64>,
}

impl ProofLedger {
    /// A missing file is an empty ledger.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{} is not a proof ledger", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))
    }

    /// Records the proofs paid during a step (the paid counter went from
    /// before to after) at now; whether there were any.
    pub fn record_paid(&mut self, before: u64, after: u64, now: u64) -> bool {
        if after <= before {
            return false;
        }
        self.record(now, after - before);
        true
    }

    /// Records n proofs paid at now and forgets those outside the window.
    pub fn record(&mut self, now: u64, n: u64) {
        self.paid.extend(std::iter::repeat(now).take(n as usize));
        self.paid.retain(|&t| now.saturating_sub(t) < BUDGET_WINDOW_SECS);
    }

    /// Proofs paid in the window ending at now.
    pub fn paid_in_window(&self, now: u64) -> u64 {
        self.paid.iter().filter(|&&t| now.saturating_sub(t) < BUDGET_WINDOW_SECS).count() as u64
    }

    /// None when another paid proof fits a budget of per_day; else the unix
    /// time the oldest counted proof leaves the window.
    pub fn next_free(&self, now: u64, per_day: u64) -> Option<u64> {
        if self.paid_in_window(now) < per_day {
            return None;
        }
        let oldest = self.paid.iter().filter(|&&t| now.saturating_sub(t) < BUDGET_WINDOW_SECS).min().copied().unwrap_or(now);
        Some(oldest + BUDGET_WINDOW_SECS)
    }
}

/// A10: what the proof budgets allow the next step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// --max-proofs is not reached (once it is, the operator stops).
    pub lifetime_left: bool,
    /// The daily budget is spent until this unix time (a wanted proof waits).
    pub daily_next: Option<u64>,
}

impl Budgets {
    pub fn at(max_proofs: Option<u64>, paid: u64, per_day: Option<u64>, ledger: &ProofLedger, now: u64) -> Self {
        Self {
            lifetime_left: max_proofs.map_or(true, |max| paid < max),
            daily_next: per_day.and_then(|max| ledger.next_free(now, max)),
        }
    }

    pub fn may_prove(&self) -> bool {
        self.lifetime_left && self.daily_next.is_none()
    }
}

/// A10: one PROVE in PROVE wei.
const PROVE_WEI: u128 = 1_000_000_000_000_000_000;

/// Whether a Prover Network balance (PROVE wei) is under the alarm, in whole
/// PROVE. An alarm of 0 never fires.
pub fn prove_low(balance: alloy_primitives::U256, alarm_prove: u64) -> bool {
    balance < alloy_primitives::U256::from(alarm_prove as u128 * PROVE_WEI)
}

/// A PROVE wei amount as PROVE with 4 decimals, rounded down.
pub fn fmt_prove(wei: alloy_primitives::U256) -> String {
    let unit = alloy_primitives::U256::from(PROVE_WEI);
    let frac = (wei % unit) / alloy_primitives::U256::from(PROVE_WEI / 10_000);
    format!("{}.{:04} PROVE", wei / unit, frac.to::<u64>())
}

/// Parses the verifier state read with `STATE_KEYS`. A missing key reads as
/// null or "" on Magi.
pub fn parse_verifier_state(state: &HashMap<String, Option<String>>) -> Result<VerifierState> {
    Ok(VerifierState {
        beacon_head: num(state, "bh")?,
        last_height: num(state, "h")?,
        program_vkey: get(state, "sp1vk").map(str::to_string),
    })
}

/// Beacon chain slot length in seconds.
const SECONDS_PER_SLOT: u64 = 12;

/// How old the verifier's beacon head is, in seconds, when that is over
/// `max_age` (zero disables the check). A proof continues from the stored head
/// and trusts that head's sync committee, whose members may since have exited
/// with nothing at stake (sync-committee signatures are never slashable), so
/// an old head lets old keys sign a fork the verifier would follow. Across
/// bounds the head its SP1-Helios proofs may start from at one week for this.
/// On demand the head moves only when the bridge needs a proof, so a quiet
/// bridge's head would age without bound; the operator proves at this age.
pub fn head_too_old(beacon_head: u64, genesis_time: u64, now: u64, max_age: Duration) -> Option<u64> {
    let age = now.saturating_sub(genesis_time.saturating_add(beacon_head.saturating_mul(SECONDS_PER_SLOT)));
    (!max_age.is_zero() && age > max_age.as_secs()).then_some(age)
}

/// Whether to prove now, from the bot's needs file (RP-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Demand {
    /// The bot wants a proof and the batch window has passed.
    Prove(String),
    /// Nothing wanted, or the batch window is still open.
    Wait(String),
}

/// Reads the bot's needs file (`{"want_proof", "since", "reasons", "updated"}`,
/// unix seconds): prove when a proof has been wanted for `batch_window`. A file
/// not updated for `stale_after` means the bot is down; then nobody would use
/// a proof (map, attest, confirm), so nothing is proved. A file not updated
/// since `not_before` (when this operator's last proof landed) still asks for
/// that proof: the bot has not seen it land yet.
pub fn demand(needs: &str, now: u64, batch_window: Duration, stale_after: Duration, not_before: u64) -> Demand {
    let v: serde_json::Value = match serde_json::from_str(needs) {
        Ok(v) => v,
        Err(e) => return Demand::Wait(format!("needs file unreadable: {e}")),
    };
    let updated = v["updated"].as_u64().unwrap_or(0);
    if now.saturating_sub(updated) > stale_after.as_secs() {
        return Demand::Wait(format!("needs file not updated for {}s; is the bot running?", now.saturating_sub(updated)));
    }
    if updated <= not_before {
        return Demand::Wait("needs file predates the last proof landing".into());
    }
    if v["want_proof"] != serde_json::Value::Bool(true) {
        return Demand::Wait("no proof wanted".into());
    }
    let since = v["since"].as_u64().unwrap_or(now);
    let waited = now.saturating_sub(since);
    if waited < batch_window.as_secs() {
        return Demand::Wait(format!("proof wanted for {waited}s, batching up to {}s", batch_window.as_secs()));
    }
    Demand::Prove(v["reasons"].to_string())
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

/// What one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A proof landed.
    Proved,
    /// Nothing new to prove, or no proof wanted yet.
    Idle,
    /// The proof budget is spent: a proof would be next.
    BudgetSpent,
}

pub struct MagiOperator {
    pub prover: MagiZkProver,
    pub execution_rpc: ExecutionRpc,
    pub consensus_rpc: String,
    pub chain_id: u64,
    pub submitter: MagiSubmitterConfig,
    /// How long a submitted call may take to show in the verifier state.
    pub land_timeout: Duration,
    /// Proofs the Prover Network returned (paid), landed or not: what
    /// --max-proofs counts, so a paid proof that fails to land still counts.
    pub proofs_paid: std::sync::atomic::AtomicU64,
    /// RP-9: the bot's needs file (on demand); None proves every checkpoint.
    pub needs_file: Option<std::path::PathBuf>,
    /// How long a wanted proof waits so one proof covers what arrives meanwhile.
    pub batch_window: Duration,
    /// A needs file older than this means the bot is down.
    pub needs_stale_after: Duration,
    /// Unix time the last proof landed: a needs file must be newer to count.
    pub last_landed: std::sync::atomic::AtomicU64,
    /// Prove when the verifier's beacon head is older than this, even if the
    /// bot wants nothing (see head_too_old). Zero: never.
    pub max_head_age: Duration,
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

    /// The verifier's trusted sync committee hash for period(head) ("sc-<period>"),
    /// the committee a proof from `head` must start from. Missing means the
    /// verifier would refuse any proof from this head, so nothing is proved.
    async fn trusted_committee(&self, head: u64) -> Result<B256> {
        let key = format!("sc-{}", head / SLOTS_PER_SYNC_PERIOD);
        let raw = crate::magi_prover::fetch_contract_state(
            &self.submitter.graphql_urls,
            &self.submitter.contract_id,
            &[key.as_str()],
        )
        .await?;
        hash(&raw, &key).context("the verifier holds no sync committee for its beacon head's period; not proving")
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

    /// One step: prove and submit, if a proof is wanted. With may_prove false
    /// (the proof budget is spent) a step that would request a paid proof
    /// returns BudgetSpent instead.
    pub async fn run_once(&self, may_prove: bool) -> Result<Step> {
        if let Some(path) = &self.needs_file {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let needs = std::fs::read_to_string(path).unwrap_or_default();
            let not_before = self.last_landed.load(std::sync::atomic::Ordering::SeqCst);
            match demand(&needs, now, self.batch_window, self.needs_stale_after, not_before) {
                Demand::Wait(why) => match self.stale_head(now).await {
                    Some(st) => {
                        if !may_prove {
                            return Ok(Step::BudgetSpent);
                        }
                        return self.prove(&st).await;
                    }
                    None => {
                        info!("not proving: {why}");
                        return Ok(Step::Idle);
                    }
                },
                Demand::Prove(why) => info!("proof wanted: {why}"),
            }
        }
        if !may_prove {
            return Ok(Step::BudgetSpent);
        }
        let st = self.state().await?;
        self.prove(&st).await
    }

    /// The verifier state when its beacon head is older than max_head_age. A
    /// failed read is logged and taken as not stale: the next step reads again.
    async fn stale_head(&self, now: u64) -> Option<VerifierState> {
        if self.max_head_age.is_zero() {
            return None;
        }
        let genesis_time = match helios_ethereum::config::networks::Network::from_chain_id(self.chain_id) {
            Ok(n) => n.to_base_config().chain.genesis_time,
            Err(_) => {
                warn!("chain {} has no known beacon genesis time; not checking the head's age", self.chain_id);
                return None;
            }
        };
        let st = match self.state().await {
            Ok(st) => st,
            Err(e) => {
                warn!("cannot read the verifier state to check its head's age: {e:#}");
                return None;
            }
        };
        let age = head_too_old(st.beacon_head, genesis_time, now, self.max_head_age)?;
        info!(
            "proof wanted: the verifier's beacon head (slot {}) is {} h old, over the {} h limit (nothing else is wanted)",
            st.beacon_head,
            age / 3600,
            self.max_head_age.as_secs() / 3600
        );
        Some(st)
    }

    async fn prove(&self, st: &VerifierState) -> Result<Step> {
        let local = self.prover.lightclient_vkey();
        if !vkey_matches(st.program_vkey.as_deref(), &local) {
            bail!(
                "the verifier's program vkey ({}) is not this prover's ({local}); not proving (rotate the verifier's vkey or run the matching ELF)",
                st.program_vkey.as_deref().unwrap_or("unset")
            );
        }
        let committee = self.trusted_committee(st.beacon_head).await?;
        let client = get_client(Some(st.beacon_head), &self.consensus_rpc, self.chain_id).await?;
        let Some(proof) = self
            .prover
            .prove_header_update(&client, st.beacon_head, committee, &self.proofs_paid)
            .await?
        else {
            return Ok(Step::Idle);
        };
        let paid = self.proofs_paid.load(std::sync::atomic::Ordering::SeqCst);
        info!("proof {paid} received from the Prover Network");
        let pv = proof.public_values.to_vec();
        let po = ProofOutputs::abi_decode(&pv).context("public values are not ProofOutputs")?;
        let tip: u64 = po.executionBlockNumber.try_into().context("execution block number")?;
        let new_head: u64 = po.newHead.try_into().context("beacon head")?;
        ensure!(tip > st.last_height, "proven block {tip} is not above the stored tip {}", st.last_height);

        // RP-9: only the proven block's header; the bot attests the others.
        let header = self.execution_rpc.header_by_number(tip).await?;
        ensure!(
            header.hash_slow() == po.executionBlockHash,
            "execution RPC block {tip} is not the proven block {}",
            po.executionBlockHash
        );
        let rlps = vec![alloy_rlp::encode(&header)];
        let proof_bytes = proof.bytes();
        let payload = proof_payload(&proof_bytes, &pv, &rlps);
        ensure!(
            node_payload_size(&payload) <= MAX_CONTRACT_PAYLOAD,
            "the proof and its header do not fit a {MAX_CONTRACT_PAYLOAD}-byte payload"
        );
        info!("submitProof slot {} -> {new_head}, block {tip}", st.beacon_head);
        let tx = submit_call(&self.submitter, "submitProof", &payload).await?;
        info!("submitProof tx {tx}");
        // >=: another operator's proof may land past this one.
        self.wait_for("submitProof", |s| s.beacon_head >= new_head).await?;
        self.prover.limits.clear_request(); // RP-10: landed, nothing to resume
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        self.last_landed.store(now, std::sync::atomic::Ordering::SeqCst);
        Ok(Step::Proved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_trusted_committee_as_the_verifier_stores_it() {
        // The verifier stores "sc-<period>" as bare lowercase hex
        // (normalizeHash32), unlike "lbh", which carries 0x.
        let bare = "827cc35b6e6fda5f987d7c04634679f14a6bc4a7675ee49b5698a7e161c10545";
        let mut m: HashMap<String, Option<String>> = HashMap::new();
        m.insert("sc-1393".into(), Some(bare.into()));
        let got = hash(&m, "sc-1393").unwrap();
        assert_eq!(got, format!("0x{bare}").parse::<B256>().unwrap());
        assert!(hash(&m, "sc-1394").is_err()); // no committee for that period
        assert_eq!(11411808 / SLOTS_PER_SYNC_PERIOD, 1393);
    }

    fn state(kv: &[(&str, &str)]) -> HashMap<String, Option<String>> {
        let mut m: HashMap<String, Option<String>> = STATE_KEYS.iter().map(|k| (k.to_string(), None)).collect();
        for (k, v) in kv {
            m.insert(k.to_string(), Some(v.to_string()));
        }
        m
    }

    #[test]
    fn reads_the_verifier_state() {
        let st = parse_verifier_state(&state(&[("bh", "8224"), ("h", "140")])).unwrap();
        assert_eq!((st.beacon_head, st.last_height, st.program_vkey), (8224, 140, None));
        assert!(parse_verifier_state(&state(&[("bh", "8224")])).is_err());
        assert!(parse_verifier_state(&state(&[("bh", "8224"), ("h", "")])).is_err()); // deleted reads as ""
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
        let st = parse_verifier_state(&state(&[("bh", "8224"), ("h", "140"), ("sp1vk", local)])).unwrap();
        assert_eq!(st.program_vkey.as_deref(), Some(local));
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
    fn the_daily_budget_counts_the_last_24_hours() {
        let day = BUDGET_WINDOW_SECS;
        let mut l = ProofLedger::default();
        assert_eq!(l.next_free(1_000_000, 3), None);
        l.record(1_000_000, 2);
        l.record(1_000_100, 1);
        assert_eq!(l.paid_in_window(1_000_100), 3);
        assert_eq!(l.next_free(1_000_100, 3), Some(1_000_000 + day), "the oldest proof frees a slot a day after it was paid");
        assert_eq!(l.next_free(1_000_100, 4), None);
        assert_eq!(l.next_free(1_000_000 + day - 1, 3), Some(1_000_000 + day));
        assert_eq!(l.next_free(1_000_000 + day, 3), None, "both proofs paid at 1,000,000 have left the window");
        l.record(1_000_000 + day, 1);
        assert_eq!(l.paid, vec![1_000_100, 1_000_000 + day], "recording forgets proofs outside the window");
    }

    #[test]
    fn either_budget_stops_paid_proofs() {
        let mut l = ProofLedger::default();
        assert!(!l.record_paid(3, 3, 100), "nothing paid during the step");
        assert!(l.paid.is_empty());
        assert!(l.record_paid(3, 5, 100));
        assert_eq!(l.paid, vec![100, 100]);
        let b = Budgets::at(None, 5, None, &l, 200);
        assert!(b.may_prove(), "no budget set");
        let b = Budgets::at(Some(5), 5, None, &l, 200);
        assert_eq!(b, Budgets { lifetime_left: false, daily_next: None });
        assert!(!b.may_prove());
        let b = Budgets::at(Some(6), 5, Some(2), &l, 200);
        assert_eq!(b, Budgets { lifetime_left: true, daily_next: Some(100 + BUDGET_WINDOW_SECS) });
        assert!(!b.may_prove(), "the daily budget alone stops a paid proof");
        assert!(Budgets::at(Some(6), 5, Some(3), &l, 200).may_prove());
        assert!(Budgets::at(None, 5, Some(2), &l, 100 + BUDGET_WINDOW_SECS).may_prove(), "a day later the slots are free");
    }

    #[test]
    fn the_ledger_survives_a_restart() {
        let path = std::env::temp_dir().join(format!("magi-ledger-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(ProofLedger::load(&path).unwrap(), ProofLedger::default(), "no file: nothing paid yet");
        let mut l = ProofLedger::default();
        l.record(5_000, 2);
        l.save(&path).unwrap();
        let back = ProofLedger::load(&path).unwrap();
        assert_eq!(back.next_free(5_001, 2), Some(5_000 + BUDGET_WINDOW_SECS));
        std::fs::write(&path, b"{").unwrap();
        assert!(ProofLedger::load(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_prove_alarm_fires_under_its_threshold() {
        use alloy_primitives::U256;
        let prove = |n: u128| U256::from(n * PROVE_WEI);
        assert!(prove_low(prove(24), 25));
        assert!(prove_low(prove(25) - U256::from(1), 25));
        assert!(!prove_low(prove(25), 25));
        assert!(!prove_low(U256::ZERO, 0), "0 turns the alarm off");
        assert_eq!(fmt_prove(prove(25)), "25.0000 PROVE");
        assert_eq!(fmt_prove(U256::from(1_234_567_000_000_000_000u128)), "1.2345 PROVE");
        assert_eq!(fmt_prove(U256::from(99_999_999_999_999u128)), "0.0000 PROVE");
    }

    #[test]
    fn payloads_are_the_verifier_shape() {
        let rlps = vec![vec![0xf9, 0x02]];
        let p: serde_json::Value = serde_json::from_str(&proof_payload(&[1, 2], &[3], &rlps)).unwrap();
        assert_eq!(p["proof"], "0102");
        assert_eq!(p["public_values"], "03");
        assert_eq!(p["headers"][0]["rlp_hex"], "f902");
        assert_eq!(p["headers"][0].as_object().unwrap().len(), 1);
        // A Groth16 proof, its public values and one ~680-byte Glamsterdam header fit.
        assert!(node_payload_size(&proof_payload(&[0u8; 356], &[0u8; 448], &[vec![0u8; 700]])) <= MAX_CONTRACT_PAYLOAD);
        // The node counts the JSON string literal: quotes are escaped.
        assert_eq!(node_payload_size(r#"{"a":"b"}"#), r#""{\"a\":\"b\"}""#.len());
    }

    #[test]
    fn proves_on_demand_after_the_batch_window() {
        let w = Duration::from_secs(600);
        let stale = Duration::from_secs(900);
        let f = |want: bool, since: u64, updated: u64| {
            serde_json::json!({"want_proof": want, "since": since, "updated": updated, "reasons": ["x"]}).to_string()
        };
        assert!(matches!(demand(&f(false, 0, 1000), 1000, w, stale, 0), Demand::Wait(_)), "nothing wanted: idle");
        assert!(matches!(demand(&f(true, 900, 1000), 1000, w, stale, 0), Demand::Wait(_)), "wanted 100 s: still batching");
        assert!(matches!(demand(&f(true, 400, 1000), 1000, w, stale, 0), Demand::Prove(_)), "wanted 600 s: prove");
        assert!(matches!(demand(&f(true, 0, 10), 1000, w, stale, 0), Demand::Wait(_)), "bot silent 990 s: not proving");
        assert!(matches!(demand("", 1000, w, stale, 0), Demand::Wait(_)), "no file");
        assert!(matches!(demand(&f(true, 1000, 1000), 1000, Duration::ZERO, stale, 0), Demand::Prove(_)), "no batching");
        // A request written before the last proof landed is that proof's.
        assert!(matches!(demand(&f(true, 400, 995), 1000, w, stale, 996), Demand::Wait(_)), "stale request: no second proof");
        assert!(matches!(demand(&f(true, 400, 997), 1000, w, stale, 996), Demand::Prove(_)), "a request after the landing counts");
    }

    #[test]
    fn a_head_over_the_age_limit_is_stale() {
        let genesis = 1_655_733_600; // Sepolia beacon genesis
        let day = 86_400;
        let limit = Duration::from_secs(5 * day);
        let head = 9_000_000u64;
        let at = genesis + head * 12; // the head slot's time
        assert_eq!(head_too_old(head, genesis, at + 5 * day, limit), None, "at the limit: not stale");
        assert_eq!(head_too_old(head, genesis, at + 5 * day + 1, limit), Some(5 * day + 1), "past the limit");
        assert_eq!(head_too_old(head, genesis, at + 60 * day, Duration::ZERO), None, "zero: never");
        assert_eq!(head_too_old(head, genesis, at - 60, limit), None, "a head ahead of the clock");
        assert_eq!(head_too_old(head, 1_606_824_023, at + 5 * day, limit).is_some(), true, "mainnet genesis is earlier: the same slot is older");
    }

    #[test]
    fn a_pending_request_round_trips_and_clears() {
        use crate::magi_prover::{NetworkLimits, PendingRequest};
        let dir = std::env::temp_dir().join(format!("magi-req-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let l = NetworkLimits { request_file: Some(dir.join("req.json")), ..Default::default() };
        assert_eq!(l.load_request().unwrap(), None);
        let r = PendingRequest { request_id: B256::repeat_byte(7), head: 8224, latest_block: 8256 };
        l.save_request(&r).unwrap();
        assert_eq!(l.load_request().unwrap(), Some(r));
        l.clear_request();
        assert_eq!(l.load_request().unwrap(), None);
        // No file configured: nothing is kept.
        let none = NetworkLimits::default();
        none.save_request(&PendingRequest { request_id: B256::ZERO, head: 1, latest_block: 2 }).unwrap();
        assert_eq!(none.load_request().unwrap(), None);
        assert_eq!(NetworkLimits::default().max_price_per_pgu, 300_000_000, "0.3 PROVE per billion PGU");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fulfilled_proof_that_fails_its_checks_is_not_resumed() {
        use crate::magi_prover::{NetworkLimits, PendingRequest};
        let dir = std::env::temp_dir().join(format!("magi-req-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let l = NetworkLimits { request_file: Some(dir.join("req.json")), ..Default::default() };
        let r = PendingRequest { request_id: B256::repeat_byte(9), head: 8224, latest_block: 8256 };
        l.save_request(&r).unwrap();
        // A passing check keeps the request (it lands, then clear_request).
        assert_eq!(l.drop_request_on_err(Ok(1u8)).unwrap(), 1);
        assert_eq!(l.load_request().unwrap(), Some(r));
        // A failing one drops it: resuming the same proof can never pass.
        assert!(l.drop_request_on_err::<()>(Err(anyhow::anyhow!("local verify failed"))).is_err());
        assert_eq!(l.load_request().unwrap(), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
