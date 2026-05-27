#![allow(clippy::too_many_arguments)]

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::sol;
use alloy_trie::TrieAccount;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::Forks;
use helios_consensus_core::types::{FinalityUpdate, LightClientStore, Update};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofInputs {
    pub updates: Vec<Update<MainnetConsensusSpec>>,
    pub finality_update: FinalityUpdate<MainnetConsensusSpec>,
    pub expected_current_slot: u64,
    pub store: LightClientStore<MainnetConsensusSpec>,
    pub genesis_root: B256,
    pub forks: Forks,
    pub contract_storage: Vec<ContractStorage>,
    /// W4 Cluster B CRIT #6 Site 5 + CRIT #23: L1 chainId the prover is
    /// running against (operator-supplied at prover startup via
    /// `Network::from_chain_id`). Committed into ProofOutputs.chainId so
    /// the on-chain zk-header-verifier can cross-check and the
    /// account-mapping contract can enforce per-chain binding (CRIT #6
    /// sites 1+2 read from the stored header).
    ///
    /// The operator runbook P5 step pins this value at prover bootstrap;
    /// CRIT #23 adds a runtime re-check on every `get_finality_update`
    /// call to detect mid-flight RPC pivots.
    pub chain_id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContractStorage {
    pub address: Address,
    pub value: TrieAccount,
    /// The proof that this contracts storage root is correct
    pub mpt_proof: Vec<Bytes>,
    /// The storage slots that we want to prove
    pub storage_slots: Vec<StorageSlotWithProof>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StorageSlotWithProof {
    pub key: B256,
    pub value: U256,
    /// The proof that this storage slot is correct
    pub mpt_proof: Vec<Bytes>,
}

sol! {
    // W4 Cluster B CRIT #6 Site 5 + W1-cluster-B-schema §1 LOCKED:
    //   - chainId APPENDED as the LAST field (sol position 12, ABI slot 11).
    //   - Position is LOCKED — inserting before storageSlots would shift slot 10
    //     (the dynamic offset pointer for storageSlots) and break every Go-side
    //     parseProvenFields-style positional decoder. Appending preserves slots
    //     0-10 byte-for-byte; the new chainId lives at PvFieldChainId=384.
    //   - The Go decoder reads `chainId` from pvBytes[408:416] (last 8 bytes
    //     of the 32-byte ABI slot, big-endian uint64). See
    //     zk-header-verifier/contract/main.go parseProvenFields.
    struct ProofOutputs {
        /// The previous beacon block header hash.
        bytes32 prevHeader;
        /// The slot of the previous head.
        uint256 prevHead;
        /// The anchor sync committee hash which was used to verify the proof.
        bytes32 prevSyncCommitteeHash;
        /// The slot of the new head.
        uint256 newHead;
        /// The new beacon block header hash.
        bytes32 newHeader;
        /// The execution state root from the execution payload of the new beacon block.
        bytes32 executionStateRoot;
        /// The execution block hash from the execution payload of the new beacon block.
        bytes32 executionBlockHash;
        /// The execution block number.
        uint256 executionBlockNumber;
        /// The sync committee hash of the current period.
        bytes32 syncCommitteeHash;
        /// The sync committee hash of the next period.
        bytes32 nextSyncCommitteeHash;
        /// Attested storage slots for the given block.
        StorageSlot[] storageSlots;
        /// W4 Cluster B Site 5: the L1 chainId this proof was generated for.
        /// Read from the helios `Forks` / `Network::from_chain_id` config at
        /// proof construction time and committed as part of the public values.
        uint64 chainId;
    }

    struct StorageProofOutputs {
        bytes32 stateRoot;
        StorageSlot[] storageSlots;
    }

    struct StorageSlot {
        bytes32 key;
        bytes32 value;
        address contractAddress;
    }
}
