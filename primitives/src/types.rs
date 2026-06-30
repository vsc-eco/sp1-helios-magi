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
    // Chain-binding (genesis + sync-committee anchoring) — see the
    // zk-header-verifier plan. `genesisRoot` is the genesis_validators_root the
    // sync-committee signatures were verified against in-circuit, committed here
    // so the on-chain verifier can pin + check it. It sits at sol position 11
    // (ABI slot 10, byte 352); `storageSlots` (dynamic) follows at slot 11.
    // The Go decoder reads `genesisRoot` from pvBytes[352:384]. The earlier
    // `chainId` field (slot 11) was REMOVED — chain identity is established by
    // genesisRoot + the trusted sync committee, not a spoofable committed scalar;
    // the verifier stamps its own configured chainId into stored headers.
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
        /// The genesis_validators_root the sync-committee signatures were
        /// verified against (chain identity). Pinned + checked on-chain.
        bytes32 genesisRoot;
        /// Attested storage slots for the given block.
        StorageSlot[] storageSlots;
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
