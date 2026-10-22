# magi-zk-oracle

Zero-knowledge Ethereum consensus light client for the Magi Network. Generates SP1 Groth16 proofs of Ethereum beacon chain finality and submits them to an on-chain WASM verifier contract, providing trustless ETH headers without requiring a full node.

Built on [SP1 Helios](https://github.com/succinctlabs/sp1-helios) v1.3.0 ([docs](https://succinctlabs.github.io/sp1-helios/)); the crate names follow upstream (`sp1-helios-*`) to keep future upstream merges small.

## Architecture

```
Beacon Chain (Consensus Layer)
        |
        v
  Helios Light Client (a16z)
        |
        v
  SP1 ZK Program (light_client.rs)
  - Verifies sync committee updates
  - Verifies finality update (pre- and post-Gloas)
  - Commits execution state root, block hash, block number, genesis root
        |
        v
  Groth16 Proof (Succinct Prover Network)
        |
        v
  Magi Verifier Contract (WASM)
  - sp1_verify_groth16 host function
  - Stores verified ETH headers on-chain
        |
        v
  Bridge / Consumer Contracts
  - contracts.read(verifierId, key)
```

## What Magi changes on top of upstream

- `ProofOutputs` adds `executionBlockHash` (the verifier keccak-checks each submitted RLP header against it) and `genesisRoot` (ABI slot 10, `pvBytes[352:384]`; chain identity, pinned by the verifier). There is no committed `chainId`.
- "No next sync committee" is committed as `0xFF..FF`, never `ZERO`, so it can not match uninitialized storage (MED Z-PR-M1). Upstream's #54 reset of `store.next_sync_committee` is kept.
- `magi_prover.rs`: Groth16 only; the consensus client's chain id is re-checked before every finality update (CRIT #23); at startup the local ELF hash must match the verifier's `elfhash` pin (HIGH #22).
- `magi_submitter.rs` / `magi_operator.rs`: submit proofs and header batches to the zk-header-verifier on Magi, sized under the node's 8192-byte payload cap, and backfill a header gap right after each proof.
- `script/build.rs` builds the guest programs in the `ghcr.io/succinctlabs/sp1:v6.8.1` image pinned by digest; `.github/workflows/elf-reproducibility.yml` fails a PR whose committed ELFs differ from that build.

Upstream's Solidity contract (`contracts/`) and its `operator` / `genesis` binaries are not part of the Magi path: they decode upstream's `ProofOutputs` layout, and the binaries are not built.

## Crates

| Crate | Description |
|---|---|
| `sp1-helios-program` | SP1 zkVM programs: `light_client` (beacon chain finality), `execution_header`, `storage` |
| `sp1-helios-primitives` | Shared types (`ProofInputs`, `ProofOutputs`, `ContractStorage`), execution-field and MPT storage proof verification |
| `sp1-helios-script` | Prover (`MagiZkProver`), Helios client setup, Magi L2 submission (`magi_submitter`), the operator loop (`magi_operator`), vkey generation, fixtures |

## Dependencies

- [SP1](https://github.com/succinctlabs/sp1) (=6.8.1): zkVM and Groth16 proving
- [Helios](https://github.com/a16z/helios) (0.12.0): Ethereum consensus light client, Gloas-ready
- [go-vsc-node](https://github.com/vsc-eco/go-vsc-node): host function (`crypto.sp1_verify_groth16`) + oracle config

## Related Repos

- [zk-header-verifier](https://github.com/vsc-eco/zk-header-verifier): WASM verifier contract deployed on Magi
- [account-mapping](https://github.com/vsc-eco/account-mapping): bridge reads verified headers from the verifier

## Usage

### Print verification keys

```bash
cargo run --release --bin vkey
```

### Run the Magi operator

Proofs are requested from the [Succinct Prover Network](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart); see `.env.example` (`NETWORK_PRIVATE_KEY`, `MAGI_OPERATOR_PRIVATE_KEY`).

```bash
cargo run --release --bin magi_operator -- \
  --source-chain-id 11155111 \
  --source-consensus-rpc "$SOURCE_CONSENSUS_RPC_URL" \
  --source-execution-rpc "$SOURCE_EXECUTION_RPC_URL" \
  --magi-graphql "$MAGI_GRAPHQL_URL" \
  --verifier-contract "$ZK_HEADER_VERIFIER_ID" \
  --net-id vsc-testnet
```

Each step proves the next finalized update and submits it, then backfills the headers the verifier is missing; it waits for every call to show in the verifier state before the next one.

## Validation

The recorded Plataberget fixtures contain signed Gloas updates, execution headers, and source storage proofs.
`gloas_transition.cbor` starts at slot 49120 and advances to slot 56416 across the Gloas fork and a committee change.
`gloas_current.cbor` advances from slot 379968 to slot 380480 after Gloas.
`proof_inputs.cbor` is a pre-Gloas update.

Run the unit and guest execution tests (the build rebuilds the ELFs in the pinned image first):

```sh
cargo test --locked --release \
  -p sp1-helios-primitives -p sp1-helios-script \
  --lib --test execute --test storage_collection --test gloas
```

The storage tests require Anvil. These tests execute the programs without generating proofs; they check the Magi outputs (`executionBlockHash`, `genesisRoot`, the `0xFF..FF` next-committee value) on both pre- and post-Gloas updates.

## Trust Model

The prover fetches beacon chain data from a consensus RPC (any Nimbus/Lighthouse endpoint). This RPC is **untrusted**: the ZK proof cryptographically verifies sync committee signatures and finality inside the circuit. A malicious RPC cannot produce a valid proof with fake data.

## Requirements

- Rust 1.91.0
- Docker (the guest programs build in the pinned SP1 image)
- Any Ethereum consensus RPC endpoint with light-client endpoints (untrusted, data only)
- A Succinct Prover Network requester key with PROVE funds
