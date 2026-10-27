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
- `magi_prover.rs`: Groth16 only; the consensus client must be configured for the expected chain id (CRIT #23; a consensus RPC serving another chain is caught in-circuit, where the committee signatures are checked under the configured genesis root, and by the verifier's genesis-root and committee anchoring); at startup the local ELF hash must match the verifier's `elfhash` pin (HIGH #22). Before paying for a proof it checks, for free, that the bootstrapped store is at the verifier's beacon head and that the executed outputs continue it (`prevHead`, `newHead`, `genesisRoot`).
- `magi_submitter.rs` / `magi_operator.rs`: submit each proof to the zk-header-verifier on Magi with the proven block's header (the verifier stores other headers on demand, RP-9), proving on demand from the bridge bot's needs file.
- `script/build.rs` builds the guest programs in the `ghcr.io/succinctlabs/sp1:v6.8.1` image pinned by digest; `.github/workflows/elf-reproducibility.yml` fails a PR whose committed ELFs differ from that build.

Upstream's `operator` / `genesis` binaries are not part of the Magi path: they target upstream's Solidity contract and its `ProofOutputs` layout, and are not built. Not carried from upstream: that contract (`contracts/`, with its `sp1-contracts` submodule), its book, its audit reports (they cover upstream's code, not this fork's changes), its agent files, its CI workflows and its operator `Dockerfile`. CI here is the ELF reproducibility check, with every third-party action pinned by commit.

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
  --net-id vsc-testnet \
  --needs-file /var/lib/evm-bot/needs.json
```

Each step proves the latest finalized update and submits it with the proven block's header; it waits for the call to show in the verifier state before the next one. Nothing is backfilled: the bridge bot stores the other headers it needs (EIP-2935 attestation, or linked down by parent hash). It proves only when the verifier's program vkey (`sp1vk`) is this ELF's (a proof for another vkey would be refused on chain but still paid for), and after a failed step it waits twice as long each time, up to an hour.

On demand: with `--needs-file` (the bot's `NEEDS_FILE`, on the same host) it proves only while the bot wants a proof (a deposit or withdrawal block above the proven tip, or withdrawals waiting on a tip header older than 45 min), once the request has waited `--batch-window-mins` (default 10) so one proof covers what arrives meanwhile, and not at all while the file goes `--needs-stale-mins` (15) without an update (the bot is down). An idle bridge costs nothing. Without `--needs-file` it proves every new checkpoint.

Every proof is paid on the Prover Network. Each request carries a price cap and deadlines: `SP1_MAX_PRICE_PER_PGU` (PROVE wei per PGU, default 300000000 = 0.3 PROVE per billion PGU; a light-client update is ~53-72M PGU), `SP1_PROOF_TIMEOUT_SECS` (1800) and `SP1_AUCTION_TIMEOUT_SECS` (120). The request id is saved to `MAGI_PROOF_REQUEST_FILE` (default `magi-proof-request.json`) before waiting, so a restart resumes a paid request instead of buying another. `--max-proofs N` stops the operator once it has been sent N proofs (counted when the network returns one, so a proof that then fails to land still counts); `--max-proofs 1` is a single paid proof, for a first run.

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

## Values for the zk-header-verifier

A fresh verifier's `init` payload comes from `magi_genesis`, from one beacon light-client bootstrap at a finalized checkpoint (the latest, or `--slot`): `initial_head`, `initial_sync_committee_hash` and `genesis_root` from the bootstrap, the anchor (`initial_height`, `initial_block_hash`) from the execution block that checkpoint finalizes (checked against the beacon header), `sp1_vkey_hash` from the committed ELF, and `groth16_vk` / `vk_root` from SP1 6.8.1. It also prints the ELF hash for the first `setExpectedElfHash`. Nothing is sent; review the output, then call `init`.

The checkpoint is the verifier's trust root. Without `--slot`, its block root comes from the checkpoint-sync services helios queries, independent of `--source-consensus-rpc`; use that for a real init. With `--slot`, the root comes from the consensus RPC itself, which could serve a bootstrap of its own: compare the printed `checkpoint block root` with an independent beacon node or explorer before calling `init`.

```bash
cargo run --release --bin magi_genesis -- \
  --source-chain-id 11155111 \
  --source-consensus-rpc "$SOURCE_CONSENSUS_RPC_URL" \
  --source-execution-rpc "$SOURCE_EXECUTION_RPC_URL" \
  --is-testnet > init.json
```

Whenever `elf/light_client` changes, the verifier needs:
- the ELF hash for `setExpectedElfHash` (HIGH #22): `sha256sum elf/light_client`
- the program vkey (`sp1_vkey_hash`, rotated with `propose`/`execute`): `cargo run --release --bin vkey`

The Groth16 verifying key and the vk root belong to the SP1 version, not the program: take them from that release's `sp1-verifier` crate (`vk-artifacts/groth16_vk.bin`, `VK_ROOT_BYTES`), never from a proof. For SP1 6.8.1 they are the same as for 6.1.0.

## Trust Model

The prover fetches beacon chain data from a consensus RPC (any Nimbus/Lighthouse endpoint). This RPC is **untrusted**: the ZK proof cryptographically verifies sync committee signatures and finality inside the circuit. A malicious RPC cannot produce a valid proof with fake data.

## Requirements

- Rust 1.93.1 (`script/rust-toolchain`)
- Docker (the guest programs build in the pinned SP1 image)
- Any Ethereum consensus RPC endpoint with light-client endpoints (untrusted, data only)
- A Succinct Prover Network requester key with PROVE funds
