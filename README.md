# magi-zk-oracle

Zero-knowledge Ethereum consensus light client for the Magi Network. Generates SP1 Groth16 proofs of Ethereum beacon chain finality and submits them to an on-chain WASM verifier contract, providing trustless ETH headers without requiring a full node.

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
  - Verifies finality update
  - Commits execution state root, block hash, block number
        |
        v
  Groth16 Proof (GPU prover)
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

## Crates

| Crate | Description |
|---|---|
| `magi-zk-oracle-program` | SP1 zkVM programs: `light_client` (beacon chain finality) and `storage` (EVM storage proofs) |
| `magi-zk-oracle-primitives` | Shared types (`ProofInputs`, `ProofOutputs`, `ContractStorage`) and MPT storage proof verification |
| `magi-zk-oracle-script` | Prover (`MagiZkProver`), Helios client setup, Magi L2 transaction submission, vkey generation |

## Dependencies

- [SP1](https://github.com/succinctlabs/sp1) (v6.1.0) — zkVM and Groth16 proving
- [Helios](https://github.com/a16z/helios) (v0.10.2) — Ethereum consensus light client
- [go-vsc-node](https://github.com/vsc-eco/go-vsc-node) `feature/zk-eth-oracle` — host function (`crypto.sp1_verify_groth16`) + oracle config

## Related Repos

- [zk-header-verifier](https://github.com/vsc-eco/zk-header-verifier) — WASM verifier contract deployed on Magi
- [account-mapping](https://github.com/vsc-eco/account-mapping) `feature/zk-verifier-integration` — bridge reads verified headers from verifier

## Usage

### Print verification keys

```bash
cargo run --bin vkey
```

### Generate a proof

```rust
use magi_zk_oracle_script::{get_client, operator::MagiZkProver};

let prover = MagiZkProver::new().await;
let client = get_client(Some(slot), consensus_rpc, chain_id).await?;
let proof = prover.prove_header_update(&client, current_head).await?;
```

### GPU proving (RunPod)

SP1 v6 supports native CUDA. No Docker required.

```bash
SP1_PROVER=cuda cargo run --release --bin operator
```

## Trust Model

The prover fetches beacon chain data from a consensus RPC (any Nimbus/Lighthouse endpoint). This RPC is **untrusted** — the ZK proof cryptographically verifies sync committee signatures and finality inside the circuit. A malicious RPC cannot produce a valid proof with fake data.

## Requirements

- Rust 1.91.0+
- SP1 toolchain (`sp1up`)
- Any Ethereum consensus RPC endpoint (untrusted, data only)
- GPU for Groth16 proving (optional, can use SP1 network)
