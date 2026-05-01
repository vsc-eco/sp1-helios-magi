# GPU Prover Setup (RunPod)

Validated 2026-05-01: Sepolia block 10764834 proven and stored on Magi testnet.
All 7 header fields independently verified against Sepolia RPC.

RunPod template: `runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04`
Container disk: 50GB+ (Groth16 proving key is ~2GB)
Clone to `/workspace` so builds survive pod restarts.

## Commands (paste one at a time)

```
curl -fsSL https://sh.rustup.rs | sh -s -- -y && source $HOME/.cargo/env
```

```
curl -L https://raw.githubusercontent.com/succinctlabs/sp1/main/sp1up/install | bash
```

```
source /root/.bashrc && sp1up --version 6.1.0
```

```
apt-get update && apt-get install -y protobuf-compiler nano
```

```
cd /workspace && git clone https://github.com/vsc-eco/sp1-helios-magi && cd sp1-helios-magi
```

```
readelf -h elf/light_client | grep Class
```

Must say ELF64. If ELF32, the ELFs are stale v5 and need rebuilding.

```
mkdir -p target/elf-compilation/riscv64im-succinct-zkvm-elf/release/
```

```
cp elf/light_client target/elf-compilation/riscv64im-succinct-zkvm-elf/release/
```

```
cp elf/storage target/elf-compilation/riscv64im-succinct-zkvm-elf/release/
```

```
sed -i 's/sp1-sdk = "6.1.0"/sp1-sdk = { version = "6.1.0", features = ["cuda"] }/' Cargo.toml
```

```
sed -i '/^anyhow/a clap = { version = "4", features = ["derive"] }' script/Cargo.toml
```

```
echo -e '\n[[bin]]\nname = "benchmark"\npath = "bin/benchmark.rs"' >> script/Cargo.toml
```

Create benchmark binary:

```
nano script/bin/benchmark.rs
```

Paste the benchmark.rs code below. Ctrl+O, Enter, Ctrl+X.

Apply operator.rs fix (execute + prove for public values):

```
nano script/src/operator.rs
```

Delete everything from `let encoded =` to end of file. Paste the operator.rs bottom half below. Ctrl+O, Enter, Ctrl+X.

Run:

```
SP1_SKIP_PROGRAM_BUILD=true SP1_PROVER=cuda cargo run --release --bin benchmark
```

## benchmark.rs

Paste into `script/bin/benchmark.rs`:

```rust
use anyhow::Result;
use clap::Parser;
use magi_zk_oracle_script::{operator::MagiZkProver, get_client};
use std::time::Instant;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "https://ethereum-sepolia-beacon-api.publicnode.com")]
    consensus_rpc: String,
    #[arg(long, default_value = "11155111")]
    chain_id: u64,
}
#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let prover = MagiZkProver::new().await;
    let current_slot = {
        let c = get_client(None, &args.consensus_rpc, args.chain_id).await?;
        c.store.finalized_header.beacon().slot
    };
    let bootstrap_slot = current_slot.saturating_sub(64);
    eprintln!("current: {} bootstrap: {}", current_slot, bootstrap_slot);
    let client = get_client(Some(bootstrap_slot), &args.consensus_rpc, args.chain_id).await?;
    let t = Instant::now();
    let proof = prover.prove_header_update(&client, 0).await?;
    if let Some(p) = proof {
        eprintln!("TIME: {:.1}s PROOF: {}B PV: {}B", t.elapsed().as_secs_f64(), p.bytes().len(), p.public_values.as_slice().len());
        std::fs::write("/tmp/proof.bin", p.bytes())?;
        std::fs::write("/tmp/public_values.bin", p.public_values.as_slice())?;
    } else { eprintln!("No proof generated"); }
    Ok(())
}
```

## operator.rs bottom half

Delete from `let encoded =` to end of file in `script/src/operator.rs`, paste this:

```rust
        let encoded = serde_cbor::to_vec(&inputs).context("Failed to encode proof inputs")?;

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&encoded);

        let mut prove_stdin = SP1Stdin::new();
        prove_stdin.write_slice(&encoded);

        let (public_values, _) = self
            .client
            .execute(LIGHTCLIENT_ELF, stdin)
            .await
            .context("Execution failed")?;

        let mut proof = self
            .client
            .prove(&self.lightclient_pk, prove_stdin)
            .groth16()
            .await
            .context("Groth16 proving failed")?;

        proof.public_values = public_values;

        info!("Proof generated for slot {latest_block}");
        Ok(Some(proof))
    }

    pub fn lightclient_vkey(&self) -> String {
        self.lightclient_pk.verifying_key().bytes32()
    }

    pub fn storage_vkey(&self) -> String {
        self.storage_pk.verifying_key().bytes32()
    }
}
```

## Gotchas

- **ELFs must be 64-bit**: SP1 v6 uses riscv64im. Old v5 ELFs are 32-bit and fail with "ELF has a segment that is below the STACK_TOP"
- **include_elf! path**: Looks at `target/elf-compilation/riscv64im-succinct-zkvm-elf/release/`, not `elf/`. Must copy when using SP1_SKIP_PROGRAM_BUILD=true
- **cargo prove build fails**: socket2 can't compile for RISC-V because helios pulls networking deps. Use pre-built ELFs + SP1_SKIP_PROGRAM_BUILD=true
- **protobuf-compiler**: sp1-prover-types needs protoc, not installed by default
- **CUDA feature**: Must add `features = ["cuda"]` to sp1-sdk in Cargo.toml
- **Container disk**: 50GB+ needed. Groth16 proving key extracts to ~/.sp1/circuits/
- **Clone to /workspace**: Container disk wipes on resize. /workspace is the persistent volume
- **Web terminal paste limit**: RunPod web terminal truncates at ~30 lines. Use nano
- **Bash ! expansion**: If pasting code with `!` into bash (not nano), run `set +H` first
- **CUDA public_values empty**: CUDA GPU prover does NOT return public_values. Must execute() locally first (CPU, fast) to capture them, then prove() on GPU. Both use same stdin built from same encoded bytes. operator.rs uses LIGHTCLIENT_ELF const for execute.
- **execute() API**: Takes `(Elf, SP1Stdin)` by value (consumes both). Returns `(SP1PublicValues, ExecutionReport)` -- 2-tuple not 3.
- **Bootstrap from latest = panic**: If helios bootstraps to the latest finalized slot and the finality update returns the same slot, the ZK program panics (`assert new_head > prev_head`). Benchmark bootstraps from current-64 (2 epochs back). Production operator uses last proven slot from contract state.
- **exit_code in proof**: Proof bytes contain exit_code at offset 4-36. Must be all zeros. exit_code=1 means the ZK program panicked and the verifier contract will reject.
- **SP1 circuit version mismatch**: go-vsc-node testdata has SP1 v6.0.0 artifacts (groth16_vk SHA256 prefix 0e78f4db, vk_root 008cd56e). GPU prover uses v6.1.0 (prefix 4388a21c, vk_root 002f850e). Contract MUST be initialized with v6.1.0 values from `~/.sp1/circuits/groth16/v6.1.0/groth16_vk.bin`.
- **ABI tuple offset**: alloy's abi_encode() adds a 32-byte tuple offset prefix (0x0000...0020) to the public values. Contract must read this offset and index fields relative to it, not use hardcoded byte offsets. Fixed in verifier contract vsc1BYaUWugyzXmxJLQ8YzvBAQtmTnongVcyYH.
- **Deploy fee required**: Magi state engine requires 10 TBD fee transfer with vsc.create_contract. Deploys without fee land on Hive but contract never registers on Magi (silent failure).

## Proof Structure (356 bytes)

```
[0:4]     SHA256(groth16_vk) prefix (v6.1.0: 4388a21c)
[4:36]    exit_code (must be all zeros)
[36:68]   vk_root (v6.1.0: 002f850e...)
[68:100]  nonce
[100:356] raw Gnark Groth16 proof (256 bytes)
```

## Public Values Structure (416 bytes, ABI-encoded)

```
[0:32]    ABI tuple offset (0x20 = 32)
[32:64]   prevHeader (beacon tree hash)
[64:96]   prevHead (beacon slot, uint256)
[96:128]  prevSyncCommitteeHash
[128:160] newHead (beacon slot, uint256)
[160:192] newHeader (beacon tree hash)
[192:224] executionStateRoot
[224:256] executionBlockHash
[256:288] executionBlockNumber (uint256)
[288:320] syncCommitteeHash
[320:352] nextSyncCommitteeHash
[352:384] storageSlots length
[384:416] (empty storage slots)
```

## Stored Header Format (128 bytes per block)

```
[0:8]     blockNumber (uint64 big-endian)
[8:40]    stateRoot (32 bytes)
[40:72]   transactionsRoot (32 bytes)
[72:104]  receiptsRoot (32 bytes)
[104:112] baseFeePerGas (uint64 big-endian)
[112:120] gasLimit (uint64 big-endian)
[120:128] timestamp (uint64 big-endian)
```

## Output

- `/tmp/proof.bin` -- Groth16 proof bytes (356B)
- `/tmp/public_values.bin` -- ABI-encoded ProofOutputs (416B)

## Observed Timing (RunPod A100-equivalent)

- Total benchmark: ~284s
- R1CS + proving key load: ~27s (cached after first run)
- Constraint solving: ~25s
- Groth16 proving: ~65s
- Proof verification: ~3s
- Execute (CPU, local): seconds

## Verifier Contract (testnet, validated 2026-05-01)

- ZK verifier: `vsc1BYaUWugyzXmxJLQ8YzvBAQtmTnongVcyYH` (ABI offset fix)
- EVM bridge: `vsc1Bonneig3DziAMxZkRdXqGHLAboSeuHAPfw`
- Action: `submitProof`
- rc_limit: 200000
- Deploy account: `magi.contracts` on Hive testnet
- Hive testnet API: `https://testnet.techcoderx.com`
- Magi testnet GraphQL: `https://magi-test.techcoderx.com/api/v1/graphql`

## Verifier Init Params (SP1 v6.1.0)

- sp1_vkey_hash: `00f701535d87c17492e85e1b32649f2578a4e02e7e314401c726af21bba2523d`
- vk_root: `002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`
- groth16_vk: from `~/.sp1/circuits/groth16/v6.1.0/groth16_vk.bin` (492 bytes, SHA256 prefix 4388a21c)

## Previous Contract IDs (dead/broken)

- `vsc1BbR6AMNwmPFrc1MjMMWkpaQCAfzwCmXgkj` -- no-fee deploy, never registered
- `vsc1BZc4WYum9tYHiovtWCbJDkoMhEJcBhvqxz` -- no-fee deploy, never registered
- `vsc1Bkfh9qqutrFn97QNEgCHLpygyUWE7AxsyG` -- wrong ABI offsets, initialized with stale v6.0.0 artifacts
