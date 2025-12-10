# sevs-signature
SEVS (Seed-Expanded Verkle Signatures): A compact post-quantum signature scheme with 540-byte signatures and 128-bit security

# SEVS: Seed-Expanded Verkle Signatures

A compact post-quantum digital signature scheme achieving 540-byte signatures with 128-bit security.

## Features

- **540-byte signatures** (77.7% smaller than Dilithium-2)
- **128-bit post-quantum security** (Module-LWE and Module-SIS)
- **Fast verification**: 2-5ms per signature, O(n log n) for batch
- **Production-tested**: 11,000+ blocks validated on Celereum blockchain
- **RLE compression**: 78% compression ratio for hints

## Quick Start

```bash
cd sevs-signature
cargo build --release
cargo run --release --bin security_audit
