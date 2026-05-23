High-Performance Bitcoin Keyspace Scanner (FASTSCAN v2+)

A collection of experimental, high-performance C++ scanners designed for research and benchmarking of Bitcoin elliptic-curve key derivation and address generation.

These projects demonstrate extremely optimized CPU-based processing of secp256k1 key derivation, HASH160 computation, and multiple Bitcoin address formats using multithreaded brute-force style iteration over large keyspaces.

⚙️ Core Features
High-performance multithreaded architecture (up to 32+ threads)
secp256k1-based public key generation (libsecp256k1)
Incremental public key optimization (tweak-add +1)
SHA256 + RIPEMD160 HASH160 computation
Memory-mapped address database lookup (mmap)
Binary search over preprocessed HASH160 datasets
Support for multiple Bitcoin address formats:
Legacy P2PKH (1...)
Bech32 P2WPKH (bc1...)
P2SH wrapped scripts (P2SH-P2WPKH, P2SH-P2WSH, P2SH-P2PKH)
Experimental / hybrid script formats
Progress saving & resume support
High-throughput atomic counters and worker pool design
🚀 Performance Characteristics
Extremely optimized CPU execution pipeline
Incremental key stepping instead of full regeneration
Parallel chunk-based processing
mmap-based zero-copy dataset access
Designed for sustained multi-million key evaluations per second (depending on CPU)
🧠 Project Variants

This repository includes multiple FASTSCAN versions:

FASTSCAN v2 (Base)
Compressed + uncompressed public key HASH160 scanning
P2PKH (legacy 1...) + basic Bech32 support
Core mmap binary lookup engine
FASTSCAN v2+ (Extended Scripts)

Adds support for advanced Bitcoin script types:

P2SH-P2WPKH
P2SH-P2WSH (single-sig witness script)
P2SH-P2PKH
Extended Base58 encoding pipeline

Focus: broader script coverage beyond standard P2PKH.

FASTSCAN v2 (FAKE P2PK / Experimental Mode)
Experimental reconstruction of “fake” P2PK-style addresses
Base58Check reconstruction from derived HASH160(pubkey)
Debug-oriented address transformation pipeline

Focus: research and blockchain data compatibility testing.

FASTSCAN v2 (Bech32 Optimized Variant)
Reduced compression pipeline (compressed pubkeys only)
Direct Bech32 (bc1...) encoding for P2WPKH
Lightweight hashing path for maximum throughput

Focus: performance optimization for SegWit address scanning.

📂 Required Dataset Files

The scanner requires preprocessed binary HASH160 databases:

addresses_1.bin
addresses_bc1.bin
Format:
Each file contains raw 20-byte HASH160 entries
Entries must be sorted lexicographically
File size must be divisible by 20 bytes
Stored as continuous binary blocks:
[20 bytes HASH160][20 bytes HASH160][20 bytes HASH160]...

These files are memory-mapped using mmap() for ultra-fast lookup.

🛠 Build
g++ main.cpp -O2 -std=c++17 \
    -lssl -lcrypto -lsecp256k1 -lpthread \
    -o fastscan
▶️ Usage
./fastscan addresses_1.bin <start_bit> <end_bit> [--resume]

Example:

./fastscan addresses_bc1.bin 20 80

Resume mode:

./fastscan addresses_1.bin 20 80 --resume
⚠️ Notes
Requires Linux or WSL environment
Requires OpenSSL + libsecp256k1
Performance is highly CPU-dependent (scales with cores and cache)
Uses memory-mapped binary lookup for maximum speed
📌 Important

This project is intended strictly for:

cryptographic research
educational purposes
performance benchmarking
Bitcoin protocol experimentation

You must use only datasets and keys you own or have permission to test.

🧪 Design Philosophy

FASTSCAN v2+ focuses on:

eliminating redundant EC operations
maximizing CPU cache locality
minimizing memory allocations
using incremental public key updates instead of recomputation
pushing secp256k1 to sustained high-throughput workloads
