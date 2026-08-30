// engine_nex3fh1.h - Nex3FH1 file hashing engine
//
// Purpose: Hash the CONTENTS of a file for integrity verification or
// file-based key derivation. Designed for pentesting / security research.
//
// Design:
//   * Streaming hash: file is read in 64 KiB chunks (handles large files
//     without loading them entirely into memory).
//   * SHA-512 Merkle-tree-style accumulation: each chunk updates a rolling
//     state, so the final hash depends on every byte of the file.
//   * Final iteration loop wraps the accumulated state with salt + pepper
//     to slow down brute-force attempts.
//   * HKDF-expand elongates the master key to the final output length.
//
// Output format (PHC-like):
//   $nexhash$nex3fh1$<level>$<iterations>$<file_size>$<salt_hex>$<hash_hex>
// where salt_hex is 64 hex chars (32 bytes) and hash_hex is 256 hex chars
// (128 bytes / 1024 bits).
#ifndef ENGINE_NEX3FH1_H
#define ENGINE_NEX3FH1_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex3FH1Params {
    uint32_t iterations;
    uint32_t salt_bytes;     // 32
    uint32_t chunk_size;     // 65536 (64 KiB)
    uint32_t output_bytes;   // 128 -> 256 hex chars
};

Nex3FH1Params nex3fh1_params_for_level(Level level);

// Hash a file's contents.
// Throws std::runtime_error if the file cannot be opened.
std::string nex3fh1_encode_file(Level level, const std::string& file_path);

// Verify: re-hash file at file_path, compare with stored PHC.
// Returns false if file cannot be read or hash mismatch.
bool nex3fh1_verify_file(const std::string& phc, const std::string& file_path);

} // namespace nexhash

#endif
