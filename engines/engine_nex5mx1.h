// engine_nex5mx1.h - Nex5MX1 Argon2-based message engine
//
// Combines a password (key) with arbitrary text (message) to produce a
// 16384-hex-char (65536-bit) hash. Uses Argon2id (memory-hard) as the
// core KDF, then HKDF-expand to elongate to the final output length.
//
// Design philosophy:
//   * Same interleaved password+text buffer as nex4mx1 (anti-collision).
//   * Argon2id produces a 64-byte master key with memory-hardness, so
//     GPU/ASIC attackers must allocate large memory per parallel lane.
//   * Additional PBKDF2-style SHA-512 iterations add CPU cost on top of
//     the memory cost.
//   * HKDF-expand elongates the master key to 8192 bytes (16384 hex chars).
//
// Naming (per NexHash engine naming scheme v1.0):
//   nex  5    M   X   1
//   |    |    |   |   |
//   |    |    |   |   └─ version 1
//   |    |    |   └──── miXed (Argon2id + SHA-512 + SHA-256)
//   |    |    └──────── Message (password + text)
//   |    └───────────── Length class 5 (10000+ hex chars; this = 16384)
//   └───────────────── NexHash prefix
//
// Output format (PHC-like):
//   $nexhash$nex5mx1$<level>$<argon2_params>$<salt_hex>$<hash_hex>
// where:
//   argon2_params = m,t,p (e.g. "65536,3,1" = 64 MiB, 3 iterations, 1 lane)
//   salt_hex      = 64 hex chars (32 bytes)
//   hash_hex      = exactly 16384 hex chars (8192 bytes)
#ifndef ENGINE_NEX5MX1_H
#define ENGINE_NEX5MX1_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex5MX1Params {
    uint32_t argon2_memory_kib;   // m (Argon2 memory in KiB)
    uint32_t argon2_iterations;   // t (Argon2 iterations)
    uint32_t argon2_parallelism;  // p (Argon2 lanes)
    uint32_t sha_iterations;      // additional SHA-512 rounds
    uint32_t salt_bytes;          // 32
    uint32_t output_bytes;        // 8192 -> 16384 hex chars
};

Nex5MX1Params nex5mx1_params_for_level(Level level);

// Encode: hash the combination of password + text using Argon2id.
// Either password or text may be empty, but not both.
// Throws std::invalid_argument if both are empty.
std::string nex5mx1_encode(Level level,
                           const std::string& password,
                           const std::string& text);

// Verify: re-derive hash from password + text, compare with stored PHC.
bool nex5mx1_verify(const std::string& phc,
                    const std::string& password,
                    const std::string& text);

} // namespace nexhash

#endif
