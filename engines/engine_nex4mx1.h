// engine_nex4mx1.h - Nex4MX1 keyed message hash engine
//
// Combines a password (key) with arbitrary text (message) to produce a
// 2048-hex-char (8192-bit) hash. Designed for authenticated message hashing
// where both the secret (password) and the data (text) must influence the
// output in a cryptographically inseparable way.
//
// Design philosophy (NOT naive concatenation):
//   Instead of feeding "password + text" to a hash function (which has
//   collision problems: ("ab", "c") and ("a", "bc") produce the same input),
//   Nex4MX1 builds an interleaved buffer with per-byte type tags:
//
//     [len_pw 8B LE][len_text 8B LE]
//     [0x01][pw[0]][0x02][text[0]]
//     [0x01][pw[1]][0x02][text[1]]
//     ...
//     [0x02][text[k]]   (when password exhausted)
//     ...
//
//   Tag bytes 0x01 and 0x02 identify the next byte as password or text,
//   so (P="a", T="bc") and (P="ab", T="c") produce different buffers.
//   Length prefixes at the start also bind the exact lengths, preventing
//   any length-extension-style ambiguity.
//
// Naming (per NexHash engine naming scheme v1.0):
//   nex  4    M   X   1
//   |    |    |   |   |
//   |    |    |   |   └─ version 1
//   |    |    |   └──── miXed (SHA-256 + SHA-512)
//   |    |    └──────── Message (password + text)
//   |    └───────────── Length class 4 (1000-9999 hex chars; this = 2048)
//   └───────────────── NexHash prefix
//
// Output format (PHC-like):
//   $nexhash$nex4mx1$<level>$<iterations>$<salt_hex>$<hash_hex>
// salt_hex is 64 hex chars (32 bytes), hash_hex is exactly 2048 hex chars
// (1024 bytes).
#ifndef ENGINE_NEX4MX1_H
#define ENGINE_NEX4MX1_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex4MX1Params {
    uint32_t iterations;
    uint32_t salt_bytes;     // 32
    uint32_t output_bytes;   // 1024 -> 2048 hex chars
};

Nex4MX1Params nex4mx1_params_for_level(Level level);

// Encode: hash the combination of password + text.
// Either password or text may be empty, but not both.
// Throws std::invalid_argument if both are empty.
std::string nex4mx1_encode(Level level,
                           const std::string& password,
                           const std::string& text);

// Verify: re-derive hash from password + text, compare with stored PHC.
// Returns false if inputs are invalid or hash mismatch.
bool nex4mx1_verify(const std::string& phc,
                    const std::string& password,
                    const std::string& text);

} // namespace nexhash

#endif
