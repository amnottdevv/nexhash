// engine_nex3ph1.h - Nex3PH1 custom engine
//
// Produces a 432-hex-character (1728-bit) key derived from the password.
// Design goals vs. legacy NexHash:
//   * No hardcoded pepper in source — pepper is read from $NEXHASH_PEPPER env var
//     (empty by default, which is fine; pepper is optional defense-in-depth).
//   * CSPRNG salt (std::random_device, not mt19937).
//   * PBKDF2-style iteration with counter (no security-through-obscurity mixing).
//   * HKDF-expand-style output elongation to reach exactly 432 hex chars.
//   * Constant-time final comparison.
//
// Output format (PHC-like):
//   $nexhash$nex3ph1$<level>$<iterations>$<salt_hex>$<hash_hex>
// where salt_hex is 32 hex chars (16 bytes) and hash_hex is 432 hex chars (216 bytes).
#ifndef ENGINE_NEX3PH1_H
#define ENGINE_NEX3PH1_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex3PH1Params {
    uint32_t iterations;
    uint32_t salt_bytes;    // 16
    uint32_t output_bytes;  // 216 -> 432 hex chars
};

Nex3PH1Params nex3ph1_params_for_level(Level level);

std::string nex3ph1_encode(Level level, const std::string& password);
bool nex3ph1_verify(const std::string& phc, const std::string& password);

} // namespace nexhash

#endif
