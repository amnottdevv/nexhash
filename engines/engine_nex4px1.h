// engine_nex4px1.h - Nex4PX1 custom engine
//
// Produces a 1240-hex-character (4960-bit) key derived from the password.
// Same design philosophy as Nex4dC6 but longer output and stronger mixing:
//   * Uses SHA-512 in the compress stage (same as Nex4dC6).
//   * Uses SHA-256 in the expand stage for finer-grained output chunks,
//     producing more T(i) blocks (and thus more diffusion per byte of output).
//   * Adds an extra "stretch" round at the end of compress for added cost.
//
// Output format (PHC-like):
//   $nexhash$nex4px1$<level>$<iterations>$<salt_hex>$<hash_hex>
// salt_hex is 64 hex chars (32 bytes), hash_hex is 1240 hex chars (620 bytes).
#ifndef ENGINE_NEX4PX1_H
#define ENGINE_NEX4PX1_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex4PX1Params {
    uint32_t iterations;
    uint32_t salt_bytes;    // 32
    uint32_t output_bytes;  // 620 -> 1240 hex chars
};

Nex4PX1Params nex4px1_params_for_level(Level level);

std::string nex4px1_encode(Level level, const std::string& password);
bool nex4px1_verify(const std::string& phc, const std::string& password);

} // namespace nexhash

#endif
