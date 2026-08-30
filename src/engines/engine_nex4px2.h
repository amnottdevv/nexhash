// engine_nex4px2.h - Nex4PX2 custom engine (8743 hex chars output)
//
// Same design philosophy as Nex9D7 but with substantially longer output
// for use cases that require very long key material (e.g. multi-layer
// encryption where different segments of the hash are used as independent
// sub-keys).
//
// Output format (PHC-like):
//   $nexhash$nex4px2$<level>$<iterations>$<salt_hex>$<hash_hex>
// salt_hex is 64 hex chars (32 bytes), hash_hex is exactly 8743 hex chars.
//
// Note: 8743 is an odd number of hex chars. We generate 4372 raw bytes
// (= 8744 hex chars) and truncate the final string to 8743 chars. The
// last hex char of the output therefore represents only the high 4 bits
// of the 4372nd byte; this is harmless and does not weaken the hash
// (an attacker still has to brute-force the full 4372 bytes).
#ifndef ENGINE_NEX4PX2_H
#define ENGINE_NEX4PX2_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

struct Nex4PX2Params {
    uint32_t iterations;
    uint32_t salt_bytes;      // 32
    uint32_t output_chars;    // 8743
};

Nex4PX2Params nex4px2_params_for_level(Level level);

std::string nex4px2_encode(Level level, const std::string& password);
bool nex4px2_verify(const std::string& phc, const std::string& password);

} // namespace nexhash

#endif
