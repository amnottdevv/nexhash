// engine_bcrypt.h - Bcrypt engine
#ifndef ENGINE_BCRYPT_H
#define ENGINE_BCRYPT_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

// Bcrypt cost factor per level (log2 rounds).
// Cost N => 2^N iterations of Blowfish key setup.
struct BcryptParams {
    uint32_t cost;        // log2 rounds (4..31)
    uint32_t salt_len;    // 16 bytes (bcrypt-fixed)
};

BcryptParams bcrypt_params_for_level(Level level);

// Encode password with bcrypt at given level.
// Output: raw bcrypt PHC string ($2b$...) — no nexhash wrapper.
std::string bcrypt_encode(Level level, const std::string& password);

// Verify password against a bcrypt PHC string.
bool bcrypt_verify(const std::string& phc, const std::string& password);

} // namespace nexhash

#endif
