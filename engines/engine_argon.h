// engine_argon.h - Argon2id engine
#ifndef ENGINE_ARGON_H
#define ENGINE_ARGON_H

#include <string>
#include <cstdint>
#include "nexhash_core.h"

namespace nexhash {

// Argon2id parameters per level
struct Argon2Params {
    uint32_t memory_kib;   // m (in KiB)
    uint32_t iterations;   // t
    uint32_t parallelism;  // p
    uint32_t salt_len;     // bytes
    uint32_t hash_len;     // bytes
};

// Get parameters for level 1/2/3.
// Throws std::out_of_range if level not in {1,2,3}.
Argon2Params argon2_params_for_level(Level level);

// Encode password with Argon2id at given level.
// Output: raw argon2 PHC string (no nexhash wrapper).
std::string argon2_encode(Level level, const std::string& password);

// Verify password against an argon2 PHC string.
bool argon2_verify(const std::string& phc, const std::string& password);

} // namespace nexhash

#endif
