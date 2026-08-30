// engine_argon.cpp - Argon2id engine implementation
#include "engine_argon.h"
#include "argon2.h"
#include <stdexcept>
#include <cstring>
#include <random>
#include <sstream>
#include <vector>

namespace nexhash {

// CSPRNG using OS entropy (Linux: /dev/urandom, Windows: BCryptGenRandom)
static void random_bytes(uint8_t* buf, size_t len) {
    std::random_device rd;  // cppreference guarantees this is implementation-defined
                            // CSPRNG on most modern platforms; for production, prefer
                            // getrandom()/BCryptGenRandom directly.
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>(rd());
    }
}

Argon2Params argon2_params_for_level(Level level) {
    switch (level) {
        case 1: return { 16 * 1024,  2, 1, 16, 32 };  // 16 MiB, ~50ms
        case 2: return { 64 * 1024,  3, 1, 16, 32 };  // 64 MiB, ~200ms
        case 3: return {256 * 1024,  4, 1, 16, 32 };  // 256 MiB, ~1s
        default: throw std::out_of_range("argon2: level must be 1, 2, or 3");
    }
}

std::string argon2_encode(Level level, const std::string& password) {
    Argon2Params p = argon2_params_for_level(level);

    std::vector<uint8_t> salt(p.salt_len);
    random_bytes(salt.data(), salt.size());

    // Argon2 PHC-encoded output: ~$argon2id$v=19$m=NNNN,t=N,p=N$<salt_b64>$<hash_b64>
    // Typical length ~100-150 chars. 512 is comfortably safe.
    constexpr size_t ENCODED_BUF_LEN = 512;
    std::vector<char> encoded(ENCODED_BUF_LEN);

    int rc = argon2id_hash_encoded(
        p.iterations, p.memory_kib, p.parallelism,
        password.data(), password.size(),
        salt.data(), salt.size(),
        p.hash_len,                // hashlen (libargon2 computes hash internally)
        encoded.data(), encoded.size()
    );

    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("argon2 encode: ") + argon2_error_message(rc));
    }

    return std::string(encoded.data());
}

bool argon2_verify(const std::string& phc, const std::string& password) {
    // argon2_verify itself does a constant-time comparison internally.
    int rc = argon2id_verify(phc.c_str(), password.data(), password.size());
    return rc == ARGON2_OK;
}

} // namespace nexhash
