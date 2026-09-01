// engine_bcrypt.cpp - Bcrypt engine using openwall crypt_blowfish
#include "engine_bcrypt.h"

extern "C" {
#include "crypt_blowfish.h"
}

#include <stdexcept>
#include <cstring>
#include <random>
#include <sstream>

namespace nexhash {

// Output buffer size for bcrypt PHC string. bcrypt output is:
//   "$2b$" + "NN" + "$" + 22-char-salt + 31-char-hash + NUL
//   = 4 + 2 + 1 + 22 + 31 + 1 = 61 bytes. 64 is safe.
static constexpr int BCRYPT_OUTPUT_SIZE = 64;
// Salt string buffer for crypt_gensalt output.
static constexpr int BCRYPT_SALT_STR_SIZE = 32;

BcryptParams bcrypt_params_for_level(Level level) {
    switch (level) {
        case 1: return { 10, 16 };  // ~50ms
        case 2: return { 12, 16 };  // ~200ms
        case 3: return { 14, 16 };  // ~800ms
        default: throw std::out_of_range("bcrypt: level must be 1, 2, or 3");
    }
}

static void random_bytes(unsigned char* buf, size_t len) {
    std::random_device rd;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<unsigned char>(rd());
    }
}

std::string bcrypt_encode(Level level, const std::string& password) {
    BcryptParams p = bcrypt_params_for_level(level);

    // Generate raw 16-byte salt, then encode it into a bcrypt salt string.
    unsigned char raw_salt[16];
    random_bytes(raw_salt, sizeof(raw_salt));

    char salt_str[BCRYPT_SALT_STR_SIZE];
    char* s = _crypt_gensalt_blowfish_rn(
        "$2b$",                                       // prefix
        static_cast<unsigned long>(p.cost),
        reinterpret_cast<const char*>(raw_salt),
        static_cast<int>(sizeof(raw_salt)),
        salt_str,
        static_cast<int>(sizeof(salt_str))
    );
    if (s == nullptr) {
        throw std::runtime_error("bcrypt: _crypt_gensalt_blowfish_rn failed");
    }

    // Hash the password with the salt string.
    char output[BCRYPT_OUTPUT_SIZE];
    char* result = _crypt_blowfish_rn(password.c_str(), salt_str,
                                      output, sizeof(output));
    if (result == nullptr) {
        throw std::runtime_error("bcrypt: _crypt_blowfish_rn failed");
    }

    return std::string(result);
}

bool bcrypt_verify(const std::string& phc, const std::string& password) {
    // Re-hash password using the salt+cost embedded in the stored PHC.
    // If password matches, the output will be identical to the input PHC.
    char output[BCRYPT_OUTPUT_SIZE];
    char* result = _crypt_blowfish_rn(password.c_str(), phc.c_str(),
                                      output, sizeof(output));
    if (result == nullptr) {
        return false;
    }

    // Constant-time comparison (openwall doesn't guarantee one internally).
    std::string computed(result);
    if (computed.size() != phc.size()) {
        return false;
    }
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < computed.size(); ++i) {
        diff |= static_cast<unsigned char>(computed[i]) ^ static_cast<unsigned char>(phc[i]);
    }
    return diff == 0;
}

} // namespace nexhash
