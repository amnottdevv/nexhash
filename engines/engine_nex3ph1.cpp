// engine_nex3ph1.cpp - Nex3PH1 custom engine (432 hex chars / 1728-bit output)
#include "engine_nex3ph1.h"
#include "sha512.h"
#include "sha256.h"
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

namespace nexhash {

// Optional pepper from environment. Empty if not set.
// NOTE: this is NOT compiled into the binary as a string literal — the binary
// contains only the code that *reads* the env var, not the secret itself.
static std::string get_pepper() {
    const char* p = std::getenv("NEXHASH_PEPPER");
    return p ? std::string(p) : std::string();
}

Nex3PH1Params nex3ph1_params_for_level(Level level) {
    switch (level) {
        case 1: return { 100'000, 16, 216 };  // 432 hex chars
        case 2: return { 500'000, 16, 216 };
        case 3: return {1'000'000, 16, 216 };
        default: throw std::out_of_range("nex3ph1: level must be 1, 2, or 3");
    }
}

static void random_bytes(unsigned char* buf, size_t len) {
    std::random_device rd;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<unsigned char>(rd());
    }
}

static std::string to_hex(const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0xF]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

// PBKDF2-style compression: iterate SHA-512 N times, mixing salt+password+counter.
// Returns 64 raw bytes (512 bits).
static void compress_iterate(const std::string& salt_hex,
                             const std::string& password,
                             const std::string& pepper,
                             uint32_t iterations,
                             unsigned char out[64]) {
    // Seed state: H0 = SHA512(salt || pepper || password || "Nex3PH1-init")
    std::string init = salt_hex + pepper + password + "Nex3PH1-init";
    std::string h = SHA512::hash(init);

    for (uint32_t i = 1; i < iterations; ++i) {
        // Mix in iteration counter to avoid fixed-point cycles.
        std::string ctr = std::to_string(i);
        h = SHA512::hash(h + salt_hex + pepper + password + ctr);
    }

    // Convert hex string to raw bytes.
    for (int i = 0; i < 64; ++i) {
        unsigned int b;
        std::sscanf(h.c_str() + i * 2, "%2x", &b);
        out[i] = static_cast<unsigned char>(b);
    }
}

// HKDF-expand-style elongation: produce `out_len` bytes from a 64-byte master key.
// T(0) = empty
// T(i) = SHA512(T(i-1) || master_key || counter_byte(i))
// output = T(1) || T(2) || ... truncated to out_len
static void expand_output(const unsigned char master[64],
                          const std::string& salt_hex,
                          size_t out_len,
                          unsigned char* out) {
    std::string prev;  // T(0) = empty
    size_t produced = 0;
    uint32_t counter = 1;

    while (produced < out_len) {
        // Build input: prev || master(64 raw bytes) || salt_hex || counter
        std::string input = prev;
        input.append(reinterpret_cast<const char*>(master), 64);
        input += salt_hex;
        input += std::to_string(counter);

        std::string h = SHA512::hash(input);  // 128 hex chars = 64 bytes
        // Convert to raw bytes
        unsigned char raw[64];
        for (int i = 0; i < 64; ++i) {
            unsigned int b;
            std::sscanf(h.c_str() + i * 2, "%2x", &b);
            raw[i] = static_cast<unsigned char>(b);
        }

        size_t take = std::min<size_t>(64, out_len - produced);
        std::memcpy(out + produced, raw, take);
        produced += take;

        prev = h;
        ++counter;
    }
}

std::string nex3ph1_encode(Level level, const std::string& password) {
    Nex3PH1Params p = nex3ph1_params_for_level(level);
    std::string pepper = get_pepper();

    // Generate salt.
    std::vector<unsigned char> salt(p.salt_bytes);
    random_bytes(salt.data(), salt.size());
    std::string salt_hex = to_hex(salt.data(), salt.size());

    // Compress to 64-byte master key.
    unsigned char master[64];
    compress_iterate(salt_hex, password, pepper, p.iterations, master);

    // Expand to target output length.
    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(master, salt_hex, p.output_bytes, hash.data());

    std::string hash_hex = to_hex(hash.data(), hash.size());

    // Format: $nexhash$nex3ph1$<level>$<iterations>$<salt_hex>$<hash_hex>
    std::ostringstream ss;
    ss << "$nexhash$nex3ph1$" << level << "$" << p.iterations << "$"
       << salt_hex << "$" << hash_hex;
    return ss.str();
}

bool nex3ph1_verify(const std::string& phc, const std::string& password) {
    // Parse: $nexhash$nex3ph1$<level>$<iterations>$<salt_hex>$<hash_hex>
    // Expected token count = 7 (split by '$').
    if (phc.rfind("$nexhash$nex3ph1$", 0) != 0 && phc.rfind("$nexhash$nex4dc6$", 0) != 0) return false;

    std::vector<std::string> tokens;
    std::string cur;
    for (char c : phc) {
        if (c == '$') { tokens.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    tokens.push_back(cur);
    // tokens: ["", "nexhash", "nex3ph1", level, iterations, salt_hex, hash_hex]
    if (tokens.size() != 7) return false;

    int level;
    try {
        level = std::stoi(tokens[3]);
    } catch (...) { return false; }

    uint32_t iterations;
    try {
        unsigned long it = std::stoul(tokens[4]);
        if (it > 0xFFFFFFFFULL) return false;
        iterations = static_cast<uint32_t>(it);
    } catch (...) { return false; }

    const std::string& salt_hex = tokens[5];
    const std::string& stored_hash_hex = tokens[6];

    if (salt_hex.size() != 32) return false;       // 16 bytes -> 32 hex
    if (stored_hash_hex.size() != 432) return false;  // 216 bytes -> 432 hex

    Nex3PH1Params p = nex3ph1_params_for_level(level);
    // If stored iterations differ from canonical for this level, accept the stored
    // value (allows future upgrades). But sanity-check range.
    if (iterations == 0 || iterations > 100'000'000) return false;

    std::string pepper = get_pepper();

    unsigned char master[64];
    compress_iterate(salt_hex, password, pepper, iterations, master);

    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(master, salt_hex, p.output_bytes, hash.data());

    std::string computed_hex = to_hex(hash.data(), hash.size());

    // Constant-time compare.
    if (computed_hex.size() != stored_hash_hex.size()) return false;
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < computed_hex.size(); ++i) {
        diff |= static_cast<unsigned char>(computed_hex[i])
              ^ static_cast<unsigned char>(stored_hash_hex[i]);
    }
    return diff == 0;
}

} // namespace nexhash
