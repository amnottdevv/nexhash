// engine_nex4px2.cpp - Nex4PX2 custom engine (8743 hex chars output)
#include "engine_nex4px2.h"
#include "sha512.h"
#include "sha256.h"
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <algorithm>

namespace nexhash {

// Output is exactly 8743 hex chars. 8743 / 2 = 4371.5, so we generate
// 4372 raw bytes (= 8744 hex chars) and truncate the final string to 8743.
static constexpr uint32_t OUTPUT_CHARS = 8743;
static constexpr uint32_t OUTPUT_BYTES = 4372;  // 8744 hex chars, truncate to 8743

static std::string get_pepper() {
    const char* p = std::getenv("NEXHASH_PEPPER");
    return p ? std::string(p) : std::string();
}

Nex4PX2Params nex4px2_params_for_level(Level level) {
    switch (level) {
        case 1: return { 100'000, 32, OUTPUT_CHARS };
        case 2: return { 500'000, 32, OUTPUT_CHARS };
        case 3: return {1'000'000, 32, OUTPUT_CHARS };
        default: throw std::out_of_range("nex4px2: level must be 1, 2, or 3");
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

static std::vector<unsigned char> from_hex(const std::string& s) {
    if (s.size() % 2 != 0) return {};
    std::vector<unsigned char> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int b;
        if (std::sscanf(s.c_str() + i * 2, "%2x", &b) != 1) return {};
        out[i] = static_cast<unsigned char>(b);
    }
    return out;
}

// Stronger compress: dual-hash (SHA-512 + SHA-256) chained with counter.
// Produces 64 bytes of master key material.
static void compress_iterate(const std::string& salt_hex,
                             const std::string& password,
                             const std::string& pepper,
                             uint32_t iterations,
                             unsigned char out[64]) {
    std::string init = salt_hex + pepper + password + "Nex4PX2-init";
    std::string h = SHA512::hash(init);
    std::string h256 = SHA256::hash(h + salt_hex + pepper + password);

    for (uint32_t i = 1; i < iterations; ++i) {
        std::string ctr = std::to_string(i);
        // Alternate SHA-512 and SHA-256 to force both algorithms to be inverted
        // by any attacker (modest cost increase, no real entropy gain, but
        // makes generic hardware-accelerated SHA-512 crackers less useful).
        if ((i & 1) == 0) {
            h = SHA512::hash(h + h256 + salt_hex + pepper + password + ctr);
            h256 = SHA256::hash(h);
        } else {
            h256 = SHA256::hash(h + h256 + salt_hex + pepper + password + ctr);
            h = SHA512::hash(h256 + h);
        }
    }

    // Final stretch: 4 extra rounds to break any iterative shortcut.
    for (int s = 0; s < 4; ++s) {
        h = SHA512::hash(h + h256 + std::to_string(s));
    }

    auto raw = from_hex(h);
    if (raw.size() != 64) {
        std::memset(out, 0, 64);
        return;
    }
    std::memcpy(out, raw.data(), 64);
}

// HKDF-expand using SHA-256 (32-byte chunks). More iterations needed than
// SHA-512 but better diffusion per output byte for our purposes.
static void expand_output(const unsigned char master[64],
                          const std::string& salt_hex,
                          size_t out_len,
                          unsigned char* out) {
    std::string prev;
    size_t produced = 0;
    uint32_t counter = 1;

    while (produced < out_len) {
        std::string input = prev;
        input.append(reinterpret_cast<const char*>(master), 64);
        input += salt_hex;
        input += std::to_string(counter);

        std::string h = SHA256::hash(input);  // 64 hex chars = 32 bytes
        auto raw = from_hex(h);
        if (raw.size() != 32) {
            std::memset(out + produced, 0, out_len - produced);
            return;
        }

        size_t take = std::min<size_t>(32, out_len - produced);
        std::memcpy(out + produced, raw.data(), take);
        produced += take;

        prev = h;
        ++counter;
    }
}

std::string nex4px2_encode(Level level, const std::string& password) {
    Nex4PX2Params p = nex4px2_params_for_level(level);
    std::string pepper = get_pepper();

    std::vector<unsigned char> salt(p.salt_bytes);
    random_bytes(salt.data(), salt.size());
    std::string salt_hex = to_hex(salt.data(), salt.size());

    unsigned char master[64];
    compress_iterate(salt_hex, password, pepper, p.iterations, master);

    // Generate 4372 bytes (= 8744 hex chars), then truncate to 8743 chars.
    std::vector<unsigned char> hash(OUTPUT_BYTES);
    expand_output(master, salt_hex, OUTPUT_BYTES, hash.data());

    std::string hash_hex_full = to_hex(hash.data(), hash.size());
    std::string hash_hex = hash_hex_full.substr(0, OUTPUT_CHARS);

    std::ostringstream ss;
    ss << "$nexhash$nex4px2$" << level << "$" << p.iterations << "$"
       << salt_hex << "$" << hash_hex;
    return ss.str();
}

bool nex4px2_verify(const std::string& phc, const std::string& password) {
    if (phc.rfind("$nexhash$nex4px2$", 0) != 0 && phc.rfind("$nexhash$nex9jx5$", 0) != 0) return false;

    std::vector<std::string> tokens;
    std::string cur;
    for (char c : phc) {
        if (c == '$') { tokens.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    tokens.push_back(cur);
    if (tokens.size() != 7) return false;

    int level;
    try { level = std::stoi(tokens[3]); } catch (...) { return false; }

    uint32_t iterations;
    try {
        unsigned long it = std::stoul(tokens[4]);
        if (it > 0xFFFFFFFFULL) return false;
        iterations = static_cast<uint32_t>(it);
    } catch (...) { return false; }

    const std::string& salt_hex = tokens[5];
    const std::string& stored_hash_hex = tokens[6];

    if (salt_hex.size() != 64) return false;
    if (stored_hash_hex.size() != OUTPUT_CHARS) return false;

    Nex4PX2Params p;
    try {
        p = nex4px2_params_for_level(level);
    } catch (...) { return false; }
    if (iterations == 0 || iterations > 100'000'000) return false;

    std::string pepper = get_pepper();

    unsigned char master[64];
    compress_iterate(salt_hex, password, pepper, iterations, master);

    std::vector<unsigned char> hash(OUTPUT_BYTES);
    expand_output(master, salt_hex, OUTPUT_BYTES, hash.data());

    std::string computed_hex_full = to_hex(hash.data(), hash.size());
    std::string computed_hex = computed_hex_full.substr(0, OUTPUT_CHARS);

    if (computed_hex.size() != stored_hash_hex.size()) return false;
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < computed_hex.size(); ++i) {
        diff |= static_cast<unsigned char>(computed_hex[i])
              ^ static_cast<unsigned char>(stored_hash_hex[i]);
    }
    return diff == 0;
}

} // namespace nexhash
