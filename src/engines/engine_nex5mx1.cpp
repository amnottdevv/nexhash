// engine_nex5mx1.cpp - Nex5MX1 Argon2-based message engine implementation
#include "engine_nex5mx1.h"
#include "sha512.h"
#include "sha256.h"
#include "argon2.h"
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>

namespace nexhash {

static constexpr uint32_t OUTPUT_BYTES = 8192;  // 16384 hex chars

// Tag bytes for interleaved buffer (same scheme as nex4mx1).
static constexpr uint8_t TAG_PASSWORD = 0x01;
static constexpr uint8_t TAG_TEXT     = 0x02;

static std::string get_pepper() {
    const char* p = std::getenv("NEXHASH_PEPPER");
    return p ? std::string(p) : std::string();
}

Nex5MX1Params nex5mx1_params_for_level(Level level) {
    switch (level) {
        case 1: return { 16 * 1024,  2, 1, 10'000, 32, OUTPUT_BYTES };  // 16 MiB
        case 2: return { 64 * 1024,  3, 1, 50'000, 32, OUTPUT_BYTES };  // 64 MiB
        case 3: return {256 * 1024,  4, 1,100'000, 32, OUTPUT_BYTES };  // 256 MiB
        default: throw std::out_of_range("nex5mx1: level must be 1, 2, or 3");
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

static void append_u64_le(std::string& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<char>(v & 0xFF));
        v >>= 8;
    }
}

// Build the interleaved buffer (identical to nex4mx1's scheme).
// See engine_nex4mx1.cpp for the design rationale.
static std::string build_interleave_buffer(const std::string& password,
                                           const std::string& text) {
    std::string buf;
    append_u64_le(buf, static_cast<uint64_t>(password.size()));
    append_u64_le(buf, static_cast<uint64_t>(text.size()));

    size_t max_len = std::max(password.size(), text.size());
    buf.reserve(16 + max_len * 4);
    for (size_t i = 0; i < max_len; ++i) {
        if (i < password.size()) {
            buf.push_back(static_cast<char>(TAG_PASSWORD));
            buf.push_back(password[i]);
        }
        if (i < text.size()) {
            buf.push_back(static_cast<char>(TAG_TEXT));
            buf.push_back(text[i]);
        }
    }
    return buf;
}

// Phase 1: Argon2id to derive 64-byte master key.
// Uses interleave buffer as the "password" input and salt as the salt.
// Memory-hard: forces attacker to allocate `m` KiB per parallel lane.
static void argon2_derive_master(const std::string& interleave_buf,
                                 const uint8_t* salt,
                                 size_t salt_len,
                                 uint32_t m_kib,
                                 uint32_t t,
                                 uint32_t p,
                                 unsigned char out[64]) {
    int rc = argon2id_hash_raw(
        t, m_kib, p,
        interleave_buf.data(), interleave_buf.size(),
        salt, salt_len,
        out, 64
    );
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("nex5mx1: argon2 failed: ")
                                 + argon2_error_message(rc));
    }
}

// Phase 2: Additional SHA-512 iterations to add CPU cost on top of memory cost.
// Mixes master key with interleave buffer + salt + pepper + counter.
static void sha_iterate(const unsigned char master[64],
                        const std::string& interleave_buf,
                        const std::string& salt_hex,
                        const std::string& pepper,
                        uint32_t iterations,
                        unsigned char out[64]) {
    std::string master_hex = to_hex(master, 64);
    std::string h = SHA512::hash(master_hex + interleave_buf + salt_hex + pepper + "nex5mx1-stretch");

    for (uint32_t i = 1; i < iterations; ++i) {
        h = SHA512::hash(h + master_hex + salt_hex + pepper + std::to_string(i));
    }

    auto raw = from_hex(h);
    if (raw.size() != 64) {
        std::memset(out, 0, 64);
        return;
    }
    std::memcpy(out, raw.data(), 64);
}

// Phase 3: HKDF-expand using SHA-256 (32-byte chunks) to reach 8192 bytes.
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

        std::string h = SHA256::hash(input);
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

std::string nex5mx1_encode(Level level,
                           const std::string& password,
                           const std::string& text) {
    if (password.empty() && text.empty()) {
        throw std::invalid_argument(
            "nex5mx1: at least one of password or text must be non-empty"
        );
    }

    Nex5MX1Params p = nex5mx1_params_for_level(level);
    std::string pepper = get_pepper();

    // Generate salt.
    std::vector<unsigned char> salt(p.salt_bytes);
    random_bytes(salt.data(), salt.size());
    std::string salt_hex = to_hex(salt.data(), salt.size());

    // Build interleaved buffer.
    std::string interleave_buf = build_interleave_buffer(password, text);

    // Phase 1: Argon2id master key (memory-hard).
    unsigned char master[64];
    argon2_derive_master(interleave_buf, salt.data(), salt.size(),
                         p.argon2_memory_kib, p.argon2_iterations,
                         p.argon2_parallelism, master);

    // Phase 2: Additional SHA-512 iterations (CPU cost).
    unsigned char stretched[64];
    sha_iterate(master, interleave_buf, salt_hex, pepper, p.sha_iterations, stretched);

    // Phase 3: HKDF-expand to 8192 bytes.
    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(stretched, salt_hex, p.output_bytes, hash.data());

    std::string hash_hex = to_hex(hash.data(), hash.size());

    // Format: $nexhash$nex5mx1$<level>$<m,t,p>$<salt_hex>$<hash_hex>
    std::ostringstream ss;
    ss << "$nexhash$nex5mx1$" << level << "$"
       << p.argon2_memory_kib << "," << p.argon2_iterations << "," << p.argon2_parallelism << ","
       << p.sha_iterations << "$"
       << salt_hex << "$" << hash_hex;
    return ss.str();
}

bool nex5mx1_verify(const std::string& phc,
                    const std::string& password,
                    const std::string& text) {
    if (phc.rfind("$nexhash$nex5mx1$", 0) != 0) return false;

    // Parse: $nexhash$nex5mx1$<level>$<m,t,p,sha>$<salt_hex>$<hash_hex>
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

    // Parse argon2 params: "m,t,p,sha"
    const std::string& params_str = tokens[4];
    uint32_t m_kib, t_iter, p_lanes, sha_iter;
    {
        char dummy;
        std::istringstream ps(params_str);
        if (!(ps >> m_kib >> dummy >> t_iter >> dummy >> p_lanes >> dummy >> sha_iter)) {
            return false;
        }
        if (dummy != ',' || m_kib == 0 || t_iter == 0 || p_lanes == 0) return false;
    }

    const std::string& salt_hex = tokens[5];
    const std::string& stored_hash_hex = tokens[6];

    if (salt_hex.size() != 64) return false;
    if (stored_hash_hex.size() != 16384) return false;  // 8192 bytes

    Nex5MX1Params p;
    try {
        p = nex5mx1_params_for_level(level);
    } catch (...) { return false; }

    // Sanity check: stored argon2 params should match canonical for the level.
    // (If we ever change params, old hashes with different params can still
    // verify as long as they're in valid ranges — accept them.)
    if (m_kib > 4 * 1024 * 1024) return false;  // cap at 4 GiB
    if (t_iter == 0 || t_iter > 1000) return false;
    if (p_lanes == 0 || p_lanes > 16) return false;
    if (sha_iter > 10'000'000) return false;

    if (password.empty() && text.empty()) return false;

    std::string pepper = get_pepper();
    std::string interleave_buf = build_interleave_buffer(password, text);

    // Convert salt_hex to raw bytes for argon2.
    auto salt_raw = from_hex(salt_hex);
    if (salt_raw.size() != 32) return false;

    // Re-derive using the *stored* parameters (allows future param changes
    // without breaking old hashes).
    unsigned char master[64];
    try {
        argon2_derive_master(interleave_buf, salt_raw.data(), salt_raw.size(),
                             m_kib, t_iter, p_lanes, master);
    } catch (...) {
        return false;
    }

    unsigned char stretched[64];
    sha_iterate(master, interleave_buf, salt_hex, pepper, sha_iter, stretched);

    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(stretched, salt_hex, p.output_bytes, hash.data());

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
