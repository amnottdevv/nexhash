// engine_nex4mx1.cpp - Nex4MX1 keyed message hash engine implementation
//
// The core innovation here is the interleaved byte buffer with type tags.
// See engine_nex4mx1.h for the design rationale.
#include "engine_nex4mx1.h"
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

static constexpr uint32_t OUTPUT_BYTES = 1024;  // 2048 hex chars

// Tag bytes that identify which input a byte came from.
// Chosen so they cannot collide with normal ASCII printable chars (0x20-0x7E)
// or with each other, and so a buffer can be unambiguously decoded back
// into (password, text) if needed.
static constexpr uint8_t TAG_PASSWORD = 0x01;
static constexpr uint8_t TAG_TEXT     = 0x02;

static std::string get_pepper() {
    const char* p = std::getenv("NEXHASH_PEPPER");
    return p ? std::string(p) : std::string();
}

Nex4MX1Params nex4mx1_params_for_level(Level level) {
    switch (level) {
        case 1: return { 100'000, 32, OUTPUT_BYTES };
        case 2: return { 500'000, 32, OUTPUT_BYTES };
        case 3: return {1'000'000, 32, OUTPUT_BYTES };
        default: throw std::out_of_range("nex4mx1: level must be 1, 2, or 3");
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

// Append a 64-bit little-endian length to a string buffer.
static void append_u64_le(std::string& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<char>(v & 0xFF));
        v >>= 8;
    }
}

// Build the interleaved buffer.
//
// Format:
//   [len_password as 8-byte LE][len_text as 8-byte LE]
//   for i in 0..max(len_password, len_text):
//     if i < len_password:  [0x01][password[i]]
//     if i < len_text:      [0x02][text[i]]
//
// This guarantees:
//   1. Different (password, text) pairs never produce the same buffer.
//   2. Order is preserved (i=0 first, then i=1, ...).
//   3. Lengths are explicitly bound, preventing length-extension ambiguity.
//   4. Tags make the byte stream self-describing.
static std::string build_interleave_buffer(const std::string& password,
                                           const std::string& text) {
    std::string buf;
    // Header: 16 bytes (two 8-byte LE lengths)
    append_u64_le(buf, static_cast<uint64_t>(password.size()));
    append_u64_le(buf, static_cast<uint64_t>(text.size()));

    // Interleaved body with per-byte type tags.
    size_t max_len = std::max(password.size(), text.size());
    buf.reserve(16 + max_len * 4);  // worst case: 4 bytes per index (2 tags + 2 data)
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

// Phase 2-4: compress interleaved buffer through iterations.
// Produces 64-byte master key.
static void compress_iterate(const std::string& interleave_buf,
                             const std::string& salt_hex,
                             const std::string& pepper,
                             uint32_t iterations,
                             unsigned char out[64]) {
    // Initial state mixes the buffer with salt+pepper+lengths (already in buf).
    std::string init = interleave_buf + salt_hex + pepper + "nex4mx1-init";
    std::string h = SHA512::hash(init);
    std::string h256 = SHA256::hash(h + salt_hex + pepper);

    for (uint32_t i = 1; i < iterations; ++i) {
        std::string ctr = std::to_string(i);
        // Alternate SHA-512 and SHA-256 to force any attacker to invert both
        // algorithms (modest cost increase, breaks generic SHA-512 crackers).
        if ((i & 1) == 0) {
            h = SHA512::hash(h + h256 + interleave_buf + salt_hex + pepper + ctr);
            h256 = SHA256::hash(h);
        } else {
            h256 = SHA256::hash(h + h256 + interleave_buf + salt_hex + pepper + ctr);
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

// Phase 5: HKDF-expand using SHA-256 (32-byte chunks).
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

std::string nex4mx1_encode(Level level,
                           const std::string& password,
                           const std::string& text) {
    if (password.empty() && text.empty()) {
        throw std::invalid_argument(
            "nex4mx1: at least one of password or text must be non-empty"
        );
    }

    Nex4MX1Params p = nex4mx1_params_for_level(level);
    std::string pepper = get_pepper();

    // Generate salt.
    std::vector<unsigned char> salt(p.salt_bytes);
    random_bytes(salt.data(), salt.size());
    std::string salt_hex = to_hex(salt.data(), salt.size());

    // Build interleaved buffer (the core of this engine).
    std::string interleave_buf = build_interleave_buffer(password, text);

    // Compress to master key.
    unsigned char master[64];
    compress_iterate(interleave_buf, salt_hex, pepper, p.iterations, master);

    // Expand to target output length.
    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(master, salt_hex, p.output_bytes, hash.data());

    std::string hash_hex = to_hex(hash.data(), hash.size());

    std::ostringstream ss;
    ss << "$nexhash$nex4mx1$" << level << "$" << p.iterations << "$"
       << salt_hex << "$" << hash_hex;
    return ss.str();
}

bool nex4mx1_verify(const std::string& phc,
                    const std::string& password,
                    const std::string& text) {
    if (phc.rfind("$nexhash$nex4mx1$", 0) != 0) return false;

    // Parse: $nexhash$nex4mx1$<level>$<iter>$<salt_hex>$<hash_hex>
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

    if (salt_hex.size() != 64) return false;          // 32 bytes
    if (stored_hash_hex.size() != 2048) return false; // 1024 bytes

    Nex4MX1Params p;
    try {
        p = nex4mx1_params_for_level(level);
    } catch (...) { return false; }
    if (iterations == 0 || iterations > 100'000'000) return false;

    // Either input may be empty, but both empty is invalid.
    if (password.empty() && text.empty()) return false;

    std::string pepper = get_pepper();
    std::string interleave_buf = build_interleave_buffer(password, text);

    unsigned char master[64];
    compress_iterate(interleave_buf, salt_hex, pepper, iterations, master);

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
