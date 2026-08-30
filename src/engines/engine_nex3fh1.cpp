// engine_nex3fh1.cpp - Nex3FH1 file hashing engine implementation
#include "engine_nex3fh1.h"
#include "sha512.h"
#include "sha256.h"
#include <stdexcept>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <random>

namespace nexhash {

static std::string get_pepper() {
    const char* p = std::getenv("NEXHASH_PEPPER");
    return p ? std::string(p) : std::string();
}

Nex3FH1Params nex3fh1_params_for_level(Level level) {
    switch (level) {
        case 1: return {  50'000, 32, 65536, 128 };
        case 2: return { 200'000, 32, 65536, 128 };
        case 3: return { 500'000, 32, 65536, 128 };
        default: throw std::out_of_range("nex3fh1: level must be 1, 2, or 3");
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

// Phase 1: Stream file through SHA-512 in chunks.
// Returns the hex of the accumulated state and writes the total file size
// to file_size_out.
static std::string stream_file_hash(const std::string& file_path,
                                    uint32_t chunk_size,
                                    uint64_t& file_size_out) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("nex3fh1: cannot open file: " + file_path);
    }

    std::string state = "nex3fh1-init";
    std::vector<char> buf(static_cast<size_t>(chunk_size));
    uint64_t total_bytes = 0;
    uint64_t chunk_counter = 0;

    while (file) {
        file.read(buf.data(), static_cast<std::streamsize>(chunk_size));
        std::streamsize got = file.gcount();
        if (got <= 0) break;

        // state = SHA512(state || chunk_data || counter)
        std::string input = state;
        input.append(buf.data(), static_cast<size_t>(got));
        input += std::to_string(chunk_counter);
        state = SHA512::hash(input);

        total_bytes += static_cast<uint64_t>(got);
        ++chunk_counter;
    }

    file_size_out = total_bytes;
    return state;
}

// Phase 2: Apply iterations with salt + pepper to the accumulated state.
// Produces 64-byte master key.
static void iterate_state(const std::string& accumulated_state,
                          const std::string& salt_hex,
                          const std::string& pepper,
                          uint64_t file_size,
                          uint32_t iterations,
                          unsigned char out[64]) {
    std::string h = SHA512::hash(
        accumulated_state + salt_hex + pepper + std::to_string(file_size)
    );

    for (uint32_t i = 1; i < iterations; ++i) {
        h = SHA512::hash(h + salt_hex + pepper + std::to_string(i));
    }

    auto raw = from_hex(h);
    if (raw.size() != 64) {
        std::memset(out, 0, 64);
        return;
    }
    std::memcpy(out, raw.data(), 64);
}

// Phase 3: HKDF-expand to target output length using SHA-512.
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

        std::string h = SHA512::hash(input);  // 128 hex = 64 bytes
        auto raw = from_hex(h);
        if (raw.size() != 64) {
            std::memset(out + produced, 0, out_len - produced);
            return;
        }

        size_t take = std::min<size_t>(64, out_len - produced);
        std::memcpy(out + produced, raw.data(), take);
        produced += take;

        prev = h;
        ++counter;
    }
}

std::string nex3fh1_encode_file(Level level, const std::string& file_path) {
    Nex3FH1Params p = nex3fh1_params_for_level(level);
    std::string pepper = get_pepper();

    // Generate salt.
    std::vector<unsigned char> salt(p.salt_bytes);
    random_bytes(salt.data(), salt.size());
    std::string salt_hex = to_hex(salt.data(), salt.size());

    // Stream file.
    uint64_t file_size = 0;
    std::string accumulated = stream_file_hash(file_path, p.chunk_size, file_size);

    // Iterate.
    unsigned char master[64];
    iterate_state(accumulated, salt_hex, pepper, file_size, p.iterations, master);

    // Expand.
    std::vector<unsigned char> hash(p.output_bytes);
    expand_output(master, salt_hex, p.output_bytes, hash.data());

    std::string hash_hex = to_hex(hash.data(), hash.size());

    // Format: $nexhash$nex3fh1$<level>$<iter>$<file_size>$<salt_hex>$<hash_hex>
    std::ostringstream ss;
    ss << "$nexhash$nex3fh1$" << level << "$" << p.iterations << "$"
       << file_size << "$" << salt_hex << "$" << hash_hex;
    return ss.str();
}

bool nex3fh1_verify_file(const std::string& phc, const std::string& file_path) {
    if (phc.rfind("$nexhash$nex3fh1$", 0) != 0 && phc.rfind("$nexhash$nex7f1$", 0) != 0) return false;

    // Parse: $nexhash$nex3fh1$<level>$<iter>$<file_size>$<salt_hex>$<hash_hex>
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : phc) {
        if (c == '$') { tokens.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    tokens.push_back(cur);
    // tokens: ["", "nexhash", "nex3fh1", level, iter, file_size, salt_hex, hash_hex]
    if (tokens.size() != 8) return false;

    int level;
    try { level = std::stoi(tokens[3]); } catch (...) { return false; }

    uint32_t iterations;
    try {
        unsigned long it = std::stoul(tokens[4]);
        if (it > 0xFFFFFFFFULL) return false;
        iterations = static_cast<uint32_t>(it);
    } catch (...) { return false; }

    // file_size is stored but we don't strictly require it to match
    // (the hash itself depends on file contents). It is informational.
    uint64_t stored_file_size;
    try {
        unsigned long long fs = std::stoull(tokens[5]);
        stored_file_size = static_cast<uint64_t>(fs);
        (void)stored_file_size;  // suppress unused warning
    } catch (...) { return false; }

    const std::string& salt_hex = tokens[6];
    const std::string& stored_hash_hex = tokens[7];

    if (salt_hex.size() != 64) return false;        // 32 bytes
    if (stored_hash_hex.size() != 256) return false; // 128 bytes

    Nex3FH1Params p;
    try {
        p = nex3fh1_params_for_level(level);
    } catch (...) { return false; }
    if (iterations == 0 || iterations > 100'000'000) return false;

    std::string pepper = get_pepper();

    // Re-hash file. If file cannot be opened, return false (don't throw).
    uint64_t actual_file_size = 0;
    std::string accumulated;
    try {
        accumulated = stream_file_hash(file_path, p.chunk_size, actual_file_size);
    } catch (...) {
        return false;
    }

    unsigned char master[64];
    iterate_state(accumulated, salt_hex, pepper, actual_file_size, iterations, master);

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
