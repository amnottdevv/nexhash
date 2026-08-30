// nexhash_core.h - Multi-engine password/file/message hashing dispatcher
#ifndef NEXHASH_CORE_H
#define NEXHASH_CORE_H

#include <string>

namespace nexhash {

// Available engines.
// Naming convention (per NexHash engine naming scheme v1.0):
//   nex<L><T><C><V>
//   L = Length class (1=1-9, 2=10-99, 3=100-999, 4=1000-9999, 5=10000+)
//   T = Type (P=password, F=file, M=message/keyed-hash)
//   C = Core algorithm (A=argon2, B=bcrypt, H=SHA-512, S=SHA-256, X=mixed)
//   V = Version (1-9)
enum class Engine {
    Argon2,    // External standard (Argon2id)
    Bcrypt,    // External standard (bcrypt $2b$)
    Nex3PH1,   // 432 hex / 1728-bit, password, SHA-512, v1  (formerly nex4dc6)
    Nex4PX1,   // 1240 hex / 4960-bit, password, mixed, v1   (formerly nex9d7)
    Nex3FH1,   // 256 hex / 1024-bit, file, SHA-512, v1      (formerly nex7f1)
    Nex4PX2,   // 8743 hex, password, mixed, v2              (formerly nex9jx5)
    Nex4MX1,   // 2048 hex / 8192-bit, message (password+text), mixed, v1
    Nex5MX1,   // 16384 hex / 65536-bit, message (password+text), Argon2+SHA, v1
};

using Level = int;  // 1, 2, or 3

// Check if engine operates on files (not passwords).
bool is_file_engine(Engine engine);

// Check if engine takes both password and text (message engines).
bool is_message_engine(Engine engine);

// Password-based hashing.
std::string encode(Engine engine, Level level, const std::string& password);
bool verify(const std::string& crypt, const std::string& password);

// File-based hashing.
std::string encode_file(Engine engine, Level level, const std::string& file_path);
bool verify_file(const std::string& crypt, const std::string& file_path);

// Message-based hashing (password + text).
std::string encode_message(Engine engine, Level level,
                           const std::string& password,
                           const std::string& text);
bool verify_message(const std::string& crypt,
                    const std::string& password,
                    const std::string& text);

// Parse engine name (case-insensitive). Accepts both current canonical names
// and legacy aliases (nex4dc6 -> nex3ph1, nex9d7 -> nex4px1, etc.).
// Returns false on unknown name.
bool parse_engine(const std::string& name, Engine& out);

// Canonical name for an engine (always the new name, never the legacy alias).
std::string engine_name(Engine engine);

inline bool valid_level(Level l) { return l >= 1 && l <= 3; }

} // namespace nexhash

#endif
