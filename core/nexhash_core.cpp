// nexhash_core.cpp - Dispatcher implementation
#include "nexhash_core.h"
#include "engine_argon.h"
#include "engine_bcrypt.h"
#include "engine_nex3ph1.h"
#include "engine_nex4px1.h"
#include "engine_nex3fh1.h"
#include "engine_nex4px2.h"
#include "engine_nex4mx1.h"
#include "engine_nex5mx1.h"
#include <stdexcept>
#include <algorithm>
#include <cctype>

namespace nexhash {

bool parse_engine(const std::string& name, Engine& out) {
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    // External standards
    if (lower == "argon2"   || lower == "argon2id") { out = Engine::Argon2;   return true; }
    if (lower == "bcrypt"   || lower == "2b")        { out = Engine::Bcrypt;   return true; }

    // Canonical names (new scheme)
    if (lower == "nex3ph1")  { out = Engine::Nex3PH1;  return true; }
    if (lower == "nex4px1")  { out = Engine::Nex4PX1;  return true; }
    if (lower == "nex3fh1")  { out = Engine::Nex3FH1;  return true; }
    if (lower == "nex4px2")  { out = Engine::Nex4PX2;  return true; }
    if (lower == "nex4mx1")  { out = Engine::Nex4MX1;  return true; }
    if (lower == "nex5mx1")  { out = Engine::Nex5MX1;  return true; }

    // Legacy aliases (backward compatibility — old hashes still verify)
    if (lower == "nex4dc6")  { out = Engine::Nex3PH1;  return true; }
    if (lower == "nex9d7")   { out = Engine::Nex4PX1;  return true; }
    if (lower == "nex7f1")   { out = Engine::Nex3FH1;  return true; }
    if (lower == "nex9jx5")  { out = Engine::Nex4PX2;  return true; }

    return false;
}

std::string engine_name(Engine engine) {
    switch (engine) {
        case Engine::Argon2:   return "argon2";
        case Engine::Bcrypt:   return "bcrypt";
        case Engine::Nex3PH1:  return "nex3ph1";
        case Engine::Nex4PX1:  return "nex4px1";
        case Engine::Nex3FH1:  return "nex3fh1";
        case Engine::Nex4PX2:  return "nex4px2";
        case Engine::Nex4MX1:  return "nex4mx1";
        case Engine::Nex5MX1:  return "nex5mx1";
    }
    return "unknown";
}

bool is_file_engine(Engine engine) {
    return engine == Engine::Nex3FH1;
}

bool is_message_engine(Engine engine) {
    return engine == Engine::Nex4MX1 || engine == Engine::Nex5MX1;
}

// ============= Password-based =============
std::string encode(Engine engine, Level level, const std::string& password) {
    if (!valid_level(level)) {
        throw std::out_of_range("level must be 1, 2, or 3");
    }
    switch (engine) {
        case Engine::Argon2:   return argon2_encode(level, password);
        case Engine::Bcrypt:   return bcrypt_encode(level, password);
        case Engine::Nex3PH1:  return nex3ph1_encode(level, password);
        case Engine::Nex4PX1:  return nex4px1_encode(level, password);
        case Engine::Nex4PX2:  return nex4px2_encode(level, password);
        case Engine::Nex3FH1:
            throw std::runtime_error(
                engine_name(engine) + " is a file engine; use --hash-file instead"
            );
        case Engine::Nex4MX1:
        case Engine::Nex5MX1:
            throw std::runtime_error(
                engine_name(engine) + " is a message engine; use --encode --text instead"
            );
    }
    throw std::runtime_error("unknown engine");
}

bool verify(const std::string& crypt, const std::string& password) {
    if (crypt.rfind("$argon2", 0) == 0) {
        return argon2_verify(crypt, password);
    }
    if (crypt.rfind("$2b$", 0) == 0 ||
        crypt.rfind("$2a$", 0) == 0 ||
        crypt.rfind("$2y$", 0) == 0) {
        return bcrypt_verify(crypt, password);
    }
    // Accept both new prefix and legacy alias for each custom engine.
    if (crypt.rfind("$nexhash$nex3ph1$", 0) == 0 ||
        crypt.rfind("$nexhash$nex4dc6$", 0) == 0) {
        return nex3ph1_verify(crypt, password);
    }
    if (crypt.rfind("$nexhash$nex4px1$", 0) == 0 ||
        crypt.rfind("$nexhash$nex9d7$", 0) == 0) {
        return nex4px1_verify(crypt, password);
    }
    if (crypt.rfind("$nexhash$nex4px2$", 0) == 0 ||
        crypt.rfind("$nexhash$nex9jx5$", 0) == 0) {
        return nex4px2_verify(crypt, password);
    }
    return false;
}

// ============= File-based =============
std::string encode_file(Engine engine, Level level, const std::string& file_path) {
    if (!valid_level(level)) {
        throw std::out_of_range("level must be 1, 2, or 3");
    }
    switch (engine) {
        case Engine::Nex3FH1:  return nex3fh1_encode_file(level, file_path);
        default:
            throw std::runtime_error(
                engine_name(engine) + " is not a file engine; "
                "use --encode --password or --encode --text instead"
            );
    }
}

bool verify_file(const std::string& crypt, const std::string& file_path) {
    if (crypt.rfind("$nexhash$nex3fh1$", 0) == 0 ||
        crypt.rfind("$nexhash$nex7f1$", 0) == 0) {
        return nex3fh1_verify_file(crypt, file_path);
    }
    return false;
}

// ============= Message-based (password + text) =============
std::string encode_message(Engine engine, Level level,
                           const std::string& password,
                           const std::string& text) {
    if (!valid_level(level)) {
        throw std::out_of_range("level must be 1, 2, or 3");
    }
    switch (engine) {
        case Engine::Nex4MX1:  return nex4mx1_encode(level, password, text);
        case Engine::Nex5MX1:  return nex5mx1_encode(level, password, text);
        default:
            throw std::runtime_error(
                engine_name(engine) + " is not a message engine; "
                "use --encode --password (no --text) instead"
            );
    }
}

bool verify_message(const std::string& crypt,
                    const std::string& password,
                    const std::string& text) {
    if (crypt.rfind("$nexhash$nex4mx1$", 0) == 0) {
        return nex4mx1_verify(crypt, password, text);
    }
    if (crypt.rfind("$nexhash$nex5mx1$", 0) == 0) {
        return nex5mx1_verify(crypt, password, text);
    }
    return false;
}

} // namespace nexhash
