// excepts-cli.cpp - Helpful error reporting implementation
#include "excepts-cli.h"
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>

namespace nexhash::cli_errors {

// ANSI color codes (disabled automatically by most terminals when not a TTY,
// but we keep them — users who pipe to a file can use --no-color in the CLI).
constexpr const char* RED     = "\033[31m";
constexpr const char* CYAN    = "\033[36m";
constexpr const char* BOLD    = "\033[1m";
constexpr const char* DIM     = "\033[2m";
constexpr const char* RESET   = "\033[0m";

void error(const std::string& message) {
    std::cerr << RED << BOLD << "[error] : " << RESET
              << RED << message << RESET << "\n";
}

void tip(const std::string& suggestion) {
    std::cerr << CYAN << "[tip]   : " << RESET
              << CYAN << suggestion << RESET << "\n";
}

[[noreturn]] void fail(const std::string& message,
                       const std::string& tip_text) {
    error(message);
    if (!tip_text.empty()) {
        tip(tip_text);
    }
    std::exit(1);
}

// --- Levenshtein ---------------------------------------------------------

int levenshtein(const std::string& a, const std::string& b) {
    const size_t m = a.size();
    const size_t n = b.size();
    std::vector<int> prev(n + 1);
    std::vector<int> curr(n + 1);

    for (size_t j = 0; j <= n; ++j) prev[j] = static_cast<int>(j);

    for (size_t i = 1; i <= m; ++i) {
        curr[0] = static_cast<int>(i);
        for (size_t j = 1; j <= n; ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int del = prev[j] + 1;
            int ins = curr[j - 1] + 1;
            int sub = prev[j - 1] + cost;
            curr[j] = std::min({del, ins, sub});
        }
        std::swap(prev, curr);
    }
    return prev[n];
}

std::string closest_match(const std::string& input,
                          const std::vector<std::string>& candidates) {
    if (candidates.empty()) return "";

    std::string best;
    int best_dist = -1;
    for (const auto& c : candidates) {
        int d = levenshtein(input, c);
        if (best_dist < 0 || d < best_dist) {
            best_dist = d;
            best = c;
        }
    }

    // Only suggest if the edit distance is reasonable (<= 1/3 of input length,
    // capped at 3). Otherwise the suggestion is probably unrelated.
    int threshold = std::min(3, static_cast<int>(input.size()) / 3);
    if (best_dist > threshold) return "";
    return best;
}

// --- Specific error cases ------------------------------------------------

[[noreturn]] void unknown_flag(const std::string& flag,
                               const std::vector<std::string>& known_flags) {
    std::string suggestion = closest_match(flag, known_flags);
    std::string msg = "Unknown flag: " + flag;
    std::string tip_text;
    if (!suggestion.empty()) {
        tip_text = "Did you mean " + suggestion + "?";
    } else {
        tip_text = "Run 'nexhash --help' to see all available flags.";
    }
    fail(msg, tip_text);
}

[[noreturn]] void missing_value(const std::string& flag) {
    std::string msg = "Flag " + flag + " requires a value.";
    std::string tip_text = "Usage: nexhash ... " + flag + " <value>";
    fail(msg, tip_text);
}

[[noreturn]] void invalid_value(const std::string& flag,
                               const std::string& value,
                               const std::string& reason,
                               const std::string& tip_text) {
    std::string msg = "Invalid value for " + flag + ": '" + value + "' (" + reason + ")";
    fail(msg, tip_text);
}

[[noreturn]] void conflict(const std::string& flag_a,
                          const std::string& flag_b,
                          const std::string& reason) {
    std::string msg = "Conflicting flags: " + flag_a + " and " + flag_b;
    if (!reason.empty()) {
        msg += " — " + reason;
    }
    std::string tip_text = "Use only one of these flags per invocation.";
    fail(msg, tip_text);
}

[[noreturn]] void required_missing(const std::string& flag,
                                  const std::string& command,
                                  const std::string& tip_text) {
    std::string msg = "Required flag " + flag + " is missing for " + command + ".";
    fail(msg, tip_text);
}

[[noreturn]] void cannot_open_output(const std::string& path,
                                     const std::string& reason) {
    std::string msg = "Cannot open output file: " + path;
    if (!reason.empty()) {
        msg += " (" + reason + ")";
    }
    std::string tip_text = "Check that the path is writable and the parent directory exists.";
    fail(msg, tip_text);
}

} // namespace nexhash::cli_errors
