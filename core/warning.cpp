// warning.cpp - Yellow warning message implementation
#include "warning.h"
#include <iostream>

namespace nexhash::warning {

// ANSI color codes
constexpr const char* YELLOW = "\033[33m";
constexpr const char* BOLD   = "\033[1m";
constexpr const char* RESET  = "\033[0m";

// Output length threshold above which we warn the user to save to a file.
constexpr size_t LONG_OUTPUT_THRESHOLD = 1000;

void warn(const std::string& message) {
    std::cerr << YELLOW << BOLD << "[warning] : " << RESET
              << YELLOW << message << RESET << "\n";
}

void long_output(size_t output_length) {
    if (output_length > LONG_OUTPUT_THRESHOLD) {
        warn("Output length is " + std::to_string(output_length)
             + " characters. Recommend saving to a file to avoid truncation.");
    }
}

void file_encryption_pentest() {
    warn("File encryption features can be misused. Only use for authorized pentesting.");
}

void high_iterations() {
    warn("High iteration count. Hashing may take several seconds.");
}

void weak_password() {
    warn("Password appears weak. Consider using a stronger password.");
}

void file_unreadable(const std::string& path) {
    warn("Cannot read file: " + path);
}

} // namespace nexhash::warning
