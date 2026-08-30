// warning.h - Yellow warning message system for NexHash
//
// All warnings print to stderr in the format:
//   [warning] : <message>
// in bold yellow. Warnings are non-fatal: the program continues after printing.
#ifndef NEXHASH_WARNING_H
#define NEXHASH_WARNING_H

#include <string>
#include <cstddef>

namespace nexhash::warning {

// Print a generic warning with the given message.
void warn(const std::string& message);

// Pre-defined contextual warnings:

// Output is long; recommend saving to a file rather than copying.
// Triggered automatically when output length exceeds the threshold.
void long_output(size_t output_length);

// File encryption feature warning - only use for authorized pentesting.
// Triggered before any file hashing/verification operation.
void file_encryption_pentest();

// High iteration count - hashing may take several seconds.
// Triggered when level == 3.
void high_iterations();

// Password appears weak.
// Triggered by --check-strength when score <= 1.
void weak_password();

// File does not exist or cannot be read.
void file_unreadable(const std::string& path);

} // namespace nexhash::warning

#endif
