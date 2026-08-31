// excepts-cli.h - Helpful error reporting for the NexHash CLI
//
// Goal: when a user passes an invalid flag, a missing value, or a conflicting
// combination of flags, the CLI should print a precise error message that
// points at the offending flag and offers a small tip on how to fix it.
// This is what separates a tool that "just exits 1" from a tool that feels
// professional.
//
// All errors are printed to stderr in the format:
//
//   [error] : <message>
//   [tip]   : <suggestion>      (optional, only when a tip is available)
//
// Exit code is always 1 for argument errors. Verification failures use
// exit code 2 and are NOT reported through this module.
#ifndef NEXHASH_EXCEPTS_CLI_H
#define NEXHASH_EXCEPTS_CLI_H

#include <string>
#include <vector>

namespace nexhash::cli_errors {

// Print "[error] : <message>" in red to stderr.
void error(const std::string& message);

// Print "[tip] : <suggestion>" in cyan to stderr.
void tip(const std::string& suggestion);

// Combined helper: prints an error message and an optional tip, then exits 1.
// If tip_text is empty, only the error line is printed.
[[noreturn]] void fail(const std::string& message,
                       const std::string& tip_text = "");

// --- Specific error cases ------------------------------------------------

// Unknown flag was passed (e.g. "--verboes").
// Suggests the closest known flag by Levenshtein distance.
[[noreturn]] void unknown_flag(const std::string& flag,
                               const std::vector<std::string>& known_flags);

// Flag requires a value but none was given (e.g. "--password" at end of args).
[[noreturn]] void missing_value(const std::string& flag);

// Flag was given an invalid value (e.g. "--level abc").
[[noreturn]] void invalid_value(const std::string& flag,
                               const std::string& value,
                               const std::string& reason,
                               const std::string& tip_text = "");

// Two flags conflict and cannot be used together.
[[noreturn]] void conflict(const std::string& flag_a,
                          const std::string& flag_b,
                          const std::string& reason);

// A required flag is missing for the active command.
[[noreturn]] void required_missing(const std::string& flag,
                                  const std::string& command,
                                  const std::string& tip_text = "");

// File could not be opened for writing.
[[noreturn]] void cannot_open_output(const std::string& path,
                                     const std::string& reason);

// --- Utilities -----------------------------------------------------------

// Compute Levenshtein edit distance between two strings.
// Used by unknown_flag() to suggest the closest known flag.
int levenshtein(const std::string& a, const std::string& b);

// Find the closest match in `candidates` for `input`.
// Returns empty string if no candidate is within reasonable edit distance.
std::string closest_match(const std::string& input,
                          const std::vector<std::string>& candidates);

} // namespace nexhash::cli_errors

#endif
