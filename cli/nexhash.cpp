// nexhash.cpp - Multi-engine NexHash CLI
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <cctype>
#include <thread>
#include "nexhash_core.h"
#include "warning.h"
#include "excepts-cli.h"

#ifdef _WIN32
#include <windows.h>
#endif

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"

void enable_ansi() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif
}

void print_ascii_art() {
    std::cout << CYAN << BOLD;
    std::cout << " _______                .__                  .__     \n";
    std::cout << " \\      \\   ____ ___  __|  |__ _____    _____|  |__  \n";
    std::cout << " /   |   \\_/ __ \\\\  \\/  /  |  \\\\__  \\  /  ___/  |  \\ \n";
    std::cout << "/    |    \\  ___/ >    <|   Y  \\/ __ \\_\\___ \\|   Y  \\\n";
    std::cout << "\\____|__  /\\___  >__/\\_ \\___|  (____  /____  >___|  /\n";
    std::cout << "        \\/     \\/      \\/    \\/     \\/     \\/     \\/ \n";
    std::cout << RESET;
    std::cout << MAGENTA << "v1.0 multi-engine  " << DIM
              << "argon2 | bcrypt | nex3ph1 | nex4px1 | nex3fh1 | nex4px2 | nex4mx1 | nex5mx1" << RESET << "\n";
    std::cout << CYAN << "follow github.com/amnottdevv/nexhash" << RESET << "\n\n";
}

// Banner ASCII art shown when --decode / --verify-file starts.
// Large art piece, magenta on a TTY, plain otherwise.
void print_decode_banner() {
    // Each line is a fixed-width string; padding handled by the art itself.
    static const char* art[] = {
        "                                                              @%%%%%%%##%%%@                                                            ",
        "                                                            %*-++++++++++*##%@                                                          ",
        "                                                          %*-*%           @%##@                                                         ",
        "                                                   %+----::-#%              @%##%    @@                                               ",
        "                                                    @%=----::-*              @@%#%@@*+@                                               ",
        "                                                    %%@#=----:-=%              @@@#-:=@                                               ",
        "                                                   @%##%@#=-=----+@            @#=:::=@                                               ",
        "                                                  @@%#%%@ @*====-==#@ *-=@     @=::::#@                                              ",
        "                                        @@@      %+%%%%%@   %+==+**%%@++%#*%@  @=--+@                                                ",
        "                                        #**++++++*% @%%%@    %+-+#-=+==*@%%@   @=--*                                                 ",
        "                                             @%%@@@@@#-+@   @@@@%*+**+*%+#%    @=--*@%%%%%@                                          ",
        "                                                    #--+@  @+-+#---#+-*#=-=%   @+--#@@@@@@@@@#=*                                     ",
        "                                                   %*--+@     @@%%@@%%%=-:::=% @+--#@*#@@@@@@*=*                                    ",
        "                                                 @*----+@    %+-+@  @#=---:::-*@+-=#@#                                              ",
        "                                                 @+---=@     @@@@     @*--------=-=#                                                 ",
        "                                                 @+==#@%@               @*=-------=#                                                 ",
        "                                                 @+%@@@%%%@               %*+++++++#                                                 ",
        "                                                 @@    @%%%%              %#%%@                                                    ",
        "                                                         @%%%@          @+=#%                                                      ",
        "                                                          @@%%*==========*@                                                    ",
        "                                                            @@@@%%@@@%@@@                                                            ",
    };
    constexpr size_t n = sizeof(art) / sizeof(art[0]);

    std::cout << "\n";
    std::cout << MAGENTA << BOLD;
    for (size_t i = 0; i < n; ++i) {
        std::cout << art[i] << "\n";
    }
    std::cout << RESET;

    // Pulsing "decrypting..." indicator — three dots that print with a short
    // delay, then clear the line. Falls back to a static line when stdout is
    // not a TTY (so logs/redirects don't get escape codes or empty lines).
    std::cout << CYAN << BOLD << "  >> decrypting" << RESET;
    std::cout.flush();
    for (int dot = 0; dot < 3; ++dot) {
        // ~120ms per dot — short enough to feel snappy, long enough to see.
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        std::cout << CYAN << "." << RESET;
        std::cout.flush();
    }
    // Carriage return + clear line, then newline so the actual output starts clean.
    std::cout << "\r\x1b[K";
    std::cout.flush();
    std::cout << "\n";
}

void print_help() {
    std::cout << YELLOW << "Usage:" << RESET << "\n";
    std::cout << "  nexhash --encode --engine <e> --level <n> --password \"<pw>\" [--output <file>]\n";
    std::cout << "  nexhash --encode --engine nex4mx1 --level <n> --password \"<pw>\" --text \"<msg>\"\n";
    std::cout << "  nexhash --decode --crypt \"<hash>\" --password \"<pw>\" [--text \"<msg>\"]\n";
    std::cout << "  nexhash --hash-file --engine <e> --level <n> --file <path> [--output <file>]\n";
    std::cout << "  nexhash --verify-file --crypt \"<hash>\" --file <path>\n";
    std::cout << "  nexhash --check-strength --password \"<pw>\" [--engine <e> --level <n>]\n";
    std::cout << "  nexhash --list-engines\n";
    std::cout << "  nexhash --benchmark --engine <e> --level <n>\n";
    std::cout << "  nexhash --version | --help\n\n";
    std::cout << YELLOW << "Options:" << RESET << "\n";
    std::cout << "  --encode          Hash a password (or password+text for nex4mx1)\n";
    std::cout << "  --decode          Verify a hash against the original input(s)\n";
    std::cout << "  --hash-file       Hash a file's contents (requires --file)\n";
    std::cout << "  --verify-file     Verify a file's hash (requires --file and --crypt)\n";
    std::cout << "  --check-strength  Estimate password strength and crack time\n";
    std::cout << "  --engine <e>      Engine: argon2 | bcrypt | nex3ph1 | nex4px1 | nex3fh1 | nex4px2 | nex4mx1 | nex5mx1\n";
    std::cout << "                    (Legacy aliases accepted: nex4dc6, nex9d7, nex7f1, nex9jx5)\n";
    std::cout << "  --level <n>       Security level: 1 (fast) | 2 (balanced) | 3 (paranoid)\n";
    std::cout << "  --password <p>    Password / secret key\n";
    std::cout << "  --text <msg>      Message text (for nex4mx1 / nex5mx1; combined with --password)\n";
    std::cout << "  --crypt <h>       Stored hash to verify against (decode / verify-file only)\n";
    std::cout << "  --file <path>     File path (for --hash-file / --verify-file / nex3fh1)\n";
    std::cout << "  --output <path>   Write hash to file instead of stdout (encode / hash-file)\n";
    std::cout << "  --list-engines    Show all engines and their per-level parameters\n";
    std::cout << "  --benchmark       Hash a test password and print elapsed time\n";
    std::cout << "  --version, -V     Print version info and exit\n";
    std::cout << "  --help, -h        Show this help\n\n";
    std::cout << YELLOW << "Engine naming scheme:" << RESET << "\n";
    std::cout << "  nex<L><T><C><V>  where:\n";
    std::cout << "    L = Length class (3=100-999, 4=1000-9999 hex chars)\n";
    std::cout << "    T = Type (P=password, F=file, M=message)\n";
    std::cout << "    C = Core algo (H=SHA-512, S=SHA-256, X=mixed, A=argon2, B=bcrypt)\n";
    std::cout << "    V = Version (1-9)\n\n";
    std::cout << YELLOW << "Environment:" << RESET << "\n";
    std::cout << "  NEXHASH_PEPPER    Optional pepper for custom engines. Set to a long random\n";
    std::cout << "                    string stored server-side (NOT compiled into the binary).\n";
}

void print_engines() {
    std::cout << CYAN << BOLD << "Engines:" << RESET << "\n\n";

    std::cout << GREEN << "  argon2   " << RESET << "(Argon2id, memory-hard, RFC 9106)\n";
    std::cout << "    Level 1: m=16 MiB,  t=2, p=1, hash=32 B  " << DIM << "(~50ms)"  << RESET << "\n";
    std::cout << "    Level 2: m=64 MiB,  t=3, p=1, hash=32 B  " << DIM << "(~200ms)" << RESET << "\n";
    std::cout << "    Level 3: m=256 MiB, t=4, p=1, hash=32 B  " << DIM << "(~1s)"    << RESET << "\n\n";

    std::cout << GREEN << "  bcrypt   " << RESET << "(Blowfish-based, de-facto standard)\n";
    std::cout << "    Level 1: cost=10 (2^10 rounds)  " << DIM << "(~50ms)"  << RESET << "\n";
    std::cout << "    Level 2: cost=12 (2^12 rounds)  " << DIM << "(~200ms)" << RESET << "\n";
    std::cout << "    Level 3: cost=14 (2^14 rounds)  " << DIM << "(~800ms)" << RESET << "\n\n";

    std::cout << GREEN << "  nex3ph1  " << RESET << "(custom, 432-hex-char / 1728-bit output; was nex4dc6)\n";
    std::cout << "    Level 1: 100,000 iterations    " << DIM << "(~150ms)"  << RESET << "\n";
    std::cout << "    Level 2: 500,000 iterations    " << DIM << "(~750ms)"  << RESET << "\n";
    std::cout << "    Level 3: 1,000,000 iterations  " << DIM << "(~1.5s)"   << RESET << "\n\n";

    std::cout << GREEN << "  nex4px1  " << RESET << "(custom, 1240-hex-char / 4960-bit output; was nex9d7)\n";
    std::cout << "    Level 1: 100,000 iterations    " << DIM << "(~250ms)"  << RESET << "\n";
    std::cout << "    Level 2: 500,000 iterations    " << DIM << "(~1.2s)"   << RESET << "\n";
    std::cout << "    Level 3: 1,000,000 iterations  " << DIM << "(~2.5s)"   << RESET << "\n\n";

    std::cout << GREEN << "  nex3fh1  " << RESET << "(file hashing engine, 256-hex-char / 1024-bit output; was nex7f1)\n";
    std::cout << "    Level 1: 50,000 iterations     " << DIM << "(depends on file size)"  << RESET << "\n";
    std::cout << "    Level 2: 200,000 iterations    " << DIM << "(depends on file size)"  << RESET << "\n";
    std::cout << "    Level 3: 500,000 iterations    " << DIM << "(depends on file size)"  << RESET << "\n\n";

    std::cout << GREEN << "  nex4px2  " << RESET << "(custom, 8743-hex-char output; was nex9jx5)\n";
    std::cout << "    Level 1: 100,000 iterations    " << DIM << "(~500ms)"  << RESET << "\n";
    std::cout << "    Level 2: 500,000 iterations    " << DIM << "(~2.5s)"   << RESET << "\n";
    std::cout << "    Level 3: 1,000,000 iterations  " << DIM << "(~5s)"     << RESET << "\n\n";

    std::cout << GREEN << "  nex4mx1  " << RESET << "(message engine, 2048-hex-char / 8192-bit output; password+text)\n";
    std::cout << "    Level 1: 100,000 iterations    " << DIM << "(~400ms)"  << RESET << "\n";
    std::cout << "    Level 2: 500,000 iterations    " << DIM << "(~2s)"     << RESET << "\n";
    std::cout << "    Level 3: 1,000,000 iterations  " << DIM << "(~4s)"     << RESET << "\n\n";

    std::cout << GREEN << "  nex5mx1  " << RESET << "(message engine, 16384-hex-char / 65536-bit output; Argon2id+SHA)\n";
    std::cout << "    Level 1: Argon2 m=16MB t=2  + 10k SHA-512  " << DIM << "(~150ms)"  << RESET << "\n";
    std::cout << "    Level 2: Argon2 m=64MB t=3  + 50k SHA-512  " << DIM << "(~500ms)"  << RESET << "\n";
    std::cout << "    Level 3: Argon2 m=256MB t=4 + 100k SHA-512 " << DIM << "(~2s)"     << RESET << "\n";
}

// ==================== Password strength estimator ====================

struct StrengthResult {
    int score;              // 0-4
    double entropy_bits;
    std::string verdict;    // Very Weak / Weak / Fair / Good / Strong
    std::string suggestions;
};

static StrengthResult estimate_strength(const std::string& pw) {
    StrengthResult r{};
    if (pw.empty()) {
        r.score = 0;
        r.entropy_bits = 0;
        r.verdict = "Very Weak";
        r.suggestions = "Password is empty.";
        return r;
    }

    // Character class detection
    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (char c : pw) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= 'A' && c <= 'Z') has_upper = true;
        else if (c >= '0' && c <= '9') has_digit = true;
        else has_symbol = true;
    }

    int charset_size = 0;
    if (has_lower)  charset_size += 26;
    if (has_upper)  charset_size += 26;
    if (has_digit)  charset_size += 10;
    if (has_symbol) charset_size += 32;

    // Raw entropy
    double raw_entropy = static_cast<double>(pw.size())
                         * std::log2(charset_size > 0 ? charset_size : 1);

    // Penalty for common patterns
    double penalty = 0;
    // Sequential chars (abc, 123)
    int seq_count = 0;
    for (size_t i = 2; i < pw.size(); ++i) {
        if (pw[i] - pw[i-1] == 1 && pw[i-1] - pw[i-2] == 1) seq_count++;
    }
    penalty += seq_count * 4;
    // Repeated chars (aaaa)
    int rep_count = 0;
    for (size_t i = 1; i < pw.size(); ++i) {
        if (pw[i] == pw[i-1]) rep_count++;
    }
    penalty += rep_count * 3;

    // Common password check (small list)
    static const std::vector<std::string> common = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "letmein", "monkey", "dragon", "iloveyou", "admin",
        "welcome", "master", "sunshine", "password1", "123456789"
    };
    std::string lower_pw;
    lower_pw.reserve(pw.size());
    for (char c : pw) lower_pw.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    for (const auto& c : common) {
        if (lower_pw.find(c) != std::string::npos) {
            penalty += 20;
            break;
        }
    }

    r.entropy_bits = std::max(0.0, raw_entropy - penalty);

    // Score
    if (r.entropy_bits < 28)       { r.score = 0; r.verdict = "Very Weak"; }
    else if (r.entropy_bits < 40)  { r.score = 1; r.verdict = "Weak"; }
    else if (r.entropy_bits < 60)  { r.score = 2; r.verdict = "Fair"; }
    else if (r.entropy_bits < 80)  { r.score = 3; r.verdict = "Good"; }
    else                            { r.score = 4; r.verdict = "Strong"; }

    // Suggestions
    if (pw.size() < 12)            r.suggestions += "Use at least 12 characters. ";
    if (!has_upper)                r.suggestions += "Add uppercase letters. ";
    if (!has_digit)                r.suggestions += "Add digits. ";
    if (!has_symbol)               r.suggestions += "Add symbols. ";
    if (r.suggestions.empty())     r.suggestions = "Password looks good.";

    return r;
}

// Format crack time (in seconds) as human-readable string.
static std::string format_time(double seconds) {
    if (seconds < 1)           return "less than 1 second";
    if (seconds < 60)          return std::to_string(static_cast<long long>(seconds)) + " seconds";
    if (seconds < 3600)        return std::to_string(static_cast<long long>(seconds / 60)) + " minutes";
    if (seconds < 86400)       return std::to_string(static_cast<long long>(seconds / 3600)) + " hours";
    if (seconds < 31536000)    return std::to_string(static_cast<long long>(seconds / 86400)) + " days";
    double years = seconds / 31536000.0;
    if (years < 1000)          return std::to_string(static_cast<long long>(years)) + " years";
    if (years < 1e6)           return std::to_string(static_cast<long long>(years / 1000)) + " thousand years";
    if (years < 1e9)           return std::to_string(static_cast<long long>(years / 1e6)) + " million years";
    if (years < 1e12)          return std::to_string(static_cast<long long>(years / 1e9)) + " billion years";
    return "effectively unbreakable";
}

// Rough GPU attack rates (guesses/sec) per engine, single RTX 4090.
// These are pessimistic (attacker-friendly) estimates.
static double attack_rate_guesses_per_sec(nexhash::Engine engine, nexhash::Level level) {
    double base = 0;
    switch (engine) {
        case nexhash::Engine::Argon2:   base = 100;    break;  // memory-hard limits GPU parallelism
        case nexhash::Engine::Bcrypt:   base = 1000;   break;
        case nexhash::Engine::Nex3PH1:  base = 5;      break;  // 100k+ iterations of SHA-512
        case nexhash::Engine::Nex4PX1:  base = 2;      break;  // more iterations + dual hash
        case nexhash::Engine::Nex4PX2:  base = 1;      break;  // most expensive
        case nexhash::Engine::Nex4MX1:  base = 1;      break;  // similar cost to nex4px2
        case nexhash::Engine::Nex5MX1:  base = 50;     break;  // Argon2id-based (memory-hard)
        case nexhash::Engine::Nex3FH1:  base = 0;      break;  // file engine, not applicable
    }
    if (base <= 0) return 0;
    // Higher level = slower
    return base / static_cast<double>(level);
}

// ==================== Output helpers ====================

// Write the final hash/result string to stdout (default) or to a file
// (when --output is set). On file open failure, prints a helpful error and
// exits. On success, returns silently so the caller can continue printing
// other diagnostic output if needed.
static void write_result(const std::string& result, const std::string& output_path) {
    if (output_path.empty()) {
        std::cout << result << "\n";
        return;
    }
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        nexhash::cli_errors::cannot_open_output(output_path, "ofstream open failed");
    }
    out << result;
    if (!out) {
        nexhash::cli_errors::cannot_open_output(output_path, "write failed (disk full?)");
    }
    out.close();
    std::cout << GREEN << "Hash saved to: " << output_path << RESET << "\n";
}

// ==================== Main ====================

int main(int argc, char* argv[]) {
    enable_ansi();

    std::string command, password, crypt, engine_str, file_path, text, output_path;
    int level = 2;  // default
    bool benchmark = false;

    // All known flags, used for "did you mean" suggestions on unknown flags.
    const std::vector<std::string> known_flags = {
        "--encode", "--decode", "--hash-file", "--verify-file",
        "--check-strength", "--list-engines", "--benchmark",
        "--version", "--help",
        "--engine", "--level", "--password", "--text",
        "--crypt", "--file", "--output",
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--encode") command = "encode";
        else if (arg == "--decode") command = "decode";
        else if (arg == "--hash-file") command = "hash-file";
        else if (arg == "--verify-file") command = "verify-file";
        else if (arg == "--check-strength") command = "check-strength";
        else if (arg == "--list-engines") command = "list";
        else if (arg == "--benchmark") benchmark = true;
        else if (arg == "--version" || arg == "-V") {
            std::cout << "nexhash v1.0\n";
            std::cout << "engines: argon2, bcrypt, nex3ph1, nex4px1, nex3fh1, nex4px2, nex4mx1, nex5mx1\n";
            std::cout << "legacy aliases: nex4dc6, nex9d7, nex7f1, nex9jx5 (still accepted on input)\n";
            std::cout << "build: " << __DATE__ << " " << __TIME__ << "\n";
            return 0;
        }
        else if (arg == "--help" || arg == "-h") {
            print_ascii_art();
            print_help();
            return 0;
        }
        // --- Flags with values ---
        else if (arg == "--engine") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            engine_str = argv[++i];
        }
        else if (arg == "--level") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            std::string lv = argv[++i];
            try {
                size_t pos = 0;
                int parsed = std::stoi(lv, &pos);
                if (pos != lv.size() || parsed < 1 || parsed > 3) {
                    nexhash::cli_errors::invalid_value(
                        arg, lv, "must be 1, 2, or 3",
                        "Level 1 = fast, 2 = balanced (default), 3 = paranoid.");
                }
                level = parsed;
            } catch (const std::exception&) {
                nexhash::cli_errors::invalid_value(
                    arg, lv, "not a valid integer",
                    "Level 1 = fast, 2 = balanced (default), 3 = paranoid.");
            }
        }
        else if (arg == "--password") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            password = argv[++i];
        }
        else if (arg == "--text") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            text = argv[++i];
        }
        else if (arg == "--crypt") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            crypt = argv[++i];
        }
        else if (arg == "--file") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            file_path = argv[++i];
        }
        else if (arg == "--output") {
            if (i + 1 >= argc) nexhash::cli_errors::missing_value(arg);
            output_path = argv[++i];
        }
        else {
            // Unknown flag — suggest the closest known flag.
            nexhash::cli_errors::unknown_flag(arg, known_flags);
        }
    }

    if (command.empty() && !benchmark) {
        print_ascii_art();
        print_help();
        return 0;
    }

    if (command == "list") {
        print_ascii_art();
        print_engines();
        return 0;
    }

    if (benchmark) {
        if (engine_str.empty()) {
            std::cerr << RED << "Error: --benchmark requires --engine." << RESET << "\n";
            return 1;
        }
        nexhash::Engine engine;
        if (!nexhash::parse_engine(engine_str, engine)) {
            std::cerr << RED << "Error: unknown engine: " << engine_str << RESET << "\n";
            return 1;
        }
        if (nexhash::is_file_engine(engine)) {
            std::cerr << RED << "Error: cannot benchmark file engine "
                      << nexhash::engine_name(engine) << " (requires a file)." << RESET << "\n";
            return 1;
        }
        if (nexhash::is_message_engine(engine)) {
            std::cerr << RED << "Error: cannot benchmark message engine "
                      << nexhash::engine_name(engine)
                      << " (requires --password and --text; use --encode instead)." << RESET << "\n";
            return 1;
        }
        if (!nexhash::valid_level(level)) {
            std::cerr << RED << "Error: level must be 1, 2, or 3." << RESET << "\n";
            return 1;
        }
        std::cout << CYAN << "Benchmarking " << nexhash::engine_name(engine)
                  << " level " << level << "..." << RESET << "\n";
        auto t0 = std::chrono::high_resolution_clock::now();
        std::string h = nexhash::encode(engine, level, "benchmark-test-password");
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::cout << GREEN << "Done in " << std::fixed << std::setprecision(2) << ms << " ms" << RESET << "\n";
        std::cout << DIM << "Output length: " << h.size() << " chars" << RESET << "\n";
        return 0;
    }

    // ============= ENCODE (password and/or text) =============
    if (command == "encode") {
        if (engine_str.empty()) {
            std::cerr << RED << "Error: --engine is required for --encode." << RESET << "\n";
            return 1;
        }
        nexhash::Engine engine;
        if (!nexhash::parse_engine(engine_str, engine)) {
            std::cerr << RED << "Error: unknown engine: " << engine_str << RESET << "\n";
            std::cerr << "Use --list-engines to see available engines.\n";
            return 1;
        }
        if (nexhash::is_file_engine(engine)) {
            std::cerr << RED << "Error: " << nexhash::engine_name(engine)
                      << " is a file engine. Use --hash-file --file <path> instead." << RESET << "\n";
            return 1;
        }
        if (!nexhash::valid_level(level)) {
            std::cerr << RED << "Error: level must be 1, 2, or 3." << RESET << "\n";
            return 1;
        }

        // Warn on high iteration count
        if (level == 3) {
            nexhash::warning::high_iterations();
        }

        // Detect message engine (requires --password and --text)
        bool is_msg = nexhash::is_message_engine(engine);
        if (is_msg) {
            if (password.empty() && text.empty()) {
                std::cerr << RED << "Error: " << nexhash::engine_name(engine)
                          << " requires at least one of --password or --text." << RESET << "\n";
                return 1;
            }
            std::cout << CYAN << "Starting message hash [engine=" << nexhash::engine_name(engine)
                      << ", level=" << level << "]..." << RESET << "\n";
            std::cout << DIM << "  password length: " << password.size() << " chars" << RESET << "\n";
            std::cout << DIM << "  text length:      " << text.size() << " chars" << RESET << "\n";
        } else {
            if (password.empty()) {
                std::cerr << RED << "Error: --password is required for --encode with "
                          << nexhash::engine_name(engine) << "." << RESET << "\n";
                return 1;
            }
            if (!text.empty()) {
                std::cerr << YELLOW << "Warning: --text is ignored by engine "
                          << nexhash::engine_name(engine)
                          << " (not a message engine)." << RESET << "\n";
            }
            std::cout << CYAN << "Starting hash [engine=" << nexhash::engine_name(engine)
                      << ", level=" << level << "]..." << RESET << "\n";
        }

        auto t0 = std::chrono::high_resolution_clock::now();
        std::string result;
        try {
            if (is_msg) {
                result = nexhash::encode_message(engine, level, password, text);
            } else {
                result = nexhash::encode(engine, level, password);
            }
        } catch (const std::exception& e) {
            std::cerr << RED << "Error: " << e.what() << RESET << "\n";
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::cout << GREEN << BOLD << "Hash successfully created!" << RESET
                  << DIM << "  (" << std::fixed << std::setprecision(2) << ms << " ms)" << RESET << "\n";

        // Warn on long output (skipped when writing to file, since the file
        // is precisely the recommended workaround for long output).
        if (output_path.empty()) {
            nexhash::warning::long_output(result.size());
        }

        write_result(result, output_path);
        return 0;
    }

    // ============= DECODE (verify password and/or text) =============
    if (command == "decode") {
        if (crypt.empty()) {
            nexhash::cli_errors::required_missing("--crypt", "--decode");
        }

        // Detect message-engine hash by PHC prefix.
        bool is_msg_hash = (crypt.rfind("$nexhash$nex4mx1$", 0) == 0) ||
                           (crypt.rfind("$nexhash$nex5mx1$", 0) == 0);

        if (is_msg_hash) {
            if (password.empty() && text.empty()) {
                nexhash::cli_errors::required_missing(
                    "--password (or --text)", "--decode with nex4mx1/nex5mx1"
                );
            }
        } else {
            if (password.empty()) {
                nexhash::cli_errors::required_missing("--password", "--decode");
            }
        }

        // Cinematic banner before the actual hashing work.
        print_decode_banner();

        bool ok;
        try {
            if (is_msg_hash) {
                std::cout << CYAN << "Starting message verification..." << RESET << "\n";
                ok = nexhash::verify_message(crypt, password, text);
            } else {
                std::cout << CYAN << "Starting verification..." << RESET << "\n";
                ok = nexhash::verify(crypt, password);
            }
        } catch (const std::exception& e) {
            std::cerr << RED << "Error: " << e.what() << RESET << "\n";
            return 1;
        }
        if (ok) {
            std::cout << GREEN << BOLD << "[OK] Verification SUCCESSFUL! Input matches." << RESET << "\n";
            return 0;
        } else {
            std::cout << RED << BOLD << "[FAIL] Verification FAILED! Input does not match." << RESET << "\n";
            return 2;
        }
    }

    // ============= HASH-FILE (nex7f1 or default) =============
    if (command == "hash-file") {
        if (file_path.empty()) {
            std::cerr << RED << "Error: --file is required for --hash-file." << RESET << "\n";
            return 1;
        }

        // Default engine for hash-file is nex7f1
        nexhash::Engine engine;
        if (engine_str.empty()) {
            engine = nexhash::Engine::Nex3FH1;
            std::cout << DIM << "No engine specified, using nex7f1 (file hashing engine)." << RESET << "\n";
        } else {
            if (!nexhash::parse_engine(engine_str, engine)) {
                std::cerr << RED << "Error: unknown engine: " << engine_str << RESET << "\n";
                return 1;
            }
            if (!nexhash::is_file_engine(engine)) {
                std::cerr << RED << "Error: " << nexhash::engine_name(engine)
                          << " is not a file engine. Use --encode --password instead." << RESET << "\n";
                return 1;
            }
        }
        if (!nexhash::valid_level(level)) {
            std::cerr << RED << "Error: level must be 1, 2, or 3." << RESET << "\n";
            return 1;
        }

        // Pentest warning
        nexhash::warning::file_encryption_pentest();
        if (level == 3) {
            nexhash::warning::high_iterations();
        }

        std::cout << CYAN << "Hashing file [engine=" << nexhash::engine_name(engine)
                  << ", level=" << level << "]..." << RESET << "\n";
        std::cout << DIM << "  file: " << file_path << RESET << "\n";

        auto t0 = std::chrono::high_resolution_clock::now();
        std::string result;
        try {
            result = nexhash::encode_file(engine, level, file_path);
        } catch (const std::exception& e) {
            std::cerr << RED << "Error: " << e.what() << RESET << "\n";
            nexhash::warning::file_unreadable(file_path);
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::cout << GREEN << BOLD << "File hash successfully created!" << RESET
                  << DIM << "  (" << std::fixed << std::setprecision(2) << ms << " ms)" << RESET << "\n";
        write_result(result, output_path);
        return 0;
    }

    // ============= VERIFY-FILE =============
    if (command == "verify-file") {
        if (file_path.empty()) {
            nexhash::cli_errors::required_missing("--file", "--verify-file");
        }
        if (crypt.empty()) {
            nexhash::cli_errors::required_missing("--crypt", "--verify-file");
        }

        // Pentest warning
        nexhash::warning::file_encryption_pentest();

        // Cinematic banner before the actual verify work.
        print_decode_banner();

        std::cout << CYAN << "Verifying file hash..." << RESET << "\n";
        std::cout << DIM << "  file: " << file_path << RESET << "\n";

        bool ok;
        try {
            ok = nexhash::verify_file(crypt, file_path);
        } catch (const std::exception& e) {
            std::cerr << RED << "Error: " << e.what() << RESET << "\n";
            return 1;
        }
        if (ok) {
            std::cout << GREEN << BOLD << "[OK] Verification SUCCESSFUL! File matches stored hash." << RESET << "\n";
            return 0;
        } else {
            std::cout << RED << BOLD << "[FAIL] Verification FAILED! File does not match." << RESET << "\n";
            return 2;
        }
    }

    // ============= CHECK-STRENGTH =============
    if (command == "check-strength") {
        if (password.empty()) {
            std::cerr << RED << "Error: --password is required for --check-strength." << RESET << "\n";
            return 1;
        }

        StrengthResult r = estimate_strength(password);

        std::cout << CYAN << BOLD << "Password Strength Analysis" << RESET << "\n";
        std::cout << "--------------------------------\n";
        std::cout << "  Password length:    " << password.size() << "\n";
        std::cout << "  Estimated entropy:  " << std::fixed << std::setprecision(1)
                  << r.entropy_bits << " bits\n";
        std::cout << "  Verdict:            ";

        // Color the verdict
        const char* verdict_color;
        switch (r.score) {
            case 0: verdict_color = RED;     break;
            case 1: verdict_color = RED;     break;
            case 2: verdict_color = YELLOW;  break;
            case 3: verdict_color = GREEN;   break;
            case 4: verdict_color = GREEN;   break;
            default: verdict_color = RESET;  break;
        }
        std::cout << verdict_color << BOLD << r.verdict << RESET << "\n";
        std::cout << "  Suggestions:        " << r.suggestions << "\n\n";

        // Estimated crack time per engine
        std::cout << CYAN << BOLD << "Estimated crack time (single RTX 4090 GPU):" << RESET << "\n";
        std::cout << "  (Assumes attacker knows the engine and level)\n\n";

        // If user specified engine+level, show that one specifically
        if (!engine_str.empty()) {
            nexhash::Engine e;
            if (nexhash::parse_engine(engine_str, e) && nexhash::valid_level(level)
                && !nexhash::is_file_engine(e)) {
                double rate = attack_rate_guesses_per_sec(e, level);
                // Average attack = half the search space
                double seconds = std::pow(2.0, r.entropy_bits) / (2.0 * rate);
                std::cout << "  " << GREEN << nexhash::engine_name(e) << " L" << level << ": "
                          << RESET << format_time(seconds) << "\n\n";
            } else if (nexhash::is_file_engine(e)) {
                std::cout << "  " << DIM << "Note: " << nexhash::engine_name(e)
                          << " is a file engine; crack time not applicable." << RESET << "\n\n";
            }
        }

        // Show all engines at level 2 (default comparison)
        std::cout << "  " << DIM << "Comparison at level 2:" << RESET << "\n";
        for (auto e : {nexhash::Engine::Argon2, nexhash::Engine::Bcrypt,
                       nexhash::Engine::Nex3PH1, nexhash::Engine::Nex4PX1,
                       nexhash::Engine::Nex4PX2, nexhash::Engine::Nex4MX1,
                       nexhash::Engine::Nex5MX1}) {
            double rate = attack_rate_guesses_per_sec(e, 2);
            if (rate <= 0) continue;
            double seconds = std::pow(2.0, r.entropy_bits) / (2.0 * rate);
            std::cout << "    " << std::left << std::setw(10) << nexhash::engine_name(e)
                      << ": " << format_time(seconds) << "\n";
        }

        // Weak password warning
        if (r.score <= 1) {
            std::cout << "\n";
            nexhash::warning::weak_password();
        }

        return 0;
    }

    return 0;
}
