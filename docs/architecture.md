# Architecture

NexHash is organised as a small set of clearly separated modules. The source tree is intentionally flat enough to read top-to-bottom in a single sitting, while still separating concerns between CLI parsing, dispatch, cryptography, and individual engines.

## Source tree

```
nexhash/
├── src/
│   ├── cli/
│   │   └── nexhash.cpp              # CLI entry point and argument parsing
│   ├── core/
│   │   ├── nexhash_core.h           # Dispatcher public API
│   │   ├── nexhash_core.cpp         # Engine routing, alias parsing, backward compat
│   │   ├── warning.h                # Warning system API
│   │   └── warning.cpp              # Yellow warning message printer
│   ├── crypto/
│   │   ├── sha256.h / sha256.cpp    # SHA-256 implementation
│   │   └── sha512.h / sha512.cpp    # SHA-512 implementation
│   └── engines/
│       ├── engine_argon.h / .cpp    # Argon2id wrapper
│       ├── engine_bcrypt.h / .cpp   # bcrypt wrapper (openwall)
│       ├── engine_nex3ph1.h / .cpp  # 432-hex password engine
│       ├── engine_nex4px1.h / .cpp  # 1240-hex password engine
│       ├── engine_nex3fh1.h / .cpp  # file hashing engine
│       ├── engine_nex4px2.h / .cpp  # 8743-hex password engine
│       ├── engine_nex4mx1.h / .cpp  # 2048-hex message engine
│       └── engine_nex5mx1.h / .cpp  # 16384-hex message engine (Argon2-based)
├── lib/
│   ├── argon2/                      # PHC-winner Argon2 reference source (C)
│   │   ├── argon2.h / argon2.c      # public API + entry point
│   │   ├── core.h / core.c          # core filling logic
│   │   ├── blake2/                  # BLAKE2b used by Argon2
│   │   ├── encoding.h / encoding.c  # PHC string encoder/decoder
│   │   ├── thread.h / thread.c      # portable thread wrapper
│   │   ├── ref.c                    # pure-C implementation (default)
│   │   └── opt.c                    # SSE2 / AVX2 implementation (optional)
│   └── bcrypt/
│       ├── crypt_blowfish.h / .c    # bcrypt implementation
│       └── ow-crypt.h               # public crypt(3)-style API
├── build/                           # object files and static libraries
│   ├── libargon2.a
│   └── libcrypt_blowfish.a
├── dist/
│   └── nexhash                      # final binary
├── docs/                            # this documentation
├── .github/workflows/run_mkdocs.yml # CI workflow for docs deployment
├── mkdocs.yaml                      # MkDocs configuration
├── Makefile                         # cross-platform build
└── README.md
```

## Module responsibilities

### `src/cli/`

The CLI layer parses command-line arguments, prints user-facing output (with colour when stdout is a TTY), and forwards the parsed inputs to the dispatcher. It contains no cryptographic logic and no direct calls to engines.

### `src/core/`

The dispatcher exposes a small API:

- `parse_engine(name, &engine)` — accepts both canonical names and legacy aliases.
- `engine_name(engine)` — returns the canonical name.
- `is_file_engine(engine)` / `is_message_engine(engine)` — type predicates.
- `encode(...)` / `verify(...)` — password engines.
- `encode_file(...)` / `verify_file(...)` — file engines.
- `encode_message(...)` / `verify_message(...)` — message engines.

The verify functions auto-detect the engine from the PHC prefix, so callers do not need to know which engine produced a hash.

The warning module centralises user-facing warnings so they are consistent across commands.

### `src/crypto/`

Self-contained SHA-256 and SHA-512 implementations. They expose both an incremental `update` / `final` API and a one-shot `hash(string)` helper. They are not optimised for raw throughput — the dominant cost in NexHash is the iteration loop, not a single hash call.

### `src/engines/`

Each engine is a single header + source pair implementing `encode` and `verify` (and `encode_file` / `verify_file` for the file engine). Engines do not depend on each other; they only depend on `src/crypto/` and (for some) `lib/argon2` or `lib/bcrypt`.

### `lib/`

Vendored third-party sources. These are compiled as C (not C++) and statically linked. No modifications have been made to the upstream algorithms; the only NexHash-specific change is the `BF_ASM=0` define passed to bcrypt to force the pure-C path for portability.

## Build pipeline

The Makefile uses pattern rules to compile each source subtree with the appropriate flags:

1. **C++ sources** (`src/**/*.cpp`) are compiled with C++17, `-O2`, and include paths pointing at every `src/` subdirectory plus `lib/argon2` and `lib/bcrypt`. This lets engine sources use `#include "engine_nex5mx1.h"` without path prefixes.
2. **Argon2 C sources** are compiled with `-std=c89 -pthread` and the Argon2 include path. The blake2 subdirectory has its own pattern rule to handle the extra path component.
3. **bcrypt C sources** are compiled with `-DBF_ASM=0` to force the pure-C path, ensuring portability across MinGW and 32-bit targets.
4. Static libraries `libargon2.a` and `libcrypt_blowfish.a` are produced with `ar rcs`.
5. The final binary links all application object files plus the two static libraries and pthreads.

Object files are placed flat in `build/` (no subdirectories) with prefixes (`argon2_`, `bcrypt_`) to avoid name collisions.

## Adding a new engine

To add a new engine:

1. Create `src/engines/engine_<name>.h` and `engine_<name>.cpp`. Implement `<name>_encode` and `<name>_verify` (or `_encode_file` / `_verify_file` for a file engine, or `_encode` / `_verify` taking both password and text for a message engine).
2. Add a new value to the `Engine` enum in `src/core/nexhash_core.h`.
3. Add the canonical name (and any legacy alias) to `parse_engine` and the reverse mapping to `engine_name` in `src/core/nexhash_core.cpp`.
4. Add the new engine to the appropriate dispatch function (`encode` / `encode_file` / `encode_message` and the corresponding verify).
5. Update `is_file_engine` / `is_message_engine` if applicable.
6. Add the engine to the CLI: `print_engines()` list, the `--help` text, the `--version` output, and any relevant detection logic in `--decode`.
7. Add the source files to `APP_SRCS` in `Makefile`.
8. Add the engine to the test matrix in the `test` target.

## Verification flow

When `--decode` is invoked:

1. The CLI inspects the PHC prefix of `--crypt` to determine which engine produced it.
2. If the prefix matches a message engine (`nex4mx1`, `nex5mx1`), the CLI requires `--password` and/or `--text` and calls `verify_message`.
3. Otherwise, the CLI requires `--password` and calls `verify`.
4. The dispatcher forwards to the engine's `verify` function.
5. The engine parses the PHC string, re-derives the hash from the supplied input(s) using the stored parameters, and compares with the stored hash using a constant-time XOR accumulator.
6. The CLI prints `[OK]` or `[FAIL]` and exits with code `0` or `2`.

Legacy prefixes (`nex4dc6`, `nex9d7`, `nex7f1`, `nex9jx5`) are accepted transparently by the corresponding engine's verify function.

## Output format

Every custom engine produces a PHC-style string with `$`-delimited fields:

```
$nexhash$<engine>$<level>$<params>$<salt_hex>$<hash_hex>
```

The `<params>` field is engine-specific:

- For pure iteration engines (`nex3ph1`, `nex4px1`, `nex4px2`, `nex4mx1`): just the iteration count.
- For the file engine (`nex3fh1`): iteration count and file size.
- For the Argon2-based message engine (`nex5mx1`): `m,t,p,sha_iter` (Argon2 memory, iterations, parallelism, plus the SHA stretch count).

All hex strings are lowercase. Salt and hash lengths are fixed per engine and validated on verify.
