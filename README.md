# NexHash

Multi-engine password, file, and message hashing CLI.

NexHash provides eight hashing engines (six custom + two industry standards) with three security levels each. It supports password hashing, streaming file hashing, and keyed-message authentication in a single binary with no runtime dependencies.

## Engines

| Engine    | Output (hex) | Type    | Algorithm                              |
|-----------|--------------|---------|----------------------------------------|
| `argon2`  | 43 chars     | passwd  | Argon2id (RFC 9106, memory-hard)       |
| `bcrypt`  | 53 chars     | passwd  | bcrypt ($2b$)                          |
| `nex3ph1` | 432 chars    | passwd  | PBKDF2-style + HKDF-expand (SHA-512)   |
| `nex4px1` | 1240 chars   | passwd  | PBKDF2-style + HKDF-expand (SHA mixed) |
| `nex3fh1` | 256 chars    | file    | Streaming SHA-512 + iter + HKDF        |
| `nex4px2` | 8743 chars   | passwd  | PBKDF2-style + HKDF-expand (SHA mixed) |
| `nex4mx1` | 2048 chars   | message | Interleaved P+T + PBKDF2 + HKDF        |
| `nex5mx1` | 16384 chars  | message | Interleaved P+T + Argon2id + SHA + HKDF|

## Quick start

```bash
# Build (Linux / macOS)
make

# Build (Windows, MSYS2 MinGW 64-bit terminal)
mingw32-make

# Hash a password
./dist/nexhash --encode --engine argon2 --level 2 --password "secret"

# Verify a password
./dist/nexhash --decode --crypt "<hash>" --password "secret"

# Hash a file
./dist/nexhash --hash-file --file document.pdf --level 2

# Hash a keyed message (password + text)
./dist/nexhash --encode --engine nex5mx1 --level 2 \
  --password "secret" --text "message to authenticate"

# Check password strength
./dist/nexhash --check-strength --password "MyP@ssw0rd"

# List engines
./dist/nexhash --list-engines
```

## Documentation

Full documentation is in the [`docs/`](docs/) directory and is published via MkDocs. See [Installation](docs/install.md), [Usage](docs/usage.md), [Engines](docs/engines.md), [Security](docs/security.md), [Naming scheme](docs/naming-scheme.md), and [Architecture](docs/architecture.md).

## Build

The Makefile is cross-platform and works with GCC, Clang, and MinGW-w64. Argon2 and bcrypt are statically linked from vendored sources in `lib/` so there are no runtime library dependencies.

```bash
make              # build the binary
make test         # run roundtrip tests for all engines
make benchmark    # benchmark all engines at level 1
make clean        # remove build artifacts
make help         # show all targets
```

See [Installation](docs/install.md) for Windows-specific instructions and build variables.

## Pepper (optional)

Custom engines accept a server-side pepper via the `NEXHASH_PEPPER` environment variable. The pepper is never compiled into the binary.

```bash
export NEXHASH_PEPPER="$(openssl rand -hex 32)"
./dist/nexhash --encode --engine nex3ph1 --level 2 --password "secret"
```

## License

- NexHash code: MIT
- Argon2 reference implementation: CC0 / Apache 2.0
- crypt_blowfish: Public domain (Solar Designer / Openwall)
