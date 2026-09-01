# NexHash

NexHash is a multi-engine password, file, and message hashing command-line tool. It bundles eight hashing engines — two industry standards (Argon2id, bcrypt) and six custom engines — with three security levels each, into a single statically-linked binary.

## What it does

- **Password hashing** — generate PHC-format password hashes suitable for storage.
- **File hashing** — stream large files through a keyed digest without loading them entirely into memory.
- **Keyed-message hashing** — combine a secret (password) with arbitrary text and produce a collision-resistant authenticated digest.
- **Password strength estimation** — analyze a password and estimate crack time against each engine.
- **Benchmarking** — measure per-engine hashing time on the current machine.

## Engines at a glance

| Engine    | Output (hex) | Type    | Memory-hard | Use case                          |
|-----------|--------------|---------|-------------|-----------------------------------|
| `argon2`  | 43 chars     | passwd  | yes         | Password storage (recommended)    |
| `bcrypt`  | 53 chars     | passwd  | partial     | Password storage (legacy compat)  |
| `nex3ph1` | 432 chars    | passwd  | no          | Long password hashes              |
| `nex4px1` | 1240 chars   | passwd  | no          | Very long password hashes         |
| `nex3fh1` | 256 chars    | file    | no          | File integrity / keyed file hash  |
| `nex4px2` | 8743 chars   | passwd  | no          | Experimental very long key deriv. |
| `nex4mx1` | 2048 chars   | message | no          | Keyed-message authentication      |
| `nex5mx1` | 16384 chars  | message | yes         | Keyed-message authentication (hardened) |

See [Engines](engines.md) for parameter tables and design notes, or [Naming scheme](naming-scheme.md) for how engine names are decoded.

## Why use it

- **Single binary, no runtime dependencies.** Argon2 and bcrypt are vendored and statically linked.
- **Cross-platform.** Builds on Linux, macOS, and Windows (MinGW-w64).
- **Self-describing hashes.** Every hash encodes its engine, level, and parameters, so old hashes keep verifying even after parameter upgrades.
- **Optional server-side pepper.** Pepper is read from an environment variable, never compiled into the binary.
- **Constant-time verification.** All comparisons use XOR accumulators to avoid timing leaks.

## Where to go next

- [Installation](install.md) — how to build NexHash from source.
- [Usage](usage.md) — complete CLI flag reference.
- [CLI overview](cli.md) — screenshots and example invocations.
- [Engines](engines.md) — full engine specifications.
- [Security](security.md) — threat model, recommendations, and known limitations.
- [Architecture](architecture.md) — source tree layout and design notes.
