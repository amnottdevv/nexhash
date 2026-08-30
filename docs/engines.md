# Engines

NexHash ships with eight engines. Each one has a stable output format and is self-describing — the engine name, level, and parameters are encoded in the produced hash, so verification does not need any out-of-band configuration.

## Standards-based engines

### `argon2` — Argon2id (RFC 9106)

Memory-hard password hashing. Winner of the Password Hashing Competition (2015). The recommended default for new password storage.

Output format (standard PHC):

```
$argon2id$v=19$m=<mem>,t=<iter>,p=<lanes>$<salt_b64>$<hash_b64>
```

| Level | Memory (m) | Iterations (t) | Parallelism (p) | Hash length |
|-------|-----------|----------------|-----------------|-------------|
| 1     | 16 MiB    | 2              | 1               | 32 bytes    |
| 2     | 64 MiB    | 3              | 1               | 32 bytes    |
| 3     | 256 MiB   | 4              | 1               | 32 bytes    |

### `bcrypt` — Blowfish-based (Openwall crypt_blowfish)

The de-facto standard for legacy password storage. Uses the `$2b$` prefix.

Output format (standard PHC):

```
$2b$<cost>$<salt_hash_53_chars>
```

| Level | Cost (log2 rounds) |
|-------|--------------------|
| 1     | 10                 |
| 2     | 12                 |
| 3     | 14                 |

## Custom password engines

### `nex3ph1` — 432-hex-char password hash

PBKDF2-style iteration of SHA-512 followed by HKDF-expand to elongate the master key to 216 bytes (432 hex chars).

Output format:

```
$nexhash$nex3ph1$<level>$<iterations>$<salt_hex>$<hash_hex>
```

Salt is 16 bytes (32 hex chars). Hash is 216 bytes (432 hex chars).

| Level | Iterations |
|-------|------------|
| 1     | 100,000    |
| 2     | 500,000    |
| 3     | 1,000,000  |

### `nex4px1` — 1240-hex-char password hash

Dual-hash (SHA-512 + SHA-256) chained iteration. Alternating hash algorithms force any attacker to invert both.

Output format:

```
$nexhash$nex4px1$<level>$<iterations>$<salt_hex>$<hash_hex>
```

Salt is 32 bytes (64 hex chars). Hash is 620 bytes (1240 hex chars).

| Level | Iterations |
|-------|------------|
| 1     | 100,000    |
| 2     | 500,000    |
| 3     | 1,000,000  |

### `nex4px2` — 8743-hex-char password hash

Same construction as `nex4px1` but produces a substantially longer output. The 8743-character length is achieved by generating 4372 raw bytes (8744 hex chars) and truncating the final string by one character.

Output format:

```
$nexhash$nex4px2$<level>$<iterations>$<salt_hex>$<hash_hex>
```

Salt is 32 bytes (64 hex chars). Hash is 4372 bytes (8743 hex chars after truncation).

| Level | Iterations |
|-------|------------|
| 1     | 100,000    |
| 2     | 500,000    |
| 3     | 1,000,000  |

## File engine

### `nex3fh1` — Streaming file hash

Hashes the contents of a file in 64 KiB chunks, accumulating a rolling SHA-512 state. The file is never loaded entirely into memory, so very large files can be hashed efficiently. After streaming, the accumulated state is wrapped with salt and pepper through a fixed iteration count, then HKDF-expanded to 128 bytes (256 hex chars).

Output format:

```
$nexhash$nex3fh1$<level>$<iterations>$<file_size>$<salt_hex>$<hash_hex>
```

Salt is 32 bytes (64 hex chars). Hash is 128 bytes (256 hex chars). The file size is stored for informational purposes; the hash itself depends on every byte of the file.

| Level | Iterations |
|-------|------------|
| 1     | 50,000     |
| 2     | 200,000    |
| 3     | 500,000    |

## Message engines

Message engines combine a password (acting as a secret key) with arbitrary text. Both inputs are interleaved into a single buffer with per-byte type tags before being fed to the underlying KDF. This prevents the collision problem that naive `password + text` concatenation suffers from — `("ab", "c")` and `("a", "bc")` produce different buffers.

### `nex4mx1` — 2048-hex-char keyed message hash

Pure-CPU construction: PBKDF2-style alternating SHA-512 / SHA-256 iterations, then HKDF-expand to 1024 bytes (2048 hex chars).

Output format:

```
$nexhash$nex4mx1$<level>$<iterations>$<salt_hex>$<hash_hex>
```

Salt is 32 bytes (64 hex chars). Hash is 1024 bytes (2048 hex chars).

| Level | Iterations |
|-------|------------|
| 1     | 100,000    |
| 2     | 500,000    |
| 3     | 1,000,000  |

### `nex5mx1` — 16384-hex-char keyed message hash, Argon2id-based

Three-phase construction:

1. **Argon2id** (memory-hard) derives a 64-byte master key from the interleaved buffer and salt.
2. **SHA-512 stretch** adds CPU cost on top of the memory cost.
3. **HKDF-expand** (SHA-256) elongates the master key to 8192 bytes (16384 hex chars).

Output format:

```
$nexhash$nex5mx1$<level>$<m,t,p,sha_iter>$<salt_hex>$<hash_hex>
```

The Argon2 parameters (`m`, `t`, `p`) and the SHA iteration count are stored in the PHC string itself, so hashes generated with older parameters continue to verify correctly even if future versions change the defaults.

| Level | Argon2 memory (m) | Argon2 iterations (t) | Parallelism (p) | SHA-512 iterations |
|-------|-------------------|------------------------|------------------|--------------------|
| 1     | 16 MiB            | 2                      | 1                | 10,000             |
| 2     | 64 MiB            | 3                      | 1                | 50,000             |
| 3     | 256 MiB           | 4                      | 1                | 100,000            |

## Legacy engine aliases

Old engine names from earlier NexHash releases are still accepted on input. Output always uses the canonical name.

| Old name   | Canonical name |
|------------|----------------|
| `nex4dc6`  | `nex3ph1`      |
| `nex9d7`   | `nex4px1`      |
| `nex7f1`   | `nex3fh1`      |
| `nex9jx5`  | `nex4px2`      |

Hashes generated with the old prefixes will continue to verify. New hashes use the canonical prefix.

## Recommendations

| Use case                                | Recommended engine    | Recommended level |
|-----------------------------------------|-----------------------|-------------------|
| Password storage (new deployment)       | `argon2`              | 2 or 3            |
| Password storage (legacy compat)        | `bcrypt`              | 2                 |
| File integrity verification             | `nex3fh1`             | 2                 |
| Keyed-message authentication (hardened) | `nex5mx1`             | 2                 |
| Keyed-message authentication (fast)     | `nex4mx1`             | 1                 |
| Long key derivation (non-memory-hard)   | `nex4px1`             | 2                 |
