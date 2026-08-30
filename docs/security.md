# Security

This page documents the security design of NexHash, the threat model, recommendations, and known limitations.

## Threat model

NexHash assumes an attacker who:

- Has read access to the stored hash database (offline attack).
- Knows the engine and level used to produce each hash (Kerckhoffs's principle).
- Has access to the NexHash binary (so the algorithm is fully known).
- Has access to commodity GPU hardware (single RTX 4090 used as a reference baseline).

NexHash does **not** assume the attacker has:

- The server-side pepper (when `NEXHASH_PEPPER` is set and kept secret).
- Memory-hard cracking hardware beyond commodity GPUs.

## Security properties

### Constant-time comparison

Every verification path compares the computed hash with the stored hash using an XOR accumulator. Short-circuit comparison (`==` on the first differing byte) is not used anywhere in the verification path.

### Cryptographic random salt

Salts are generated using `std::random_device`, which on Linux, macOS, and modern Windows (MinGW-w64) reads from the operating system CSPRNG. The legacy `mt19937` PRNG is not used.

### Self-describing hashes

The PHC-style hash string embeds the engine name, level, iteration count, and (for `nex5mx1`) the Argon2 parameters. This means:

- Old hashes continue to verify after parameter upgrades.
- An attacker cannot trick the verifier into using weaker parameters than were used at hash time.
- The verifier rejects malformed hashes (wrong field count, out-of-range parameters, wrong salt/hash length).

### Optional server-side pepper

Custom engines accept a pepper through the `NEXHASH_PEPPER` environment variable. The pepper is:

- Never compiled into the binary (no string literal in the source).
- Not stored in the hash output (no `pepper_hash` field).
- Mixed into the iteration loop alongside the salt and password.

If the database is leaked but the pepper is not, the attacker must brute-force the pepper in addition to the password.

### Anti-collision for message engines

The `nex4mx1` and `nex5mx1` engines do not concatenate `password + text`. Instead, they build an interleaved buffer:

```
[len_password 8B LE][len_text 8B LE]
[0x01][pw[0]][0x02][text[0]]
[0x01][pw[1]][0x02][text[1]]
...
```

Tag bytes `0x01` and `0x02` identify whether the next byte came from the password or the text. Length prefixes bind the exact lengths. This guarantees that `("ab", "c")` and `("a", "bc")` produce different buffers, so the resulting hashes differ.

## Recommendations

### For password storage

Use `argon2` at level 2 or 3. Argon2id is the audited industry standard (RFC 9106, PHC winner 2015). It is memory-hard, which forces GPU and ASIC attackers to allocate large memory per parallel cracking lane.

```bash
nexhash --encode --engine argon2 --level 3 --password "<password>"
```

If you must maintain compatibility with existing `$2b$` hashes, use `bcrypt` at level 2 or 3.

### For file integrity

Use `nex3fh1` at level 2 or 3. It streams files in 64 KiB chunks, so memory usage is bounded regardless of file size.

```bash
nexhash --hash-file --file release.tar.gz --level 2
```

### For keyed-message authentication

Use `nex5mx1` at level 2 for new deployments. It is memory-hard (Argon2id) and produces a 16384-character output, making it expensive to attack on commodity hardware.

```bash
nexhash --encode --engine nex5mx1 --level 2 \
  --password "<server-secret>" \
  --text "<message-to-authenticate>"
```

Use `nex4mx1` at level 1 if you need lower latency and can tolerate a CPU-only construction.

### For pepper setup

Generate a strong random pepper and store it in your secret manager or environment configuration. Never commit it to source control.

```bash
export NEXHASH_PEPPER="$(openssl rand -hex 32)"
```

Rotate the pepper only with a full rehash of all stored hashes — there is no in-place rotation mechanism.

## Known limitations

### Memory-hard engines are CPU-bound on GPU

`argon2` and `nex5mx1` are memory-hard, which significantly raises the cost of GPU attacks. However, they are not ASIC-resistant. A determined adversary with custom silicon could in principle build a more efficient cracker. This is a fundamental limitation of any password hashing scheme and not specific to NexHash.

### Custom engines are not audited

The `nex3ph1`, `nex4px1`, `nex4px2`, `nex4mx1`, `nex5mx1`, and `nex3fh1` engines use constructions designed for NexHash. They have not undergone formal third-party cryptographic review. For high-stakes deployments, prefer `argon2` or `bcrypt`.

### `--check-strength` is heuristic

The strength estimator uses character-class detection, pattern penalties, and a small common-password list. It is a rough guide, not a substitute for a proper password policy. The crack-time estimates assume a single RTX 4090 GPU and are pessimistic (attacker-friendly).

### No key rotation

NexHash does not provide a built-in rehash-on-login mechanism. Applications that need to upgrade hash parameters must implement their own migration logic — typically: verify with old parameters, and if successful, rehash with new parameters and update storage.

### Timing of file operations

File hashing time depends on file size. An attacker who can observe hashing latency may be able to infer rough file size. This is generally not a concern for stored-hash verification, but should be considered if file hashing is exposed through an interactive API.

## Reporting vulnerabilities

If you discover a security issue in NexHash, please open a private security advisory on GitHub rather than a public issue.

## Hardening checklist

- [ ] Use `argon2` level 2 or 3 for password storage.
- [ ] Set `NEXHASH_PEPPER` to a 256-bit random value.
- [ ] Restrict file permissions on the pepper source (env file, systemd unit, etc.).
- [ ] Verify all stored hashes with the constant-time `--decode` path.
- [ ] Use `nex5mx1` for new keyed-message authentication.
- [ ] Benchmark on your target hardware and pick the highest level that meets your latency budget.
