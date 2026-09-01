# Usage

NexHash is a single CLI binary. All operations are invoked through subcommand-style flags.

## Command summary

```
nexhash --encode --engine <e> --level <n> --password "<pw>" [--output <file>]
nexhash --encode --engine nex4mx1 --level <n> --password "<pw>" --text "<msg>"
nexhash --decode --crypt "<hash>" --password "<pw>" [--text "<msg>"]
nexhash --hash-file --engine <e> --level <n> --file <path> [--output <file>]
nexhash --verify-file --crypt "<hash>" --file <path>
nexhash --check-strength --password "<pw>" [--engine <e> --level <n>]
nexhash --list-engines
nexhash --benchmark --engine <e> --level <n>
nexhash --version | --help
```

## Flags

| Flag             | Required for                    | Description                                            |
|------------------|---------------------------------|--------------------------------------------------------|
| `--encode`       | password / message hashing      | Hash the given input(s) and print the resulting crypt  |
| `--decode`       | password / message verification | Re-derive the hash and compare with `--crypt`          |
| `--hash-file`    | file hashing                    | Hash the contents of `--file`                          |
| `--verify-file`  | file verification               | Re-hash `--file` and compare with `--crypt`            |
| `--check-strength` | password analysis             | Print entropy estimate and per-engine crack time       |
| `--engine <e>`   | encode / hash-file / benchmark  | One of the engines listed by `--list-engines`          |
| `--level <n>`    | encode / hash-file / benchmark  | `1` (fast), `2` (balanced, default), `3` (paranoid)    |
| `--password <p>` | encode / decode / check-strength | Password or secret key                               |
| `--text <msg>`   | message engines only            | Message text; combined with `--password` for nex4mx1/nex5mx1 |
| `--crypt <h>`    | decode / verify-file            | Stored hash to verify against                          |
| `--file <path>`  | hash-file / verify-file         | Path to the file to hash or verify                     |
| `--output <path>`| optional, encode / hash-file    | Write hash to file instead of stdout                   |
| `--list-engines` | —                               | List all engines and their per-level parameters        |
| `--benchmark`    | —                               | Hash a fixed test password and print elapsed time      |
| `--version`      | —                               | Print build info and exit                              |
| `--help`         | —                               | Print help text and exit                               |

## Writing hashes to a file

Long-engine outputs (such as `nex4px2` at 8834 characters or `nex5mx1` at 16484 characters) are inconvenient to copy from the terminal. Pass `--output <path>` to write the hash directly to a file:

```bash
nexhash --encode --engine nex4px2 --level 3 --password "secret" --output hash.txt
# Hash saved to: hash.txt
```

When `--output` is set, the "output is long" warning is suppressed (writing to a file is precisely the recommended workaround).

The flag also works with `--hash-file`:

```bash
nexhash --hash-file --file document.pdf --level 2 --output document.hash
```

## Error reporting

When a flag is misspelled, missing a value, or given an invalid value, NexHash prints a precise error and an optional tip, then exits with code 1. The CLI never silently drops to the help menu.

```
$ nexhash --encode --engne argon2 --level 1 --password "x"
[error] : Unknown flag: --engne
[tip]   : Did you mean --engine?
```

```
$ nexhash --encode --engine argon2 --level abc --password "x"
[error] : Invalid value for --level: 'abc' (not a valid integer)
[tip]   : Level 1 = fast, 2 = balanced (default), 3 = paranoid.
```

```
$ nexhash --encode --engine argon2 --level 1 --password
[error] : Flag --password requires a value.
[tip]   : Usage: nexhash ... --password <value>
```

The "did you mean" suggestion uses Levenshtein edit distance over all known flags. If no close match exists, the tip points to `--help` instead.

## Password hashing

```bash
nexhash --encode --engine argon2 --level 2 --password "hunter2"
# $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
```

```bash
nexhash --decode --crypt "$argon2id$v=19$m=65536,t=3,p=1$..." --password "hunter2"
# [OK] Verification SUCCESSFUL! Input matches.
```

## File hashing

```bash
nexhash --hash-file --file document.pdf --level 2
# $nexhash$nex3fh1$2$200000$<file_size>$<salt>$<hash>
```

```bash
nexhash --verify-file --crypt "$nexhash$nex3fh1$..." --file document.pdf
# [OK] Verification SUCCESSFUL! File matches stored hash.
```

The default engine for `--hash-file` is `nex3fh1`. Any tampering with the file produces a different hash, so verification will fail.

## Keyed-message hashing

Message engines (`nex4mx1`, `nex5mx1`) combine a password (secret key) with arbitrary text. The two inputs are interleaved at the byte level with type tags to prevent the collision attacks that naive concatenation suffers from.

```bash
nexhash --encode --engine nex5mx1 --level 2 \
  --password "server-secret" \
  --text "GET /api/users 2026-08-30T10:00:00Z"
# $nexhash$nex5mx1$2$65536,3,1,50000$<salt>$<hash>
```

```bash
nexhash --decode --crypt "$nexhash$nex5mx1$..." \
  --password "server-secret" \
  --text "GET /api/users 2026-08-30T10:00:00Z"
# [OK] Verification SUCCESSFUL! Input matches.
```

Either input may be empty, but not both. The decode mode auto-detects message-engine hashes by their PHC prefix.

## Password strength

```bash
nexhash --check-strength --password "correct horse battery staple"
```

Output includes entropy estimate, a verdict (Very Weak / Weak / Fair / Good / Strong), suggestions, and estimated crack time for each engine at level 2. Pass `--engine` and `--level` to estimate against a specific configuration.

## Listing engines

```bash
nexhash --list-engines
```

Prints the parameter table for every engine and level.

## Benchmarking

```bash
nexhash --benchmark --engine nex5mx1 --level 3
```

Hashes a fixed test input and prints elapsed time. Useful for picking the right level for your hardware.

## Environment variables

| Variable          | Default | Description                                                                 |
|-------------------|---------|-----------------------------------------------------------------------------|
| `NEXHASH_PEPPER`  | unset   | Optional pepper mixed into all custom engines. Never compiled into binary. |

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | Success                                              |
| 1    | Invalid arguments or runtime error                   |
| 2    | Verification failed (password / file / text mismatch)|

## Warnings

NexHash prints yellow `[warning] :` messages to `stderr` in the following situations:

- Output exceeds 1000 characters and no `--output` file is set — recommend saving to a file to avoid truncation.
- File hashing or file verification — reminder that file features can be misused; only use for authorized testing.
- Level 3 selected — hashing may take several seconds.
- Weak password detected by `--check-strength`.
- File cannot be read.

Warnings are non-fatal; the program continues after printing.

