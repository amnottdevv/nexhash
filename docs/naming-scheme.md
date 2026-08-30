# Naming scheme

All custom engines follow the naming scheme `nex<L><T><C><V>`. Each character has a fixed meaning, so the name of an engine can be read off to determine its output length class, type, core algorithm, and version.

## Format

```
nex <L> <T> <C> <V>
│   │   │   │   │
│   │   │   │   └─ Version
│   │   │   └──── Core algorithm
│   │   └────── Type
│   └──────── Length class
└──────────── NexHash prefix
```

Total length: seven characters (`nex` + four). All characters are lowercase.

## Fields

### `<L>` — Length class

A single digit indicating the order of magnitude of the output hex length.

| Digit | Range (hex chars)        | Range (bits)        |
|-------|--------------------------|---------------------|
| 1     | 1 – 9                    | 4 – 36              |
| 2     | 10 – 99                  | 40 – 396            |
| 3     | 100 – 999                | 400 – 3 996         |
| 4     | 1 000 – 9 999            | 4 000 – 39 996      |
| 5     | 10 000+                  | 40 000+             |

External standards (`argon2`, `bcrypt`) do not follow this scheme — their names are reserved for compatibility with existing PHC strings.

### `<T>` — Type

A single letter indicating what the engine hashes.

| Letter | Meaning   | Input                                    |
|--------|-----------|------------------------------------------|
| `P`    | Password  | A single secret string                   |
| `F`    | File      | A path to a file (streamed)              |
| `M`    | Message   | A password (key) plus arbitrary text     |
| `K`    | Key       | Key derivation (reserved for future use) |
| `B`    | Blob      | Arbitrary byte buffer (reserved)         |

### `<C>` — Core algorithm

A single letter identifying the underlying cryptographic primitive.

| Letter | Meaning                            |
|--------|------------------------------------|
| `A`    | Argon2 family (memory-hard)        |
| `B`    | bcrypt / Blowfish                  |
| `H`    | SHA-512                            |
| `S`    | SHA-256                            |
| `X`    | Mixed (combination of primitives)  |

### `<V>` — Version

A single digit (1 – 9) tracking breaking changes within an engine. Incremented when the produced output for the same input changes — for example, when the iteration formula or output length changes. Performance optimisations and bug fixes that leave the output identical do not increment the version.

## Decoding examples

| Name        | Length class | Type    | Core  | Version | Decoded meaning                                          |
|-------------|--------------|---------|-------|---------|----------------------------------------------------------|
| `nex3ph1`   | 3 (100–999)  | Password| SHA-512 | 1     | 432-hex password hash, SHA-512 based                     |
| `nex4px1`   | 4 (1k–10k)   | Password| Mixed   | 1     | 1240-hex password hash, mixed SHA-256/512                |
| `nex3fh1`   | 3 (100–999)  | File    | SHA-512 | 1     | 256-hex file hash, SHA-512 streaming                     |
| `nex4px2`   | 4 (1k–10k)   | Password| Mixed   | 2     | 8743-hex password hash, mixed SHA, version 2             |
| `nex4mx1`   | 4 (1k–10k)   | Message | Mixed   | 1     | 2048-hex keyed-message hash, mixed SHA                   |
| `nex5mx1`   | 5 (10k+)     | Message | Mixed   | 1     | 16384-hex keyed-message hash, Argon2id + mixed SHA       |

## Reserved future names

The scheme leaves room for additional engines. Examples of names that may appear in later releases:

| Name        | Possible meaning                                                  |
|-------------|-------------------------------------------------------------------|
| `nex5pk1`   | 10000+ hex password key, SHA-256 based                            |
| `nex4fa1`   | ~5000 hex file hash, Argon2-based (memory-hard file hashing)      |
| `nex4ma1`   | ~5000 hex keyed-message hash, Argon2-based                        |
| `nex2mb1`   | ~50 hex short-message hash, bcrypt-based                          |
| `nex3ks1`   | ~300 hex key derivation, SHA-256 based                            |

If a future engine produces output that cannot be described by the existing fields, the scheme will be extended rather than reused with a conflicting meaning.
