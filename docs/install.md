# Installation

NexHash builds from source with GCC, Clang, or MinGW-w64. Argon2 and bcrypt sources are vendored under `lib/` and statically linked, so the resulting binary has no runtime library dependencies beyond the system libc and pthreads.

## Prerequisites

### Linux

```bash
# Debian / Ubuntu
sudo apt install build-essential

# Fedora / RHEL
sudo dnf install gcc-c++ make
```

### macOS

```bash
# Xcode command line tools
xcode-select --install
```

### Windows

Install [MSYS2](https://www.msys2.org/), then in the **MSYS2 MinGW 64-bit** terminal:

```bash
pacman -S mingw-w64-x86_64-gcc make
```

## Build

From the project root:

```bash
make            # build dist/nexhash
make test       # build + run roundtrip tests
make benchmark  # build + benchmark all engines at level 1
make libs       # build only the static libraries (libargon2.a, libcrypt_blowfish.a)
make clean      # remove build/ and dist/
make help       # show all targets
```

On Windows, replace `make` with `mingw32-make`.

The compiled binary is placed at `dist/nexhash` (Linux/macOS) or `dist/nexhash.exe` (Windows).

## Build variables

The Makefile accepts the following overrides:

| Variable        | Default                  | Description                                            |
|-----------------|--------------------------|--------------------------------------------------------|
| `CXX`           | `g++` (or `clang++` on macOS) | C++ compiler                                      |
| `CC`            | `cc`                     | C compiler (used for Argon2 and bcrypt sources)        |
| `CXX_OPT`       | `-O2`                    | Optimization flag (use `-O3` for maximum speed)        |
| `ARGON2_IMPL`   | `ref`                    | Argon2 implementation: `ref` (pure C) or `opt` (SSE2)  |

Examples:

```bash
make CXX=clang++                         # use Clang
make ARGON2_IMPL=opt CXX_OPT=-O3         # maximum performance build
make CXX=x86_64-w64-mingw32-g++ EXE=.exe # cross-compile for Windows from Linux
```

## Verifying the build

After building, run the test target to confirm all engines work:

```bash
make test
```

Expected output includes roundtrip tests for every engine and level, plus backward-compatibility checks for the legacy engine names.

## Installation to system paths

NexHash does not ship with an install target by design — copy the binary manually:

```bash
sudo cp dist/nexhash /usr/local/bin/
nexhash --version
```

## Docker

A minimal Dockerfile for trying NexHash without a local toolchain:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make
ENTRYPOINT ["/src/dist/nexhash"]
```

Build and run:

```bash
docker build -t nexhash .
docker run --rm -it nexhash --list-engines
```
