# NexHash v1.0 — Cross-platform Makefile (restructured)
# Works on: Linux (gcc/g++), Windows (MinGW-w64), macOS (clang)
#
# Directory layout:
#   src/cli/         - main CLI binary
#   src/core/        - dispatcher + warning system
#   src/crypto/      - SHA-256 / SHA-512 implementations
#   src/engines/     - all hashing engines (one .h/.cpp pair per engine)
#   lib/argon2/      - PHC-winner Argon2 reference source (C)
#   lib/bcrypt/      - openwall crypt_blowfish source (C)
#   build/           - object files + static libraries
#   dist/            - final binary
#
# Usage:
#   make            # build nexhash binary
#   make clean      # remove build artifacts
#   make test       # build and run roundtrip tests for all engines/levels
#   make benchmark  # benchmark all engines at level 1
#   make libs       # build static libs only (libargon2.a, libcrypt_blowfish.a)
#   make dist       # build and copy binary to dist/
#   make help       # show all targets
#
# On Windows, use:  mingw32-make
# On Linux/macOS:   make

# ============================================================
# 0. OS detection
# ============================================================
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE := .exe
    RM := del /Q /F
    MKDIR_P := mkdir
    CXX ?= g++
    AR ?= ar
    PLATFORM_LIBS := -lpthread
else
    UNAME_S := $(shell uname -s)
    EXE :=
    RM := rm -f
    MKDIR_P := mkdir -p
    ifeq ($(UNAME_S),Linux)
	PLATFORM := linux
	CXX ?= g++
	AR ?= ar
	PLATFORM_LIBS := -lpthread -ldl
    else ifeq ($(UNAME_S),Darwin)
	PLATFORM := macos
	CXX ?= clang++
	AR ?= ar
	PLATFORM_LIBS := -lpthread
    else ifneq (,$(findstring MINGW,$(UNAME_S)))
	PLATFORM := mingw
	EXE := .exe
	CXX ?= g++
	AR ?= ar
	PLATFORM_LIBS := -lpthread
    else
	PLATFORM := unknown
	CXX ?= g++
	AR ?= ar
	PLATFORM_LIBS := -lpthread
    endif
endif

# ============================================================
# 1. Paths
# ============================================================
ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRC      := $(ROOT)/src
CLI_SRC  := $(SRC)/cli
CORE_SRC := $(SRC)/core
CRYPTO_SRC := $(SRC)/crypto
ENG_SRC  := $(SRC)/engines
LIB      := $(ROOT)/lib
ARGON2_SRC := $(LIB)/argon2
BCRYPT_SRC := $(LIB)/bcrypt
BUILD    := $(ROOT)/build
DIST     := $(ROOT)/dist

# ============================================================
# 2. Compiler / linker flags
# ============================================================
CXX_STD      := -std=c++17
CXX_OPT      := -O2
CXX_WARN     := -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function

# Include paths - so source files can use simple #include "engine_xxx.h"
# regardless of which subdirectory they live in.
CXX_INCLUDES := \
    -I$(CLI_SRC) \
    -I$(CORE_SRC) \
    -I$(CRYPTO_SRC) \
    -I$(ENG_SRC) \
    -I$(ARGON2_SRC) \
    -I$(BCRYPT_SRC)

# Force bcrypt to use pure-C path (skip x86.S assembly for portability).
BCRYPT_DEFS := -DBF_ASM=0

# Argon2 C source (compiled as C, not C++)
CC           ?= cc
C_STD        := -std=c89
C_OPT        := -O2
C_WARN       := -Wall
ARGON2_IMPL  ?= ref
ARGON2_CFLAGS := $(C_STD) $(C_OPT) $(C_WARN) -I$(ARGON2_SRC) -pthread

CXXFLAGS     := $(CXX_STD) $(CXX_OPT) $(CXX_WARN) $(CXX_INCLUDES)
LDFLAGS      := $(PLATFORM_LIBS)

# ============================================================
# 3. Source / object lists
# ============================================================
# Our own C++ sources (one entry per file, with full path)
APP_SRCS := \
    $(CRYPTO_SRC)/sha256.cpp \
    $(CRYPTO_SRC)/sha512.cpp \
    $(CORE_SRC)/warning.cpp \
    $(CORE_SRC)/nexhash_core.cpp \
    $(ENG_SRC)/engine_argon.cpp \
    $(ENG_SRC)/engine_bcrypt.cpp \
    $(ENG_SRC)/engine_nex3ph1.cpp \
    $(ENG_SRC)/engine_nex4px1.cpp \
    $(ENG_SRC)/engine_nex3fh1.cpp \
    $(ENG_SRC)/engine_nex4px2.cpp \
    $(ENG_SRC)/engine_nex4mx1.cpp \
    $(ENG_SRC)/engine_nex5mx1.cpp \
    $(CLI_SRC)/nexhash.cpp

# Object files: source path/to/file.cpp -> build/file.o (flat names, no subdir)
APP_OBJS := $(patsubst $(CORE_SRC)/%.cpp,$(BUILD)/%.o,$(filter $(CORE_SRC)/%,$(APP_SRCS)))
APP_OBJS += $(patsubst $(CRYPTO_SRC)/%.cpp,$(BUILD)/%.o,$(filter $(CRYPTO_SRC)/%,$(APP_SRCS)))
APP_OBJS += $(patsubst $(ENG_SRC)/%.cpp,$(BUILD)/%.o,$(filter $(ENG_SRC)/%,$(APP_SRCS)))
APP_OBJS += $(patsubst $(CLI_SRC)/%.cpp,$(BUILD)/%.o,$(filter $(CLI_SRC)/%,$(APP_SRCS)))

# Argon2 C sources (top-level + blake2 subdir)
ARGON2_TOP_SRCS := \
    $(ARGON2_SRC)/argon2.c \
    $(ARGON2_SRC)/core.c \
    $(ARGON2_SRC)/thread.c \
    $(ARGON2_SRC)/encoding.c \
    $(ARGON2_SRC)/$(ARGON2_IMPL).c
ARGON2_BLAKE2_SRCS := \
    $(ARGON2_SRC)/blake2/blake2b.c

ARGON2_OBJS := \
    $(patsubst $(ARGON2_SRC)/%.c,$(BUILD)/argon2_%.o,$(ARGON2_TOP_SRCS)) \
    $(patsubst $(ARGON2_SRC)/blake2/%.c,$(BUILD)/argon2_blake2_%.o,$(ARGON2_BLAKE2_SRCS))

# Bcrypt C sources
BCRYPT_SRCS := $(BCRYPT_SRC)/crypt_blowfish.c
BCRYPT_OBJS := $(patsubst $(BCRYPT_SRC)/%.c,$(BUILD)/bcrypt_%.o,$(BCRYPT_SRCS))

# Static libs
ARGON2_LIB  := $(BUILD)/libargon2.a
BCRYPT_LIB  := $(BUILD)/libcrypt_blowfish.a

# Final binary
TARGET := $(DIST)/nexhash$(EXE)

# ============================================================
# 4. Phony targets
# ============================================================
.PHONY: all clean test benchmark libs dist help

all: $(TARGET)

help:
	@echo "NexHash v1.0 Makefile"
	@echo ""
	@echo "Detected platform: $(PLATFORM)"
	@echo "Compiler:          $(CXX)"
	@echo ""
	@echo "Targets:"
	@echo "  make            Build nexhash binary"
	@echo "  make libs       Build static libraries only"
	@echo "  make test       Build and run roundtrip tests (all engines, levels 1-3)"
	@echo "  make benchmark  Benchmark all engines at level 1"
	@echo "  make dist       Same as 'make all'"
	@echo "  make clean      Remove build/ and dist/"
	@echo "  make help       Show this help"
	@echo ""
	@echo "Variables (override with: make VAR=value):"
	@echo "  CXX=<compiler>           Default: g++ (or clang++ on macOS)"
	@echo "  ARGON2_IMPL=ref|opt      Default: ref (pure-C). 'opt' uses SSE2/AVX2."
	@echo "  CXX_OPT=<flag>           Default: -O2 (use -O3 for max speed)"

# ============================================================
# 5. Directory setup
# ============================================================
$(BUILD) $(DIST):
	@-$(MKDIR_P) $@ 2>/dev/null

# ============================================================
# 6. Pattern rules: compile sources
# ============================================================
# C++ files in src/core/
$(BUILD)/%.o: $(CORE_SRC)/%.cpp | $(BUILD)
	@echo "  CXX  [core]    $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# C++ files in src/crypto/
$(BUILD)/%.o: $(CRYPTO_SRC)/%.cpp | $(BUILD)
	@echo "  CXX  [crypto]  $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# C++ files in src/engines/
$(BUILD)/%.o: $(ENG_SRC)/%.cpp | $(BUILD)
	@echo "  CXX  [engine]  $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# C++ files in src/cli/
$(BUILD)/%.o: $(CLI_SRC)/%.cpp | $(BUILD)
	@echo "  CXX  [cli]     $(notdir $<)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Argon2 C files (top-level)
$(BUILD)/argon2_%.o: $(ARGON2_SRC)/%.c | $(BUILD)
	@echo "  CC   [argon2]  $(notdir $<)"
	@$(CC) $(ARGON2_CFLAGS) -c $< -o $@

# Argon2 blake2 subdir
$(BUILD)/argon2_blake2_%.o: $(ARGON2_SRC)/blake2/%.c | $(BUILD)
	@echo "  CC   [argon2/blake2] $(notdir $<)"
	@$(CC) $(ARGON2_CFLAGS) -c $< -o $@

# Bcrypt C files
$(BUILD)/bcrypt_%.o: $(BCRYPT_SRC)/%.c | $(BUILD)
	@echo "  CC   [bcrypt]  $(notdir $<)"
	@$(CC) $(C_STD) $(C_OPT) $(C_WARN) $(BCRYPT_DEFS) -I$(BCRYPT_SRC) -c $< -o $@

# ============================================================
# 7. Static libraries
# ============================================================
$(ARGON2_LIB): $(ARGON2_OBJS)
	@echo "  AR   $(notdir $@)"
	@$(AR) rcs $@ $(ARGON2_OBJS)

$(BCRYPT_LIB): $(BCRYPT_OBJS)
	@echo "  AR   $(notdir $@)"
	@$(AR) rcs $@ $(BCRYPT_OBJS)

libs: $(ARGON2_LIB) $(BCRYPT_LIB)

# ============================================================
# 8. Final binary link
# ============================================================
$(TARGET): $(APP_OBJS) $(ARGON2_LIB) $(BCRYPT_LIB) | $(DIST)
	@echo "  LINK $(notdir $@)"
	@$(CXX) $(CXX_OPT) $(APP_OBJS) $(ARGON2_LIB) $(BCRYPT_LIB) $(LDFLAGS) -o $@
	@echo "  DONE $(notdir $@)"
	@echo "  Binary size: $$(du -h $(TARGET) | cut -f1)"

# ============================================================
# 9. Test / benchmark
# ============================================================
test: $(TARGET)
	@echo ""
	@echo "=== Roundtrip tests (password engines, levels 1-3) ==="
	@for e in argon2 bcrypt nex3ph1 nex4px1 nex4px2; do \
	  for l in 1 2 3; do \
	    H=$$($(TARGET) --encode --engine $$e --level $$l --password "TestPass!" 2>&1 | grep -E '^\$$') && \
	    OK=$$($(TARGET) --decode --crypt "$$H" --password "TestPass!" 2>&1 | grep -oE '\[(OK|FAIL)\]') && \
	    LEN=$${#H} && \
	    printf "  %-10s L%d  hash_len=%-6s verify=%s\n" "$$e" "$$l" "$$LEN" "$$OK" ; \
	  done ; \
	done
	@echo ""
	@echo "=== Message engine tests (nex4mx1 + nex5mx1, level 1) ==="
	@for e in nex4mx1 nex5mx1; do \
	  H=$$($(TARGET) --encode --engine $$e --level 1 --password "secret" --text "Hello world!" 2>&1 | grep -E '^\$$') && \
	  OK=$$($(TARGET) --decode --crypt "$$H" --password "secret" --text "Hello world!" 2>&1 | grep -oE '\[(OK|FAIL)\]') && \
	  printf "  %-10s L1  hash_len=%-6s verify=%s\n" "$$e" "$${#H}" "$$OK" ; \
	done
	@echo ""
	@echo "=== File hashing test (nex3fh1, level 1) ==="
	@echo "test file content for nexhash" > /tmp/nexhash_test_file.txt
	@H=$$($(TARGET) --hash-file --engine nex3fh1 --level 1 --file /tmp/nexhash_test_file.txt 2>&1 | grep -E '^\$$') && \
	 OK=$$($(TARGET) --verify-file --crypt "$$H" --file /tmp/nexhash_test_file.txt 2>&1 | grep -oE '\[(OK|FAIL)\]') && \
	 printf "  nex3fh1    L1  hash_len=%-6s verify=%s\n" "$${#H}" "$$OK"
	@rm -f /tmp/nexhash_test_file.txt
	@echo ""
	@echo "=== Backward compatibility (legacy aliases still verify) ==="
	@H=$$($(TARGET) --encode --engine nex4dc6 --level 1 --password "legacy" 2>&1 | grep -E '^\$$') && \
	 printf "  old name 'nex4dc6' -> parses, hash prefix: %s\n" "$$(echo $$H | cut -d'$$' -f3)"

benchmark: $(TARGET)
	@echo ""
	@echo "=== Benchmarks (level 1) ==="
	@for e in argon2 bcrypt nex3ph1 nex4px1 nex4px2; do \
	  echo "--- $$e ---" ; \
	  $(TARGET) --benchmark --engine $$e --level 1 2>&1 | tail -2 ; \
	done

dist: $(TARGET)

# ============================================================
# 10. Clean
# ============================================================
clean:
	@echo "Cleaning build artifacts..."
ifeq ($(PLATFORM),windows)
	-@if exist $(BUILD) rmdir /S /Q $(BUILD)
	-@if exist $(DIST)  rmdir /S /Q $(DIST)
else
	-@$(RM) -r $(BUILD)
	-@$(RM) -r $(DIST)
endif
	@echo "Done."
