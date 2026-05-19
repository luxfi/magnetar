# Magnetar constant-time analysis harness — dudect bridge.
#
# Builds the cgo shim libraries (libmagnetar_verify, libmagnetar_combine)
# and links the C dudect harnesses against them.
#
# Prereqs (run once):
#   ./fetch.sh           # pulls dudect.h at the pinned commit
#
# Build:
#   make                 # both verify + combine
#   make verify          # just verify
#   make combine         # just combine
#
# Run:
#   ./dudect_verify      # smoke test (10000 samples/batch x 4 batches)
#   ./dudect_combine     # smoke test (1000 samples/batch x 4 batches —
#                          Magnetar Combine includes SLH-DSA
#                          SignDeterministic, slower than Pulsar's
#                          Combine because the FORS+HT tree walk is
#                          larger than ML-DSA's matrix product)
#
# Full submission run (10^9 samples on a pinned-CPU quiet host):
#   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
#   DUDECT_SAMPLES=500000  DUDECT_MAX_BATCHES=1000 ./dudect_combine

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Shared-library extension is .dylib on macOS, .so elsewhere.
ifeq ($(UNAME_S),Darwin)
    SHLIB_EXT := dylib
    RPATH_FLAG := -Wl,-rpath,@loader_path
else
    SHLIB_EXT := so
    RPATH_FLAG := -Wl,-rpath,'$$ORIGIN'
endif

# Source paths.
REPO_ROOT := $(shell cd ../.. && pwd)
DUDECT_HDR := dudect/src/dudect.h

# C compile flags. -O2 is the default per dudect's own build; the
# leakage signal is preserved at -O2 because the inner do_one_computation
# call boundary is opaque to the compiler.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wno-unused-parameter -I. -Idudect/src
LDFLAGS ?=
LDLIBS  := -lm

# Force-include the ARM compat shim on AArch64 hosts so dudect.h's
# x86 intrinsics resolve.
ifeq ($(UNAME_M),arm64)
    CFLAGS += -include dudect_compat.h
endif
ifeq ($(UNAME_M),aarch64)
    CFLAGS += -include dudect_compat.h
endif

# Go env. GOWORK=off matches scripts/checks/go-tests.sh — this repo
# uses a single-module layout.
GO     ?= go
GOENV  := GOWORK=off CGO_ENABLED=1

.PHONY: all verify combine clean check-dudect

all: verify combine

libmagnetar_verify.$(SHLIB_EXT): verify_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags magnetar_verify_ct \
		-o libmagnetar_verify.$(SHLIB_EXT) \
		./verify_ct.go

libmagnetar_combine.$(SHLIB_EXT): combine_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags magnetar_combine_ct \
		-o libmagnetar_combine.$(SHLIB_EXT) \
		./combine_ct.go

dudect_verify: dudect_verify.c libmagnetar_verify.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_verify dudect_verify.c \
		-L. -lmagnetar_verify $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_combine: dudect_combine.c libmagnetar_combine.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_combine dudect_combine.c \
		-L. -lmagnetar_combine $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

verify: dudect_verify
combine: dudect_combine

check-dudect:
	@if [ ! -f $(DUDECT_HDR) ]; then \
		echo "==> dudect.h missing — run ./fetch.sh"; \
		exit 1; \
	fi

clean:
	rm -f dudect_verify dudect_combine
	rm -f libmagnetar_verify.$(SHLIB_EXT) libmagnetar_verify.h
	rm -f libmagnetar_combine.$(SHLIB_EXT) libmagnetar_combine.h
