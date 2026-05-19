// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build magnetar_verify_ct

// verify_ct.go — cgo bridge exposing magnetar.Verify to the C dudect
// harness in dudect_verify.c.
//
// HONEST CT-population framing (NOT a FIPS 205 citation).
//
// FIPS 205 itself does not carve out a "valid signatures only" CT
// requirement for Verify — §10.3 is the Verify algorithm spec, not a
// CT requirement section. The reason we test the valid-signature
// population here is OPERATIONAL, not standards-cited:
//
//   * Verify holds no long-term secret state. An attacker observing
//     the rejection-path timing of garbage bytes does not learn any
//     confidential value — the attacker SUPPLIED the garbage.
//   * The class of inputs over which Verify is interesting to
//     constant-time-test is the class of inputs an attacker would
//     submit to extract information about a SECRET in the verifier.
//     Verify has no secret, so the empirically meaningful CT
//     property is "signatures with identical structural validity
//     should not be timing-distinguishable" — i.e., the valid-sig
//     class.
//   * circl's slhdsa.Verify (the dispatch target of magnetar.Verify)
//     is documented as constant-time over the valid-signature
//     pipeline. Our test exercises that pipeline.
//
// The dudect harness BOTH classes are VALID signatures on the same
// (pk, message); they differ only in the per-signing randomness
// (SignRandomized per FIPS 205 §10.2 randomized signing path), so the
// byte strings vary but the verify pipeline executes the same code
// path. Any timing difference dudect detects between class-A and
// class-B samples is a real signature-content-dependent timing in
// Verify.
//
// The bridge precomputes a pool of K_VALID valid signatures at
// startup. prepare_inputs (in dudect_verify.c) copies pool[0] for
// every class-A sample (Welch's t-test requires identical class-A
// inputs) and pool[rand % K_VALID] for class-B.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmagnetar_verify.dylib ./verify_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// kValidPool — number of independent valid signatures the bridge
// precomputes. Larger K = more uniform class-B distribution. SLH-DSA
// signing is slower than ML-DSA signing (hash-tree depth vs
// rejection-loop in lattice), so we use a smaller pool than Pulsar's
// 64 to keep setup time bounded.
const kValidPool = 16

var (
	fixtureParams *magnetar.Params
	fixturePub    *magnetar.PublicKey
	fixtureMsg    []byte
	// validPool holds kValidPool valid signatures over the same
	// (pk, message), differing only in per-signing randomness.
	validPool [kValidPool]*magnetar.Signature
)

//export magnetar_verify_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success, non-zero on
// failure. Must be called once before magnetar_verify_ct.
//
// We use ModeM192s (the Magnetar recommended production target). The
// fixture pk and signature pool are freshly generated under
// crypto/rand; the dudect class-A vs class-B distinction is the
// only source of variation across measurement samples.
func magnetar_verify_ct_setup() C.int {
	params := magnetar.MustParamsFor(magnetar.ModeM192s)

	sk, err := magnetar.GenerateKey(params, rand.Reader)
	if err != nil {
		return 1
	}

	msg := []byte("dudect constant-time smoke: Magnetar SLH-DSA-SHAKE-192s Verify")

	// Build the K-entry valid-signature pool. Each sig is a fresh
	// SignRandomized call; with crypto/rand they are byte-distinct
	// even though all valid under the same pk.
	for k := 0; k < kValidPool; k++ {
		sig, err := magnetar.Sign(params, sk, msg, nil, true, rand.Reader)
		if err != nil {
			return 2
		}
		if vErr := magnetar.Verify(params, sk.Pub, msg, sig); vErr != nil {
			return 3
		}
		validPool[k] = sig
	}

	fixtureParams = params
	fixturePub = sk.Pub
	fixtureMsg = msg
	return 0
}

//export magnetar_verify_ct_sig_size
//
// Returns the per-sample input width: one full FIPS 205 SLH-DSA-SHAKE-192s
// signature = 16224 bytes. The C harness sizes its dudect chunk to this.
func magnetar_verify_ct_sig_size() C.size_t {
	if fixtureParams == nil {
		return 0
	}
	return C.size_t(fixtureParams.SignatureSize)
}

//export magnetar_verify_ct_pool_size
//
// Returns the number of valid signatures in the per-startup pool.
func magnetar_verify_ct_pool_size() C.size_t {
	return C.size_t(kValidPool)
}

//export magnetar_verify_ct_copy_pool
//
// Copy the validPool[idx] signature bytes into `dst` (must be at
// least sig_size bytes). idx is reduced mod kValidPool. Returns 0
// on success, non-zero on failure.
func magnetar_verify_ct_copy_pool(idx C.size_t, dst *C.uint8_t) C.int {
	if fixtureParams == nil {
		return 1
	}
	i := uint64(idx) % uint64(kValidPool)
	sig := validPool[i]
	if sig == nil || len(sig.Bytes) != fixtureParams.SignatureSize {
		return 2
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), fixtureParams.SignatureSize)
	copy(dstSlice, sig.Bytes)
	return 0
}

//export magnetar_verify_ct
//
// One dudect measurement sample.
//
// `data` points to a `sig_size`-byte buffer containing a (valid)
// signature. The bridge calls magnetar.Verify on it. Both class-A
// and class-B samples carry VALID signatures (from validPool); any
// timing difference is a real data-dependent path in Verify, not a
// rejection-path artifact.
//
// IMPORTANT: this function must NOT branch on the data beyond what
// Verify itself does. The return value is discarded — dudect cares
// about timing, not the verification result.
func magnetar_verify_ct(data *C.uint8_t) {
	if fixtureParams == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), fixtureParams.SignatureSize)
	sigBytes := make([]byte, fixtureParams.SignatureSize)
	copy(sigBytes, src)
	sig := &magnetar.Signature{Mode: fixtureParams.Mode, Bytes: sigBytes}
	_ = magnetar.Verify(fixtureParams, fixturePub, fixtureMsg, sig)
}

func main() {}
