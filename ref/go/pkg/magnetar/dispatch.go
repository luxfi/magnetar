// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// dispatch.go — parallel-CPU dispatch infrastructure shared by the
// per-validator standalone (ValidatorBatchVerify, VerifyAggregateCert)
// batch verification paths.
//
// SLH-DSA Verify is ~50ms per signature for SHAKE-192s on Apple
// M1 Max, so goroutine startup (~10µs) is amortised at any
// non-trivial batch size. Above the concurrent threshold the
// per-signer Verify is forked across runtime.GOMAXPROCS workers
// using the same fork-join pattern as
// luxfi/crypto/slhdsa.VerifyBatch (gpu.go verifyBatchConcurrent).
//
// The dispatch tier is observable via LastValidatorBatchTier so
// the test suite can assert provenance — auditable evidence of
// dispatch behaviour at runtime.

import (
	"errors"
	"sync"
)

// Errors returned by the registry-checked cert verification path.
// Registry-binding violations are FATAL at the standalone (cert)
// surface; at the ValidatorBatchVerify surface the caller is
// responsible for the registry binding and these errors are not
// produced.
var (
	// ErrUnknownValidator is returned when a SignedBundle / cert
	// entry carries a ValidatorID that does not appear in the
	// knownValidators map. The protocol-layer driver MUST filter
	// these out (or treat their presence as a slashable offence
	// per the consensus layer's rules) before retrying.
	ErrUnknownValidator = errors.New("magnetar: bundle from unknown validator")

	// ErrValidatorPubkeyMismatch is returned when the bundle's
	// embedded public key does not byte-equal the public key
	// registered in knownValidators for that ValidatorID. Protects
	// against a malicious validator binding a different pk to its
	// NodeID mid-quorum.
	ErrValidatorPubkeyMismatch = errors.New("magnetar: bundle public key does not match known validator")
)

// ValidatorBatchTier is the dispatch tier the most recent
// ValidatorBatchVerify call took. Exposed for the BatchVerify
// provenance test; mirrors the slhdsa.DispatchTier shape from
// luxfi/crypto/slhdsa/provenance.go but is local to magnetar.
// When magnetar is embedded in a system using luxfi/crypto's GPU
// substrate, callers should query slhdsa.GetProvenance() at the
// upstream layer instead.
type ValidatorBatchTier int

const (
	// validatorBatchUnknown is the initial value before any
	// ValidatorBatchVerify call has run.
	validatorBatchUnknown ValidatorBatchTier = iota

	// validatorBatchSerial means the dispatch ran on a single
	// goroutine (batch size < validatorBatchConcurrentThreshold).
	validatorBatchSerial

	// validatorBatchConcurrent means the per-signer Verify was
	// forked across GOMAXPROCS goroutines. Mirrors
	// slhdsa.TierGoroutineParallelCPU.
	validatorBatchConcurrent
)

// String returns the canonical name of the dispatch tier.
func (t ValidatorBatchTier) String() string {
	switch t {
	case validatorBatchSerial:
		return "serial-cpu"
	case validatorBatchConcurrent:
		return "goroutine-parallel-cpu"
	default:
		return "unknown"
	}
}

// validatorBatchConcurrentThreshold is the minimum batch size at
// which ValidatorBatchVerify forks the per-signer Verify across
// GOMAXPROCS goroutines.
//
// Exposed as a package-level var (not a const) so test code can
// drop it to 2 to exercise the parallel path on a small batch.
var validatorBatchConcurrentThreshold = 2

// validatorBatchLastTier records the dispatch tier of the most
// recent ValidatorBatchVerify call. Single-writer, eventually-
// consistent — same model as
// luxfi/crypto/slhdsa.pluginStrongSymbolCache.
//
// Protected by a mutex (not atomic.Int32) because the test suite
// needs read-after-write ordering visibility on Apple Silicon
// where atomic Load on a different goroutine may observe a stale
// value across the goroutine-pool boundary.
var (
	validatorBatchLastTierMu sync.Mutex
	validatorBatchLastTier   = validatorBatchUnknown
)

// recordValidatorBatchTier publishes the dispatch tier of the
// just-completed ValidatorBatchVerify call.
func recordValidatorBatchTier(t ValidatorBatchTier) {
	validatorBatchLastTierMu.Lock()
	validatorBatchLastTier = t
	validatorBatchLastTierMu.Unlock()
}

// LastValidatorBatchTier returns the dispatch tier of the most
// recent ValidatorBatchVerify call. Used by the BatchVerify
// provenance test to confirm the parallel goroutine path is being
// exercised. Mirrors luxfi/crypto/slhdsa.GetProvenance() in
// purpose — auditable evidence of dispatch behaviour at runtime.
func LastValidatorBatchTier() ValidatorBatchTier {
	validatorBatchLastTierMu.Lock()
	defer validatorBatchLastTierMu.Unlock()
	return validatorBatchLastTier
}

// ctEqualBytes compares two byte slices in constant time relative
// to their CONTENTS (the lengths are public; an early-return on
// length mismatch is acceptable). Returns true iff lengths match
// and every byte is equal.
//
// We do not use crypto/subtle.ConstantTimeCompare here so the
// magnetar package's CT footprint is self-contained: ctEqual32
// (transcript.go) and ctEqualBytes are the entire CT primitive
// surface (the rest of the package's CT discipline is
// byte-by-byte OR-accumulation in PublicKey.Equal etc).
func ctEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
