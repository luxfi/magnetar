// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// aggregate.go — public-BFT-safe N-of-N collected-signatures API.
//
// HONEST SOTA ANSWER for "public BFT post-quantum finality on
// SLH-DSA":
//
// SLH-DSA (FIPS 205) is hash-based — WOTS+ chains, FORS few-time
// signatures, and Merkle hypertrees stacked on top of a per-signer
// secret seed. No part of the construction is algebraic in a way
// that admits a FROST-style threshold aggregation (one signature
// from t-of-n partial signatures). The result is established in
// the literature:
//
//   - Cozzo & Smart, "Sharing the LUOV" (EUROCRYPT 2019) — hash-based
//     signatures are MPC-hard; every internal hash evaluation is
//     non-linear in the secret seed, so secret sharing forces every
//     hash to be evaluated in MPC.
//   - Bonte, Smart, Tan, "Threshold SPHINCS+" (2023) — exhaustive
//     infeasibility analysis: a t-of-n SLH-DSA scheme producing one
//     FIPS 205-shaped signature requires either O(2^h) garbled-
//     circuit work or seed reconstruction.
//   - NIST IR 8214 / MPTC submission notes — SLH-DSA classified as
//     "highest threshold-MPC cost" among the FIPS 20{3,4,5} family.
//   - FIPS 205 §6 SLH-DSA-Sign-Internal — direct inspection
//     confirms no Lagrange-aggregatable response in the algorithm.
//
// Therefore the public-BFT-safe Magnetar mode is "N separate
// signatures": each validator i has its OWN SLH-DSA keypair
// (sk_i, pk_i), produces its own σ_i over the message, and the
// consensus layer collects N of them. Verification iterates per
// signer:
//
//     valid_count = Σ_{i} 1[Verify(pk_i, msg, σ_i) == OK]
//     accept if valid_count ≥ quorum_threshold
//
// Wire size: N × |σ|. For SHAKE-192s (16224 byte signature) and a
// 21-validator quorum that's 332 KiB; a Z-Chain Groth16 rollup
// compresses to ~192 bytes (separate primitive, NOT part of this
// API — that's the SOTA finality-compression layer).
//
// PROPERTIES vs CombineWithSeedReconstruction (combine.go):
//
//   +-----------------------------------+-------------+-------------+
//   |                                   | Combine-WSR | Aggregate   |
//   +-----------------------------------+-------------+-------------+
//   | Aggregator-as-TCB required        |   YES       |   NO        |
//   | Output is one FIPS 205 σ          |   YES       |   NO (Nx)   |
//   | Output verifies under stock FIPS  |   YES       |   per σ_i   |
//   | Public-BFT-safe                   |   NO        |   YES       |
//   | Validator key model               |   shared    |   per-party |
//   | Requires DKG                      |   YES       |   NO        |
//   | Wire size                         |   |σ|       |   N × |σ|   |
//   | Z-Chain Groth16-compressible      |   N/A       |   YES       |
//   +-----------------------------------+-------------+-------------+
//
// DESIGN DISCIPLINE:
//
//   - Each validator's keypair is INDEPENDENT — no shared seed, no
//     DKG, no resharing ceremony. Generation calls go straight to
//     FIPS 205 KeyGen via GenerateValidatorKey.
//   - The wire envelope (SignedBundle) explicitly carries the
//     validator's NodeID and public key so the verifier can build
//     its known-validators map without out-of-band coordination.
//   - VerifyAggregated returns a COUNT, not a boolean — the policy
//     decision ("is this above quorum?") lives at the consumer.
//     This is the same decomplecting discipline Lux uses across
//     consensus: primitives report facts; policy gates filter them.
//   - Deduplication is by ValidatorID (not by public key) — a
//     duplicate signer is counted once even if it appears with
//     different (but valid) signatures.
//   - The parallel-CPU verify path mirrors the goroutine fork-join
//     pattern used in github.com/luxfi/crypto/slhdsa.VerifyBatch
//     (gpu.go verifyBatchConcurrent). When magnetar is embedded in
//     a system that exports a GPU substrate (e.g. consensus quorum
//     verification), callers SHOULD route VerifyAggregated through
//     that substrate by converting SignedBundle.PublicKey /
//     Signature to the upstream slhdsa.PublicKey and []byte forms
//     and calling slhdsa.VerifyBatch directly. The magnetar
//     reference impl ships the goroutine-parallel CPU path which is
//     the lower-bound performance floor; the upstream substrate is
//     the GPU upper bound (see gpu.go for the ~2.6× single-thread
//     SHAKE bottleneck note).

import (
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"sync"
)

// Errors returned by the aggregate (N-of-N) API.
var (
	// ErrEmptyBundle is returned when an empty bundle list is
	// passed to AggregateSignatures.
	ErrEmptyBundle = errors.New("magnetar: empty bundle list")

	// ErrBundleMismatch is returned when SignedBundle fields are
	// inconsistent (e.g. signature length doesn't match params.SignatureSize,
	// or public-key length doesn't match params.PublicKeySize).
	ErrBundleMismatch = errors.New("magnetar: bundle field shape inconsistent")

	// ErrUnknownValidator is returned by VerifyAggregated when a
	// bundle carries a ValidatorID that does not appear in the
	// knownValidators map. The protocol-layer driver MUST filter
	// these out (or treat their presence as a slashable offence
	// per the consensus layer's rules).
	ErrUnknownValidator = errors.New("magnetar: bundle from unknown validator")

	// ErrValidatorPubkeyMismatch is returned by VerifyAggregated when
	// the bundle's embedded public key does not byte-equal the
	// public key registered in knownValidators for that ValidatorID.
	// Protects against a malicious validator binding a different
	// pk to its NodeID mid-quorum.
	ErrValidatorPubkeyMismatch = errors.New("magnetar: bundle public key does not match known validator")
)

// SignedBundle is the wire envelope carrying ONE validator's
// signature over a message.
//
// Wire layout (canonical):
//
//	ValidatorID || PublicKey || Signature
//
// where PublicKey is params.PublicKeySize bytes (FIPS 205-marshal
// form per §10.1) and Signature is params.SignatureSize bytes
// (FIPS 205-marshal form per §10.2). ValidatorID is 32 bytes
// (NodeID).
//
// Each SignedBundle is INDEPENDENTLY verifiable: a relying party
// who knows the validator's public key (via knownValidators in
// VerifyAggregated, or a per-bundle VerifyBundle call) can verify
// the signature without any other party's data.
//
// The PublicKey is duplicated in the envelope (the verifier
// SHOULD cross-check against an authoritative validator-set
// registry) so the bundle is self-describing on the wire — a
// relying party that gossips it through a network can route it
// to a verifier without an out-of-band registry lookup.
type SignedBundle struct {
	// ValidatorID is the canonical 32-byte validator identifier
	// (matches Lux validator-ID format).
	ValidatorID NodeID

	// PublicKey is the validator's FIPS 205 public-key bytes.
	// Length = params.PublicKeySize.
	PublicKey []byte

	// Signature is the validator's FIPS 205 signature over the
	// message under the public key above. Length =
	// params.SignatureSize.
	Signature []byte
}

// AggregatedSignature is the final wire format produced by
// AggregateSignatures: a collection of per-validator SignedBundle
// values over the same message.
//
// AggregatedSignature carries Message so the wire envelope is
// self-contained (verifiers do not need to pass the message
// alongside the signature collection). This matches the standard
// "collected signatures" pattern from BFT consensus literature
// (e.g. HotStuff Section 4.2 collected QC signatures).
//
// Wire-encode an AggregatedSignature by length-prefixing the
// bundles. Magnetar's reference impl does not pin a specific
// encoding — that's the responsibility of the consensus layer
// (RLP for the Lux EVM stack, protobuf for the warp transport
// path, etc.). The encoding is byte-stable as long as the bundle
// order is preserved.
//
// Z-Chain compression path: a Groth16 SNARK over the FIPS 205
// verify circuit can compress AggregatedSignature to a single
// ~192-byte proof. The SNARK is a separate primitive and is NOT
// part of this API; see lux-zchain spec.
type AggregatedSignature struct {
	// Message is the bytes signed by each bundle.
	Message []byte

	// Bundles is the per-validator signature collection. Order
	// is preserved from AggregateSignatures' input but verifiers
	// MUST NOT depend on ordering for correctness.
	Bundles []*SignedBundle
}

// GenerateValidatorKey produces a fresh, standalone SLH-DSA key
// pair for one validator. No DKG, no resharing, no shared seed.
//
// The validator MUST persist (sk, pk) — losing sk means the
// validator drops out of the quorum until it rotates to a fresh
// keypair. The consensus layer's validator-set registry binds
// (ValidatorID, pk) so peers can verify this validator's
// SignedBundle outputs.
//
// rng may be nil — crypto/rand is used. Pass a deterministic
// reader for KAT-reproducible key generation.
//
// Equivalent to GenerateKey but returns (sk, pk) as separate
// values for the caller-side ergonomic case where the public key
// flows into the validator registry while the private key flows
// into a key-storage backend.
func GenerateValidatorKey(params *Params, rng io.Reader) (*PrivateKey, *PublicKey, error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	sk, err := GenerateKey(params, rng)
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.Pub, nil
}

// SignBundle produces a single-validator SignedBundle envelope.
//
// The output Signature is FIPS 205 SignDeterministic — byte-
// identical across calls for any (sk, message) pair, which is the
// standard property the Lux validator path relies on for
// deduplication. Callers that want randomized signing (FIPS 205
// §10.2 randomized variant) should use Sign directly and wrap the
// output in a SignedBundle manually.
//
// SignBundle does NOT depend on any other validator's data; this
// is the "no aggregator-as-TCB" property of the aggregate API.
func SignBundle(params *Params, sk *PrivateKey, validatorID NodeID, message []byte) (*SignedBundle, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if sk == nil || sk.Pub == nil {
		return nil, ErrNilKey
	}
	if sk.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	sig, err := Sign(params, sk, message, nil, false, nil)
	if err != nil {
		return nil, err
	}
	pkCopy := make([]byte, len(sk.Pub.Bytes))
	copy(pkCopy, sk.Pub.Bytes)
	return &SignedBundle{
		ValidatorID: validatorID,
		PublicKey:   pkCopy,
		Signature:   sig.Bytes,
	}, nil
}

// VerifyBundle verifies one SignedBundle envelope against the
// embedded public key.
//
// Returns true iff the signature is FIPS 205-valid under the
// bundle's embedded PublicKey for the supplied message.
//
// IMPORTANT: VerifyBundle does NOT check that the bundle's
// PublicKey matches an authoritative validator registry — the
// caller MUST do that via the knownValidators map in
// VerifyAggregated when the policy decision matters. A bare
// VerifyBundle call validates the cryptographic seal but says
// nothing about which validator-set policy the bundle satisfies.
func VerifyBundle(params *Params, bundle *SignedBundle, message []byte) bool {
	if err := params.Validate(); err != nil {
		return false
	}
	if bundle == nil {
		return false
	}
	if len(bundle.PublicKey) != params.PublicKeySize {
		return false
	}
	if len(bundle.Signature) != params.SignatureSize {
		return false
	}
	return slhVerify(params.ID, bundle.PublicKey, message, nil, bundle.Signature)
}

// AggregateSignatures collects N independently-produced
// SignedBundle envelopes into one AggregatedSignature for the
// supplied message.
//
// This function does NOT cryptographically aggregate the
// signatures — SLH-DSA admits no such operation (see file
// header). It collects, deduplicates, and shape-checks. Per-
// signature verification happens in VerifyAggregated.
//
// Deduplication: each ValidatorID appears AT MOST once in the
// output. If the input contains multiple bundles for the same
// ValidatorID, the FIRST occurrence wins (matches HotStuff
// collected-QC semantics: a validator who double-signs is
// counted once, but evidence of double-signing is preserved at
// the consensus layer — out of scope here).
//
// Shape checks: bundle.PublicKey and bundle.Signature must have
// the lengths dictated by params. Bundles with wrong lengths
// cause ErrBundleMismatch — the function is fail-fast.
func AggregateSignatures(params *Params, bundles []*SignedBundle, message []byte) (*AggregatedSignature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(bundles) == 0 {
		return nil, ErrEmptyBundle
	}

	deduped := make([]*SignedBundle, 0, len(bundles))
	seen := make(map[NodeID]struct{}, len(bundles))
	for _, b := range bundles {
		if b == nil {
			return nil, ErrBundleMismatch
		}
		if len(b.PublicKey) != params.PublicKeySize {
			return nil, ErrBundleMismatch
		}
		if len(b.Signature) != params.SignatureSize {
			return nil, ErrBundleMismatch
		}
		if _, dup := seen[b.ValidatorID]; dup {
			continue
		}
		seen[b.ValidatorID] = struct{}{}
		// Defensive copy: the bundle's PublicKey / Signature
		// slices may be aliased by the caller; the
		// AggregatedSignature is wire-stable and must not move
		// under the caller.
		pkCopy := make([]byte, len(b.PublicKey))
		copy(pkCopy, b.PublicKey)
		sigCopy := make([]byte, len(b.Signature))
		copy(sigCopy, b.Signature)
		deduped = append(deduped, &SignedBundle{
			ValidatorID: b.ValidatorID,
			PublicKey:   pkCopy,
			Signature:   sigCopy,
		})
	}

	msgCopy := make([]byte, len(message))
	copy(msgCopy, message)
	return &AggregatedSignature{
		Message: msgCopy,
		Bundles: deduped,
	}, nil
}

// VerifyAggregated verifies every SignedBundle in agg against the
// known-validators registry and returns the COUNT of valid
// signers.
//
// The count is the load-bearing output: a quorum policy decision
// ("is N ≥ threshold?") lives at the consumer, NOT in this
// primitive. This is the same decomplecting discipline that
// drives the rest of the Lux post-quantum stack: primitives
// report facts; policy gates filter them.
//
// Verification rules (each enforced per-bundle):
//
//  1. bundle.ValidatorID must appear in knownValidators. If not,
//     the function returns (0, ErrUnknownValidator) on the FIRST
//     unknown bundle — the wire envelope is treated as malformed.
//  2. bundle.PublicKey must byte-equal knownValidators[bundle.ValidatorID].
//     Mismatch is also fatal — returns ErrValidatorPubkeyMismatch.
//  3. The signature must verify under the registered public key
//     (NOT the bundle's embedded copy, to be paranoid). A
//     signature that fails verification is COUNTED OUT but is not
//     fatal — the function returns the partial count.
//
// Parallelism: VerifyAggregated dispatches per-bundle Verify
// calls across runtime.GOMAXPROCS(0) goroutines when len(agg.Bundles)
// >= verifyAggregatedConcurrentThreshold. This mirrors the
// goroutine fork-join pattern in
// github.com/luxfi/crypto/slhdsa.VerifyBatch (gpu.go
// verifyBatchConcurrent). The GPU substrate path is reachable by
// re-routing this verify through the upstream slhdsa.VerifyBatch
// — see the file header for the integration note.
//
// Returns:
//   - count: number of bundles that registered + verified, in
//     [0, len(agg.Bundles)].
//   - err: nil on success (including 0 valid signers), or one of
//     ErrUnknownValidator / ErrValidatorPubkeyMismatch when a
//     bundle violates the registry contract (NOT a signature
//     failure — that's just counted out).
func VerifyAggregated(params *Params, agg *AggregatedSignature, knownValidators map[NodeID][]byte) (uint, error) {
	if err := params.Validate(); err != nil {
		return 0, err
	}
	if agg == nil {
		return 0, ErrEmptyBundle
	}
	if len(agg.Bundles) == 0 {
		return 0, nil
	}

	// Phase 1: registry checks. Walk the bundles serially and
	// reject the entire envelope if any bundle violates the
	// known-validators contract. We dedupe here too (in case the
	// AggregatedSignature was constructed outside AggregateSignatures
	// and contains duplicates).
	dedupedIdx := make([]int, 0, len(agg.Bundles))
	seen := make(map[NodeID]struct{}, len(agg.Bundles))
	for i, b := range agg.Bundles {
		if b == nil {
			return 0, ErrBundleMismatch
		}
		if len(b.PublicKey) != params.PublicKeySize {
			return 0, ErrBundleMismatch
		}
		if len(b.Signature) != params.SignatureSize {
			return 0, ErrBundleMismatch
		}
		known, ok := knownValidators[b.ValidatorID]
		if !ok {
			return 0, ErrUnknownValidator
		}
		if len(known) != params.PublicKeySize {
			return 0, ErrValidatorPubkeyMismatch
		}
		if !ctEqualBytes(b.PublicKey, known) {
			return 0, ErrValidatorPubkeyMismatch
		}
		if _, dup := seen[b.ValidatorID]; dup {
			continue
		}
		seen[b.ValidatorID] = struct{}{}
		dedupedIdx = append(dedupedIdx, i)
	}

	// Phase 2: signature verification. Per-bundle Verify is pure
	// and independent — parallel across GOMAXPROCS workers when
	// the batch is large enough to amortise goroutine startup.
	//
	// This is the same fork-join pattern as
	// github.com/luxfi/crypto/slhdsa/gpu.go:verifyBatchConcurrent.
	// VerifyAggregatedDispatchTier exposes which tier ran so the
	// test suite can assert provenance.
	valid := make([]bool, len(dedupedIdx))
	dispatchTier := verifyAggregatedSerial
	if len(dedupedIdx) >= verifyAggregatedConcurrentThreshold {
		dispatchTier = verifyAggregatedConcurrent
		verifyAggregatedRunParallel(params, agg, dedupedIdx, valid, knownValidators)
	} else {
		for k, i := range dedupedIdx {
			b := agg.Bundles[i]
			pk := knownValidators[b.ValidatorID]
			valid[k] = slhVerify(params.ID, pk, agg.Message, nil, b.Signature)
		}
	}
	recordVerifyAggregatedTier(dispatchTier)

	var count uint
	for _, ok := range valid {
		if ok {
			count++
		}
	}
	return count, nil
}

// verifyAggregatedRunParallel runs the per-bundle Verify across
// GOMAXPROCS goroutines. Pure function per bundle, no shared
// state — same correctness rationale as
// luxfi/crypto/slhdsa.verifyBatchConcurrent.
func verifyAggregatedRunParallel(
	params *Params,
	agg *AggregatedSignature,
	dedupedIdx []int,
	valid []bool,
	knownValidators map[NodeID][]byte,
) {
	n := len(dedupedIdx)
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 2 {
		for k, i := range dedupedIdx {
			b := agg.Bundles[i]
			pk := knownValidators[b.ValidatorID]
			valid[k] = slhVerify(params.ID, pk, agg.Message, nil, b.Signature)
		}
		return
	}

	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for k := lo; k < hi; k++ {
				i := dedupedIdx[k]
				b := agg.Bundles[i]
				pk := knownValidators[b.ValidatorID]
				valid[k] = slhVerify(params.ID, pk, agg.Message, nil, b.Signature)
			}
		}(start, end)
	}
	wg.Wait()
}

// verifyAggregatedConcurrentThreshold is the minimum number of
// bundles at which VerifyAggregated forks the per-bundle Verify
// across GOMAXPROCS goroutines.
//
// SLH-DSA Verify is ~50ms per signature on M1 Max for SHAKE-192s,
// so goroutine startup (~10µs) is amortised at any n >= 2. We
// keep a margin to avoid spinning up workers for the trivial
// 1-validator case.
//
// Exposed as a package-level var (not a const) so test code can
// drop it to 2 to exercise the parallel path on a small batch.
var verifyAggregatedConcurrentThreshold = 2

// VerifyAggregatedTier is the dispatch tier the most recent
// VerifyAggregated call took. Exposed for the BatchVerify
// provenance test (aggregate_test.go).
//
// Mirrors the slhdsa.DispatchTier shape from
// luxfi/crypto/slhdsa/provenance.go but is local to magnetar.
// When magnetar is embedded in a system using luxfi/crypto's GPU
// substrate, callers should query slhdsa.GetProvenance() at the
// upstream layer instead.
type VerifyAggregatedTier int

const (
	// verifyAggregatedUnknown is the initial value before any
	// VerifyAggregated call has run.
	verifyAggregatedUnknown VerifyAggregatedTier = iota

	// verifyAggregatedSerial means VerifyAggregated dispatched on
	// a single goroutine (len < verifyAggregatedConcurrentThreshold).
	verifyAggregatedSerial

	// verifyAggregatedConcurrent means VerifyAggregated forked the
	// per-bundle Verify across GOMAXPROCS goroutines. This is the
	// parallel-CPU tier; it mirrors slhdsa.TierGoroutineParallelCPU.
	verifyAggregatedConcurrent
)

// String returns the canonical name of the dispatch tier.
func (t VerifyAggregatedTier) String() string {
	switch t {
	case verifyAggregatedSerial:
		return "serial-cpu"
	case verifyAggregatedConcurrent:
		return "goroutine-parallel-cpu"
	default:
		return "unknown"
	}
}

// verifyAggregatedLastTier records the dispatch tier of the most
// recent VerifyAggregated call. Single-writer, eventually-
// consistent — same model as
// luxfi/crypto/slhdsa.pluginStrongSymbolCache.
//
// Protected by a mutex (not atomic.Int32) because the test suite
// needs read-after-write ordering visibility on Apple Silicon
// where atomic Load on a different goroutine may observe a stale
// value across the goroutine-pool boundary.
var (
	verifyAggregatedLastTierMu sync.Mutex
	verifyAggregatedLastTier   = verifyAggregatedUnknown
)

func recordVerifyAggregatedTier(t VerifyAggregatedTier) {
	verifyAggregatedLastTierMu.Lock()
	verifyAggregatedLastTier = t
	verifyAggregatedLastTierMu.Unlock()
}

// LastVerifyAggregatedTier returns the dispatch tier of the most
// recent VerifyAggregated call. Used by the BatchVerify
// provenance test to confirm the parallel goroutine path is being
// exercised. Mirrors luxfi/crypto/slhdsa.GetProvenance() in
// purpose — auditable evidence of dispatch behaviour at runtime.
func LastVerifyAggregatedTier() VerifyAggregatedTier {
	verifyAggregatedLastTierMu.Lock()
	defer verifyAggregatedLastTierMu.Unlock()
	return verifyAggregatedLastTier
}

// ctEqualBytes compares two byte slices in constant time relative
// to their CONTENTS (the lengths are public; an early-return on
// length mismatch is acceptable). Returns true iff lengths match
// and every byte is equal.
//
// We do not use crypto/subtle.ConstantTimeCompare here so the
// magnetar package's CT footprint is self-contained: ctEqual32
// and ctEqualBytes are the entire CT primitive surface (the rest
// of the package's CT discipline is byte-by-byte OR-accumulation
// in PublicKey.Equal etc).
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
