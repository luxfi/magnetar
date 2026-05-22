// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// standalone.go — Per-validator standalone SLH-DSA: the PRIMARY,
// CANONICAL primitive for public-BFT post-quantum consensus.
//
// HONEST ARCHITECTURE FRAMING
// ===========================
//
// SLH-DSA (FIPS 205) is HASH-BASED. It has no algebraic structure
// that admits FROST-style threshold aggregation. The literature
// confirms this is fundamental:
//
//   - Cozzo & Smart (EUROCRYPT 2019), "Sharing the LUOV": every
//     internal SHAKE/SHA-2 evaluation in an HBS scheme is a
//     non-linear function of the secret seed. Secret-sharing the
//     seed forces every hash to be evaluated under MPC.
//   - Bonte, Smart, Tan (2023), "Threshold SPHINCS+": exhaustive
//     infeasibility analysis. There is no efficient t-of-n SLH-DSA
//     scheme producing a single FIPS 205-shaped signature without
//     either (a) reconstructing the seed (dealer or aggregator in
//     TCB) or (b) running full MPC over the SHA-256/SHAKE hash tree
//     (multi-second per signature, multi-megabyte of comms).
//   - NIST IR 8214 / MPTC submission notes: SLH-DSA is classified
//     as "highest threshold-MPC cost" among FIPS 20{3,4,5}.
//   - FIPS 205 §6 (slh_sign_internal): direct inspection confirms
//     no Lagrange-aggregatable response.
//
// THE PUBLIC-BFT-SAFE PRIMARY PRIMITIVE for SLH-DSA is therefore
// "N separate signatures" — each validator i holds its OWN keypair
// (sk_i, pk_i), each produces a single-party FIPS 205 σ_i over the
// message, and the consensus layer collects N of them into a
// ValidatorAggregateCert:
//
//   ValidatorAggregateCert = (Mode, Signers, PubKeys, Sigs)
//
// Verification:
//
//   valid_count = Σ_i 1[FIPS 205 Verify(pk_i, msg, σ_i) ∧ pk_i = registry(i)]
//   accept iff valid_count ≥ quorum_threshold
//
// Wire size: N × |σ|. For SHAKE-192s (16,224-byte σ) and a 21-validator
// quorum that's ~332 KiB. A Z-Chain Groth16 rollup compresses this to
// ~192 bytes; the rollup is a SEPARATE primitive (lux-zchain spec),
// not part of this API.
//
// WHY NOT THRESHOLD HBS FOR PUBLIC CONSENSUS
// ==========================================
//
// The thbs subpackage (ref/go/pkg/thbs/) ships TRUE threshold HBS
// per McGrew et al. ePrint 2019/793. Its v1 setup is DEALER-BACKED:
// a single dealer generates the per-element secrets and Shamir-shares
// them. Dealer-backed threshold HBS is RESEARCHED but NOT public-BFT-
// safe (the dealer learns every secret element at setup time).
//
// A truly public-DKG threshold HBS requires:
//   (A) PVSS distribution of per-element entropy contributions:
//       x_{slot,e} = Σ_j r_{j,slot,e}; no party holds x.
//   (B) MPC over the SHA-256/SHAKE hash tree to compute the public
//       Merkle root from secret-shared leaves WITHOUT REVEALING the
//       leaves. This is the hard frontier (Damgård-Pastro-Smart-
//       Zakarias SPDZ 2012, Wang-Ranellucci-Katz "Global-Scale Secure
//       Multiparty Computation" 2017, Boyle-Gilboa-Ishai "Function
//       Secret Sharing" 2015).
//
// (A) is shipped at thbs/dkg2/ as a skeleton. (B) is open research
// tracked at BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1. Until (B) lands,
// thbs is APPROPRIATE for M-Chain bridge custody (where a TEE'd
// dealer is in the TCB by policy) but NOT for public BFT.
//
// FOR PUBLIC BFT: USE THIS FILE.
//
// API CONTRACT
// ============
//
//   - PerValidatorKeypair generates a STANDALONE FIPS 205 keypair.
//     No DKG. No dealer. No shared seed. Each validator runs this
//     ONCE, persists (sk_i, pk_i), and registers pk_i in the
//     validator-set commitment.
//
//   - ValidatorSign is the canonical signing primitive. Equivalent
//     to single-party FIPS 205 SignDeterministic on (sk_i, message).
//     The output is a raw |σ|-byte slice ready for the consensus
//     layer's wire format. Pass rng != nil only if you want the
//     FIPS 205 RANDOMIZED variant; the default (rng == nil) is the
//     deterministic variant matching SignDeterministic byte-for-byte.
//
//   - ValidatorBatchVerify verifies N (pub, msg, sig) triples in
//     parallel via the same goroutine fork-join pattern used in
//     luxfi/crypto/slhdsa.VerifyBatch. Returns a bitmap of
//     valid/invalid per signer.
//
//   - ValidatorAggregateCert is the wire envelope shipped in a
//     QuasarCert or rolled up via Z-Chain Groth16. Carries N
//     independently-verifiable signatures.
//
//   - VerifyAggregateCert verifies the entire bundle against a
//     known-validator allowlist. Signatures from unknown validators
//     are counted as INVALID (defense against impersonation). The
//     function returns the COUNT of valid signers; the quorum
//     decision lives at the consumer.
//
// DECOMPLECTING DISCIPLINE
// ========================
//
//   - The signing primitive (ValidatorSign) takes ONE secret key and
//     produces ONE signature. It does NOT reach for any aggregator,
//     ceremony state, or shared material. A single-validator signing
//     a single message is a single function call with NO surrounding
//     protocol context.
//
//   - The verification primitive (ValidatorBatchVerify) takes N
//     PUBLIC inputs and returns N independent booleans. No
//     cross-signer coupling.
//
//   - The cert primitive (ValidatorAggregateCert / VerifyAggregateCert)
//     adds REGISTRY BINDING (knownValidators) on top of batch verify.
//     The registry is the consensus layer's authoritative validator-
//     set; the cert primitive consumes it but does not own it.
//
//   - The quorum decision (count ≥ threshold) lives at the CONSUMER.
//     This primitive REPORTS facts; policy gates filter them.
//
// COMPOSITION WITH THE EXISTING AGGREGATE API
// ===========================================
//
// The aggregate.go API (SignedBundle, AggregateSignatures,
// VerifyAggregated, etc.) ships the SAME computational graph under
// a "bundle / aggregate" shape: bundles carry self-describing
// PublicKey bytes in the envelope; AggregateSignatures dedupes and
// shape-checks; VerifyAggregated cross-checks against a registry.
// That API STAYS — it is the SDK-friendly form.
//
// The standalone.go API is the EXPLICIT-SEMANTIC form for the
// consensus layer: ValidatorSign returns raw σ bytes that flow
// straight into a wire envelope without going through SignedBundle;
// ValidatorAggregateCert carries the (PubKeys, Sigs, Signers)
// triple as parallel slices ready to be Groth16-compressed.
//
// Both APIs are byte-compatible: a ValidatorAggregateCert built
// from N ValidatorSign outputs verifies under VerifyAggregated
// after a trivial conversion (see toSignedBundles below). The
// duplication is DELIBERATE — bundles are the SDK shape;
// aggregate-cert is the consensus-wire shape.

import (
	"errors"
	"io"
	"runtime"
)

// (crypto/rand is reached via Sign indirectly; this file does not
// directly source randomness.)

// Errors returned by the standalone (public-BFT) API.
var (
	// ErrAggregateCertEmpty is returned by VerifyAggregateCert when
	// the cert carries zero signers.
	ErrAggregateCertEmpty = errors.New("magnetar: aggregate cert has no signers")

	// ErrAggregateCertShape is returned when the parallel slices
	// (Signers, PubKeys, Sigs) have mismatched lengths or any
	// individual entry has the wrong byte length for the cert's Mode.
	ErrAggregateCertShape = errors.New("magnetar: aggregate cert has mismatched slice shapes")

	// ErrAggregateCertMode is returned when a cert carries a Mode
	// the params do not match.
	ErrAggregateCertMode = errors.New("magnetar: aggregate cert mode mismatch")
)

// PerValidatorKeypair generates a STANDALONE SLH-DSA keypair for
// one validator.
//
// Public-BFT contract:
//
//   - No DKG, no shares, no dealer, no MPC.
//   - Each validator runs this INDEPENDENTLY on its own host with
//     its own RNG.
//   - The validator persists (sk, pk) — losing sk means dropping
//     out of the quorum until rotating to a fresh keypair.
//   - The consensus layer's validator-set registry binds
//     (ValidatorID, pk) so peers can verify this validator's
//     signatures.
//
// This is the FIPS 205 keygen primitive: the returned PublicKey is
// byte-identical to what circl/slhdsa.Scheme().DeriveKey would emit
// on the same seed; the returned PrivateKey carries the seed and
// can be used with ValidatorSign or any other Magnetar sign path.
//
// rng may be nil (crypto/rand is used). Pass a deterministic
// reader for KAT-reproducible key generation.
//
// Equivalent semantics to GenerateValidatorKey in aggregate.go;
// this is the EXPLICIT-SEMANTIC name for the public-BFT path.
func PerValidatorKeypair(params *Params, rng io.Reader) (*PrivateKey, *PublicKey, error) {
	return GenerateValidatorKey(params, rng)
}

// ValidatorSign is the canonical public-BFT signing primitive.
//
// Returns the raw FIPS 205 signature bytes (length =
// params.SignatureSize for sk's mode). The signature verifies under
// unmodified circl/slhdsa.Verify against the validator's public key
// (sk.Pub.Bytes).
//
// Semantics: this is ONE validator's contribution to a multi-
// validator certificate. The consensus layer collects N
// ValidatorSign outputs into a ValidatorAggregateCert via
// BuildAggregateCert.
//
// Determinism: when rng is nil, the output is FIPS 205
// SignDeterministic — byte-identical across calls for any (sk,
// message) pair. This is the recommended mode for the Lux
// validator path because it lets the consensus layer dedupe
// duplicate broadcasts at the wire layer.
//
// When rng is non-nil, the output is FIPS 205 SignRandomized with
// n bytes of fresh randomness drawn from rng. Use the randomized
// variant only if you specifically need the hedged-against-bad-RNG
// property; the deterministic variant is the standard recommendation
// for consensus.
//
// ctx is intentionally omitted: this primitive is the wire-format
// canonical sign. Bind chain-id / block-height into the message
// upstream of this call (the consensus layer's transcript-hash
// pattern handles this; see luxfi/consensus QuasarCert).
//
// If you need an explicit ctx, use Sign in sign.go directly.
func ValidatorSign(sk *PrivateKey, rng io.Reader, message []byte) ([]byte, error) {
	if sk == nil {
		return nil, ErrNilKey
	}
	params, err := ParamsFor(sk.Mode)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(params, sk, message, nil, rng != nil, rng)
	if err != nil {
		return nil, err
	}
	return sig.Bytes, nil
}

// ValidatorBatchVerify verifies N (pub, msg, sig) triples and
// returns a bitmap of valid/invalid per signer.
//
// Parallelism: this routes through the same goroutine fork-join
// pattern as VerifyAggregated (above the
// verifyAggregatedConcurrentThreshold the work is forked across
// GOMAXPROCS workers). The pattern mirrors
// luxfi/crypto/slhdsa.VerifyBatch — when magnetar is embedded in a
// system that exports a GPU substrate (e.g. consensus quorum
// verification routing through crypto/slhdsa.VerifyBatch with the
// luxcpp/lux-accel SLH-DSA GPU plugin loaded), callers SHOULD
// route their batch through that upstream primitive for the GPU
// upper bound. This package ships the goroutine-parallel CPU
// floor.
//
// Returns:
//   - bitmap[i] = true iff slhdsa.Verify(pubs[i].Bytes, msgs[i], sigs[i])
//     accepts. Per-signer verify failures are reported as bitmap[i] =
//     false, NOT as an error.
//   - err = nil on success, even when some signatures fail; err is
//     non-nil only for STRUCTURAL violations (length mismatches,
//     mode mismatches, nil inputs).
//
// Provenance: the dispatch tier (serial vs goroutine-parallel) is
// observable via LastVerifyAggregatedTier — the same hook the
// aggregate.go path uses, since ValidatorBatchVerify and
// VerifyAggregated share the same parallel-CPU dispatch.
func ValidatorBatchVerify(params *Params, pubs []*PublicKey, msgs [][]byte, sigs [][]byte) ([]bool, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(pubs)
	if n != len(msgs) || n != len(sigs) {
		return nil, ErrAggregateCertShape
	}
	out := make([]bool, n)
	if n == 0 {
		return out, nil
	}
	// Shape + mode checks first; any structural failure is fatal so
	// the caller does not consume a half-validated bitmap.
	for i := 0; i < n; i++ {
		if pubs[i] == nil {
			return nil, ErrNilPublicKey
		}
		if pubs[i].Mode != params.Mode {
			return nil, ErrModeMismatch
		}
		if len(pubs[i].Bytes) != params.PublicKeySize {
			return nil, ErrPublicKeyWrongSize
		}
		if len(sigs[i]) != params.SignatureSize {
			return nil, ErrSignatureWrongSize
		}
	}

	// Build the per-bundle AggregatedSignature view so we can reuse
	// the existing parallel-CPU dispatch in VerifyAggregated. We
	// intentionally do NOT pass a knownValidators map here — the
	// bitmap path is for the lower-level case where the registry
	// binding is handled by the caller (VerifyAggregateCert is the
	// registry-binding wrapper).
	//
	// We dispatch directly so we get the same provenance hook
	// (LastVerifyAggregatedTier) without paying the dedupe pass —
	// in this primitive the caller has already chosen the input
	// order.
	dispatchTier := verifyAggregatedSerial
	if n >= verifyAggregatedConcurrentThreshold {
		dispatchTier = verifyAggregatedConcurrent
		validatorBatchVerifyConcurrent(params, pubs, msgs, sigs, out)
	} else {
		for i := 0; i < n; i++ {
			out[i] = slhVerify(params.ID, pubs[i].Bytes, msgs[i], nil, sigs[i])
		}
	}
	recordVerifyAggregatedTier(dispatchTier)
	return out, nil
}

// validatorBatchVerifyConcurrent runs per-signer Verify across
// GOMAXPROCS goroutines for the message-batch case (each signer
// gets its own message). Pure function per signer, no shared
// state — same byte-equality contract as the serial path and as
// VerifyAggregated's parallel dispatch.
func validatorBatchVerifyConcurrent(params *Params, pubs []*PublicKey, msgs [][]byte, sigs [][]byte, out []bool) {
	n := len(pubs)
	workers := runtimeGOMAXPROCS()
	if workers > n {
		workers = n
	}
	if workers < 2 {
		for i := 0; i < n; i++ {
			out[i] = slhVerify(params.ID, pubs[i].Bytes, msgs[i], nil, sigs[i])
		}
		return
	}

	type job struct {
		lo, hi int
	}
	jobs := make([]job, 0, workers)
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
		jobs = append(jobs, job{lo: start, hi: end})
	}
	done := make(chan struct{}, len(jobs))
	for _, j := range jobs {
		go func(lo, hi int) {
			for i := lo; i < hi; i++ {
				out[i] = slhVerify(params.ID, pubs[i].Bytes, msgs[i], nil, sigs[i])
			}
			done <- struct{}{}
		}(j.lo, j.hi)
	}
	for i := 0; i < len(jobs); i++ {
		<-done
	}
}

// runtimeGOMAXPROCS wraps runtime.GOMAXPROCS(0) so callers don't
// re-import runtime here.
func runtimeGOMAXPROCS() int {
	return runtime.GOMAXPROCS(0)
}

// ValidatorAggregateCert is the wire envelope for N per-validator
// SLH-DSA signatures over a SINGLE message.
//
// Wire layout (canonical, parallel-slices form):
//
//   Mode || N || Signers[0] || ... || Signers[N-1]
//        || PubKeys[0] || ... || PubKeys[N-1]
//        || Sigs[0] || ... || Sigs[N-1]
//
// where:
//   - Mode is one byte.
//   - N is a 4-byte big-endian count.
//   - Each Signers[i] is 32 bytes (NodeID).
//   - Each PubKeys[i] is params.PublicKeySize bytes.
//   - Each Sigs[i] is params.SignatureSize bytes.
//
// (Magnetar's reference impl does NOT pin a specific transport
// encoding — that's the responsibility of the consensus layer.
// RLP / protobuf / canonical binary are all reasonable choices.
// The parallel-slices form is INTENTIONALLY chosen over a nested
// SignedBundle list because it maps directly to Z-Chain Groth16
// rollup input where the prover's wire shape is N parallel
// witnesses, not N records.)
//
// All N signatures are over the SAME message. If the consensus
// layer needs distinct per-signer messages (e.g. per-signer
// transcript binding), use ValidatorBatchVerify directly.
//
// This shape is the SIBLING of AggregatedSignature (aggregate.go):
//   - AggregatedSignature: nested SignedBundle list, SDK-friendly,
//     self-describing per-bundle.
//   - ValidatorAggregateCert: parallel-slices, consensus-wire
//     friendly, Z-Chain-rollup-friendly.
//
// Both are byte-equivalent under conversion (see toSignedBundles).
type ValidatorAggregateCert struct {
	// Mode is the FIPS 205 parameter set every signature targets.
	Mode Mode

	// Signers carries each signer's canonical 32-byte validator
	// identifier (NodeID).
	Signers []NodeID

	// PubKeys carries each signer's FIPS 205 public-key bytes.
	// Length per entry = params.PublicKeySize. Length of slice =
	// len(Signers).
	PubKeys [][]byte

	// Sigs carries each signer's FIPS 205 signature bytes. Length
	// per entry = params.SignatureSize. Length of slice =
	// len(Signers).
	Sigs [][]byte
}

// BuildAggregateCert constructs a ValidatorAggregateCert from N
// parallel slices.
//
// The function performs shape + mode validation and a defensive
// copy of each PubKeys[i] / Sigs[i] (the caller's slices may be
// aliased; the cert is wire-stable and must not move under the
// caller).
//
// Returns ErrAggregateCertShape on any shape mismatch.
func BuildAggregateCert(params *Params, signers []NodeID, pubKeys [][]byte, sigs [][]byte) (*ValidatorAggregateCert, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(signers)
	if n != len(pubKeys) || n != len(sigs) {
		return nil, ErrAggregateCertShape
	}
	if n == 0 {
		return nil, ErrAggregateCertEmpty
	}
	outPubs := make([][]byte, n)
	outSigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		if len(pubKeys[i]) != params.PublicKeySize {
			return nil, ErrAggregateCertShape
		}
		if len(sigs[i]) != params.SignatureSize {
			return nil, ErrAggregateCertShape
		}
		pk := make([]byte, params.PublicKeySize)
		copy(pk, pubKeys[i])
		sg := make([]byte, params.SignatureSize)
		copy(sg, sigs[i])
		outPubs[i] = pk
		outSigs[i] = sg
	}
	signersCopy := make([]NodeID, n)
	copy(signersCopy, signers)
	return &ValidatorAggregateCert{
		Mode:    params.Mode,
		Signers: signersCopy,
		PubKeys: outPubs,
		Sigs:    outSigs,
	}, nil
}

// VerifyAggregateCert verifies every signature in cert against the
// registered public key for that signer and returns the COUNT of
// valid signers.
//
// Verification rules (each enforced per signer):
//
//  1. cert.Signers[i] must appear in knownValidators. If not, that
//     signer is COUNTED AS INVALID. This is a defense-in-depth choice
//     against impersonation: an attacker who slips a SignedBundle
//     from an unknown validator into the cert does NOT crash the
//     verifier, but does NOT gain a count either. (Compare to
//     VerifyAggregated which returns ErrUnknownValidator as a fatal
//     error; the standalone form is more permissive on registry
//     misses because the cert may be Groth16-rolled-up over a
//     stale registry and the verifier should not abort the entire
//     batch on one stale entry.)
//
//  2. cert.PubKeys[i] must byte-equal knownValidators[cert.Signers[i]].
//     A pubkey mismatch is also counted as INVALID (NOT fatal) —
//     same rationale as (1).
//
//  3. The signature must verify under the REGISTERED public key (not
//     the cert's embedded copy, to be paranoid).
//
//  4. Duplicate signers are deduped: the FIRST occurrence wins and
//     subsequent occurrences are silently dropped (NOT counted twice,
//     NOT counted as invalid — the consensus layer can collect proof
//     of double-signing separately via per-signer Sigs comparison).
//
// The count is the load-bearing output: a quorum policy decision
// ("is N ≥ threshold?") lives at the consumer, NOT in this
// primitive. This is the same decomplecting discipline the rest of
// the Lux post-quantum stack uses.
//
// Returns:
//   - validCount: number of signers that verified, in [0, len(cert.Signers)].
//   - err: nil on success (including 0 valid signers), or one of
//     ErrAggregateCertEmpty / ErrAggregateCertShape /
//     ErrAggregateCertMode when the cert is structurally malformed.
func VerifyAggregateCert(cert *ValidatorAggregateCert, message []byte, knownValidators map[NodeID][]byte) (int, error) {
	if cert == nil {
		return 0, ErrAggregateCertEmpty
	}
	params, err := ParamsFor(cert.Mode)
	if err != nil {
		return 0, ErrAggregateCertMode
	}
	n := len(cert.Signers)
	if n == 0 {
		return 0, ErrAggregateCertEmpty
	}
	if n != len(cert.PubKeys) || n != len(cert.Sigs) {
		return 0, ErrAggregateCertShape
	}
	for i := 0; i < n; i++ {
		if len(cert.PubKeys[i]) != params.PublicKeySize {
			return 0, ErrAggregateCertShape
		}
		if len(cert.Sigs[i]) != params.SignatureSize {
			return 0, ErrAggregateCertShape
		}
	}

	// Phase 1: dedupe Signers, build the verify queue, and
	// classify each entry as (verifiable, against-which-pk) or
	// (skip — unknown signer / pubkey mismatch).
	type entry struct {
		idx        int
		registered []byte
		verifiable bool
	}
	entries := make([]entry, 0, n)
	seen := make(map[NodeID]struct{}, n)
	for i := 0; i < n; i++ {
		if _, dup := seen[cert.Signers[i]]; dup {
			continue
		}
		seen[cert.Signers[i]] = struct{}{}
		known, ok := knownValidators[cert.Signers[i]]
		if !ok {
			entries = append(entries, entry{idx: i, verifiable: false})
			continue
		}
		if len(known) != params.PublicKeySize {
			entries = append(entries, entry{idx: i, verifiable: false})
			continue
		}
		if !ctEqualBytes(cert.PubKeys[i], known) {
			entries = append(entries, entry{idx: i, verifiable: false})
			continue
		}
		entries = append(entries, entry{idx: i, registered: known, verifiable: true})
	}

	// Phase 2: per-signer Verify, parallel above the concurrent
	// threshold. We build flat slices for the parallel dispatch.
	verifiableIdx := make([]int, 0, len(entries))
	for _, e := range entries {
		if e.verifiable {
			verifiableIdx = append(verifiableIdx, e.idx)
		}
	}
	results := make(map[int]bool, len(verifiableIdx))
	if len(verifiableIdx) > 0 {
		pubs := make([]*PublicKey, len(verifiableIdx))
		msgs := make([][]byte, len(verifiableIdx))
		sigs := make([][]byte, len(verifiableIdx))
		for k, idx := range verifiableIdx {
			pubs[k] = &PublicKey{Mode: params.Mode, Bytes: cert.PubKeys[idx]}
			msgs[k] = message
			sigs[k] = cert.Sigs[idx]
		}
		bitmap, vErr := ValidatorBatchVerify(params, pubs, msgs, sigs)
		if vErr != nil {
			return 0, vErr
		}
		for k, idx := range verifiableIdx {
			results[idx] = bitmap[k]
		}
	}

	// Phase 3: tally. Verifiable + valid = count++; verifiable +
	// invalid = count untouched; non-verifiable = count untouched.
	count := 0
	for _, e := range entries {
		if !e.verifiable {
			continue
		}
		if results[e.idx] {
			count++
		}
	}
	return count, nil
}
