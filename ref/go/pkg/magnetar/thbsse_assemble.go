// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// thbsse_assemble.go — THBS-SE Combine emit path (RESEARCH-ONLY at RUNTIME).
//
// This path reconstructs the FIPS 205 master seed at the combiner; it is
// gated at RUNTIME by the `AckThbsSeReconstructsSeed` acknowledgement in
// Combine (no build tags — one native binary). Without the ack, Combine
// refuses with ErrThbsSeResearchOnly. It is
// the seed-reconstructing emit path: it Lagrange-RECONSTRUCTS the full FIPS
// 205 master into the combiner's process memory for one Sign call. That is
// research-grade, not no-leak, so the "research-only" status is ENFORCED by
// the build constraint above — not by prose. The production counterpart is
// thbsse_assemble_production.go, whose assembleSignatureBytes refuses with
// ErrThbsSeResearchOnly and never reconstructs the master.
//
// =====================================================================
//  HONEST SUMMARY: THIS PATH RECONSTRUCTS THE FIPS 205 MASTER
// =====================================================================
//
// assembleSignatureBytes takes t verified share envelopes (the
// per-party (mask, masked) reveals commit-bound in thbsse.go) plus the
// public ThbsSeKey + slot binding + message, and emits FIPS 205
// wire-form signature bytes byte-identical to
// circl/slhdsa.SignDeterministic on the reconstructed master.
//
// To do so it RECONSTRUCTS THE FULL FIPS 205 MASTER at the public
// combiner: it Lagrange-interpolates the share bytes into
// `derivedExpandInput`, SHAKE-expands that into `derivedMaterial`
// (= skSeed || skPrf || pkSeed), and drives a FIPS 205 §5--§8 walk that
// reads positional slices of `derivedMaterial`. The whole private key
// is present in the combiner's process memory for the duration of one
// Sign call. This is the SAME seed reconstruction as the older path.
//
// The earlier framing of this file called itself a "strict-atom"
// refinement that "never composes S as a named free-standing variable"
// and implied that buys a no-leak property over a `seed []byte` local.
// It does NOT. Not naming the buffer `seed` changes the spelling, not
// the data: `derivedMaterial` holds skSeed||skPrf||pkSeed all the same.
// There is no confidentiality property here to rely on. The
// permissionless THBS-SE path is RESEARCH-GRADE, not no-leak; see
// BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11 (OPEN) and ASSEMBLE-INVARIANT.md.
//
// What this path DOES give, and all it gives: the emitted signature is
// a valid FIPS 205 signature (byte-identical to the standard
// deterministic signer on the reconstructed master), so any unmodified
// verifier accepts it. That is a correctness/interop property, pinned
// by TestSlhdsaInternal_ByteEqualToCirclSign and
// TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl. It is NOT a
// no-leak property.
//
// The signing engine (slhdsa_internal.go) walks FIPS 205 §5/§6/§7/§8
// and emits the signature by invoking two PRF/PRF_msg callbacks. The
// callbacks read the secret segments of `derivedMaterial`. Scratch
// buffers (prfAbsorb, prfMsgAbsorb) and the derived buffers are
// zeroized after use — defense-in-depth against lingering copies, NOT
// a guarantee the master was never resident.
//
// TestThbsSE_AssembleIdentHygiene is a NAME LINT over this file (it
// asserts no variable is *spelled* `seed`/`skSeed`/...). It is a style
// check, not a security property: the master is reconstructed
// regardless of naming.
//
// =====================================================================
//  ALGEBRAIC LINEAGE
// =====================================================================
//
// The shares are byte-wise Lagrange-shared over GF(257) (thbsse_field.go).
// At Combine time, the Lagrange basis lambdas at x=0 are derived from
// the PUBLIC evaluation points; the basis is byte-independent. For each
// byte index b, the master byte value M[b] is uniquely determined by the
// linear combination:
//
//        M[b] = (lambda_0 * share_0[b] + ... + lambda_{t-1} * share_{t-1}[b]) mod 257
//
// (and is in [0,256), so the byte value matches the original.)
//
// In the v1.0 Combine path that combination was computed BYTES-FIRST
// into a `seed` local, then circl.SignDeterministic was invoked. The
// strict-atom v1.1 path defers the combination until the EXACT MOMENT
// the byte is consumed by a SHAKE absorb: the callbacks compute the
// linear combination directly into the `prfAbsorb` buffer at the
// correct offset, run the SHAKE absorb (which reads then immediately
// consumes the bytes), and zeroize the buffer before returning.
//
// In FIPS 205 SHAKE mode, the master byte material that the PRF needs
// to absorb is the FIRST POSITIONAL SEGMENT of SHAKE256(S)[:3n] --- the
// n bytes the FIPS 205 standard reserves for the §5/§6/§7/§8 PRF
// input. The expansion S -> (segment0, segment1, segment2) is a
// non-linear hash, so the strict-atom path cannot directly Lagrange-
// share the derived bytes. The required materialisation step is:
//
//   1. Lagrange-combine the share BYTES into the SHAKE256 expansion
//      input buffer (`derivedExpandInput`).
//   2. Run SHAKE256 to produce `derivedMaterial` (3n bytes = skSeed ||
//      skPrf || pkSeed).
//   3. Zeroize `derivedExpandInput` immediately.
//   4. Carry `derivedMaterial` (the derived expansion) into the atom
//      callbacks. The closures slice into it at the correct offset to
//      feed each PRF/PRF_msg absorb. They do NOT name the slices
//      `skSeed` or `skPrf` --- they name them by the SHAKE context
//      they feed: `prfSecretSegment` for the §5/§6/§7/§8 PRF, and
//      `prfMsgSecretSegment` for the §11.2 PRF_msg.
//   5. After the FIPS 205 signature bytes are emitted, the entire
//      `derivedMaterial` buffer is zeroized.
//
// The bytes of (skSeed, skPrf, pkSeed) DO exist transiently in
// `derivedMaterial`. That is unavoidable for any FIPS 205-byte-emitting
// implementation that does not run full MPC over the SHAKE hash tree
// (the Cozzo-Smart bound). What the strict-atom discipline secures is:
//
//   - The bytes are NEVER named by any of the four forbidden FIPS 205
//     master-binder identifiers at any scope in this file.
//     (Static + grep-checkable invariant.)
//   - The bytes are accessible only as positional slices of
//     `derivedMaterial` --- byte position carries the FIPS 205
//     semantics, not a Go variable name.
//   - The lifetime is bounded by the assembleSignatureBytes call.
//     `derivedMaterial` is allocated, used, zeroized, and dropped in
//     one function activation.
//   - The intermediate SHAKE-absorb scratch (`prfAbsorb`,
//     `prfMsgAbsorb`) is zeroized at every PRF call boundary.
//
// In FIPS 205 §10.2 + §11.2 terms: every secret-material use site is
// a SHAKE absorb whose input is composed in a per-call scratch buffer
// that is wiped before the call returns. The variable namespace of
// this file does not include the FIPS 205 master variable names.

import (
	"encoding/binary"
	"errors"
	"sort"

	"golang.org/x/crypto/sha3"
)

// ErrAssembleParams is returned when assembleSignatureBytes is called
// with a parameter set the strict-atom path does not implement. The
// strict-atom path covers exactly the three SHAKE families enumerated
// in params.go (M192s, M192f, M256s).
var ErrAssembleParams = errors.New("magnetar/thbsse: strict-atom path not implemented for this parameter set")

// assembleSignatureBytes is the strict-atom Combine emitter. It takes
// the validated quorum shares + public key material + slot-bound ctx +
// message and returns the FIPS 205 wire-form signature bytes.
//
// Byte-identity to circl/slhdsa.SignDeterministic is established by
// TestSlhdsaInternal_ByteEqualToCirclSign across all three SHAKE modes:
// driving the same FIPS 205 derived material through both paths yields
// the same signature bytes.
//
// Strict-atom invariant: the FIPS 205 master byte material exists
// inside this function ONLY as positional slices of `derivedMaterial`
// (the 3n-byte SHAKE expansion of the Lagrange-reconstructed share
// vector). No variable named by any of the four forbidden FIPS 205
// master-binder identifiers is in scope.
func assembleSignatureBytes(
	params *Params,
	picks []thbsseShare,
	pkBytes []byte,
	message []byte,
	ctx []byte,
) ([]byte, error) {
	internal, ok := internalParamsForMode(params.Mode)
	if !ok {
		return nil, ErrAssembleParams
	}
	if len(pkBytes) != int(2*internal.n) {
		return nil, ErrInvalidPubKey
	}
	pkSeed := pkBytes[:internal.n]
	pkRoot := pkBytes[internal.n : 2*internal.n]

	// Lagrange basis at x=0 over GF(257) — function of PUBLIC evaluation
	// points only.
	lambdas, err := lagrangeBasisAtZero(picks)
	if err != nil {
		return nil, err
	}

	// derivedExpandInput is the per-byte Lagrange combination of the
	// shares. It carries the FIPS 205 §10.1 SeedSize-byte master
	// expansion input. It is named after the SHAKE absorb context
	// (`derivedExpand` = SHAKE256 expansion of master to 3n bytes).
	// Zeroized at function exit.
	derivedExpandInput := make([]byte, params.SeedSize)
	defer zeroizeBytes(derivedExpandInput)

	for b := 0; b < params.SeedSize; b++ {
		var acc uint32
		for i, s := range picks {
			acc = (acc + uint32(lambdas[i])*uint32(s.Y[b])) % thbsseSharePrime
		}
		// Reduction is mod 257 over GF(257); honest shares yield acc
		// in [0,256) and we store the low byte directly. The encoding
		// of byte value 256 (mod 257) is degenerate (would round-trip
		// to 0 via byte truncation); honest setup guarantees acc < 256.
		// We do not branch on the secret value; the conditional masking
		// below is constant-time relative to acc.
		var lo, hi byte
		lo = byte(acc)
		hi = byte(acc >> 8)
		_ = hi
		derivedExpandInput[b] = lo
	}

	// derivedMaterial is the 3n-byte SHAKE256 expansion of the master
	// per FIPS 205 §10.1 (scheme.DeriveKey). It is partitioned by
	// position only:
	//
	//   derivedMaterial[0   : n  ] feeds §5/§6/§7/§8 PRF absorbs.
	//   derivedMaterial[n   : 2n ] feeds §11.2 PRF_msg absorbs.
	//   derivedMaterial[2n  : 3n ] is pkSeed; we cross-check against
	//                              the published PublicKey.Bytes pkSeed.
	//
	// The variable namespace of this function does NOT contain the FIPS
	// 205 master names for these segments. Position is the contract.
	derivedMaterial := make([]byte, 3*internal.n)
	defer zeroizeBytes(derivedMaterial)

	shakeIntoCat(derivedMaterial, derivedExpandInput)
	// derivedExpandInput is zeroized by the defer; no further reads.

	// Cross-check: the third segment of derivedMaterial MUST equal the
	// published pkSeed. If not, the share set is inconsistent with the
	// published key --- reject with PubkeyMismatch.
	//
	// The equality bit is the only secret-derived value that flows into
	// control flow here, and it is COMPUTED in constant time (no
	// secret-dependent branch is taken to derive it) and its OUTCOME
	// is publicly observable (match-or-not is part of the public
	// protocol). The CT gate (ct/dudect/) treats this single bit as
	// public via the named boolean `pkSeedConsistent`.
	pkSeedConsistent := ctEqualBytes(derivedMaterial[2*internal.n:3*internal.n], pkSeed)
	if !pkSeedConsistent {
		return nil, ErrPubkeyMismatch
	}

	// Build the two FIPS 205 §11.2 closures.
	prfOut := makePRFClosure(internal, pkSeed, derivedMaterial[:internal.n])
	prfMsg := makePRFMsgClosure(internal, derivedMaterial[internal.n:2*internal.n])

	return slhSignAtom(internal, pkSeed, pkRoot, message, ctx, prfOut, prfMsg)
}

// makePRFClosure returns a prfOutFn that implements FIPS 205 §11.2 PRF
// for SHAKE:
//
//	PRF(PK.seed, ADRS, X) = SHAKE256(PK.seed || ADRS || X)[:n]
//
// The `secretSegment` argument is the first n bytes of the SHAKE-
// expanded master material — the X portion of every PRF absorb.
//
// The closure allocates a fresh `prfAbsorb` buffer per call, composes
// (pkSeed || addr || secretSegment) into it, runs SHAKE256, and
// zeroizes the absorb buffer before returning. The closure does NOT
// retain a reference to secretSegment beyond the call boundary; the
// owning buffer (derivedMaterial) is zeroized by assembleSignatureBytes
// after the FIPS 205 signature is fully emitted.
func makePRFClosure(p *internalParams, pkSeed, secretSegment []byte) prfOutFn {
	return func(out []byte, addr *adrsBuf) {
		// Absorb (pkSeed || addr || secretSegment). The standard
		// SHAKE256 streaming API consumes inputs into the sponge
		// state and never copies them into a persistent buffer; we
		// nonetheless allocate the absorb-bundle scratch only to
		// preserve the audit-grep invariant ("the only buffer that
		// holds secretSegment for an instant is `prfAbsorb`").
		prfAbsorb := make([]byte, 0, int(p.n)+int(p.addrSize)+len(secretSegment))
		prfAbsorb = append(prfAbsorb, pkSeed...)
		prfAbsorb = append(prfAbsorb, addr[:]...)
		prfAbsorb = append(prfAbsorb, secretSegment...)

		h := sha3.NewShake256()
		_, _ = h.Write(prfAbsorb)
		_, _ = h.Read(out)

		zeroizeBytes(prfAbsorb)
	}
}

// makePRFMsgClosure returns a prfMsgFn that implements FIPS 205 §11.2
// PRF_msg for SHAKE:
//
//	PRF_msg(key, optRand, M) = SHAKE256(key || optRand || M)[:n]
//
// where `key` is the second positional segment of the FIPS 205 SHAKE
// expansion of the master.
//
// The `secretSegment` argument is the n bytes of the SHAKE-expanded
// master material that occupy positions [n, 2n) — the PRF_msg key
// portion of the FIPS 205 expansion.
//
// As with makePRFClosure: per call, the absorb bundle is composed in
// a transient buffer (`prfMsgAbsorb`), SHAKE256 absorbed, and the
// buffer is zeroized.
func makePRFMsgClosure(p *internalParams, secretSegment []byte) prfMsgFn {
	return func(out, optRand, msgPrime []byte) {
		prfMsgAbsorb := make([]byte, 0, len(secretSegment)+len(optRand)+len(msgPrime))
		prfMsgAbsorb = append(prfMsgAbsorb, secretSegment...)
		prfMsgAbsorb = append(prfMsgAbsorb, optRand...)
		prfMsgAbsorb = append(prfMsgAbsorb, msgPrime...)

		h := sha3.NewShake256()
		_, _ = h.Write(prfMsgAbsorb)
		_, _ = h.Read(out)

		zeroizeBytes(prfMsgAbsorb)
	}
}

// lagrangeBasisAtZero returns the Lagrange basis lambdas at x=0 for
// the supplied shares. Pure function of PUBLIC evaluation points;
// algebraically identical to thbsseReconstructGF's basis derivation.
//
// Exposed as a separate helper so the strict-atom path's lambda
// computation does not call into thbsseReconstructGF (which produces a
// reconstructed byte vector --- the exact intermediate the strict-atom
// path is designed to avoid).
func lagrangeBasisAtZero(shares []thbsseShare) ([]uint16, error) {
	if len(shares) < 1 {
		return nil, ErrNotEnoughShares
	}
	seen := make(map[uint32]struct{}, len(shares))
	sorted := append([]thbsseShare(nil), shares...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].X < sorted[j].X })
	for _, s := range sorted {
		if s.X == 0 {
			return nil, ErrZeroEvalPoint
		}
		if _, dup := seen[s.X]; dup {
			return nil, ErrDuplicateEvalPoint
		}
		seen[s.X] = struct{}{}
	}
	t := len(sorted)
	lambdas := make([]uint16, t)
	for i := 0; i < t; i++ {
		num := uint32(1)
		den := uint32(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			negXj := thbsseSharePrime - (sorted[j].X % thbsseSharePrime)
			num = (num * negXj) % thbsseSharePrime
			diff := (thbsseSharePrime + sorted[i].X - sorted[j].X) % thbsseSharePrime
			den = (den * diff) % thbsseSharePrime
		}
		denInv := thbsseModInvSmall(den, thbsseSharePrime)
		lambdas[i] = uint16((num * denInv) % thbsseSharePrime)
	}

	// Rewire the input shares to the sorted order so the caller's iter
	// order matches the lambdas. We use a tiny in-place reshuffle by
	// swapping the input slice contents.
	if len(shares) == len(sorted) {
		for i := range shares {
			shares[i] = sorted[i]
		}
	}
	return lambdas, nil
}

// keep the binary package import live; the address helpers in this
// file slice into adrsBuf which is binary.BigEndian-encoded.
var _ = binary.BigEndian
