// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// thbsse_field.go --- GF(257) byte-wise share arithmetic used INTERNALLY by
// the THBS-SE construction (thbsse.go).
//
// This file is the entire field-math footprint of the threshold path.
// No other primitive in the magnetar package consumes these helpers;
// the per-validator standalone path (standalone.go) is FIPS 205 only
// and does not touch them. The unexported names keep them out of the
// public API surface.
//
// =====================================================================
//  Why byte-wise GF(257)
// =====================================================================
//
// The THBS-SE setup shares a 4n-byte SLH-DSA scheme seed (96 bytes for
// SHAKE-192s, 128 bytes for SHAKE-256s; per FIPS 205 sec 10.1). Byte
// values 0..255 fit in [0, 257) and share values fit in [0, 257), so
// each share value packs as one uint16 lane. Reconstruction at x=0
// returns the original byte in [0, 257); honest shares carry byte
// values in [0, 256) and reduction yields the original seed byte.
//
// GF(257) is the smallest prime > 255: every byte value is a distinct
// non-zero field element, the lambdas fit in a u16, and the modular
// inverse uses Fermat's little theorem on a 9-bit exponent (fast and
// constant-time relative to the secret share values).
//
// The choice is consistent with Pulsar's GF(257) wire — it lets the
// audit reuse the same per-byte-share analysis across siblings.
//
// =====================================================================
//  No PVSS in this file
// =====================================================================
//
// The PVSS / leaderless-DKG primitive is OUT OF SCOPE for this file
// (and for the magnetar package). The protocol shape calls for the
// committee to "run leaderless PVSS/DKG for slot-local key" in a
// SIBLING primitive — luxfi/threshold's DKG package — and feed the
// resulting (PK, [share_i]) tuple into NewThbsSeKeyFromShares
// (thbsse.go). NewThbsSeKey (the deterministic-dealer variant) is the
// KAT-reproducible reference that lives here for byte-identity
// testing and for foundation-HSM single-host bootstrap; it is not the
// production path.
//
// The deterministic-dealer reference uses the SAME wire-shape shares
// the PVSS path produces, so a setup transcript produced by the PVSS
// path is byte-equal to one produced by the dealer for the same input
// secret material. The PVSS scheme choice (Schoenmakers 1999 over a
// prime-order subgroup, with a hash-to-byte mixing step) is
// documented in the paper sec 5.2; the wire-level surface is the
// share envelope (mask || masked_share) which is identical under
// both setups.

import "errors"

// thbsseSharePrime is the small prime used for per-byte Shamir sharing
// in the THBS-SE setup. 257 is the smallest prime > 255 so it admits
// every byte value as a distinct field element.
const thbsseSharePrime uint32 = 257

// thbsseShare contains one party's per-byte Shamir share of a
// seed_size-byte secret. Each element is a value in [0, 257) stored
// in a uint16 lane. The Y slice has length seed_size.
type thbsseShare struct {
	X uint32   // Shamir evaluation point in [1, p); 1-indexed
	Y []uint16 // per-byte share value at X (each in [0, p))
}

// Errors produced by the THBS-SE field-arithmetic layer. Exported
// because Combine surfaces them to callers; the names are
// THBS-SE-scoped to make the audit footprint obvious.
var (
	// ErrInvalidThreshold is returned by NewThbsSeKey when n < t or
	// t < 1.
	ErrInvalidThreshold = errors.New("magnetar/thbsse: invalid threshold (n < t or t < 1)")

	// ErrCommitteeTooLarge is returned when n > MaxCommittee257 (= 256).
	// The GF(257) field admits exactly 256 distinct non-zero
	// evaluation points.
	ErrCommitteeTooLarge = errors.New("magnetar/thbsse: committee larger than 256 parties (GF(257) wire)")

	// ErrNotEnoughShares is returned by share reconstruction when
	// fewer than t shares are presented.
	ErrNotEnoughShares = errors.New("magnetar/thbsse: not enough shares for reconstruction")

	// ErrZeroEvalPoint is returned when a share carries x=0 (the
	// reserved point that holds the secret).
	ErrZeroEvalPoint = errors.New("magnetar/thbsse: evaluation point x=0 is reserved for the secret")

	// ErrDuplicateEvalPoint is returned when two shares share the
	// same x.
	ErrDuplicateEvalPoint = errors.New("magnetar/thbsse: duplicate evaluation point in shares")

	// ErrShareWireSize is returned when a share's wire bytes do not
	// match the params.SeedSize * 2 width.
	ErrShareWireSize = errors.New("magnetar/thbsse: share has wrong wire size")
)

// MaxCommittee257 is the maximum committee size under byte-wise
// Shamir over GF(257). 256 is exactly q-1 = 257-1, the upper bound
// on distinct non-zero evaluation points.
const MaxCommittee257 = 256

// thbsseDealRandom shares a seed_size-byte secret across n parties
// with reconstruction threshold t. Thin wrapper around
// thbsseDealRandomGF that lifts each byte secret[b] to a GF(257)
// value. Used by the deterministic-dealer setup path.
func thbsseDealRandom(secret []byte, n, t int, coeffStream []byte) ([]thbsseShare, error) {
	gf := make([]uint16, len(secret))
	for b := 0; b < len(secret); b++ {
		gf[b] = uint16(secret[b])
	}
	return thbsseDealRandomGF(gf, n, t, coeffStream)
}

// thbsseDealRandomGF shares a seedSize-element GF(257) secret vector
// across n parties with reconstruction threshold t. Each party 1..n
// gets a share at evaluation point i. The (t-1) polynomial
// coefficients per slot are pulled from coeffStream; if the stream
// is short, it is stretched via cSHAKE256(coeffStream,
// tag=MAGNETAR-THBSSE-SHARE-V1).
func thbsseDealRandomGF(secret []uint16, n, t int, coeffStream []byte) ([]thbsseShare, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}
	seedSize := len(secret)

	needed := (t - 1) * seedSize * 2
	if needed < 2 {
		needed = 2
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagThbsSeShareDeal)
	}

	// coeffs[d][b] is the degree-d coefficient for slot b.
	// coeffs[0][b] is the constant term --- the secret value itself.
	coeffs := make([][]uint16, t)
	for d := 0; d < t; d++ {
		coeffs[d] = make([]uint16, seedSize)
	}
	for b := 0; b < seedSize; b++ {
		coeffs[0][b] = secret[b] % uint16(thbsseSharePrime)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < seedSize; b++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			coeffs[d][b] = uint16(r % thbsseSharePrime)
		}
	}

	shares := make([]thbsseShare, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
		shares[i-1].Y = make([]uint16, seedSize)
		x := uint32(i)
		for b := 0; b < seedSize; b++ {
			// Horner's method.
			acc := uint32(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint32(coeffs[d][b])) % thbsseSharePrime
			}
			shares[i-1].Y[b] = uint16(acc)
		}
	}
	return shares, nil
}

// thbsseReconstructGF Lagrange-interpolates the constant term as a
// seedSize-element GF(257) vector. Used by Combine.
func thbsseReconstructGF(shares []thbsseShare, seedSize int) ([]uint16, error) {
	out := make([]uint16, seedSize)
	if len(shares) < 1 {
		return out, ErrNotEnoughShares
	}
	// Reduce every evaluation point mod p once, and guard on the reduced value.
	// A raw x of 257 (== p) is the reserved secret point 0, and x and x+257 are
	// one point presented twice; comparing raw values would admit both. The
	// reduced points also keep the Lagrange denominator below from underflowing —
	// (p + x_i - x_j) is positive only when x_j < p.
	seen := make(map[uint32]struct{}, len(shares))
	xs := make([]uint32, len(shares))
	for idx, s := range shares {
		xr := s.X % thbsseSharePrime
		if xr == 0 {
			return out, ErrZeroEvalPoint
		}
		if _, dup := seen[xr]; dup {
			return out, ErrDuplicateEvalPoint
		}
		seen[xr] = struct{}{}
		if len(s.Y) != seedSize {
			return out, ErrShareWireSize
		}
		xs[idx] = xr
	}

	t := len(shares)
	// Lagrange basis values at x=0 over GF(p).
	// lambda_i = prod_{j != i} (-x_j) / (x_i - x_j) mod p
	lambdas := make([]uint16, t)
	for i := 0; i < t; i++ {
		num := uint32(1)
		den := uint32(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			negXj := thbsseSharePrime - xs[j]
			num = (num * negXj) % thbsseSharePrime
			diff := (thbsseSharePrime + xs[i] - xs[j]) % thbsseSharePrime
			den = (den * diff) % thbsseSharePrime
		}
		denInv := thbsseModInvSmall(den, thbsseSharePrime)
		lambdas[i] = uint16((num * denInv) % thbsseSharePrime)
	}

	for b := 0; b < seedSize; b++ {
		var acc uint32
		for i := 0; i < t; i++ {
			acc = (acc + uint32(lambdas[i])*uint32(shares[i].Y[b])) % thbsseSharePrime
		}
		out[b] = uint16(acc)
	}
	return out, nil
}

// thbsseModInvSmall computes the modular inverse of a mod p where p
// is a small prime. Uses Fermat's little theorem (a^(p-2) === a^-1
// mod p). p must be prime and a must be in [1, p).
func thbsseModInvSmall(a, p uint32) uint32 {
	return thbsseModPowSmall(a, p-2, p)
}

// thbsseModPowSmall computes (base^exp) mod p via square-and-multiply.
func thbsseModPowSmall(base, exp, p uint32) uint32 {
	result := uint32(1)
	b := base % p
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * b) % p
		}
		b = (b * b) % p
		exp >>= 1
	}
	return result
}

// thbsseShareToBytes serialises a thbsseShare's Y component to wire
// form (big-endian uint16 per byte position).
func thbsseShareToBytes(s thbsseShare) []byte {
	out := make([]byte, len(s.Y)*2)
	for b := 0; b < len(s.Y); b++ {
		out[2*b] = byte(s.Y[b] >> 8)
		out[2*b+1] = byte(s.Y[b])
	}
	return out
}

// thbsseShareFromBytes deserialises a wire-form Y component.
func thbsseShareFromBytes(x uint32, buf []byte) thbsseShare {
	seedSize := len(buf) / 2
	s := thbsseShare{X: x, Y: make([]uint16, seedSize)}
	for b := 0; b < seedSize; b++ {
		s.Y[b] = uint16(buf[2*b])<<8 | uint16(buf[2*b+1])
	}
	return s
}

// EvalPointFromID derives a deterministic non-zero Shamir evaluation
// point in [1, 257) from a NodeID. Used by callers that want an
// ID-stable evaluation point rather than a position-in-committee
// point. The default setup uses (committee_index + 1) which is
// simpler and KAT-stable.
func EvalPointFromID(id NodeID) uint32 {
	digest := cshake256(id[:], 1, tagThbsSeShareDeal)
	return uint32(digest[0])%(thbsseSharePrime-1) + 1
}
