// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// shamir.go — byte-wise Shamir secret sharing over GF(257) for the
// SLH-DSA scheme seed.
//
// Why byte-wise over GF(257): the threshold layer shares a 4n-byte
// SLH-DSA scheme seed (96 bytes for SHAKE-192s, 128 bytes for
// SHAKE-256s). The byte values 0..255 fit in [0, 257) and share
// values fit in [0, 257) which need 9 bits → packs as one uint16
// per per-byte share value. Reconstruction at x=0 returns the
// original byte in [0, 256) (mod 256) because the polynomial's
// constant term is the byte.
//
// The choice of GF(257) keeps the wire-share size minimal: each
// share is seed_size × uint16 bytes, regardless of which SLH-DSA
// parameter set is in use.
//
// All arithmetic is constant-time mod p via the small-prime
// modular inverse.

import "errors"

// shamirPrime is the small prime used for per-byte Shamir sharing.
// 257 is the smallest prime > 255 so it admits every byte value as
// a distinct field element.
const shamirPrime uint32 = 257

// shamirShare contains one party's per-byte Shamir share of a
// seed_size-byte secret. Each element is a value in [0, 257)
// stored in a uint16 lane. The Y slice has length seed_size.
type shamirShare struct {
	X uint32   // Shamir evaluation point in [1, p); 1-indexed
	Y []uint16 // per-byte share value at X (each in [0, p))
}

// shamirShareErrs.
var (
	ErrInvalidThreshold   = errors.New("magnetar: invalid threshold (n < t or t < 1)")
	ErrCommitteeTooLarge  = errors.New("magnetar: committee larger than 256 parties (shamir GF(257))")
	ErrNotEnoughShares    = errors.New("magnetar: not enough shares for reconstruction")
	ErrZeroEvalPoint      = errors.New("magnetar: evaluation point x=0 is reserved for the secret")
	ErrDuplicateEvalPoint = errors.New("magnetar: duplicate evaluation point in shares")
	ErrShareWireSize      = errors.New("magnetar: share has wrong wire size")
)

// shamirDealRandom shares a seed_size-byte secret across n parties
// with reconstruction threshold t.
//
// Thin wrapper around shamirDealRandomGF that lifts each byte
// secret[b] to a GF(257) value. Used by the DKG path where each
// party's contribution IS a seed_size-byte vector.
func shamirDealRandom(secret []byte, n, t int, coeffStream []byte) ([]shamirShare, error) {
	gf := make([]uint16, len(secret))
	for b := 0; b < len(secret); b++ {
		gf[b] = uint16(secret[b])
	}
	return shamirDealRandomGF(gf, n, t, coeffStream)
}

// shamirDealRandomGF shares a seedSize-element GF(257) secret
// vector across n parties with reconstruction threshold t. Each
// party 1..n gets a share at evaluation point i. The (t-1)
// polynomial coefficients per slot are pulled from coeffStream.
//
// If coeffStream is shorter than needed, it is stretched via
// cSHAKE256(coeffStream, tag=MAGNETAR-SEED-SHARE-V1).
func shamirDealRandomGF(secret []uint16, n, t int, coeffStream []byte) ([]shamirShare, error) {
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
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}

	// coeffs[d][b] is the degree-d coefficient for slot b.
	// coeffs[0][b] is the constant term — the secret value itself.
	coeffs := make([][]uint16, t)
	for d := 0; d < t; d++ {
		coeffs[d] = make([]uint16, seedSize)
	}
	for b := 0; b < seedSize; b++ {
		coeffs[0][b] = secret[b] % uint16(shamirPrime)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < seedSize; b++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			coeffs[d][b] = uint16(r % shamirPrime)
		}
	}

	shares := make([]shamirShare, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
		shares[i-1].Y = make([]uint16, seedSize)
		x := uint32(i)
		for b := 0; b < seedSize; b++ {
			// Horner's method.
			acc := uint32(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint32(coeffs[d][b])) % shamirPrime
			}
			shares[i-1].Y[b] = uint16(acc)
		}
	}
	return shares, nil
}

// shamirReconstructGF Lagrange-interpolates the constant term as a
// seedSize-element GF(257) vector. Used by Combine to preserve
// byte-value 256 across reconstruction; the caller routes the
// 16-bit GF result through a cSHAKE256 mix that absorbs the 256/0
// distinction.
func shamirReconstructGF(shares []shamirShare, seedSize int) ([]uint16, error) {
	out := make([]uint16, seedSize)
	if len(shares) < 1 {
		return out, ErrNotEnoughShares
	}
	seen := make(map[uint32]struct{}, len(shares))
	for _, s := range shares {
		if s.X == 0 {
			return out, ErrZeroEvalPoint
		}
		if _, dup := seen[s.X]; dup {
			return out, ErrDuplicateEvalPoint
		}
		seen[s.X] = struct{}{}
		if len(s.Y) != seedSize {
			return out, ErrShareWireSize
		}
	}

	t := len(shares)
	// Lagrange basis values at x=0 over GF(p).
	// λ_i = Π_{j≠i} (-x_j) / (x_i - x_j) mod p
	lambdas := make([]uint16, t)
	for i := 0; i < t; i++ {
		num := uint32(1)
		den := uint32(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			negXj := shamirPrime - (shares[j].X % shamirPrime)
			num = (num * negXj) % shamirPrime
			diff := (shamirPrime + shares[i].X - shares[j].X) % shamirPrime
			den = (den * diff) % shamirPrime
		}
		denInv := modInvSmall(den, shamirPrime)
		lambdas[i] = uint16((num * denInv) % shamirPrime)
	}

	for b := 0; b < seedSize; b++ {
		var acc uint32
		for i := 0; i < t; i++ {
			acc = (acc + uint32(lambdas[i])*uint32(shares[i].Y[b])) % shamirPrime
		}
		out[b] = uint16(acc)
	}
	return out, nil
}

// modInvSmall computes the modular inverse of a mod p where p is a
// small prime. Uses Fermat's little theorem (a^(p-2) ≡ a^-1 mod p).
// p must be prime and a must be in [1, p).
func modInvSmall(a, p uint32) uint32 {
	return modPowSmall(a, p-2, p)
}

// modPowSmall computes (base^exp) mod p via square-and-multiply.
func modPowSmall(base, exp, p uint32) uint32 {
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

// shareToBytes serialises a shamirShare's Y component to wire form
// (big-endian uint16 per byte position).
func shareToBytes(s shamirShare) []byte {
	out := make([]byte, len(s.Y)*2)
	for b := 0; b < len(s.Y); b++ {
		out[2*b] = byte(s.Y[b] >> 8)
		out[2*b+1] = byte(s.Y[b])
	}
	return out
}

// shareFromBytes deserialises a wire-form Y component.
func shareFromBytes(x uint32, buf []byte) shamirShare {
	seedSize := len(buf) / 2
	s := shamirShare{X: x, Y: make([]uint16, seedSize)}
	for b := 0; b < seedSize; b++ {
		s.Y[b] = uint16(buf[2*b])<<8 | uint16(buf[2*b+1])
	}
	return s
}

// EvalPointFromID derives a deterministic non-zero Shamir
// evaluation point in [1, 257) from a NodeID. Used by callers that
// want an ID-stable evaluation point rather than a position-in-
// committee point. The DKG default uses (committee_index + 1)
// which is simpler and KAT-stable.
func EvalPointFromID(id NodeID) uint32 {
	digest := cshake256(id[:], 1, tagSeedShare)
	return uint32(digest[0])%(shamirPrime-1) + 1
}
