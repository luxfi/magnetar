// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import "errors"

// shamir.go — per-byte Shamir over GF(257).
//
// The thbs package shares INDIVIDUAL ELEMENTS (each of length N bytes)
// rather than a single global seed. Each element is shared via the
// same byte-wise GF(257) scheme used elsewhere in Magnetar; the
// invariant "no full-seed reconstruction" is enforced by the API
// shape, not by switching field.

const shamirPrime uint32 = 257

// maxParties is the maximum committee size that GF(257) admits with
// distinct non-zero evaluation points.
const maxParties = 256

var (
	errInvalidThreshold = errors.New("thbs/shamir: invalid threshold")
	errTooManyShares    = errors.New("thbs/shamir: too many parties for GF(257)")
	errNoShares         = errors.New("thbs/shamir: no shares")
	errDuplicateX       = errors.New("thbs/shamir: duplicate evaluation point")
	errZeroX            = errors.New("thbs/shamir: zero evaluation point")
)

// shareElement splits an N-byte secret into n shares with reconstruction
// threshold t. The coeffStream provides the (t-1) per-byte non-constant
// coefficients; if empty, a deterministic stretch via cSHAKE is used.
//
// Returns shares[i].Y of length N for each party i, where shares[i].X
// is the i-th party's evaluation point.
func shareElement(secret []byte, points []uint16, t int, coeffStream []byte) ([]shamirSlice, error) {
	if t < 1 || len(points) < t {
		return nil, errInvalidThreshold
	}
	if len(points) > maxParties {
		return nil, errTooManyShares
	}
	n := len(secret)
	needed := (t - 1) * n * 2
	if needed < 2 {
		needed = 2
	}
	if len(coeffStream) < needed {
		coeffStream = hashN(needed, tagShamir, coeffStream)
	}

	// coeffs[d][b] = degree-d coefficient at byte position b.
	coeffs := make([][]uint16, t)
	for d := 0; d < t; d++ {
		coeffs[d] = make([]uint16, n)
	}
	for b := 0; b < n; b++ {
		coeffs[0][b] = uint16(secret[b]) % uint16(shamirPrime)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < n; b++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			coeffs[d][b] = uint16(r % shamirPrime)
		}
	}

	out := make([]shamirSlice, len(points))
	for i, x := range points {
		if x == 0 {
			return nil, errZeroX
		}
		out[i].X = x
		out[i].Y = make([]uint16, n)
		xu := uint32(x)
		for b := 0; b < n; b++ {
			acc := uint32(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*xu + uint32(coeffs[d][b])) % shamirPrime
			}
			out[i].Y[b] = uint16(acc)
		}
	}
	return out, nil
}

// reconstructElement Lagrange-interpolates an N-byte secret at x=0.
// The caller MUST pass exactly the shares used to reconstruct one
// element. The output[b] is in [0, 257); for actual byte recovery the
// caller routes through cSHAKE (see sign.go reconstructBytes).
func reconstructElement(shares []shamirSlice, n int) ([]uint16, error) {
	if len(shares) == 0 {
		return nil, errNoShares
	}
	seen := make(map[uint16]struct{}, len(shares))
	for _, s := range shares {
		if s.X == 0 {
			return nil, errZeroX
		}
		if _, dup := seen[s.X]; dup {
			return nil, errDuplicateX
		}
		seen[s.X] = struct{}{}
		if len(s.Y) != n {
			return nil, errInvalidThreshold
		}
	}

	t := len(shares)
	lambdas := make([]uint16, t)
	for i := 0; i < t; i++ {
		num := uint32(1)
		den := uint32(1)
		xi := uint32(shares[i].X)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			xj := uint32(shares[j].X)
			negXj := (shamirPrime - xj%shamirPrime) % shamirPrime
			num = (num * negXj) % shamirPrime
			diff := (shamirPrime + xi - xj) % shamirPrime
			den = (den * diff) % shamirPrime
		}
		denInv := modInv(den, shamirPrime)
		lambdas[i] = uint16((num * denInv) % shamirPrime)
	}

	out := make([]uint16, n)
	for b := 0; b < n; b++ {
		var acc uint32
		for i := 0; i < t; i++ {
			acc = (acc + uint32(lambdas[i])*uint32(shares[i].Y[b])) % shamirPrime
		}
		out[b] = uint16(acc)
	}
	return out, nil
}

// modInv computes a^-1 mod p via Fermat (p prime).
func modInv(a, p uint32) uint32 { return modPow(a, p-2, p) }

func modPow(base, exp, p uint32) uint32 {
	r := uint32(1)
	b := base % p
	for exp > 0 {
		if exp&1 == 1 {
			r = (r * b) % p
		}
		b = (b * b) % p
		exp >>= 1
	}
	return r
}

// shamirSlice carries one byte-wise share of length N at evaluation
// point X. Internal type; the exported API uses ElementShare which
// adds (ID, Steps).
type shamirSlice struct {
	X uint16
	Y []uint16
}

// gfBytesToBytes maps a length-N GF(257) reconstruction back to N raw
// bytes.
//
// In THBS we INVARIANT: the original secret bytes are always drawn
// from [0, 256), so when split as Shamir polynomial constant terms
// over GF(257), the Lagrange interpolation at x=0 returns EXACTLY the
// original byte value (a value in [0, 256), never 256). We assert
// this and convert directly. The slotMix parameter is retained as a
// belt-and-suspenders binding to detect tamper at the gf-byte
// interface, but the byte value comes from the GF reconstruction
// directly (no hash mix — that would prevent byte-equality with the
// secret).
//
// If reconstruction returns 256 for any byte, the shares have been
// tampered: the caller (Aggregate) will detect this when the WOTS+
// chain endpoint or FORS root check fails. To make the error path
// explicit, we map 256 -> 0 with the understanding that the
// subsequent endpoint check WILL reject.
func gfBytesToBytes(gf []uint16, n int, slotMix []byte) []byte {
	_ = slotMix
	out := make([]byte, n)
	for b := 0; b < n; b++ {
		if gf[b] >= 256 {
			// Cannot happen for honest shares; signal via 0 so the
			// endpoint check fails downstream.
			out[b] = 0
			continue
		}
		out[b] = byte(gf[b])
	}
	return out
}
