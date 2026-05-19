// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"bytes"
	"testing"
)

func TestShamir_DealReconstruct_Basic(t *testing.T) {
	// Share a 96-byte (SHAKE-192s) seed with (n=5, t=3) and check
	// that every 3-element subset reconstructs the secret.
	seed := bytes.Repeat([]byte{0xAB}, 96)
	for i := range seed {
		seed[i] = byte(i ^ 0x55)
	}
	coeffs := bytes.Repeat([]byte{0xAA}, (3-1)*96*2)
	shares, err := shamirDealRandom(seed, 5, 3, coeffs)
	if err != nil {
		t.Fatalf("shamirDealRandom: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Reconstruct from the first 3.
	rec, err := shamirReconstructGF(shares[:3], 96)
	if err != nil {
		t.Fatalf("shamirReconstructGF: %v", err)
	}
	for b := 0; b < 96; b++ {
		// The byte should be the GF(257) representation of the
		// original byte (in [0, 256]). Since every byte was in
		// [0, 256), the GF(257) reconstruction must equal the
		// byte value.
		if rec[b] != uint16(seed[b]) {
			t.Fatalf("reconstructed byte %d: got %d want %d", b, rec[b], seed[b])
		}
	}
}

func TestShamir_ReconstructFromAnySubset(t *testing.T) {
	// (n=4, t=3). Any 3 of the 4 shares should reconstruct.
	seed := make([]byte, 96)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	coeffs := bytes.Repeat([]byte{0xCD}, (3-1)*96*2)
	shares, err := shamirDealRandom(seed, 4, 3, coeffs)
	if err != nil {
		t.Fatalf("shamirDealRandom: %v", err)
	}
	subsets := [][]int{
		{0, 1, 2},
		{0, 1, 3},
		{0, 2, 3},
		{1, 2, 3},
	}
	for _, sub := range subsets {
		picked := make([]shamirShare, len(sub))
		for i, j := range sub {
			picked[i] = shares[j]
		}
		rec, err := shamirReconstructGF(picked, 96)
		if err != nil {
			t.Fatalf("reconstruct %v: %v", sub, err)
		}
		for b := 0; b < 96; b++ {
			if rec[b] != uint16(seed[b]) {
				t.Fatalf("subset %v: byte %d: got %d want %d", sub, b, rec[b], seed[b])
			}
		}
	}
}

func TestShamir_DuplicateEvalPointRejected(t *testing.T) {
	seed := make([]byte, 96)
	coeffs := bytes.Repeat([]byte{0xEE}, (3-1)*96*2)
	shares, _ := shamirDealRandom(seed, 5, 3, coeffs)
	dup := []shamirShare{shares[0], shares[0], shares[1]}
	if _, err := shamirReconstructGF(dup, 96); err == nil {
		t.Fatalf("expected ErrDuplicateEvalPoint")
	}
}

func TestShamir_ZeroEvalPointRejected(t *testing.T) {
	zero := []shamirShare{
		{X: 0, Y: make([]uint16, 96)},
		{X: 1, Y: make([]uint16, 96)},
		{X: 2, Y: make([]uint16, 96)},
	}
	if _, err := shamirReconstructGF(zero, 96); err == nil {
		t.Fatalf("expected ErrZeroEvalPoint")
	}
}

func TestShamir_TooLargeCommitteeRejected(t *testing.T) {
	if _, err := shamirDealRandom(make([]byte, 96), 257, 3, nil); err == nil {
		t.Fatalf("expected ErrCommitteeTooLarge")
	}
}

func TestShamir_ThresholdInvalidRejected(t *testing.T) {
	if _, err := shamirDealRandom(make([]byte, 96), 3, 0, nil); err == nil {
		t.Fatalf("expected ErrInvalidThreshold (t=0)")
	}
	if _, err := shamirDealRandom(make([]byte, 96), 3, 4, nil); err == nil {
		t.Fatalf("expected ErrInvalidThreshold (t > n)")
	}
}

func TestShamir_SeedSize128(t *testing.T) {
	// Exercise the 128-byte SHAKE-256s seed path.
	seed := make([]byte, 128)
	for i := range seed {
		seed[i] = byte(i * 13)
	}
	coeffs := bytes.Repeat([]byte{0x11}, (3-1)*128*2)
	shares, err := shamirDealRandom(seed, 5, 3, coeffs)
	if err != nil {
		t.Fatalf("shamirDealRandom (128B): %v", err)
	}
	rec, err := shamirReconstructGF(shares[:3], 128)
	if err != nil {
		t.Fatalf("shamirReconstructGF (128B): %v", err)
	}
	for b := 0; b < 128; b++ {
		if rec[b] != uint16(seed[b]) {
			t.Fatalf("byte %d: got %d want %d", b, rec[b], seed[b])
		}
	}
}

func TestShareWireRoundTrip(t *testing.T) {
	seed := make([]byte, 96)
	for i := range seed {
		seed[i] = byte(i)
	}
	coeffs := bytes.Repeat([]byte{0x77}, (3-1)*96*2)
	shares, _ := shamirDealRandom(seed, 3, 2, coeffs)
	for _, s := range shares {
		wire := shareToBytes(s)
		back := shareFromBytes(s.X, wire)
		if back.X != s.X {
			t.Fatalf("X round trip: got %d want %d", back.X, s.X)
		}
		for b := 0; b < 96; b++ {
			if back.Y[b] != s.Y[b] {
				t.Fatalf("Y[%d] round trip: got %d want %d", b, back.Y[b], s.Y[b])
			}
		}
	}
}

func TestEvalPointFromID_NonZero(t *testing.T) {
	// EvalPointFromID must never produce 0 (reserved for the
	// secret).
	for i := 0; i < 256; i++ {
		var id NodeID
		id[0] = byte(i)
		p := EvalPointFromID(id)
		if p == 0 {
			t.Fatalf("EvalPointFromID produced 0 for first byte %d", i)
		}
		if p >= shamirPrime {
			t.Fatalf("EvalPointFromID produced %d >= shamirPrime=%d", p, shamirPrime)
		}
	}
}
