// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// fors_threshold_open_test.go --- proves the distributed FORS-leaf
// threshold opening is (a) byte-identical to centralized FIPS 205
// forsSign, (b) accepted by the unmodified FIPS 205 Algorithm 17
// verifier, (c) no-reconstruct (only one-leaf-wide interpolation), and
// (d) one-time-safe (burn ledger refuses keypair reuse).

import (
	"bytes"
	"errors"
	"testing"
)

// referenceFors recomputes the centralized FIPS 205 FORS signature on md
// at addr from seed --- the byte-identity oracle. Mirrors the setup-TCB
// dealer's derivation, used here only as a test reference.
func referenceFors(t *testing.T, params *Params, seed []byte, addr ForsKeypairAddr, md []byte) (refSig, pkSeed []byte) {
	t.Helper()
	internal, ok := internalParamsForMode(params.Mode)
	if !ok {
		t.Fatalf("no internal params for mode %v", params.Mode)
	}
	derived := make([]byte, 3*internal.n)
	shakeIntoCat(derived, seed)
	pkSeed = append([]byte(nil), derived[2*internal.n:3*internal.n]...)
	prfOut := makePRFClosure(internal, pkSeed, derived[:internal.n])
	adr := addr.forsAddrBuf()
	refSig = make([]byte, internal.forsSigSize())
	forsSign(internal, refSig, pkSeed, &adr, md, prfOut)
	return refSig, pkSeed
}

// TestForsThreshold_NoReconstruct_StockVerify is the headline proof:
// a t-of-n threshold opening of the FORS leaves yields a FORS signature
// byte-identical to the centralized one, verifies under stock FIPS 205
// Algorithm 17, and is produced WITHOUT any seed reconstruction.
func TestForsThreshold_NoReconstruct_StockVerify(t *testing.T) {
	skipUnderRace(t)
	for _, mode := range []Mode{ModeM192s, ModeM256s} {
		params := MustParamsFor(mode)
		internal, _ := internalParamsForMode(mode)

		seed := make([]byte, params.SeedSize)
		_, _ = deterministicReader([]byte("magnetar-fors-threshold-seed")).Read(seed)
		md := make([]byte, internal.m)
		_, _ = deterministicReader([]byte("magnetar-fors-threshold-md")).Read(md)
		coeff := make([]byte, 4096)
		_, _ = deterministicReader([]byte("magnetar-fors-threshold-coeff")).Read(coeff)

		addr := ForsKeypairAddr{IdxTree: [3]uint32{0, 0, 0}, IdxLeaf: 3}
		n, th := 5, 3

		mat, pub, err := DistributedForsSetup(params, seed, addr, md, n, th, coeff)
		if err != nil {
			t.Fatalf("[%v] setup: %v", mode, err)
		}

		// Reference (centralized) FORS signature on the same material.
		refSig, _ := referenceFors(t, params, seed, addr, md)

		// Threshold open with a STRICT t-subset {1,3,5} (proves t-of-n,
		// not all-n).
		var partials []ForsPartialOpen
		for _, p := range []uint32{1, 3, 5} {
			po, err := mat.PartialOpen(p, md)
			if err != nil {
				t.Fatalf("[%v] PartialOpen(%d): %v", mode, p, err)
			}
			partials = append(partials, po)
		}

		ledger := NewBurnLedger()
		forsSig, err := OpenForsThreshold(pub, partials, ledger)
		if err != nil {
			t.Fatalf("[%v] OpenForsThreshold: %v", mode, err)
		}

		// (a) Byte-identity to centralized FIPS 205 forsSign.
		if !bytes.Equal(forsSig, refSig) {
			t.Fatalf("[%v] threshold FORS sig != centralized forsSign (byte-identity broken)", mode)
		}

		// (b) Stock FIPS 205 Algorithm 17 verification accepts.
		ok, err := VerifyForsThreshold(pub, forsSig)
		if err != nil {
			t.Fatalf("[%v] VerifyForsThreshold: %v", mode, err)
		}
		if !ok {
			t.Fatalf("[%v] stock FIPS 205 forsPkFromSig rejected the threshold FORS sig", mode)
		}

		// (c) A DISJOINT t-subset {2,3,4} produces the SAME bytes
		// (deterministic public combiner). Re-burn under same digest is
		// idempotent so the same ledger is reused.
		var partials2 []ForsPartialOpen
		for _, p := range []uint32{2, 3, 4} {
			po, _ := mat.PartialOpen(p, md)
			partials2 = append(partials2, po)
		}
		forsSig2, err := OpenForsThreshold(pub, partials2, ledger)
		if err != nil {
			t.Fatalf("[%v] OpenForsThreshold disjoint subset: %v", mode, err)
		}
		if !bytes.Equal(forsSig, forsSig2) {
			t.Fatalf("[%v] disjoint t-subsets produced different signatures", mode)
		}
	}
}

// TestForsThreshold_OneTimeSafety_BurnRefusal proves constraint 3: the
// same FORS keypair signing a SECOND, distinct message is refused as a
// slashable one-time-reuse equivocation.
func TestForsThreshold_OneTimeSafety_BurnRefusal(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	internal, _ := internalParamsForMode(ModeM192s)

	seed := make([]byte, params.SeedSize)
	_, _ = deterministicReader([]byte("burn-seed")).Read(seed)
	coeff := make([]byte, 4096)
	_, _ = deterministicReader([]byte("burn-coeff")).Read(coeff)
	addr := ForsKeypairAddr{IdxTree: [3]uint32{0, 0, 0}, IdxLeaf: 7}

	md1 := make([]byte, internal.m)
	_, _ = deterministicReader([]byte("burn-md-1")).Read(md1)
	md2 := make([]byte, internal.m)
	_, _ = deterministicReader([]byte("burn-md-2")).Read(md2)

	ledger := NewBurnLedger() // shared across both messages

	// First message: signs fine, burns the keypair.
	mat1, pub1, err := DistributedForsSetup(params, seed, addr, md1, 5, 3, coeff)
	if err != nil {
		t.Fatalf("setup md1: %v", err)
	}
	var p1 []ForsPartialOpen
	for _, p := range []uint32{1, 2, 3} {
		po, _ := mat1.PartialOpen(p, md1)
		p1 = append(p1, po)
	}
	if _, err := OpenForsThreshold(pub1, p1, ledger); err != nil {
		t.Fatalf("first open should succeed: %v", err)
	}

	// Second, distinct message on the SAME keypair: MUST be refused.
	mat2, pub2, err := DistributedForsSetup(params, seed, addr, md2, 5, 3, coeff)
	if err != nil {
		t.Fatalf("setup md2: %v", err)
	}
	var p2 []ForsPartialOpen
	for _, p := range []uint32{1, 2, 3} {
		po, _ := mat2.PartialOpen(p, md2)
		p2 = append(p2, po)
	}
	_, err = OpenForsThreshold(pub2, p2, ledger)
	if err == nil {
		t.Fatalf("one-time safety FAILED: second open of same keypair under a different digest was accepted")
	}
	if !errors.Is(err, ErrOneTimeReuse) {
		t.Fatalf("expected ErrOneTimeReuse, got %v", err)
	}
	var conflict *BurnConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *BurnConflict slashable evidence, got %T", err)
	}
	if conflict.Prior == conflict.New {
		t.Fatalf("burn conflict must carry two distinct digests")
	}
}

// TestForsThreshold_CommitMismatch_Rejected proves a tampered partial
// open (wrong shares) is rejected by the commit re-derivation.
func TestForsThreshold_CommitMismatch_Rejected(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	internal, _ := internalParamsForMode(ModeM192s)
	seed := make([]byte, params.SeedSize)
	_, _ = deterministicReader([]byte("commit-seed")).Read(seed)
	coeff := make([]byte, 4096)
	_, _ = deterministicReader([]byte("commit-coeff")).Read(coeff)
	md := make([]byte, internal.m)
	_, _ = deterministicReader([]byte("commit-md")).Read(md)
	addr := ForsKeypairAddr{IdxTree: [3]uint32{0, 0, 0}, IdxLeaf: 1}

	mat, pub, err := DistributedForsSetup(params, seed, addr, md, 5, 3, coeff)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var partials []ForsPartialOpen
	for _, p := range []uint32{1, 2, 3} {
		po, _ := mat.PartialOpen(p, md)
		partials = append(partials, po)
	}
	// Tamper one share value WITHOUT updating the commit.
	partials[1].LeafShares[0][0] ^= 0x01
	_, err = OpenForsThreshold(pub, partials, NewBurnLedger())
	if !errors.Is(err, ErrForsCommitMismatch) {
		t.Fatalf("expected ErrForsCommitMismatch for tampered share, got %v", err)
	}
}
