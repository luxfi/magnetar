// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// n1_byte_equality_test.go — empirical validation of the Magnetar
// Class-N1-analog output-interchangeability claim.
//
// The claim:
//
//   For any honest threshold-sign session whose share set
//   reconstructs to a centralized FIPS 205 seed S, the resulting
//   signature bytes are IDENTICAL to those produced by FIPS 205
//   SignDeterministic(DeriveKey(S), msg, ctx) — i.e., threshold-
//   sign is output-byte-equivalent to single-party deterministic
//   FIPS 205 signing under the corresponding centralized key.
//
// This is the load-bearing property of Magnetar's threshold mode:
// any stock SLH-DSA verifier accepts threshold-produced
// signatures with NO code change, because the bytes look exactly
// like a centralized FIPS 205 signature.
//
// The implementation strategy that makes this property hold is
// "centralized recovery": Combine reconstructs the master seed
// via Lagrange interpolation of the share set, derives the
// centralized FIPS 205 SK via KeyFromSeed, and calls
// SignDeterministic directly. See combine.go.
//
// This test performs an end-to-end byte-equality check:
//
//   1. Run the DKG to produce shares + group public key.
//   2. Reconstruct the master seed from a threshold quorum of
//      shares using the SAME Lagrange + cSHAKE256 mix as Combine.
//   3. Derive the centralized SK via KeyFromSeed(masterSeed).
//   4. Sign centrally with deterministic FIPS 205 mode.
//   5. Run the full threshold-sign protocol on the same (sid,
//      attempt, msg, ctx, quorum) under the same shares.
//   6. Assert that the two signatures are BYTE-IDENTICAL.
//
// Catches: any divergence between the centralized FIPS 205 path
// and the threshold-sign path — wrong Shamir coefficient, wrong
// committee root, wrong cSHAKE256 mix input layout, wrong sign-call
// arguments, etc. A regression on any of these would cause the
// signatures to differ and the test to fail.

import (
	"bytes"
	"testing"
)

// reconstructMasterSeed Lagrange-reconstructs the DKG master seed
// from a quorum of KeyShares + the full committee membership.
// This mirrors the in-Combine reconstruction at combine.go
// bit-for-bit — same shamirReconstructGF, same byteSum byte
// ordering, same committeeRoot, same cSHAKE256 tag.
func reconstructMasterSeed(t *testing.T, params *Params, quorum []*KeyShare, committee []*KeyShare) []byte {
	t.Helper()
	shares := make([]shamirShare, len(quorum))
	for i, ks := range quorum {
		shares[i] = shareFromBytes(ks.EvalPoint, ks.Share)
	}
	byteSum, err := shamirReconstructGF(shares, params.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromShares(committee)
	byteSumBytes := make([]byte, params.SeedSize*2)
	for b := 0; b < params.SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	return cshake256(mixInput, params.SeedSize, tagSeedShare)
}

func TestN1_ByteEquality_ThresholdMatchesCentralized(t *testing.T) {
	skipUnderRace(t)
	// Three configurations spanning small / typical / larger
	// thresholds. Every config must produce byte-identical
	// signatures from the two paths.
	//
	// SLH-DSA-SHAKE-192s key derivation is hash-tree-deep
	// (h=63, d=7) so KAT-sized DKG runs take several seconds
	// under the race detector. We keep the small config always
	// and gate the larger configs behind !testing.Short() so
	// `go test -race -short` finishes in ~minute.
	smallConfigs := []struct {
		name string
		n, t int
	}{
		{"3of2", 3, 2},
	}
	largeConfigs := []struct {
		name string
		n, t int
	}{
		{"5of3", 5, 3},
		{"7of4", 7, 4},
	}
	configs := smallConfigs
	if !testing.Short() {
		configs = append(configs, largeConfigs...)
	}
	for _, tc := range configs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeM192s)
			committee := makeCommittee(tc.n)
			pub, shares, _ := runDKG(t, params, committee, tc.t)

			msg := []byte("Magnetar Class-N1-analog byte-equality test")
			var ctx []byte // empty context

			// --- Threshold-sign path. ---
			var sid [16]byte
			copy(sid[:], "n1-byte-eq-sid01")
			attempt := uint32(1)
			quorumIDs := make([]NodeID, tc.t)
			for i := 0; i < tc.t; i++ {
				quorumIDs[i] = shares[i].NodeID
			}

			signers := make([]*ThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				s, err := NewThresholdSigner(params, sid, attempt, quorumIDs, shares[i], msg,
					newDetReader([]byte{byte(i), 0xBE, 0xEF}))
				if err != nil {
					t.Fatalf("NewThresholdSigner party %d: %v", i, err)
				}
				signers[i] = s
			}
			r1 := make([]*Round1Message, tc.t)
			for i, s := range signers {
				m, err := s.Round1()
				if err != nil {
					t.Fatalf("Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}
			r2 := make([]*Round2Message, tc.t)
			for i, s := range signers {
				m, _, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("Round2 party %d: %v", i, err)
				}
				r2[i] = m
			}
			thresholdSig, err := CombineWithSeedReconstruction(params, pub, msg, ctx, false, sid, attempt, quorumIDs, tc.t, r1, r2, shares)
			if err != nil {
				t.Fatalf("CombineWithSeedReconstruction: %v", err)
			}

			// --- Centralized path. ---
			quorumShares := make([]*KeyShare, tc.t)
			for i := 0; i < tc.t; i++ {
				quorumShares[i] = shares[i]
			}
			masterSeed := reconstructMasterSeed(t, params, quorumShares, shares)

			// Sanity: master_seed must derive to the same pubkey as DKG produced.
			sk, err := KeyFromSeed(params, masterSeed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			if !sk.Pub.Equal(pub) {
				t.Fatalf("reconstructed master seed does not derive to DKG group pubkey")
			}

			centralSig, err := Sign(params, sk, msg, ctx, false, nil)
			if err != nil {
				t.Fatalf("Sign (central): %v", err)
			}

			// --- Byte equality. ---
			if !bytes.Equal(thresholdSig.Bytes, centralSig.Bytes) {
				t.Errorf("threshold and centralized signature bytes differ\n"+
					"threshold: %x\ncentral:   %x", thresholdSig.Bytes[:32], centralSig.Bytes[:32])
				// Find the first divergent byte.
				for i := 0; i < len(thresholdSig.Bytes) && i < len(centralSig.Bytes); i++ {
					if thresholdSig.Bytes[i] != centralSig.Bytes[i] {
						t.Errorf("first divergent byte at offset %d: threshold=0x%02x central=0x%02x",
							i, thresholdSig.Bytes[i], centralSig.Bytes[i])
						break
					}
				}
				t.Fatalf("byte-equality theorem violated")
			}
			// Both signatures must verify under unmodified FIPS 205.
			if err := Verify(params, pub, msg, thresholdSig); err != nil {
				t.Fatalf("threshold sig fails FIPS 205 Verify: %v", err)
			}
			if err := Verify(params, pub, msg, centralSig); err != nil {
				t.Fatalf("central sig fails FIPS 205 Verify: %v", err)
			}
		})
	}
}

func TestN1_ByteEquality_DifferentQuorumsSameSignature(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: SLH-DSA-SHAKE-192s DKG with n=5 is too slow under -short")
	}
	// Test that two DISTINCT quorums (different subsets of the
	// share set) produce the SAME signature for the same
	// (message, ctx). This is a direct consequence of
	// reveal-and-aggregate's seed reconstruction being quorum-
	// independent.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(5)
	pub, shares, _ := runDKG(t, params, committee, 3)

	msg := []byte("Magnetar quorum-independence test")
	var ctx []byte

	signWith := func(idxs []int, seedTag byte) []byte {
		t.Helper()
		var sid [16]byte
		copy(sid[:], "magnetar-multi-q")
		quorum := make([]NodeID, len(idxs))
		quorumShares := make([]*KeyShare, len(idxs))
		for i, j := range idxs {
			quorum[i] = shares[j].NodeID
			quorumShares[i] = shares[j]
		}
		signers := make([]*ThresholdSigner, len(idxs))
		for i, j := range idxs {
			s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[j], msg,
				newDetReader([]byte{byte(i), seedTag}))
			signers[i] = s
		}
		r1 := make([]*Round1Message, len(idxs))
		for i, s := range signers {
			r1[i], _ = s.Round1()
		}
		r2 := make([]*Round2Message, len(idxs))
		for i, s := range signers {
			r2[i], _, _ = s.Round2(r1)
		}
		sig, err := CombineWithSeedReconstruction(params, pub, msg, ctx, false, sid, 1, quorum, len(idxs), r1, r2, shares)
		if err != nil {
			t.Fatalf("CombineWithSeedReconstruction: %v", err)
		}
		return sig.Bytes
	}

	sigA := signWith([]int{0, 1, 2}, 0xAA)
	sigB := signWith([]int{2, 3, 4}, 0xBB)
	if !bytes.Equal(sigA, sigB) {
		t.Errorf("different quorums produced different signatures (expected equal under reveal-and-aggregate)")
		// First divergent byte for debugging.
		for i := 0; i < len(sigA) && i < len(sigB); i++ {
			if sigA[i] != sigB[i] {
				t.Errorf("first divergent byte at offset %d: A=0x%02x B=0x%02x", i, sigA[i], sigB[i])
				break
			}
		}
		t.Fatalf("quorum-independence violated")
	}
}
