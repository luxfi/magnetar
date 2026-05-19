// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"testing"
)

func TestThreshold_BasicSign(t *testing.T) {
	skipUnderRace(t)
	// (n=3, t=2): sign with the minimum quorum and verify.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)

	msg := []byte("Magnetar threshold-sign basic test")
	var sid [16]byte
	copy(sid[:], "magnetar-test-1")
	attempt := uint32(1)
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID}

	signers := make([]*ThresholdSigner, 2)
	for i := 0; i < 2; i++ {
		s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], msg,
			newDetReader([]byte{byte(i), 0xAB, 0xCD}))
		if err != nil {
			t.Fatalf("NewThresholdSigner[%d]: %v", i, err)
		}
		signers[i] = s
	}
	r1 := make([]*Round1Message, 2)
	for i, s := range signers {
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("Round1[%d]: %v", i, err)
		}
		r1[i] = m
	}
	r2 := make([]*Round2Message, 2)
	for i, s := range signers {
		m, _, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("Round2[%d]: %v", i, err)
		}
		r2[i] = m
	}
	sig, err := Combine(params, pub, msg, nil, false, sid, attempt, quorum, 2, r1, r2, shares)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if err := Verify(params, pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestThreshold_VariousConfigurations(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: SLH-DSA threshold-sign with n>=5 is slow under -short")
	}
	configs := []struct{ N, T int }{
		{3, 2}, {5, 3}, {7, 4},
	}
	for _, cfg := range configs {
		cfg := cfg
		t.Run(spfNT(cfg.N, cfg.T), func(t *testing.T) {
			params := MustParamsFor(ModeM192s)
			committee := makeCommittee(cfg.N)
			pub, shares, _ := runDKG(t, params, committee, cfg.T)
			msg := []byte("multi-config threshold sign")
			sig, err := signWithQuorum(t, params, pub, shares, cfg.T, msg)
			if err != nil {
				t.Fatalf("signWithQuorum: %v", err)
			}
			if err := Verify(params, pub, msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestThreshold_TamperedRound2Rejected(t *testing.T) {
	skipUnderRace(t)
	// A Round-2 reveal that doesn't match the Round-1 commit
	// must be rejected by Combine.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)
	msg := []byte("tamper test")
	var sid [16]byte
	copy(sid[:], "tamper-sid-0001")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID}

	signers := make([]*ThresholdSigner, 2)
	for i := 0; i < 2; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg,
			newDetReader([]byte{byte(i), 0xFA, 0xCE}))
		signers[i] = s
	}
	r1 := make([]*Round1Message, 2)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*Round2Message, 2)
	for i, s := range signers {
		r2[i], _, _ = s.Round2(r1)
	}
	// Tamper: flip a bit in r2[0]'s mask half.
	r2[0].PartialSig[0] ^= 0x01
	if _, err := Combine(params, pub, msg, nil, false, sid, 1, quorum, 2, r1, r2, shares); err == nil {
		t.Fatalf("Combine accepted tampered Round-2 reveal")
	}
}

func TestThreshold_SessionMismatchRejected(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)
	msg := []byte("session-mismatch test")
	var sid1, sid2 [16]byte
	copy(sid1[:], "sid-1234567890ab")
	copy(sid2[:], "sid-DIFFERENT001")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID}

	signers := make([]*ThresholdSigner, 2)
	for i := 0; i < 2; i++ {
		s, _ := NewThresholdSigner(params, sid1, 1, quorum, shares[i], msg,
			newDetReader([]byte{byte(i), 0xBA, 0xDD}))
		signers[i] = s
	}
	r1 := make([]*Round1Message, 2)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*Round2Message, 2)
	for i, s := range signers {
		r2[i], _, _ = s.Round2(r1)
	}
	// Combine with sid2: must fail.
	if _, err := Combine(params, pub, msg, nil, false, sid2, 1, quorum, 2, r1, r2, shares); err == nil {
		t.Fatalf("Combine accepted mismatched session ID")
	}
}

func TestThreshold_NonMemberQuorumRejected(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	_, shares, _ := runDKG(t, params, committee, 2)
	msg := []byte("non-member test")
	var sid [16]byte
	copy(sid[:], "nonmember-sid01")

	var stranger NodeID
	stranger[0] = 0xFF
	quorum := []NodeID{stranger, shares[0].NodeID}

	// shares[1].NodeID isn't in quorum, but shares[1] is not the
	// quorum member here; only check shares[0] participates while
	// stranger has no key.
	if _, err := NewThresholdSigner(params, sid, 1, quorum, shares[1], msg, nil); err == nil {
		t.Fatalf("expected ErrNotInQuorum (shares[1].NodeID not in quorum)")
	}
}

// signWithQuorum runs a full ceremony: pick first t shares,
// execute Round 1, Round 2, Combine. Returns the signature.
func signWithQuorum(t *testing.T, params *Params, pub *PublicKey, shares []*KeyShare, threshold int, msg []byte) (*Signature, error) {
	t.Helper()
	quorum := make([]NodeID, threshold)
	for i := 0; i < threshold; i++ {
		quorum[i] = shares[i].NodeID
	}
	var sid [16]byte
	copy(sid[:], "magnetar-tquorum")
	attempt := uint32(7)

	signers := make([]*ThresholdSigner, threshold)
	for i := 0; i < threshold; i++ {
		s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], msg,
			newDetReader([]byte{byte(i), 0x42}))
		if err != nil {
			return nil, err
		}
		signers[i] = s
	}
	r1 := make([]*Round1Message, threshold)
	for i, s := range signers {
		m, err := s.Round1()
		if err != nil {
			return nil, err
		}
		r1[i] = m
	}
	r2 := make([]*Round2Message, threshold)
	for i, s := range signers {
		m, _, err := s.Round2(r1)
		if err != nil {
			return nil, err
		}
		r2[i] = m
	}
	return Combine(params, pub, msg, nil, false, sid, attempt, quorum, threshold, r1, r2, shares)
}
