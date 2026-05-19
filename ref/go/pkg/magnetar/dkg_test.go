// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"testing"
)

func TestDKG_BasicAgreement(t *testing.T) {
	skipUnderRace(t)
	// (n=3, t=2): smallest non-trivial committee. Every party
	// must agree on the joint group pubkey and transcript hash.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, transcript := runDKG(t, params, committee, 2)
	if pub == nil {
		t.Fatalf("nil group pubkey")
	}
	if len(pub.Bytes) != params.PublicKeySize {
		t.Fatalf("group pubkey size: got %d want %d", len(pub.Bytes), params.PublicKeySize)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}
	// Every share carries the right wire size.
	for i, s := range shares {
		if len(s.Share) != params.SeedSize*2 {
			t.Fatalf("share[%d] wire size: got %d want %d", i, len(s.Share), params.SeedSize*2)
		}
		if !s.Pub.Equal(pub) {
			t.Fatalf("share[%d].Pub differs from group pubkey", i)
		}
		if s.EvalPoint == 0 {
			t.Fatalf("share[%d] has zero eval point", i)
		}
	}
	// Transcript is non-zero.
	allZero := true
	for _, b := range transcript {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("transcript is all zero")
	}
}

func TestDKG_AllConfigurations(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: SLH-DSA DKG with n>=5 is slow under -short")
	}
	configs := []struct{ N, T int }{
		{3, 2}, {5, 3}, {7, 4}, {10, 7},
	}
	for _, cfg := range configs {
		cfg := cfg
		t.Run(modeStringConfig(cfg.N, cfg.T), func(t *testing.T) {
			params := MustParamsFor(ModeM192s)
			committee := makeCommittee(cfg.N)
			pub, shares, _ := runDKG(t, params, committee, cfg.T)
			if pub == nil {
				t.Fatalf("nil group pubkey")
			}
			if len(shares) != cfg.N {
				t.Fatalf("expected %d shares, got %d", cfg.N, len(shares))
			}
		})
	}
}

func TestDKG_EquivocationDetected(t *testing.T) {
	skipUnderRace(t)
	// Tamper with one party's Round-2 digest and check that
	// honest parties produce AbortEvidence at Round 3.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	n := 3
	sessions := make([]*DKGSession, n)
	for i := range sessions {
		seed := []byte{byte(i), 0xDD, 0xCC}
		s, _ := NewDKGSession(params, committee, 2, committee[i], newDetReader(seed))
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, n)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*DKGRound2Msg, n)
	for i, s := range sessions {
		r2[i], _ = s.Round2(r1)
	}
	// Tamper with r2[1]'s digest.
	r2[1].Digest[0] ^= 0x01
	// Honest party 0 runs Round 3 — must detect the equivocation.
	out, err := sessions[0].Round3(r2)
	if err != nil {
		t.Fatalf("Round3: %v", err)
	}
	if out.AbortEvidence == nil {
		t.Fatalf("expected AbortEvidence on digest mismatch")
	}
	if out.AbortEvidence.Kind != ComplaintEquivocation {
		t.Fatalf("expected ComplaintEquivocation, got %v", out.AbortEvidence.Kind)
	}
}

func TestDKG_MissingEnvelopeRejected(t *testing.T) {
	skipUnderRace(t)
	// A dealer that omits the recipient's envelope is rejected
	// at Round 2.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	sessions := make([]*DKGSession, 3)
	for i := range sessions {
		seed := []byte{byte(i), 0xEE}
		s, _ := NewDKGSession(params, committee, 2, committee[i], newDetReader(seed))
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, 3)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	// Strip party 0's envelope from dealer 1.
	delete(r1[1].Envelopes, committee[0])
	if _, err := sessions[0].Round2(r1); err == nil {
		t.Fatalf("expected ErrDKGMissingEnvelope")
	}
}

func TestDKG_NonMemberRejected(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	var stranger NodeID
	stranger[0] = 0xFF
	if _, err := NewDKGSession(params, committee, 2, stranger, nil); err == nil {
		t.Fatalf("expected ErrNotInQuorum for non-member")
	}
}

func TestDKG_InvalidThresholdRejected(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	if _, err := NewDKGSession(params, committee, 0, committee[0], nil); err == nil {
		t.Fatalf("expected ErrInvalidThreshold (t=0)")
	}
	if _, err := NewDKGSession(params, committee, 4, committee[0], nil); err == nil {
		t.Fatalf("expected ErrInvalidThreshold (t > n)")
	}
}

func TestDKG_DeterministicAcrossRuns(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: two DKG runs with n=5 are slow under -short")
	}
	// Two runs of the DKG with the same deterministic seeds must
	// produce byte-identical group pubkeys, transcripts, and
	// shares.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(5)
	pub1, sh1, tr1 := runDKG(t, params, committee, 3)
	pub2, sh2, tr2 := runDKG(t, params, committee, 3)
	if !pub1.Equal(pub2) {
		t.Fatalf("group pubkey not deterministic")
	}
	if tr1 != tr2 {
		t.Fatalf("transcript hash not deterministic")
	}
	for i := range sh1 {
		if string(sh1[i].Share) != string(sh2[i].Share) {
			t.Fatalf("share[%d] bytes not deterministic", i)
		}
	}
}

func modeStringConfig(n, t int) string {
	return formatConfig(n, t)
}

func formatConfig(n, t int) string {
	return spfNT(n, t)
}

func spfNT(n, t int) string {
	return itoa(t) + "of" + itoa(n)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var digits [12]byte
	i := len(digits)
	for v > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
