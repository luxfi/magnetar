// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// test_helpers_test.go — shared test utilities for deterministic
// RNG and committee construction. Lives under *_test.go so it is
// not compiled into the production binary.

import (
	"crypto/sha256"
	"io"
	"testing"
)

// skipUnderRace is a self-skip guard for tests that wrap heavy
// SLH-DSA computation. Race-detector runs add 5-10× overhead on
// SHAKE-heavy code; these tests carry no inter-goroutine
// concurrency so they cannot trigger a race condition regardless.
// Race-detector runs cover the cheap unit tests (shamir,
// transcript, types) — see CONTRIBUTING.md "Testing under race".
func skipUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("skip: SLH-DSA-heavy test under race detector (see CONTRIBUTING.md)")
	}
}

// detReader is a deterministic SHA-256-counter byte stream from a
// seed. Used by tests + KAT generator to produce reproducible
// "random" input. NOT a CSPRNG suitable for production.
type detReader struct {
	seed []byte
	buf  []byte
	off  int
}

func newDetReader(seed []byte) *detReader {
	return &detReader{seed: seed}
}

func (r *detReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			ctr := uint32(len(r.buf) / 32)
			r.buf = nil
			for i := 0; i < 128; i++ {
				h := sha256.New()
				h.Write(r.seed)
				h.Write([]byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)})
				r.buf = append(r.buf, h.Sum(nil)...)
				ctr++
			}
			r.off = 0
		}
		c := copy(p[n:], r.buf[r.off:])
		n += c
		r.off += c
	}
	return len(p), nil
}

// deterministicReader is a thin alias for newDetReader for test
// code that wants a one-liner.
func deterministicReader(seed []byte) io.Reader {
	return newDetReader(seed)
}

// makeCommittee builds a deterministic NodeID list of length n.
func makeCommittee(n int) []NodeID {
	out := make([]NodeID, n)
	for i := 0; i < n; i++ {
		// Use a 1-indexed first byte so NodeIDs are distinct and
		// sorted in canonical order.
		out[i][0] = byte(i + 1)
		// Mix in a tag so test NodeIDs don't accidentally collide
		// with KAT NodeIDs.
		copy(out[i][1:], []byte("MAGNETAR-TEST"))
	}
	return out
}

// runDKG runs an honest DKG ceremony for committee+threshold and
// returns the (group pubkey, share-set, transcript-hash). Fails
// the test on any error.
func runDKG(t *testing.T, params *Params, committee []NodeID, threshold int) (*PublicKey, []*KeyShare, [48]byte) {
	t.Helper()
	n := len(committee)
	sessions := make([]*DKGSession, n)
	for i := range sessions {
		seed := append([]byte("MAGNETAR-DKG-TEST"), []byte{byte(params.Mode), byte(n), byte(threshold), byte(i)}...)
		rng := newDetReader(seed)
		s, err := NewDKGSession(params, committee, threshold, committee[i], rng)
		if err != nil {
			t.Fatalf("NewDKGSession[%d]: %v", i, err)
		}
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, n)
	for i, s := range sessions {
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("Round1[%d]: %v", i, err)
		}
		r1[i] = m
	}
	r2 := make([]*DKGRound2Msg, n)
	for i, s := range sessions {
		m, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("Round2[%d]: %v", i, err)
		}
		r2[i] = m
	}
	outs := make([]*DKGOutput, n)
	for i, s := range sessions {
		o, err := s.Round3(r2)
		if err != nil {
			t.Fatalf("Round3[%d]: %v", i, err)
		}
		if o.AbortEvidence != nil {
			t.Fatalf("Round3[%d]: unexpected abort: %v", i, o.AbortEvidence)
		}
		outs[i] = o
	}
	// Verify all parties agree on the joint group pubkey.
	for i := 1; i < n; i++ {
		if !outs[0].GroupPubkey.Equal(outs[i].GroupPubkey) {
			t.Fatalf("party %d disagrees on group pubkey", i)
		}
		if outs[0].TranscriptHash != outs[i].TranscriptHash {
			t.Fatalf("party %d disagrees on transcript hash", i)
		}
	}
	shares := make([]*KeyShare, n)
	for i, o := range outs {
		shares[i] = o.SecretShare
	}
	return outs[0].GroupPubkey, shares, outs[0].TranscriptHash
}
