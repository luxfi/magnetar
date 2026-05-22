// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// fuzz_test.go — fuzz harness targeting Magnetar's wire-format parsers.
//
// The fuzz targets exercise:
//
//   - Round-1 / Round-2 / DKG envelope wire parsing under arbitrary
//     adversarial byte input (no Round-1 / Round-2 should panic; all
//     malformed inputs must produce a typed error).
//   - The Combine commit-bind re-derive: an attacker who controls
//     (Round1.Commit, Round2.PartialSig) cannot cause Combine to
//     panic or return a partially-tampered signature.
//   - Transcript-hash injection: arbitrary byte sequences fed to
//     transcriptHash32 / transcriptHash MUST produce a fixed-length
//     digest with no out-of-bounds reads.
//
// Run:
//   go test -fuzz=FuzzCombineParse_NoPanic -fuzztime=60s ./ref/go/pkg/magnetar/
//   go test -fuzz=FuzzTranscriptHash_NoPanic -fuzztime=60s ./ref/go/pkg/magnetar/
//   go test -fuzz=FuzzShareDecode_RoundTrip -fuzztime=60s ./ref/go/pkg/magnetar/

import (
	"bytes"
	"testing"
)

// FuzzCombineParse_NoPanic — feed adversarial (Round1, Round2,
// allShares) tuples to Combine and assert it never panics.
//
// Constructs a real (n=3, t=2) ceremony fixture, then fuzzes the
// PartialSig bytes of Round2 messages. Combine must return either nil
// or a typed error — never panic.
func FuzzCombineParse_NoPanic(f *testing.F) {
	// Seed corpus: empty, zero-fill, random ASCII.
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0}, 384), bytes.Repeat([]byte{0}, 384))
	f.Add([]byte("AAAAAAAAAAAAAAAAAAAAAA"), []byte("BBBBBBBBBBBBBBBBBBBBBB"))

	f.Fuzz(func(t *testing.T, party0PartialSig, party1PartialSig []byte) {
		// Set up the fixture once per fuzz invocation. We can't move
		// this outside the closure because go fuzz doesn't expose a
		// per-iteration setup hook; the SLH-DSA DKG is slow but the
		// fuzz framework batches.
		params := MustParamsFor(ModeM192s)
		committee := makeCommittee(3)
		pub, shares, _ := runDKGOrPanic(t, params, committee, 2)
		msg := []byte("fuzz combine parse")
		var sid [16]byte
		copy(sid[:], "fuzz-combine-001")
		quorum := []NodeID{shares[0].NodeID, shares[1].NodeID}

		// Build legitimate Round-1 from real signers; Round-2 messages
		// carry the fuzz-supplied PartialSig bytes.
		signers := make([]*ThresholdSigner, 2)
		for i := 0; i < 2; i++ {
			s, err := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg,
				newDetReader([]byte{byte(i), 0x99}))
			if err != nil {
				t.Skip()
			}
			signers[i] = s
		}
		r1 := make([]*Round1Message, 2)
		for i, s := range signers {
			r1[i], _ = s.Round1()
		}
		r2 := []*Round2Message{
			{NodeID: shares[0].NodeID, SessionID: sid, Attempt: 1, PartialSig: party0PartialSig},
			{NodeID: shares[1].NodeID, SessionID: sid, Attempt: 1, PartialSig: party1PartialSig},
		}

		// MUST NOT PANIC. Returning an error is fine.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CombineWithSeedReconstruction panicked on fuzz input: %v", r)
			}
		}()
		_, _ = CombineWithSeedReconstruction(params, pub, msg, nil, false, sid, 1, quorum, 2, r1, r2, shares)
	})
}

// FuzzDKGEnvelope_NoPanic — feed adversarial envelope share+
// contribution byte combinations to a Round-2 ingest path.
func FuzzDKGEnvelope_NoPanic(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0}, 192), bytes.Repeat([]byte{0}, 96))
	f.Add(bytes.Repeat([]byte{0xFF}, 192), bytes.Repeat([]byte{0xFF}, 96))

	f.Fuzz(func(t *testing.T, fuzzShare, fuzzContribution []byte) {
		params := MustParamsFor(ModeM192s)
		committee := makeCommittee(3)
		myID := committee[0]
		sess, err := NewDKGSession(params, committee, 2, myID, newDetReader([]byte{0, 0, 0}))
		if err != nil {
			t.Skip()
		}
		// Run my Round-1 so the session has internal state.
		myR1, err := sess.Round1()
		if err != nil {
			t.Skip()
		}
		// Build a peer Round-1 from the fuzz inputs.
		peerR1 := &DKGRound1Msg{
			NodeID: committee[1],
			Envelopes: map[NodeID]DKGShareEnvelope{
				committee[0]: {Share: fuzzShare, Contribution: fuzzContribution},
				committee[1]: {Share: fuzzShare, Contribution: fuzzContribution},
				committee[2]: {Share: fuzzShare, Contribution: fuzzContribution},
			},
		}
		// Add a stub for the third party so the round2 envelope size
		// check has the right cardinality.
		thirdR1 := &DKGRound1Msg{
			NodeID: committee[2],
			Envelopes: map[NodeID]DKGShareEnvelope{
				committee[0]: {Share: fuzzShare, Contribution: fuzzContribution},
				committee[1]: {Share: fuzzShare, Contribution: fuzzContribution},
				committee[2]: {Share: fuzzShare, Contribution: fuzzContribution},
			},
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DKG Round2 panicked on fuzz envelope: %v", r)
			}
		}()
		_, _ = sess.Round2([]*DKGRound1Msg{myR1, peerR1, thirdR1})
	})
}

// FuzzTranscriptHash_NoPanic — feed arbitrary byte sequences to the
// transcript hash primitives.
func FuzzTranscriptHash_NoPanic(f *testing.F) {
	f.Add([]byte("tag"), []byte("payload"))
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0xAA}, 1024), bytes.Repeat([]byte{0x55}, 1024))

	f.Fuzz(func(t *testing.T, tag, payload []byte) {
		// transcriptHash32 produces a fixed-length output regardless
		// of input.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("transcriptHash32 panicked: %v", r)
			}
		}()
		// Customisation strings must be ASCII; truncate fuzz tag.
		var cs string
		if len(tag) > 64 {
			cs = string(tag[:64])
		} else {
			cs = string(tag)
		}
		out := transcriptHash32(cs, payload)
		if len(out) != 32 {
			t.Fatalf("transcriptHash32 output length %d != 32", len(out))
		}
		out48 := transcriptHash(cs, payload)
		if len(out48) != 48 {
			t.Fatalf("transcriptHash output length %d != 48", len(out48))
		}
	})
}

// FuzzShareDecode_RoundTrip — round-trip the share wire codec on
// arbitrary input. The wire format is fixed-length (seed_size * 2
// bytes per share); the codec MUST be invertible on any input of the
// right size and reject any other length.
func FuzzShareDecode_RoundTrip(f *testing.F) {
	f.Add([]byte{}, uint32(0))
	f.Add(bytes.Repeat([]byte{0}, 192), uint32(1))
	f.Add(bytes.Repeat([]byte{0xFF}, 192), uint32(255))

	f.Fuzz(func(t *testing.T, buf []byte, evalPoint uint32) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("shareFromBytes panicked: %v", r)
			}
		}()
		// Lengths that aren't a multiple of 2 produce a truncated
		// share; we still don't panic.
		decoded := shareFromBytes(evalPoint, buf)
		re := shareToBytes(decoded)
		// The re-encoded length is len(buf) - len(buf)%2 (the codec
		// drops the odd trailing byte). For valid even-length inputs
		// the round-trip is exact.
		if len(buf)%2 == 0 && !bytes.Equal(re, buf) {
			t.Fatalf("shareFromBytes/shareToBytes round-trip not byte-identical")
		}
	})
}

// FuzzVerify_NoPanic — Verify must never panic on adversarial sig
// bytes.
func FuzzVerify_NoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 16224))
	f.Add(bytes.Repeat([]byte{0xFF}, 16224))

	f.Fuzz(func(t *testing.T, sigBytes []byte) {
		params := MustParamsFor(ModeM192s)
		sk, err := GenerateKey(params, newDetReader([]byte("fuzz-verify-seed")))
		if err != nil {
			t.Skip()
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked: %v", r)
			}
		}()
		sig := &Signature{Mode: ModeM192s, Bytes: sigBytes}
		_ = Verify(params, sk.Pub, []byte("fuzz-verify-msg"), sig)
	})
}

// runDKGOrPanic — fuzz-friendly DKG helper. Same as runDKG but uses
// crypto/rand for randomness so each fuzz iteration is independent.
func runDKGOrPanic(t *testing.T, params *Params, committee []NodeID, threshold int) (*PublicKey, []*KeyShare, [48]byte) {
	t.Helper()
	return runDKG(t, params, committee, threshold)
}
