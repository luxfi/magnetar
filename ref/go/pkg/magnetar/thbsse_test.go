// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sort"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// thbsse_test.go — tests for the v0.6 THBS-SE construction.
//
// Coverage matrix:
//   - TestThbsSE_Wire_FIPS205Verifiable: the load-bearing byte-identity
//     test. Combined signature verifies under unmodified
//     cloudflare/circl/sign/slhdsa.Verify across SHAKE-192s/192f/256s.
//   - TestThbsSE_RejectSeedReveal: a malicious party attempting to
//     publish SK.seed as a "share" gets rejected at verify time.
//   - TestThbsSE_RejectOversizedShareWireSize: a Round-2 partial_sig
//     of the wrong wire size is rejected with a wire-size evidence.
//     (THBS-SE shares the whole seed; this is a wire-size / commit
//     check, NOT a FORS-leaf-selection check.)
//   - TestThbsSE_RejectTamperedShareCommitMismatch: a bit-flipped
//     masked share fails commit re-derivation and is dropped with a
//     commit-mismatch evidence. (A commit-binding check, NOT a WOTS+
//     chain-base-selection check.)
//   - TestThbsSE_SlotReuseRejected: signing two distinct messages
//     under the same slot is rejected with detectable evidence.
//   - TestThbsSE_OverselectedCommittee_SurvivesWithholding: n=7, t=3
//     with 4 honest signers and 3 withholders still produces a valid
//     signature.

// thbsSeAllModes is the set of FIPS 205 parameter sets the THBS-SE
// reference implementation supports.
var thbsSeAllModes = []Mode{ModeM192s, ModeM192f, ModeM256s}

// makeThbsSeCommittee returns a sorted committee of n random NodeIDs.
// Sorting is required by NewThbsSeKey.
func makeThbsSeCommittee(t *testing.T, n int) []NodeID {
	t.Helper()
	out := make([]NodeID, n)
	for i := 0; i < n; i++ {
		_, _ = rand.Read(out[i][:])
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// makeThbsSeBinding returns a canonical slot binding for tests.
func makeThbsSeBinding(slot uint64) *ThbsSeSlotBinding {
	return &ThbsSeSlotBinding{
		ChainID:       []byte("lux-magnetar-test-chain"),
		Epoch:         1,
		Slot:          slot,
		Height:        100,
		CommitteeID:   []byte("test-committee-A"),
		MessageDomain: []byte("polaris-cert"),
	}
}

// runRound1Across runs Round1 for each share index in indices and
// returns the (r1, r2) message slices in committee order. Each party
// uses its own guard so cross-party state never leaks.
func runRound1Across(t *testing.T, params *Params, key *ThbsSeKey, binding *ThbsSeSlotBinding, msg []byte, indices []int) ([]ThbsSeRound1Msg, []ThbsSeRound2Msg) {
	t.Helper()
	r1s := make([]ThbsSeRound1Msg, 0, len(indices))
	r2s := make([]ThbsSeRound2Msg, 0, len(indices))
	for _, i := range indices {
		guard := NewThbsSeSlotGuard()
		r1, r2, err := ThbsSeRound1(params, key.Shares[i], binding, msg, guard, nil)
		if err != nil {
			t.Fatalf("share %d Round1: %v", i, err)
		}
		r1s = append(r1s, r1)
		r2s = append(r2s, r2)
	}
	return r1s, r2s
}

// TestThbsSE_Wire_FIPS205Verifiable is the headline regression test.
// It pins the v0.6 byte-identity claim: a Combine output verifies
// under unmodified cloudflare/circl/sign/slhdsa.Verify across all
// three SLH-DSA SHAKE parameter sets, on a t=3, n=5 committee.
//
// The flow:
//  1. NewThbsSeKey produces (PK, shares) for (n=5, t=3).
//  2. Three honest signers run Round 1 + Round 2 against the slot
//     binding and the message.
//  3. A public combiner (anyone) calls Combine with the assembled
//     Round-1 / Round-2 messages plus the published ThbsSeKey.
//  4. The returned Signature.Bytes is fed DIRECTLY to circl's
//     slhdsa.Verify with the ctx = ctxFromSlot(binding). No
//     Magnetar code path is hit on the verifier side.
//
// PASS ⇔ the combiner produced a wire-canonical FIPS 205 signature
// for every supported mode.
func TestThbsSE_Wire_FIPS205Verifiable(t *testing.T) {
	for _, mode := range thbsSeAllModes {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			committee := makeThbsSeCommittee(t, 5)
			key, err := NewThbsSeKey(params, 3, committee, nil)
			if err != nil {
				t.Fatalf("NewThbsSeKey: %v", err)
			}
			binding := makeThbsSeBinding(7)
			msg := []byte("lux-magnetar-thbsse-v0.6 — selected-element threshold")

			r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{0, 2, 4})
			input := ThbsSeCombineInput{
				Key:     key,
				Binding: binding,
				Message: msg,
				Round1:  r1s,
				Round2:  r2s,
			}
			sig, evidences, err := Combine(AckThbsSeReconstructsSeed, input)
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if len(evidences) != 0 {
				t.Fatalf("Combine emitted %d evidences on honest run: %+v", len(evidences), evidences)
			}
			if sig == nil {
				t.Fatalf("Combine returned nil signature on honest run")
			}
			if sig.Mode != mode {
				t.Fatalf("Signature.Mode = %v, want %v", sig.Mode, mode)
			}
			if len(sig.Bytes) != params.SignatureSize {
				t.Fatalf("Signature.Bytes len = %d, want %d", len(sig.Bytes), params.SignatureSize)
			}

			// Byte-identity check: route the signature bytes DIRECTLY
			// through circl's FIPS 205 verifier with no Magnetar code
			// path on the verify side. The ctx is the slot-bound
			// context string.
			id := slhdsaIDForMode(mode)
			pk := slhdsa.PublicKey{ID: id}
			if err := pk.UnmarshalBinary(key.PublicKey.Bytes); err != nil {
				t.Fatalf("UnmarshalBinary(pk): %v", err)
			}
			ctx := ctxFromSlot(binding)
			if !slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig.Bytes, ctx) {
				t.Fatalf("circl FIPS 205 Verify rejected the THBS-SE Combine output — byte-identity broken")
			}

			// Wire-codec round-trip: the same signature flows through
			// the canonical MAGS frame.
			wireSig, err := sig.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			wirePK, err := MarshalGroupKey(key.PublicKey)
			if err != nil {
				t.Fatalf("MarshalGroupKey: %v", err)
			}
			if !VerifyBytesCtx(wirePK, msg, ctx, wireSig) {
				t.Fatalf("VerifyBytesCtx rejected the THBS-SE Combine output via wire codec")
			}

			// Wrong ctx (slot binding tampered) must reject.
			tamperBinding := makeThbsSeBinding(7)
			tamperBinding.Slot = 8
			tamperCtx := ctxFromSlot(tamperBinding)
			if slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig.Bytes, tamperCtx) {
				t.Fatalf("circl Verify accepted a tampered slot ctx — slot binding not enforced")
			}
		})
	}
}

// TestThbsSE_RejectSeedReveal pins the invariant "no party share is
// the seed". A malicious party that publishes a Round-2 reveal whose
// "share" portion is the master seed itself MUST fail Combine's
// commit re-derivation check — the malicious party cannot have
// committed to the seed in Round 1 without violating the protocol's
// transcript bind.
//
// Specifically: the v0.6 reveal carries (mask, masked_share). For
// the malicious party to publish the seed as the share, it would
// need either the seed (which only the SETUP dealer holds, and
// which has been erased) or to forge a Round-1 commit. We construct
// the attack as: malicious party submits a Round-2 reveal whose
// masked_share is computed to make share = seed; the Round-1 commit
// it broadcast earlier is honest (commits to its real Shamir share).
// Combine recomputes the commit from the tampered reveal and
// rejects.
func TestThbsSE_RejectSeedReveal(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 5)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(11)
	msg := []byte("reject-seed-reveal-test")

	// Honest Round 1+2 from parties {0, 2, 4}.
	r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{0, 2, 4})

	// Tamper party 0's Round-2 PartialSig to look like (mask, mask XOR seed).
	// We do this by overwriting the masked portion: new masked = mask XOR fake_seed.
	// Where fake_seed is a chosen value that, if reconstructed via Shamir, would
	// not match the committed share. The commit recomputation will fail
	// because the partial_sig hashes to a different commit than the one
	// originally broadcast.
	tampered := append([]byte(nil), r2s[0].PartialSig...)
	maskLen := params.SeedSize * 2
	for i := 0; i < maskLen; i++ {
		// Flip the masked portion so the "share" portion would decode
		// to all-zero bytes (a value the party never committed to).
		tampered[maskLen+i] = tampered[:maskLen][i]
	}
	r2s[0].PartialSig = tampered

	input := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  r1s,
		Round2:  r2s,
	}
	sig, evidences, err := Combine(AckThbsSeReconstructsSeed, input)
	if err == nil {
		// 2 of 3 shares are honest — Combine succeeded because we
		// over-provisioned. Check that exactly one evidence was emitted
		// for party 0.
		if sig == nil {
			t.Fatalf("Combine returned nil sig but no err on 2 honest + 1 tampered")
		}
		if len(evidences) != 1 || evidences[0].Reason != ThbsSeShareCommitMismatch {
			t.Fatalf("Expected exactly one commit-mismatch evidence, got: %+v", evidences)
		}
		if evidences[0].PartyID != committee[0] {
			t.Fatalf("Evidence party = %x, want %x", evidences[0].PartyID, committee[0])
		}
		// 2 shares survive but threshold = 3 — Combine should have
		// returned ErrInsufficientQuor. If we got here, the test setup
		// is wrong.
		t.Fatalf("Combine should have failed with insufficient quorum after dropping tampered share")
	}
	if !errors.Is(err, ErrInsufficientQuor) {
		t.Fatalf("Expected ErrInsufficientQuor, got %v", err)
	}
	// One evidence for the tampered party.
	if len(evidences) != 1 || evidences[0].Reason != ThbsSeShareCommitMismatch {
		t.Fatalf("Expected exactly one commit-mismatch evidence, got: %+v", evidences)
	}
	if evidences[0].PartyID != committee[0] {
		t.Fatalf("Evidence party = %x, want %x", evidences[0].PartyID, committee[0])
	}
}

// TestThbsSE_RejectOversizedShareWireSize pins the invariant "a
// Round-2 PartialSig of the wrong wire size is rejected and produces a
// wire-size evidence". (THBS-SE shares the whole SLH-DSA seed; there
// are no per-FORS / per-WOTS atom reveals to "select", so this is a
// share WIRE-SIZE / commit-binding check, not a FORS-leaf-selection
// check — the earlier name was misleading.)
//
// The share is honored only when its commit re-derives correctly. Here
// a Round-2 reveal carries extra trailing bytes; it fails the
// wire-size check and the offending party is dropped with a
// ThbsSeShareWireSize evidence.
func TestThbsSE_RejectOversizedShareWireSize(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 5)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(13)
	msg := []byte("reject-unselected-fors-test")

	r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{0, 2, 4})

	// Tamper party 2: append trailing garbage (the analogue of revealing
	// an unselected FORS leaf — extra atom payload beyond the protocol's
	// allowed reveal set).
	r2s[1].PartialSig = append(r2s[1].PartialSig, []byte("extra-unselected-fors-leaf-bytes")...)

	input := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  r1s,
		Round2:  r2s,
	}
	sig, evidences, err := Combine(AckThbsSeReconstructsSeed, input)
	if err == nil {
		t.Fatalf("Combine accepted a tampered (extra-bytes) share, sig=%v evidences=%+v", sig, evidences)
	}
	if !errors.Is(err, ErrInsufficientQuor) {
		t.Fatalf("Expected ErrInsufficientQuor, got %v", err)
	}
	if len(evidences) != 1 || evidences[0].Reason != ThbsSeShareWireSize {
		t.Fatalf("Expected exactly one wire-size evidence, got %+v", evidences)
	}
	if evidences[0].PartyID != committee[2] {
		t.Fatalf("Evidence party = %x, want %x", evidences[0].PartyID, committee[2])
	}
}

// TestThbsSE_RejectTamperedShareCommitMismatch pins the invariant "a
// Round-2 reveal is honored only when its commit re-derives correctly
// under the slot binding the share was committed to". (Again: THBS-SE
// shares the whole seed; there is no WOTS+ chain base to "select", so
// this is a COMMIT-BINDING check on a tampered masked share, not a
// WOTS-selection check.)
//
// We bit-flip the masked_share portion of party 1's reveal. The
// Round-1 commit was bound to the honest (mask || masked_share); the
// tampered reveal carries (mask || masked_share XOR delta). The
// combiner's commit re-derivation produces a different digest, the
// reveal is dropped, and a ThbsSeShareCommitMismatch evidence is
// emitted. With n=5, t=3 and one tampered share, the remaining honest
// pair is below threshold, so Combine returns ErrInsufficientQuor ---
// the canonical "drop, slash, retry" signal.
func TestThbsSE_RejectTamperedShareCommitMismatch(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 5)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(14)
	msg := []byte("reject-unselected-wots-test")

	r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{0, 2, 4})

	// Tamper party 1's reveal: flip a single bit in the masked_share
	// portion. This is the canonical "reveal an unselected WOTS+ chain
	// base" attack: the recovered share decodes to a different GF(257)
	// lane than the one the party committed to.
	maskLen := params.SeedSize * 2
	tampered := append([]byte(nil), r2s[1].PartialSig...)
	tampered[maskLen] ^= 0x01 // flip first byte of masked_share
	r2s[1].PartialSig = tampered

	input := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  r1s,
		Round2:  r2s,
	}
	sig, evidences, err := Combine(AckThbsSeReconstructsSeed, input)
	if err == nil {
		t.Fatalf("Combine accepted a tampered WOTS reveal, sig=%v evidences=%+v", sig, evidences)
	}
	if !errors.Is(err, ErrInsufficientQuor) {
		t.Fatalf("Expected ErrInsufficientQuor, got %v", err)
	}
	if len(evidences) != 1 || evidences[0].Reason != ThbsSeShareCommitMismatch {
		t.Fatalf("Expected exactly one commit-mismatch evidence, got %+v", evidences)
	}
	if evidences[0].PartyID != committee[2] {
		t.Fatalf("Evidence party = %x, want %x", evidences[0].PartyID, committee[2])
	}

	// Third-party VerifyThbsSeShareEvidence must accept the evidence
	// (proof the consensus layer can slash on it without re-running
	// the combiner).
	if !VerifyThbsSeShareEvidence(params, evidences[0], binding, msg) {
		t.Fatalf("VerifyThbsSeShareEvidence rejected genuine evidence")
	}
}

// TestThbsSE_SlotReuseRejected pins the one-time enforcement
// invariant. A party that tries to sign two distinct messages
// under the same slot binding receives an EquivocationError from
// its local slot guard, AND the resulting evidence verifies under
// VerifyThbsSeEvidence.
func TestThbsSE_SlotReuseRejected(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 5)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(17)
	msgA := []byte("msg-A")
	msgB := []byte("msg-B-different")

	guard := NewThbsSeSlotGuard()
	r1A, r2A, err := ThbsSeRound1(params, key.Shares[0], binding, msgA, guard, nil)
	if err != nil {
		t.Fatalf("first Round1: %v", err)
	}
	// Second attempt under SAME slot binding but DIFFERENT message
	// must fail with EquivocationError.
	_, _, err = ThbsSeRound1(params, key.Shares[0], binding, msgB, guard, nil)
	if err == nil {
		t.Fatalf("second Round1 with reused slot succeeded — slot guard not enforcing")
	}
	var eq *ThbsSeEquivocationError
	if !errors.As(err, &eq) {
		t.Fatalf("expected *ThbsSeEquivocationError, got %T: %v", err, err)
	}
	if eq.PartyID != key.Shares[0].NodeID {
		t.Fatalf("evidence party = %x, want %x", eq.PartyID, key.Shares[0].NodeID)
	}
	if eq.PriorR1.Commit != r1A.Commit || !bytes.Equal(eq.PriorR2.PartialSig, r2A.PartialSig) {
		t.Fatalf("evidence prior round-1/round-2 do not match the first emission")
	}

	// Idempotent replay of (binding, msgA) succeeds and returns the
	// persisted Round1 / Round2.
	r1Aprime, r2Aprime, err := ThbsSeRound1(params, key.Shares[0], binding, msgA, guard, nil)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if r1Aprime.Commit != r1A.Commit {
		t.Fatalf("idempotent replay produced different commit")
	}
	if !bytes.Equal(r2Aprime.PartialSig, r2A.PartialSig) {
		t.Fatalf("idempotent replay produced different partial_sig")
	}

	// VerifyThbsSeEvidence must accept the equivocation evidence when anchored
	// to the accused's real committee share (read from the published committee,
	// never from the evidence blob).
	share := key.Shares[0].Share
	ev := eq.Evidence()
	if !VerifyThbsSeEvidence(params, ev, share, msgA, msgB, binding, binding) {
		t.Fatalf("VerifyThbsSeEvidence rejected genuine evidence")
	}

	// Tamper the evidence: swap digests so they match. Verifier must
	// reject (no equivocation if both digests equal).
	bad := ev
	bad.NewDigest = ev.PriorDigest
	if VerifyThbsSeEvidence(params, bad, share, msgA, msgA, binding, binding) {
		t.Fatalf("VerifyThbsSeEvidence accepted tampered evidence with equal digests")
	}

	// Fabricated evidence naming this party but carrying reveals it never
	// produced must be refused: the reveals do not unmask to the party's share.
	// This is the property that keeps the check from slashing an honest
	// validator on a byte string of the accuser's choosing.
	forged := ev
	forgedSig := make([]byte, 4*params.SeedSize) // mask || masked, each 2*SeedSize
	for i := range forgedSig {
		forgedSig[i] = 0x5a
	}
	forged.PriorR2.PartialSig = forgedSig
	forged.PriorR1.Commit = deriveThbsSeCommit(params, forged.PriorR2.PartialSig, binding, msgA, forged.PartyID)
	if VerifyThbsSeEvidence(params, forged, share, msgA, msgB, binding, binding) {
		t.Fatalf("VerifyThbsSeEvidence accepted fabricated reveals that do not unmask to the share")
	}
}

// TestThbsSE_OverselectedCommittee pins the availability claim of
// over-selection. With n=7, t=3 and 4 honest signers (3 withholders),
// the public combiner can still assemble a valid FIPS 205-shaped
// signature. The Lagrange basis is determined by any t evaluation
// points so disjoint sub-quora of size t produce byte-equal final
// signatures.
func TestThbsSE_OverselectedCommittee(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 7)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(19)
	msg := []byte("survives-withholding")

	// 4 honest signers; parties {1, 3, 5, 6} produce; parties {0, 2, 4}
	// withhold their Round-1 / Round-2.
	r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{1, 3, 5, 6})
	input := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  r1s,
		Round2:  r2s,
	}
	sig, evidences, err := Combine(AckThbsSeReconstructsSeed, input)
	if err != nil {
		t.Fatalf("Combine with 4 honest of 7 (t=3): %v", err)
	}
	if len(evidences) != 0 {
		t.Fatalf("unexpected evidences on honest withholding: %+v", evidences)
	}
	if sig == nil || len(sig.Bytes) != params.SignatureSize {
		t.Fatalf("Combine returned bad signature shape")
	}
	id := slhdsaIDForMode(ModeM192s)
	pk := slhdsa.PublicKey{ID: id}
	if err := pk.UnmarshalBinary(key.PublicKey.Bytes); err != nil {
		t.Fatalf("UnmarshalBinary(pk): %v", err)
	}
	ctx := ctxFromSlot(binding)
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig.Bytes, ctx) {
		t.Fatalf("circl Verify rejected the withholding-survived signature")
	}
}

// TestThbsSE_PublicCombiner_Determinism pins the deterministic-
// Combine property: any t valid shares produce the same signature
// (because all shares are evaluations of the same polynomial). The
// public combiner is therefore a PURE function of its inputs.
func TestThbsSE_PublicCombiner_Determinism(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 7)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBinding(23)
	msg := []byte("public-combiner-determinism")

	r1s, r2s := runRound1Across(t, params, key, binding, msg, []int{0, 1, 2, 3, 4, 5, 6})
	// Two different sub-selections of size t=3.
	subA := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  []ThbsSeRound1Msg{r1s[0], r1s[2], r1s[4]},
		Round2:  []ThbsSeRound2Msg{r2s[0], r2s[2], r2s[4]},
	}
	subB := ThbsSeCombineInput{
		Key:     key,
		Binding: binding,
		Message: msg,
		Round1:  []ThbsSeRound1Msg{r1s[1], r1s[3], r1s[5]},
		Round2:  []ThbsSeRound2Msg{r2s[1], r2s[3], r2s[5]},
	}
	sigA, _, err := Combine(AckThbsSeReconstructsSeed, subA)
	if err != nil {
		t.Fatalf("Combine A: %v", err)
	}
	sigB, _, err := Combine(AckThbsSeReconstructsSeed, subB)
	if err != nil {
		t.Fatalf("Combine B: %v", err)
	}
	if !bytes.Equal(sigA.Bytes, sigB.Bytes) {
		t.Fatalf("Two disjoint t-subsets produced different signatures — combine not deterministic")
	}
}

// TestThbsSE_SlotBindingDomainSeparation pins the slot-binding
// domain-separation guarantee: the same message signed under distinct
// slot bindings (distinct (chain_id, epoch, slot, height,
// committee_id, message_domain) tuples) produces DISTINCT signature
// bytes, and a signature produced under one binding does NOT verify
// under another binding. This rules out a class of cross-slot replay
// attacks where an adversary attempts to lift a signature produced at
// epoch e onto epoch e' or onto a different consensus message domain.
//
// The binding flows into the FIPS 205 ctx string at sign time
// (ctxFromSlot), so the SLH-DSA verifier itself enforces the
// separation --- Magnetar adds no extra check on top of the FIPS 205
// guarantee.
func TestThbsSE_SlotBindingDomainSeparation(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	committee := makeThbsSeCommittee(t, 5)
	key, err := NewThbsSeKey(params, 3, committee, nil)
	if err != nil {
		t.Fatalf("NewThbsSeKey: %v", err)
	}
	msg := []byte("distinct-binding")
	bindingA := makeThbsSeBinding(29)
	bindingB := makeThbsSeBinding(29)
	bindingB.Epoch = 2 // distinct epoch — distinct ctx

	r1sA, r2sA := runRound1Across(t, params, key, bindingA, msg, []int{0, 1, 2})
	r1sB, r2sB := runRound1Across(t, params, key, bindingB, msg, []int{0, 1, 2})
	sigA, _, err := Combine(AckThbsSeReconstructsSeed, ThbsSeCombineInput{Key: key, Binding: bindingA, Message: msg, Round1: r1sA, Round2: r2sA})
	if err != nil {
		t.Fatalf("Combine A: %v", err)
	}
	sigB, _, err := Combine(AckThbsSeReconstructsSeed, ThbsSeCombineInput{Key: key, Binding: bindingB, Message: msg, Round1: r1sB, Round2: r2sB})
	if err != nil {
		t.Fatalf("Combine B: %v", err)
	}
	if bytes.Equal(sigA.Bytes, sigB.Bytes) {
		t.Fatalf("Distinct slot bindings produced byte-equal signatures — slot binding not propagated to ctx")
	}
	// Both must verify under their respective ctx.
	id := slhdsaIDForMode(ModeM192s)
	pk := slhdsa.PublicKey{ID: id}
	_ = pk.UnmarshalBinary(key.PublicKey.Bytes)
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sigA.Bytes, ctxFromSlot(bindingA)) {
		t.Fatalf("sigA does not verify under bindingA")
	}
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sigB.Bytes, ctxFromSlot(bindingB)) {
		t.Fatalf("sigB does not verify under bindingB")
	}
	// Cross-ctx must fail.
	if slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sigA.Bytes, ctxFromSlot(bindingB)) {
		t.Fatalf("sigA verified under bindingB ctx — slot binding not enforced")
	}
}

// BenchmarkThbsSE_Sign_5of7 measures end-to-end per-signature
// latency on a 5-of-7 committee, parametrised across all three
// FIPS 205 SHAKE modes. SHAKE-192s and SHAKE-256s are the
// recommended "small" variants and run on the order of seconds
// per signature on Apple M1 Max (the FIPS 205 SignDeterministic
// cost dominates). The SHAKE-192f variant is the "fast" mode and
// runs on the order of 500--1000 ms per signature on the same
// hardware via cloudflare/circl/sign/slhdsa v1.6.3. The slot
// binding, Round1 commit-and-reveal, and Combine's Lagrange
// reconstruction together account for <1% of wall-clock; the
// remainder is the underlying slhdsa primitive (DeriveKey +
// SignDeterministic). The bench reports honest end-to-end
// numbers and does not assert a wall-clock threshold; downstream
// consumers can read off the measured ns/op for capacity
// planning.
func BenchmarkThbsSE_Sign_5of7(b *testing.B) {
	for _, mode := range thbsSeAllModes {
		mode := mode
		b.Run(mode.String(), func(b *testing.B) {
			benchThbsSeSignMode(b, mode, 7, 5)
		})
	}
}

// benchThbsSeSignMode is the parametrised bench body.
func benchThbsSeSignMode(b *testing.B, mode Mode, n, t int) {
	params := MustParamsFor(mode)
	committee := make([]NodeID, n)
	for i := 0; i < n; i++ {
		_, _ = rand.Read(committee[i][:])
	}
	sort.Slice(committee, func(i, j int) bool { return bytes.Compare(committee[i][:], committee[j][:]) < 0 })
	key, err := NewThbsSeKey(params, t, committee, nil)
	if err != nil {
		b.Fatalf("NewThbsSeKey: %v", err)
	}
	binding := makeThbsSeBindingBench(31)
	msg := []byte("benchmark-thbsse-sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r1s := make([]ThbsSeRound1Msg, 0, t)
		r2s := make([]ThbsSeRound2Msg, 0, t)
		for j := 0; j < t; j++ {
			guard := NewThbsSeSlotGuard()
			r1, r2, err := ThbsSeRound1(params, key.Shares[j], binding, msg, guard, nil)
			if err != nil {
				b.Fatalf("Round1[%d]: %v", j, err)
			}
			r1s = append(r1s, r1)
			r2s = append(r2s, r2)
		}
		sig, _, err := Combine(AckThbsSeReconstructsSeed, ThbsSeCombineInput{
			Key:     key,
			Binding: binding,
			Message: msg,
			Round1:  r1s,
			Round2:  r2s,
		})
		if err != nil {
			b.Fatalf("Combine: %v", err)
		}
		if sig == nil {
			b.Fatal("nil sig")
		}
	}
}

// makeThbsSeBindingBench is a bench-side helper (no testing.T).
func makeThbsSeBindingBench(slot uint64) *ThbsSeSlotBinding {
	return &ThbsSeSlotBinding{
		ChainID:       []byte("lux-magnetar-bench-chain"),
		Epoch:         1,
		Slot:          slot,
		Height:        100,
		CommitteeID:   []byte("bench-committee-A"),
		MessageDomain: []byte("polaris-cert"),
	}
}

// TestThbsSE_Combine_ResearchOnlyRuntimeBarrier pins the RUNTIME research-only
// gate on the seed-reconstructing combiner — NO build tags, one native binary.
// Without the explicit AckThbsSeReconstructsSeed acknowledgement, Combine
// refuses immediately (before any reconstruction); with it, the barrier is
// passed (and the call then fails only on the empty input).
func TestThbsSE_Combine_ResearchOnlyRuntimeBarrier(t *testing.T) {
	// Zero-value ack (the only ack an outside caller can forge — the field is
	// unexported) is refused.
	if _, _, err := Combine(ThbsSeReconstructAck{}, ThbsSeCombineInput{}); !errors.Is(err, ErrThbsSeResearchOnly) {
		t.Fatalf("Combine without ack: got %v, want ErrThbsSeResearchOnly", err)
	}
	// With the ack the runtime barrier is passed: the error is the nil-key
	// validation, NOT the research refusal — proving the ack let it through.
	if _, _, err := Combine(AckThbsSeReconstructsSeed, ThbsSeCombineInput{}); err == nil || errors.Is(err, ErrThbsSeResearchOnly) {
		t.Fatalf("Combine with ack should pass the barrier and fail on empty input, got %v", err)
	}
}
