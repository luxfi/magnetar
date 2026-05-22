// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import (
	"errors"
	"testing"
)

// slot_test.go — slot-guard persistence and equivocation-evidence
// verifiability tests.
//
// The defect these tests pin (v0.4.2 -> v0.4.3): NewGuard previously
// imported only Digest from AntiEquivState, leaving Partial
// zero-valued on restore. Subsequent equivocation produced an
// Evidence struct with ShareA = PartialSignature{} which a third
// party could not cryptographically verify.

// TestSlotGuard_PersistsPartial: after a sign + restart cycle, the
// guard's LoadPartial returns the originally-emitted PartialSignature
// (not a zero value).
func TestSlotGuard_PersistsPartial(t *testing.T) {
	pk, shares := runDealerDKG(t, 2, 3)
	g := NewGuardWithParams(&shares[0], pk.Params, 1)
	const slot Slot = 2

	msg := []byte("persisted-partial-msg")
	pA, err := SignShare(g, slot, msg)
	if err != nil {
		t.Fatalf("SignShare: %v", err)
	}

	// In-process recovery from the same guard.
	dPre, partialPre, ok := g.LoadPartial(slot)
	if !ok {
		t.Fatal("LoadPartial returned !ok before restart")
	}
	if dPre != pA.MessageDigest {
		t.Errorf("LoadPartial digest mismatch (pre-restart)")
	}
	if partialPre.PartyID != pA.PartyID {
		t.Error("LoadPartial Partial.PartyID is zero (pre-restart)")
	}
	if len(partialPre.Shares) != len(pA.Shares) {
		t.Errorf("LoadPartial Partial.Shares count %d, want %d (pre-restart)",
			len(partialPre.Shares), len(pA.Shares))
	}

	// Persist and reload through StateStore — simulates a full restart
	// where the only thing that survives is the serialised AntiEquivState.
	shares[0].AntiEquivState = g.Snapshot()
	g2 := NewGuardWithParams(&shares[0], pk.Params, 1)

	dPost, partialPost, ok := g2.LoadPartial(slot)
	if !ok {
		t.Fatal("LoadPartial returned !ok after restart")
	}
	if dPost != pA.MessageDigest {
		t.Error("LoadPartial digest mismatch (post-restart)")
	}
	if partialPost.PartyID != pA.PartyID {
		t.Error("LoadPartial Partial.PartyID is zero (post-restart) — REGRESSION")
	}
	if partialPost.MessageDigest != pA.MessageDigest {
		t.Error("LoadPartial Partial.MessageDigest mismatch (post-restart)")
	}
	if partialPost.SlotID != pA.SlotID {
		t.Error("LoadPartial Partial.SlotID mismatch (post-restart)")
	}
	if len(partialPost.Shares) != len(pA.Shares) {
		t.Errorf("LoadPartial Partial.Shares count %d, want %d (post-restart) — REGRESSION",
			len(partialPost.Shares), len(pA.Shares))
	}
	if len(partialPost.Proofs) != len(pA.Proofs) {
		t.Errorf("LoadPartial Partial.Proofs count %d, want %d (post-restart) — REGRESSION",
			len(partialPost.Proofs), len(pA.Proofs))
	}

	// Cross-check: every share/proof byte must match (deep equality).
	for i, s := range pA.Shares {
		if partialPost.Shares[i].ID != s.ID {
			t.Errorf("Shares[%d].ID mismatch", i)
		}
		if partialPost.Shares[i].X != s.X {
			t.Errorf("Shares[%d].X mismatch", i)
		}
		if partialPost.Shares[i].Steps != s.Steps {
			t.Errorf("Shares[%d].Steps mismatch", i)
		}
		if len(partialPost.Shares[i].Y) != len(s.Y) {
			t.Errorf("Shares[%d].Y length mismatch", i)
			continue
		}
		for k, y := range s.Y {
			if partialPost.Shares[i].Y[k] != y {
				t.Errorf("Shares[%d].Y[%d] mismatch", i, k)
				break
			}
		}
	}
	for i, pr := range pA.Proofs {
		if partialPost.Proofs[i].Tag != pr.Tag {
			t.Errorf("Proofs[%d].Tag mismatch", i)
		}
	}
}

// TestEquivocation_EvidenceAfterRestart: after a sign + restart cycle,
// signing a DIFFERENT message at the same slot yields
// Evidence{ShareA, ShareB} where ShareA is the FULLY-POPULATED
// pre-restart PartialSignature (this is the defect we fixed).
func TestEquivocation_EvidenceAfterRestart(t *testing.T) {
	pk, shares := runDealerDKG(t, 2, 3)
	g := NewGuardWithParams(&shares[0], pk.Params, 1)
	const slot Slot = 3

	msgA := []byte("pre-restart-msg-A")
	pA, err := SignShare(g, slot, msgA)
	if err != nil {
		t.Fatalf("SignShare(A): %v", err)
	}

	// Persist to AntiEquivState and rebuild a fresh guard from it
	// (simulating a node restart).
	shares[0].AntiEquivState = g.Snapshot()
	g2 := NewGuardWithParams(&shares[0], pk.Params, 1)

	// Now attempt to sign a DIFFERENT message at the same slot.
	msgB := []byte("post-restart-conflicting-msg-B")
	_, err = SignShare(g2, slot, msgB)
	if err == nil {
		t.Fatal("equivocation undetected after restart")
	}
	if !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation, got %v", err)
	}
	var eq *EquivocationError
	if !errors.As(err, &eq) {
		t.Fatal("expected EquivocationError")
	}
	ev := eq.Evidence

	// SlotID + DigestA agreement with pre-restart signature.
	if ev.SlotID != pA.SlotID {
		t.Error("Evidence.SlotID does not match pre-restart partial")
	}
	if ev.DigestA != pA.MessageDigest {
		t.Error("Evidence.DigestA does not match pre-restart message digest")
	}
	digestB := messageDigest(msgB, slotIDBytes(slot))
	if ev.DigestB != digestB {
		t.Error("Evidence.DigestB does not match post-restart message digest")
	}
	if ev.DigestA == ev.DigestB {
		t.Fatal("DigestA == DigestB; no equivocation")
	}

	// ShareA MUST be the FULL pre-restart PartialSignature — this is
	// what the v0.4.2 defect broke.
	if ev.ShareA.PartyID != pA.PartyID {
		t.Error("Evidence.ShareA.PartyID is zero — REGRESSION (v0.4.2 defect)")
	}
	if ev.ShareA.MessageDigest != pA.MessageDigest {
		t.Error("Evidence.ShareA.MessageDigest is zero — REGRESSION (v0.4.2 defect)")
	}
	if ev.ShareA.SlotID != pA.SlotID {
		t.Error("Evidence.ShareA.SlotID is zero — REGRESSION")
	}
	if len(ev.ShareA.Shares) != len(pA.Shares) {
		t.Errorf("Evidence.ShareA.Shares count %d, want %d — REGRESSION",
			len(ev.ShareA.Shares), len(pA.Shares))
	}
	if len(ev.ShareA.Proofs) != len(pA.Proofs) {
		t.Errorf("Evidence.ShareA.Proofs count %d, want %d — REGRESSION",
			len(ev.ShareA.Proofs), len(pA.Proofs))
	}
	// Tag-level deep equality on each proof.
	for i, p := range pA.Proofs {
		if ev.ShareA.Proofs[i].Tag != p.Tag {
			t.Errorf("Evidence.ShareA.Proofs[%d].Tag mismatch", i)
		}
	}

	// ShareB MUST also be fully populated (computed in this process).
	if ev.ShareB.MessageDigest != digestB {
		t.Error("Evidence.ShareB.MessageDigest mismatch")
	}
	if len(ev.ShareB.Shares) == 0 {
		t.Error("Evidence.ShareB.Shares empty")
	}
}

// TestEvidence_VerifiableByThirdParty: an Evidence emitted across a
// restart passes VerifyEvidence — i.e. the slashing layer can confirm
// equivocation using ONLY the Evidence struct (no access to the
// runtime guard, the dealer, or the public key required).
func TestEvidence_VerifiableByThirdParty(t *testing.T) {
	pk, shares := runDealerDKG(t, 2, 3)
	g := NewGuardWithParams(&shares[0], pk.Params, 1)
	const slot Slot = 4

	// First message, signed pre-restart.
	if _, err := SignShare(g, slot, []byte("evidence-msg-A")); err != nil {
		t.Fatalf("SignShare(A): %v", err)
	}

	// Persist and restart.
	shares[0].AntiEquivState = g.Snapshot()
	g2 := NewGuardWithParams(&shares[0], pk.Params, 1)

	// Trigger equivocation.
	_, err := SignShare(g2, slot, []byte("evidence-msg-B"))
	if err == nil {
		t.Fatal("equivocation undetected")
	}
	var eq *EquivocationError
	if !errors.As(err, &eq) {
		t.Fatalf("expected EquivocationError, got %v", err)
	}

	// Third-party verification: a fresh process with no access to g/g2
	// confirms the Evidence.
	ok, verr := VerifyEvidence(eq.Evidence)
	if verr != nil {
		t.Fatalf("VerifyEvidence returned error: %v", verr)
	}
	if !ok {
		t.Fatal("VerifyEvidence rejected a true equivocation — REGRESSION")
	}

	// Tampering with a single proof tag in ShareA must invalidate the
	// evidence (the slashing layer cannot be fooled by a forged
	// pre-restart partial).
	tampered := eq.Evidence
	tampered.ShareA.Proofs = append([]ShareProof(nil), eq.Evidence.ShareA.Proofs...)
	tampered.ShareA.Proofs[0].Tag[0] ^= 0xFF
	if ok, _ := VerifyEvidence(tampered); ok {
		t.Fatal("VerifyEvidence accepted tampered ShareA proof tag")
	}

	// Tampering with the recorded DigestA breaks the MAC check.
	tampered2 := eq.Evidence
	tampered2.DigestA[0] ^= 0x01
	if ok, _ := VerifyEvidence(tampered2); ok {
		t.Fatal("VerifyEvidence accepted mismatched DigestA")
	}

	// Replacing PartyID breaks evidence — the slashing layer must not
	// accept evidence claiming a different party signed.
	tampered3 := eq.Evidence
	tampered3.PartyID = PartyID{} // a fresh zero PartyID
	if ok, _ := VerifyEvidence(tampered3); ok {
		t.Fatal("VerifyEvidence accepted forged PartyID")
	}

	// Equal digests = not equivocation.
	tampered4 := eq.Evidence
	tampered4.DigestB = tampered4.DigestA
	if ok, _ := VerifyEvidence(tampered4); ok {
		t.Fatal("VerifyEvidence accepted DigestA == DigestB")
	}

	// Sanity: still pin pk in scope so future refactors don't drop it.
	_ = pk
}

// TestSlotGuard_PersistsPartial_Idempotent: a same-message replay after
// restart returns the originally-emitted PartialSignature byte-for-byte.
// This is the idempotency invariant that consensus replays rely on.
func TestSlotGuard_PersistsPartial_Idempotent(t *testing.T) {
	pk, shares := runDealerDKG(t, 2, 3)
	g := NewGuardWithParams(&shares[0], pk.Params, 1)
	const slot Slot = 5

	msg := []byte("idempotent-replay")
	pPre, err := SignShare(g, slot, msg)
	if err != nil {
		t.Fatalf("SignShare(pre): %v", err)
	}

	shares[0].AntiEquivState = g.Snapshot()
	g2 := NewGuardWithParams(&shares[0], pk.Params, 1)

	pPost, err := SignShare(g2, slot, msg)
	if err != nil {
		t.Fatalf("SignShare(post-restart, same msg): %v", err)
	}
	if pPost.MessageDigest != pPre.MessageDigest {
		t.Error("idempotent replay returned different digest")
	}
	if pPost.SlotID != pPre.SlotID {
		t.Error("idempotent replay returned different SlotID")
	}
	if len(pPost.Shares) != len(pPre.Shares) {
		t.Errorf("idempotent replay share count %d, want %d",
			len(pPost.Shares), len(pPre.Shares))
	}
	if len(pPost.Proofs) != len(pPre.Proofs) {
		t.Errorf("idempotent replay proof count %d, want %d",
			len(pPost.Proofs), len(pPre.Proofs))
	}
	for i, pr := range pPre.Proofs {
		if pPost.Proofs[i].Tag != pr.Tag {
			t.Errorf("idempotent replay Proofs[%d].Tag mismatch", i)
		}
	}
}
