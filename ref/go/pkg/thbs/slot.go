// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import "sync"

// slot.go — per-party anti-equivocation state machine.
//
// Hash-based one-time signatures (WOTS+) are unsafe to reuse: signing
// two distinct messages under the same WOTS+ leaf leaks the secret
// chain heads at positions where the message-derived digit values
// differ. THBS therefore REQUIRES that each (party, slot) tuple be
// used at most once.
//
// We do not RELY on the slot allocator being honest. The state
// machine here is a verifier of the local sign request: if the same
// slot is requested twice with the same message digest, the second
// call is idempotent (same shares emitted, same Tag, same byte
// output); if the same slot is requested with a DIFFERENT message
// digest, the second call returns ErrEquivocation with verifiable
// evidence the consensus layer can slash on.
//
// CRITICAL: the slot guard MUST persist the previously-emitted
// PartialSignature (not just the digest) so that equivocation
// evidence produced after a restart contains a fully-populated
// ShareA. Restoring only the digest breaks third-party verification
// of Evidence.ShareA (the share-MAC tags cannot be reconstructed
// from a zero-valued PartialSignature). See VerifyEvidence.

// stateImpl is a concurrency-safe slot state machine. The exported
// type StateStore (map alias) is the wire-shape; this is the runtime
// guard. Both use SlotRecord{Digest, Partial} as the per-slot record.
type stateImpl struct {
	mu      sync.Mutex
	records map[Slot]SlotRecord
}

// newStateImpl returns a fresh slot guard.
func newStateImpl() *stateImpl {
	return &stateImpl{records: make(map[Slot]SlotRecord)}
}

// checkAndRecord enforces the slot invariant.
//
// Behaviour:
//   - First call for `slot`: record (digest, partial) and return (false, nil, nil).
//   - Second call with matching digest: return (true, &prev, nil).
//     The caller MUST return the previous partial verbatim
//     (idempotent re-emit).
//   - Second call with mismatched digest: return (false, &prev,
//     ErrEquivocation). Caller wraps in EquivocationError with full
//     evidence; prev.Partial carries the original (third-party
//     verifiable) PartialSignature.
func (s *stateImpl) checkAndRecord(slot Slot, digest [32]byte, partial PartialSignature) (bool, *SlotRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.records[slot]; ok {
		if prev.Digest == digest {
			return true, &prev, nil
		}
		return false, &prev, ErrEquivocation
	}
	s.records[slot] = SlotRecord{Digest: digest, Partial: partial}
	return false, nil, nil
}

// load returns the persisted SlotRecord for a slot, if any.
func (s *stateImpl) load(slot Slot) (SlotRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[slot]
	return r, ok
}

// snapshot returns a defensive copy of the per-slot record map. The
// returned StateStore is suitable for serialisation; restoring a guard
// from it via NewGuard preserves the full (Digest, Partial) tuple so
// post-restart equivocation evidence remains third-party verifiable.
func (s *stateImpl) snapshot() StateStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(StateStore, len(s.records))
	for k, v := range s.records {
		// Defensive copy of share/proof slices so callers cannot mutate
		// the runtime guard via the snapshot.
		out[k] = SlotRecord{Digest: v.Digest, Partial: clonePartial(v.Partial)}
	}
	return out
}

// clonePartial deep-copies a PartialSignature so a snapshot can be
// safely mutated by callers without aliasing the runtime guard's
// records.
func clonePartial(p PartialSignature) PartialSignature {
	shares := make([]ElementShare, len(p.Shares))
	for i, s := range p.Shares {
		y := make([]uint16, len(s.Y))
		copy(y, s.Y)
		shares[i] = ElementShare{ID: s.ID, X: s.X, Y: y, Steps: s.Steps}
	}
	proofs := make([]ShareProof, len(p.Proofs))
	copy(proofs, p.Proofs)
	return PartialSignature{
		PartyID:       p.PartyID,
		SlotID:        p.SlotID,
		MessageDigest: p.MessageDigest,
		Shares:        shares,
		Proofs:        proofs,
	}
}

// PrivateShareGuard couples a PrivateShare with the runtime slot
// guard. SignShare runs against a guarded share.
//
// The dealer returns the bare PrivateShare; callers wrap with
// NewGuard before signing. (Why wrap separately: serialisation of a
// PrivateShare should not include the runtime guard's mutex state.)
//
// params and evalPoint are runtime-only sign-time hints set by
// NewGuardWithParams.
type PrivateShareGuard struct {
	Share     *PrivateShare
	state     *stateImpl
	params    HBSParams
	evalPoint uint16
}

// NewGuard wraps a PrivateShare with a fresh slot state machine. If
// the PrivateShare already carries AntiEquivState (e.g. restored from
// disk), the prior records (digest AND partial) are imported. The
// imported Partial is what makes post-restart equivocation evidence
// third-party verifiable.
func NewGuard(share *PrivateShare) *PrivateShareGuard {
	s := newStateImpl()
	if share.AntiEquivState != nil {
		for slot, rec := range share.AntiEquivState {
			s.records[slot] = SlotRecord{
				Digest:  rec.Digest,
				Partial: clonePartial(rec.Partial),
			}
		}
	}
	return &PrivateShareGuard{Share: share, state: s}
}

// Snapshot returns the StateStore wire shape suitable for serialisation.
// The returned StateStore carries (Digest, Partial) per slot — both
// fields are needed to preserve the equivocation evidence trail across
// restarts.
func (g *PrivateShareGuard) Snapshot() StateStore { return g.state.snapshot() }

// LoadPartial returns the persisted PartialSignature for a slot if the
// guard has emitted one (or restored one from disk). Used by callers
// that want to inspect the equivocation evidence trail directly.
func (g *PrivateShareGuard) LoadPartial(slot Slot) (digest [32]byte, partial PartialSignature, ok bool) {
	r, found := g.state.load(slot)
	if !found {
		return [32]byte{}, PartialSignature{}, false
	}
	return r.Digest, clonePartial(r.Partial), true
}
