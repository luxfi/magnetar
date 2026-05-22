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

// slotRecord is the per-slot record a party keeps.
type slotRecord struct {
	Digest [32]byte
	// The previously-emitted PartialSignature so we can attach it as
	// evidence on a subsequent equivocation attempt.
	Partial PartialSignature
}

// stateImpl is a concurrency-safe slot state machine. The exported
// type StateStore (map alias) is the wire-shape; this is the runtime
// guard.
type stateImpl struct {
	mu      sync.Mutex
	records map[Slot]slotRecord
}

// newStateImpl returns a fresh slot guard.
func newStateImpl() *stateImpl {
	return &stateImpl{records: make(map[Slot]slotRecord)}
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
//     evidence.
func (s *stateImpl) checkAndRecord(slot Slot, digest [32]byte, partial PartialSignature) (bool, *slotRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.records[slot]; ok {
		if prev.Digest == digest {
			return true, &prev, nil
		}
		return false, &prev, ErrEquivocation
	}
	s.records[slot] = slotRecord{Digest: digest, Partial: partial}
	return false, nil, nil
}

// snapshot returns a copy of the per-slot digest map. The
// PartialSignature payload is intentionally omitted from the snapshot:
// the StateStore wire shape is (slot -> digest), not full signature
// material. The full record is held only in the runtime guard.
func (s *stateImpl) snapshot() StateStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(StateStore, len(s.records))
	for k, v := range s.records {
		out[k] = v.Digest
	}
	return out
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
// disk), the prior records are imported.
func NewGuard(share *PrivateShare) *PrivateShareGuard {
	s := newStateImpl()
	if share.AntiEquivState != nil {
		for slot, digest := range share.AntiEquivState {
			s.records[slot] = slotRecord{Digest: digest}
		}
	}
	return &PrivateShareGuard{Share: share, state: s}
}

// Snapshot returns the StateStore wire shape suitable for serialisation.
func (g *PrivateShareGuard) Snapshot() StateStore { return g.state.snapshot() }
