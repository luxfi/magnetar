// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// key.go --- ThbsSeKey constructors. Two paths converge on the same
// wire-shape struct:
//
//   - NewThbsSeKey                     (thbsse.go) --- dealer setup.
//     A single machine samples M, byte-shares M, and the dealer is in
//     the TCB for setup only. KAT-reproducible and used for KAT
//     replay; production deployments that need to eliminate the
//     dealer use the second constructor.
//
//   - NewThbsSeKeyFromDealerlessDKG    (this file) --- dealerless
//     setup. The committee runs the Schoenmakers-style PVSS-DKG
//     defined in pvss_dkg.go and the resulting transcript is
//     consumed here to assemble a ThbsSeKey BYTE-SHAPE IDENTICAL to
//     the dealer-path output. No party (and no transient dealer)
//     ever holds the master byte vector across the full setup.
//
// The two constructors output structs that are wire-interchangeable:
// for a given master M, the share envelopes byte-equal each other and
// the SetupTranscript byte-equals. The only operational difference is
// WHO holds the secret material during setup (one machine vs. n
// machines), and the operational guarantee that no single machine
// ever holds M in the dealerless variant.

import (
	"encoding/binary"
	"errors"
)

// NewThbsSeKeyFromDealerlessDKG assembles a *ThbsSeKey from the
// transcript of a dealerless PVSS-DKG run. Closes
// BLOCKERS.md::MAGNETAR-PVSS-DKG-V11.
//
// The transcript is the public-form record of an n-party DKG; this
// constructor:
//
//  1. Re-verifies every party's Round-2 reveal against their Round-1
//     commit (delegates to VerifyDKGTranscript).
//  2. Derives the qualified set Q (the parties whose commits and
//     shares verified).
//  3. Reconstructs the public key transiently inside the same closure
//     used by VerifyDKGTranscript — `lagrangeScratch` named in the
//     PVSS-DKG file and zeroized at function exit.
//  4. Aggregates each party's received-share row over Q to produce
//     their final Shamir share at evaluation point (party_index).
//  5. Emits the ThbsSeKey with byte-shape-identical Shares to what
//     NewThbsSeKey would emit for the implicit master.
//
// Wire compatibility (proven by TestPVSS_DKG_ByteCompatWithDealerPath):
//
//   - key.Shares[i].EvalPoint = party_index (1-indexed); matches
//     NewThbsSeKey which sets EvalPoint = committee_index + 1.
//   - key.Shares[i].Share     = thbsseShareToBytes(aggregated share);
//     byte-equal for the same implicit master.
//   - key.SetupTranscript     = cSHAKE256(pk_bytes || n || t ||
//     committee[i]...) per the
//     same canonical hash NewThbsSeKey uses.
//
// If the qualified set has fewer than threshold parties, returns
// ErrPVSSQuorumLost; the caller should restart the DKG with a fresh
// committee or a fresh round.
func NewThbsSeKeyFromDealerlessDKG(tr *PVSSTranscript) (*ThbsSeKey, error) {
	if tr == nil {
		return nil, errors.New("magnetar/pvss-dkg: nil transcript")
	}
	if err := tr.Params.Validate(); err != nil {
		return nil, err
	}
	n := len(tr.Committee)
	if tr.Threshold < 1 || n < tr.Threshold {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}

	// Verify the transcript and derive (Q, pk).
	qualified, pk, err := VerifyDKGTranscript(tr)
	if err != nil {
		return nil, err
	}

	// Assemble per-party Shares by aggregating their received-share
	// rows over Q. Order: ascending committee index, matching the
	// dealer path's order.
	shares := make([]*KeyShare, n)
	for i := 0; i < n; i++ {
		yvec := AggregateShareEnvelope(tr, qualified, uint32(i+1))
		share := thbsseShare{X: uint32(i + 1), Y: yvec}
		shares[i] = &KeyShare{
			NodeID:    tr.Committee[i],
			EvalPoint: share.X,
			Share:     thbsseShareToBytes(share),
			Pub:       pk,
			Mode:      tr.Params.Mode,
		}
		zeroizeU16Slice(yvec)
	}

	// Setup transcript: same canonical bind as NewThbsSeKey. The two
	// constructors emit the same SetupTranscript for the same
	// (PK, committee, n, t) tuple, so an auditor's transcript hash
	// matches across the two paths.
	tagBuf := make([]byte, 0, 256)
	tagBuf = append(tagBuf, pk.Bytes...)
	tagBuf = binary.BigEndian.AppendUint32(tagBuf, uint32(n))
	tagBuf = binary.BigEndian.AppendUint32(tagBuf, uint32(tr.Threshold))
	for _, c := range tr.Committee {
		tagBuf = append(tagBuf, c[:]...)
	}
	var setupTr [32]byte
	copy(setupTr[:], cshake256(tagBuf, 32, tagThbsSeR1Commit))

	return &ThbsSeKey{
		Params:          tr.Params,
		PublicKey:       pk,
		Shares:          shares,
		SetupTranscript: setupTr,
		Threshold:       tr.Threshold,
		N:               n,
	}, nil
}
