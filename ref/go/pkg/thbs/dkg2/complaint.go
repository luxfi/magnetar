// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// complaint.go — Complaint round + dealer disqualification.
//
// SKELETON: this file ships the wire shape of the complaint round
// that pairs with pvss.go's Deal/Verify. A recipient that detects
// ErrCommitmentMismatch on a received share emits a Complaint
// against the dealer; the consensus round (consensus.go) tallies
// complaints and produces the QualifiedSet Q ⊆ [n] of dealers whose
// contributions survive.
//
// Bad-delivery model:
//
//  1. Dealer D broadcasts a DealtBundle whose PublicCommitments
//     promise per-recipient shares consistent with the dealer's
//     polynomial.
//  2. Recipient R checks the share against the public commitments.
//     If the check fails, R publishes a Complaint{Accuser=R,
//     Accused=D, Element=e, Witness=share} so any third party can
//     replay the verification.
//  3. The dealer D may RESPOND with a Defense{Element=e, OpenedShare=...}
//     that lets every party re-verify R's complaint against D's
//     opened share. If the defense holds, the complaint is dropped;
//     if D fails to defend (or defends incorrectly), D is added to
//     the disqualified set.
//  4. Consensus rounds (consensus.go) reach agreement on the
//     qualified set Q via the chain's BFT layer.

// ComplaintKind taxonomy. Wire-stable; do not renumber.
type ComplaintKind uint8

const (
	// ComplaintBadShare: accused dealer's share for the accuser does
	// not verify against the accused's public commitment vector.
	ComplaintBadShare ComplaintKind = 1

	// ComplaintMissingDelivery: accused dealer did not deliver any
	// share to the accuser within the round timeout.
	ComplaintMissingDelivery ComplaintKind = 2

	// ComplaintCommitmentMalformed: accused dealer's public
	// commitment vector is structurally invalid (wrong length,
	// wrong group element, etc.).
	ComplaintCommitmentMalformed ComplaintKind = 3
)

// String returns the canonical name of the complaint kind.
func (k ComplaintKind) String() string {
	switch k {
	case ComplaintBadShare:
		return "bad-share"
	case ComplaintMissingDelivery:
		return "missing-delivery"
	case ComplaintCommitmentMalformed:
		return "commitment-malformed"
	default:
		return "unknown"
	}
}

// Complaint is the wire envelope a recipient broadcasts when it
// detects deviation by a dealer during the PVSS round.
//
// Wire layout:
//   Kind || Accuser || Accused || Element || Witness
//
// The Witness payload is kind-specific:
//   - ComplaintBadShare: serialized ContributionShare for the
//     pair (Accused -> Accuser, Element)
//   - ComplaintMissingDelivery: empty
//   - ComplaintCommitmentMalformed: serialized commitment vector
//     bytes the accuser received
//
// Third parties replay the witness against the accused's broadcast
// DealtBundle to confirm the complaint is valid; the chain BFT
// layer decides which complaints to honour.
type Complaint struct {
	Kind     ComplaintKind
	Accuser  PartyID
	Accused  PartyID
	Element  ElementID
	Witness  []byte
}

// Defense is the dealer-side response to a Complaint. The dealer
// re-opens the share for the disputed element so any third party
// can confirm whether the accuser's complaint holds.
//
// Wire layout:
//   Dealer || Element || OpenedShare
type Defense struct {
	Dealer      PartyID
	Element     ElementID
	OpenedShare []uint16
}

// FileComplaint is the recipient-side step: scan received
// DealtBundles, detect mismatches, emit Complaint envelopes.
//
// SKELETON: returns nil + ErrSkeletonOnly. Real implementation:
//
//  1. Run Verify() on every received DealtBundle.
//  2. For each (element, dealer) that fails verification, emit
//     Complaint{Kind: ComplaintBadShare, Accuser: self,
//                Accused: dealer, Element: element,
//                Witness: serialized share}.
//  3. For dealers that did not deliver any share within the timeout,
//     emit Complaint{Kind: ComplaintMissingDelivery, ...}.
//  4. Return the list of complaints; caller broadcasts them.
func FileComplaint(cfg Config, self PartyID, bundles []*DealtBundle) ([]*Complaint, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return nil, ErrSkeletonOnly
}

// DealerDefend is the dealer-side step: process incoming Complaints,
// emit a Defense for each VALID complaint (or accept disqualification
// for INVALID complaints).
//
// SKELETON: returns nil + ErrSkeletonOnly. Real implementation:
//
//  1. For each Complaint against THIS dealer, re-derive the
//     contribution polynomial f_e at the accuser's EvalPoint.
//  2. If the dealer's opened share matches the value the dealer
//     committed to via PublicCommitments, emit a Defense and rely
//     on consensus to drop the complaint.
//  3. If the dealer cannot defend (e.g. genuine misdeal), do not
//     emit a Defense; the consensus round will disqualify the
//     dealer.
func DealerDefend(cfg Config, self PartyID, complaints []*Complaint) ([]*Defense, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return nil, ErrSkeletonOnly
}
