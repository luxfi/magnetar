// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// pvss.go — Publicly Verifiable Secret Sharing layer for the public
// DKG.
//
// SKELETON: this file ships the WIRE SHAPE of the PVSS-based public
// DKG for HBS. It implements:
//
//   - Per-element contribution sharing: every party j ∈ [n] samples
//     a random per-element contribution r_{j,e} for every secret
//     element e ∈ E (the WOTS+ chain heads + FORS leaves), and
//     Shamir-shares r_{j,e} across the committee at threshold t.
//   - Per-share Pedersen-style commitments so the share's
//     consistency with the dealt commitment vector is publicly
//     verifiable.
//   - Per-recipient envelope with KEM wrapping placeholder
//     (ML-KEM-768 in production; placeholder slot here).
//
// What this file does NOT do:
//
//   - It does NOT compute the public chain endpoints W_e or the
//     public Merkle root from the secret-shared elements. That
//     requires the MPC layer at root.go which is OPEN RESEARCH.
//   - It does NOT consume from a CryptoSuite or wire-format spec
//     beyond the parent thbs's GF(257) Shamir. Future work pins
//     a chain-friendly curve commitment (Pedersen on BLS12-381
//     scalar field) for aggregatable PVSS — current shape uses
//     in-package hash-based commitments only.

import (
	"errors"
)

// PartyID is the canonical party identifier, mirroring thbs.PartyID.
// Re-declared here so dkg2 has no import cycle into thbs.
type PartyID [32]byte

// ElementID is dkg2's flat key for a threshold-shared secret element.
// Mirrors thbs.ElementID but is local to avoid an import cycle.
type ElementID struct {
	Type     byte
	Slot     uint32
	ChainIdx uint16
	TreeIdx  uint16
	LeafIdx  uint32
}

// Participant identifies one party in the PVSS committee.
type Participant struct {
	ID        PartyID
	EvalPoint uint16
}

// Config parameterises a PVSS-based public DKG ceremony.
type Config struct {
	ChainID      []byte
	Epoch        uint64
	Threshold    uint16
	Participants []Participant

	// Elements is the set of secret elements the DKG produces shares
	// for. Caller derives this from the HBS parameter set:
	//   - one ElementID per (slot, ElementWOTS, chain_idx) tuple
	//   - one ElementID per (slot, ElementFORS, tree_idx, leaf_idx)
	// For SLH-DSA-SHAKE-192s with the v1 thbs parameter set this is
	// ~1.6M elements per fresh DKG — see THBS-SPEC.md.
	Elements []ElementID
}

// ContributionShare is one party's PVSS share of one dealer's
// contribution to one element. Wire-stable, signable.
type ContributionShare struct {
	// Dealer is the party that contributed the randomness.
	Dealer PartyID

	// Recipient is the party this share is addressed to.
	Recipient PartyID

	// Element is the secret element this share pertains to.
	Element ElementID

	// EvalPoint is the recipient's Shamir x-coordinate.
	EvalPoint uint16

	// Share is the per-byte GF(257) Shamir share of the dealer's
	// contribution r_{Dealer, Element}. Length matches the
	// underlying secret element byte width.
	Share []uint16

	// Commitment is the per-coefficient Pedersen-style commitment
	// vector so the recipient can verify the share is consistent
	// with what was publicly committed.
	//
	// SKELETON NOTE: the v1 commitment here is a placeholder
	// hash-based binding tag. A production PVSS layer would use a
	// pairing-friendly Pedersen commitment over BLS12-381 to admit
	// publicly verifiable shares. This skeleton documents the wire
	// slot; the cryptographer team selects the production
	// commitment scheme when integrating with the (open-research)
	// MPC-root layer.
	Commitment [][]byte
}

// DealtBundle is one dealer's full output for a PVSS round: a
// commitment vector PUBLIC to the committee plus per-recipient
// share envelopes.
type DealtBundle struct {
	// Dealer is the party that produced this bundle.
	Dealer PartyID

	// PublicCommitments is the dealer-broadcast commitment vector
	// (one Pedersen-style commitment per polynomial coefficient,
	// per element). Every party verifies share consistency against
	// this vector.
	PublicCommitments map[ElementID][][]byte

	// PerRecipient maps each recipient PartyID to that party's
	// per-element shares. Total size = n_recipients × |Elements|
	// per dealer — for the v1 thbs parameter set this dominates
	// the DKG wire cost.
	PerRecipient map[PartyID][]ContributionShare
}

// Errors returned by the PVSS layer.
var (
	// ErrInvalidPVSSConfig means the Config is malformed: bad
	// threshold, zero eval point, duplicate participants, or empty
	// element set.
	ErrInvalidPVSSConfig = errors.New("dkg2: invalid PVSS config")

	// ErrCommitmentMismatch means a recipient's verification of a
	// dealt share against the dealer's public commitment failed.
	// Triggers the complaint round (complaint.go).
	ErrCommitmentMismatch = errors.New("dkg2: PVSS share commitment mismatch")

	// ErrMPCRootNotImpl is the sentinel returned by RootMPC. The
	// MPC layer that computes public Merkle roots from
	// secret-shared leaves is open research; v0.6+ candidate.
	// See BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1.
	ErrMPCRootNotImpl = errors.New("dkg2: MPC-root computation not implemented (see BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1)")

	// ErrSkeletonOnly is the umbrella sentinel returned by
	// orchestrator functions that compose PVSS + complaint +
	// consensus + MPC root. As of the skeleton ship the
	// orchestrator returns this to make it impossible for a
	// production caller to accidentally consume the unfinished
	// pipeline.
	ErrSkeletonOnly = errors.New("dkg2: skeleton only — production caller MUST NOT consume (use thbs.DealerDKG for v1 or magnetar.ValidatorSign for public BFT)")
)

// Deal is the dealer-side PVSS step.
//
// SKELETON: ships the function signature + a stub body that returns
// ErrSkeletonOnly. Real implementation:
//
//  1. For each element e ∈ Elements:
//       a. Sample contribution r_e ∈ {0,1}^{element_byte_size}.
//       b. Generate a random degree-(t-1) polynomial f_e(X) with
//          f_e(0) = r_e (per-byte GF(257) Shamir, matching the
//          parent thbs Shamir).
//       c. Compute the per-coefficient commitment vector
//          C_e = [Comm(f_{e,0}), Comm(f_{e,1}), ..., Comm(f_{e,t-1})].
//       d. For each recipient j with EvalPoint x_j:
//            Share_{e,j} = f_e(x_j) (per byte).
//
//  2. Broadcast (commitments, per-recipient shares) as a
//     DealtBundle.
//
//  3. Wrap each per-recipient envelope under ML-KEM-768 to the
//     recipient's long-term identity public key (BLOCKERS.md::CR-8
//     pattern, matches Pulsar v0.3+).
//
// What does NOT happen here:
//
//   - The public chain-endpoint W_e is NOT computed from the
//     contribution. That requires the MPC layer at RootMPC.
//   - The dealer does NOT see or hold the JOINT secret element
//     x_e = Σ_j r_{j,e}; only its OWN contribution r_{self,e}.
func Deal(cfg Config, self PartyID) (*DealtBundle, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return nil, ErrSkeletonOnly
}

// Verify is the recipient-side PVSS step. Each party invokes Verify
// on every received DealtBundle to detect bad-delivery / commitment-
// mismatch (and feed evidence into the complaint round).
//
// SKELETON: returns ErrSkeletonOnly.
//
// Real implementation:
//
//  1. For every (element, share) pair in bundle.PerRecipient[self]:
//       a. Evaluate the dealer's public commitment polynomial at
//          self's EvalPoint x_self using the bundle's
//          PublicCommitments[element] vector.
//       b. Verify the commitment evaluation matches the per-byte
//          share. If not: return ErrCommitmentMismatch and the
//          caller raises a complaint (complaint.go).
//  2. Persist (dealer, element, share) for the consensus step.
func Verify(cfg Config, self PartyID, bundle *DealtBundle) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if bundle == nil {
		return ErrSkeletonOnly
	}
	return ErrSkeletonOnly
}

// validateConfig pins the structural invariants on Config.
func validateConfig(cfg Config) error {
	if cfg.Threshold < 1 || int(cfg.Threshold) > len(cfg.Participants) {
		return ErrInvalidPVSSConfig
	}
	if len(cfg.Elements) == 0 {
		return ErrInvalidPVSSConfig
	}
	seen := make(map[uint16]struct{}, len(cfg.Participants))
	for _, p := range cfg.Participants {
		if p.EvalPoint == 0 {
			return ErrInvalidPVSSConfig
		}
		if _, dup := seen[p.EvalPoint]; dup {
			return ErrInvalidPVSSConfig
		}
		seen[p.EvalPoint] = struct{}{}
	}
	return nil
}
