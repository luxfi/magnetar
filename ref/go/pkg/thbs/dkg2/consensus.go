// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// consensus.go — Agreement on the qualified set Q ⊆ [n] of dealers
// whose contributions survive the complaint round, and orchestrator
// for the public DKG.
//
// SKELETON: this file ships the wire shape of the qualified-set
// consensus step + the top-level Run orchestrator. Real
// implementation:
//
//  1. After PVSS Round 1 (deal) and Complaint Round (file +
//     defend), every party computes its LOCAL view of the
//     qualified set Q_self = {dealers d | no surviving complaint
//     against d}.
//  2. The committee runs a BFT consensus round on Q. In Lux this
//     means broadcasting a hash of Q_self and waiting for
//     2f+1 matching signatures; the chain layer drives this. In a
//     standalone deployment this can be a single-round broadcast +
//     local intersection.
//  3. The agreed Q is the basis for x_e = Σ_{j ∈ Q} r_{j,e} (the
//     joint contribution sum, per element).
//  4. The PUBLIC chain endpoints W_e = H^{w-1}(x_e) and the public
//     Merkle root over all W_e are derived via the MPC layer at
//     RootMPC (which is OPEN RESEARCH; see pvss.go ErrMPCRootNotImpl
//     and root.go).

// QualifiedSet is a compact dense bitmap over the committee. Bit i
// is set iff dealer with EvalPoint (i+1) is in the qualified set.
type QualifiedSet []byte

// Set marks bit i.
func (q QualifiedSet) Set(i int) {
	if i>>3 < len(q) {
		q[i>>3] |= 1 << uint(i&7)
	}
}

// Has reports whether bit i is set.
func (q QualifiedSet) Has(i int) bool {
	if i>>3 >= len(q) {
		return false
	}
	return q[i>>3]&(1<<uint(i&7)) != 0
}

// NewQualifiedSet allocates a QualifiedSet sized for `n` parties.
func NewQualifiedSet(n int) QualifiedSet {
	return make(QualifiedSet, (n+7)/8)
}

// AgreementProposal is the per-party broadcast for the qualified-set
// consensus round: each party emits its local view of Q.
//
// Wire layout:
//   Author || Epoch || QHash
//
// QHash is a hash of the canonical-ordered Q bitmap; the canonical
// order is by dealer EvalPoint ascending.
type AgreementProposal struct {
	Author PartyID
	Epoch  uint64
	QHash  [32]byte
}

// AgreementOutput is the output of the qualified-set consensus step:
// the agreed Q bitmap plus the witnesses (signed proposals) for
// auditability.
type AgreementOutput struct {
	Epoch       uint64
	Q           QualifiedSet
	Proposals   []*AgreementProposal
}

// ProposeQ is the per-party step: scan received complaints +
// defenses, compute the LOCAL view of Q, broadcast the hash.
//
// SKELETON: returns nil + ErrSkeletonOnly.
func ProposeQ(cfg Config, self PartyID, complaints []*Complaint, defenses []*Defense) (*AgreementProposal, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return nil, ErrSkeletonOnly
}

// AgreeQ is the consensus step: collect proposals, find the majority
// agreement, and return the agreed Q.
//
// SKELETON: returns nil + ErrSkeletonOnly. Real implementation
// requires plugging into the chain's BFT layer.
func AgreeQ(cfg Config, proposals []*AgreementProposal) (*AgreementOutput, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return nil, ErrSkeletonOnly
}

// Run is the top-level orchestrator for the public DKG. It composes
// PVSS deal -> verify -> complaint -> defense -> agreement -> MPC
// root computation.
//
// SKELETON: returns ErrSkeletonOnly because the MPC-root step is not
// implemented. A v1 caller MUST NOT consume Run; use
// thbs.DealerDKG for the dealer-backed v1 path or
// magnetar.PerValidatorKeypair + magnetar.ValidatorSign for the
// per-validator standalone path.
//
// When the MPC-root layer lands (v0.6+ candidate), Run will:
//
//  1. Call Deal once per dealer; collect DealtBundles.
//  2. Call Verify on every party for every bundle.
//  3. Collect FileComplaint outputs from every party; broadcast
//     DealerDefend outputs from dealers.
//  4. Each party calls ProposeQ; AgreeQ produces the qualified set.
//  5. RootMPC consumes the qualified-set shares + dealer
//     contributions and computes the PUBLIC Merkle root, returning
//     a (root, helper_data, transcript) tuple consumable by the
//     parent thbs verifier.
//
// The output of Run, when implemented, is a (PublicKey, PerParty
// shares) tuple analogous to thbs.DealerDKGAll's output — but
// PRODUCED WITHOUT A DEALER. That is the public-BFT-safe path the
// user's spec calls "DKG = PVSS for secret shares + MPC/public
// verification for derived roots."
func Run(cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	return ErrSkeletonOnly
}

// RootMPC is the unfinished STUB for the public Merkle root
// computation. Given the qualified-set shares + dealer
// contributions, it must compute the public chain endpoints W_e =
// H^{w-1}(x_e) and the public Merkle root over them WITHOUT
// REVEALING any x_e to any single party.
//
// SKELETON: returns ErrMPCRootNotImpl. See doc.go and
// BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1 for the open-research framing.
//
// The right answer is one of:
//
//   - SPDZ-style MPC over SHA-256/SHAKE (Damgård-Pastro-Smart-Zakarias
//     2012). Multi-second per element on current MP-SPDZ; for SLH-DSA-
//     SHAKE-192s with ~750K hashes per public key this is multi-hour
//     to multi-day per DKG ceremony.
//   - Garbled-circuit MPC (Wang-Ranellucci-Katz 2017). Similar order
//     of cost.
//   - Function Secret Sharing for SHA-256 specifically (Boyle-Gilboa-
//     Ishai 2015). Open research for the specific hash circuit.
//   - A different HBS instantiation with MPC-friendly hash (e.g.
//     LowMC, Poseidon, Rescue). Would NOT produce FIPS 205-
//     compatible signatures.
//
// The choice depends on the deployment economics. The cryptographer
// team selects when integrating; v0.6+ candidate.
func RootMPC(cfg Config, agreed *AgreementOutput) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	return ErrMPCRootNotImpl
}
