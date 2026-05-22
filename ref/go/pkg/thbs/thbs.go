// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package thbs implements Magnetar-THBS v1: true threshold hash-based
// signatures in the sense of McGrew, Fluhrer, Gazdag, Kampanakis, Morton,
// Westerbaan, "Coalition and Threshold Hash-Based Signatures"
// (IACR ePrint 2019/793 and the IRTF draft-mcgrew-hash-sigs line of
// work).
//
// CRITICAL DISTINCTION (this is what makes the package "true" threshold):
//
//   - For HBS schemes a signature reveals SELECTED secret elements
//     (WOTS+ chain values selected by message-digest chunks, and FORS
//     leaves selected by the FORS index digest).
//   - Threshold signing in this package shares the SECRET ELEMENTS
//     (the WOTS+ leaf chain heads and the FORS secret leaves) across
//     parties via byte-wise Shamir over GF(257).
//   - For each message, parties release shares ONLY for the elements
//     SELECTED by the message digest. Combiner Lagrange-reconstructs
//     just those elements; the verifier sees an ordinary HBS-style
//     signature.
//
// This is NOT "collect N independent SLH-DSA signatures and average
// them"; that's the wrong thing. This is the right thing.
//
// V1 SCOPE — honest:
//
//   - Setup is DEALER-BACKED. A trusted dealer generates the shared
//     WOTS+/FORS material and distributes shares. (Public DKG = v2.)
//   - Helper data (the Merkle authentication paths and the public-key
//     chain endpoints) is shipped alongside the public key. McGrew et
//     al. allow this.
//   - The verifier is a CUSTOM HBS verifier defined in this package,
//     NOT FIPS 205 SLH-DSA. v3 will produce FIPS 205-byte-identical
//     output; that is significantly more involved and is out of scope
//     for v1.
//   - Anti-equivocation: each party stores slot_id -> message_digest
//     and refuses (with evidence) any subsequent sign attempt against
//     the same slot under a different digest.
//
// HARD INVARIANT (cf. THBS-SPEC.md):
//
//	OK:        ReconstructElement(slot, elementID, shares)
//	Forbidden: ReconstructSeed, ReconstructPrivateKey,
//	           ExpandPrivateKey, DeriveAllFutureElements
//
// The only Reconstruct symbol in this package is the file-scope
// unexported reconstructElement in sign.go. No exported API returns
// future-signing material.
//
// Reference parameter set (one-slot WOTS+ + FORS Merkle, n=24,
// w=16, FORS k=14 a=12, tree height H=10):
//
//	WOTS+: 51 chain values per leaf; 24-byte chain elements
//	FORS:  14 of 4096 leaves per signature
//	Tree:  height 10 (1024 slots)
//
// These parameters are not FIPS 205 wire-compatible; that's v3.
package thbs

import "errors"

// HBSParams captures the concrete shape of the threshold HBS instance.
//
// All sizes are in bytes unless otherwise noted.
type HBSParams struct {
	// N is the hash output size in bytes (e.g. 24 for SHAKE-192-like).
	N int

	// Winternitz parameter; w in {4, 16, 256}. Number of chain values per
	// WOTS+ leaf is ceil(8n / log2 w) + checksum chains. v1 fixes w=16
	// (LogW=4), giving 51 chains per leaf for n=24.
	W    int
	LogW int

	// WOTSChains is the total number of WOTS+ chains per signature.
	// = (8n / LogW) + checksum chains.
	WOTSChains int

	// FORSK is the number of FORS Merkle trees per signature (k).
	// Each tree has 2^FORSA leaves; the signature reveals 1 leaf and the
	// auth path per tree.
	FORSK int
	// FORSA is the height of each FORS tree (a). 2^a leaves per tree.
	FORSA int

	// Height is the height of the top Merkle tree over WOTS+ leaves.
	// 2^Height slots in this v1 instance.
	Height int
}

// DefaultParams returns the v1 reference parameter set. Not FIPS 205
// wire-compatible; see THBS-SPEC.md for the v3 roadmap.
func DefaultParams() HBSParams {
	// n=24, w=16 -> WOTS+ chains = 8*24/4 + checksum
	// checksum chains for w=16, n=24: len2 = floor(log2(48*15)/4) + 1 = 3
	// (48 message chains * (w-1) = 720; log2(720) ≈ 9.49; /4 -> 2; +1 -> 3)
	return HBSParams{
		N:          24,
		W:          16,
		LogW:       4,
		WOTSChains: 51, // 48 message + 3 checksum
		FORSK:      14,
		FORSA:      12,
		Height:     10,
	}
}

// Participant identifies one party in a dealer-backed THBS committee.
type Participant struct {
	ID        PartyID
	EvalPoint uint16 // Shamir x-coordinate in [1, 257); MUST be distinct per party
}

// PartyID is the canonical party identifier. 32 bytes wide to host any
// upstream identity (Lux validator ID, Hanzo IAM hash, etc.).
type PartyID [32]byte

// DKGConfig parametrises a dealer-backed v1 DKG ceremony.
type DKGConfig struct {
	ChainID      []byte        // domain separation tag (e.g. Lux chain ID)
	Epoch        uint64        // monotonic epoch counter for key versioning
	Threshold    uint16        // t in t-of-n; >= 1 and <= len(Participants)
	Participants []Participant // committee
	Params       HBSParams
}

// PublicKey is the threshold-HBS public key.
//
// Root is the Merkle root over the WOTS+ public-key leaves for every slot
// in [0, 2^Height). DKGTranscript is the transcript hash binding this
// keygen ceremony (committee, params, epoch, chain ID). QualifiedSet
// is a bitmap marking which dealer-broadcast envelopes the committee
// agreed on (v1: all parties; v2 may carry survivors of complaint
// rounds).
type PublicKey struct {
	Params        HBSParams
	Root          []byte
	DKGTranscript []byte
	QualifiedSet  Bitmap

	// HelperData carries the dealer-precomputed authentication paths
	// AND the public WOTS+ chain endpoints (the "compressed" leaf
	// values W_i = H_w-1(x_i) per chain). McGrew et al. allow this:
	// the chain endpoints are NOT secret (they're already part of the
	// signature when used) and shipping them up-front lets the
	// combiner construct the final signature without contacting the
	// dealer again.
	HelperData *HelperData
}

// HelperData is the public auxiliary material the dealer emits alongside
// the threshold key. It is the "we precomputed the public tree for you"
// payload that McGrew et al. call out as a v1 simplification.
type HelperData struct {
	// LeafRoots[slot] is the Merkle leaf at slot index `slot`, i.e.
	// H(W_{slot, 0} || W_{slot, 1} || ... || W_{slot, WOTSChains-1}).
	// Length = 2^Height; each entry = N bytes.
	LeafRoots [][]byte

	// AuthPaths[slot] is the authentication path from leaf `slot` to the
	// root. Length = Height nodes, each N bytes. Public information.
	AuthPaths [][][]byte

	// ChainEndpoints[slot] are the public WOTS+ chain endpoints
	// W_{slot, j} = H^{w-1}(x_{slot, j}) for j in [0, WOTSChains).
	// Each entry = N bytes. The combiner uses these to validate that
	// reconstructed chain heads x_{slot, j} chain to the right
	// endpoint.
	ChainEndpoints [][][]byte

	// FORSPubRoots[slot][tree] is the FORS subtree root for slot's
	// tree `tree`. FORSK trees per slot. Each entry = N bytes. The
	// combiner uses these (with the per-leaf auth paths in the FORS
	// section) to validate the FORS portion of the signature.
	FORSPubRoots [][][]byte

	// FORSAuthPaths[slot][tree][leafIdx] is the FORS authentication
	// path inside tree `tree` at slot `slot` for leaf index `leafIdx`.
	// We materialise ALL FORSA-step paths so the combiner does not
	// have to reconstruct the tree. Each path is FORSA entries of N
	// bytes.
	FORSAuthPaths [][][][]byte
}

// Bitmap is a compact dense bitmap over committee positions. Bit i
// indexes the i-th participant in the DKGConfig.Participants list.
type Bitmap []byte

// Set marks bit i.
func (b Bitmap) Set(i int) {
	b[i>>3] |= 1 << uint(i&7)
}

// Has reports whether bit i is set.
func (b Bitmap) Has(i int) bool {
	if i>>3 >= len(b) {
		return false
	}
	return b[i>>3]&(1<<uint(i&7)) != 0
}

// NewBitmap allocates a Bitmap large enough to address `bits` positions,
// with every bit cleared.
func NewBitmap(bits int) Bitmap {
	return make(Bitmap, (bits+7)/8)
}

// PrivateShare is one party's local secret material. It is NEVER a
// reconstructable seed; it is a collection of per-element Shamir shares
// keyed by (slot, elementID).
type PrivateShare struct {
	PartyID PartyID
	Epoch   uint64

	// ElementShares is the per-element share store. Keyed by
	// (slot, elementType, elementIdx). Values are GF(257) per-byte
	// shares of length N.
	ElementShares ShareStore

	// AntiEquivState records per-slot the digest the party has
	// committed to. Reused-slot detection lives here.
	AntiEquivState StateStore
}

// ElementType distinguishes the two threshold-shared element families:
// WOTS+ chain heads and FORS secret leaves.
type ElementType uint8

const (
	// ElementWOTS is a WOTS+ chain head x_{slot, j} prior to any hash
	// chain steps. Reconstructed value is the secret leaf the
	// combiner then chains forward to the public endpoint.
	ElementWOTS ElementType = 1

	// ElementFORS is a FORS secret leaf sk_{slot, tree, leaf}. The
	// combiner reveals these directly.
	ElementFORS ElementType = 2
)

// ElementID identifies one threshold-shared element.
//
// For ElementWOTS: (Slot, ChainIdx) where ChainIdx in [0, WOTSChains).
// For ElementFORS: (Slot, TreeIdx, LeafIdx) where TreeIdx in [0, FORSK)
// and LeafIdx in [0, 2^FORSA).
type ElementID struct {
	Type     ElementType
	Slot     uint32
	ChainIdx uint16
	TreeIdx  uint16
	LeafIdx  uint32
}

// ShareStore is a map-of-shares keyed by element identity. Concrete
// implementation in dealer.go.
type ShareStore map[ElementID][]uint16

// SlotRecord is the persisted per-slot record a party keeps for
// equivocation defense. It binds the slot to BOTH the message digest
// AND the fully-populated PartialSignature that was emitted at that
// slot.
//
// Persisting the full Partial (not just the digest) is REQUIRED so
// that on subsequent equivocation a third party can verify the
// previously-emitted share's MAC tags against DigestA. A digest-only
// store breaks the evidence chain: the slashing layer would receive
// an empty PartialSignature{} for ShareA and could not cryptographically
// validate that the prior party committed to DigestA.
//
// Wire shape on disk: (Digest [32]byte, Partial PartialSignature).
// The Partial carries PartyID, SlotID, MessageDigest (= Digest),
// Shares (~params.WOTSChains+FORSK entries), and Proofs (matching).
// For the reference params (n=24, WOTSChains=51, FORSK=14) the
// per-slot record is on the order of ~3 KiB — acceptable for the
// O(active-slots-per-party) cardinality we expect (at most one
// signed slot per consensus round per party).
type SlotRecord struct {
	Digest  [32]byte
	Partial PartialSignature
}

// StateStore is the wire shape for the anti-equivocation log:
// slot -> SlotRecord{Digest, Partial}. Restored guards reconstruct
// the runtime slot guard from this map; the persisted Partial is what
// makes equivocation evidence third-party verifiable across restarts.
type StateStore map[Slot]SlotRecord

// Slot identifies a one-shot WOTS+ leaf slot (the equivalent of an
// XMSS leaf in HBS). Same slot used twice with distinct messages =
// identifiable abort.
type Slot uint32

// PartialSignature is one party's contribution to a threshold signature.
type PartialSignature struct {
	PartyID       PartyID
	SlotID        [32]byte
	MessageDigest [32]byte

	// Shares are the GF(257) per-byte share values for the SELECTED
	// elements only. Other element shares MUST NOT appear here; the
	// invariant test TestTHBS_WOTS_ReconstructsOnlySelectedChainValues
	// asserts this.
	Shares []ElementShare

	// Proofs are per-share consistency proofs (in v1: a cSHAKE256 MAC
	// binding the share to the slot, message digest, and party ID).
	// The combiner verifies each before reconstructing.
	Proofs []ShareProof
}

// ElementShare is one party's share for one element.
type ElementShare struct {
	ID    ElementID
	X     uint16 // Shamir evaluation point (matches Participant.EvalPoint)
	Y     []uint16
	Steps uint8 // For ElementWOTS: the number of hash chain steps to apply
	// to the reconstructed value. = b_j (the j-th base-w
	// digit of the message digest). For ElementFORS: ignored.
}

// ShareProof binds an ElementShare to (PartyID, SlotID, MessageDigest)
// so the combiner can reject malformed contributions.
type ShareProof struct {
	Tag [32]byte
}

// FinalSignature is the assembled threshold-HBS signature.
//
// Wire layout (v1): SlotID || ForsSig || WotsSig0 || ... || WotsSigK ||
// AuthPath. ForsSig carries the FORS leaves + per-leaf auth paths;
// WotsSig is the WOTS+ chain values for this slot; AuthPath is the
// top-tree Merkle path from leaf SlotID to Root.
//
// V1 verifier (Verify in sign.go) recomputes Root from this signature
// and rejects if it does not match PublicKey.Root.
type FinalSignature struct {
	Params    HBSParams
	SlotID    [32]byte
	ForsSig   []byte
	WotsSigs  [][]byte // WotsSigs[j] = chain value at chain j post-Steps[j] hash steps
	AuthPaths [][]byte // Top-tree auth path (Height entries of N bytes)
}

// Errors returned by the thbs package.
var (
	ErrInvalidThreshold = errors.New("thbs: invalid threshold (n < t or t < 1)")
	ErrInvalidParams    = errors.New("thbs: invalid HBS params")
	ErrDuplicateParty   = errors.New("thbs: duplicate party in committee")
	ErrZeroEvalPoint    = errors.New("thbs: evaluation point x=0 is reserved")
	ErrTooManyParties   = errors.New("thbs: committee too large for GF(257)")
	ErrSlotOutOfRange   = errors.New("thbs: slot out of range")
	ErrUnknownParty     = errors.New("thbs: party not in committee")
	ErrInsufficient     = errors.New("thbs: insufficient partial signatures")
	ErrInconsistent     = errors.New("thbs: partial signatures disagree on slot/message")
	ErrShareCount       = errors.New("thbs: partial signature has wrong number of shares")
	ErrShareProof       = errors.New("thbs: share consistency proof failed")
	ErrShareSelection   = errors.New("thbs: partial signature includes unselected element shares")
	ErrChainEndpoint    = errors.New("thbs: reconstructed WOTS+ chain endpoint mismatch")
	ErrFORSPub          = errors.New("thbs: reconstructed FORS root mismatch")
	ErrVerifyRoot       = errors.New("thbs: signature does not chain to public-key root")
	ErrEquivocation     = errors.New("thbs: party signed two distinct messages under same slot")
	ErrEvidenceMalformed = errors.New("thbs: equivocation evidence is malformed")
)

// Evidence carries proof of identifiable double-signing. The consensus
// layer slashes the offending party using this payload.
//
// Evidence is the slashable artifact. To be third-party verifiable BOTH
// ShareA and ShareB MUST be fully-populated PartialSignatures (with
// PartyID, SlotID, MessageDigest, Shares, and Proofs). The verifier
// re-derives the share-MAC tag for each entry under (PartyID, slot,
// DigestA / DigestB) and confirms it matches the proof. A
// zero-valued PartialSignature in ShareA is NOT verifiable — the
// runtime slot guard MUST persist the full prior Partial across
// restarts to preserve this property. See VerifyEvidence for the
// canonical third-party check.
type Evidence struct {
	PartyID PartyID
	SlotID  [32]byte
	DigestA [32]byte
	ShareA  PartialSignature // the first PartialSignature emitted at SlotID
	DigestB [32]byte
	ShareB  PartialSignature // the conflicting PartialSignature
}

// EquivocationError wraps ErrEquivocation with the evidence payload so
// callers can recover it via errors.As.
type EquivocationError struct {
	Err      error
	Evidence Evidence
}

// Error returns the underlying error message.
func (e *EquivocationError) Error() string { return e.Err.Error() }

// Unwrap allows errors.Is to match ErrEquivocation.
func (e *EquivocationError) Unwrap() error { return e.Err }
