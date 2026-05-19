// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// types.go — public data types used across the Magnetar reference
// implementation.

// NodeID is the canonical party identifier used in all Magnetar
// protocols. The 32-byte width matches the Lux validator-ID format
// and is wide enough to host an arbitrary external identifier
// (e.g. a Hanzo IAM subject hash). Index 0 is forbidden because the
// Shamir evaluation point at x=0 holds the master secret; any party
// with nominal index 0 is rejected.
type NodeID [32]byte

// PublicKey wraps a FIPS 205 SLH-DSA public key. The byte layout is
// exactly what circl's slhdsa.PublicKey.MarshalBinary emits —
// (seed, root) concatenation per FIPS 205 §10.1 (Algorithm 21).
//
// The headline Class-N1-analog claim of Magnetar is that a Magnetar
// threshold signature against this PublicKey verifies under
// unmodified FIPS 205 slhdsa.Verify (see Verify in verify.go).
type PublicKey struct {
	Mode  Mode
	Bytes []byte
}

// PrivateKey wraps a FIPS 205 SLH-DSA private key. Only the trusted
// dealer in keygen.go holds the full PrivateKey; threshold
// deployments hold KeyShare values produced by DKG instead.
//
// PrivateKey carries the seed it was derived from so determinism
// across re-load is preserved; the seed is the Shamir-shared
// quantity in the threshold model. Seed is variable-length (4n
// bytes per FIPS 205 §10.1).
type PrivateKey struct {
	Mode  Mode
	Bytes []byte
	Seed  []byte
	Pub   *PublicKey
}

// KeyShare is one party's portion of a threshold-DKG output. Each
// share is a (NodeID, scalar-byte-vector) tuple where the scalar
// vector is the Shamir share of the underlying SLH-DSA seed at the
// party's Shamir evaluation point.
//
// The Share field carries seed_size × uint16 lanes (big-endian),
// giving the Shamir share value in GF(257) at every byte position
// of the underlying seed. Wire layout is independent of the cSHAKE
// transcript mix.
//
// The evaluation point must be non-zero and distinct across the
// committee. v0.1 derives it from the 1-indexed committee position.
type KeyShare struct {
	NodeID    NodeID
	EvalPoint uint32 // Shamir x-coordinate in [1, 257); distinct per party
	Share     []byte // seed_size × uint16 big-endian GF(257) share values
	Pub       *PublicKey
	Mode      Mode
}

// Signature is a FIPS 205 SLH-DSA signature in its standard byte
// layout per FIPS 205 §10.2 (Algorithm 22). No Magnetar envelope
// is applied. A relying party that can verify SLH-DSA can verify
// a Magnetar Signature with no code change.
type Signature struct {
	Mode  Mode
	Bytes []byte
}

// GroupKey is the joint public key produced by DKG. The
// distinction between GroupKey and PublicKey is documentary only:
// they carry the same bytes. A *GroupKey is a *PublicKey under a
// renamed alias that signals "this is a threshold-DKG output."
type GroupKey = PublicKey

// DKGRound1Msg is the broadcast emitted by DKGSession.Round1.
//
// Protocol shape (v0.1 reveal-and-aggregate):
//   The dealer broadcasts one envelope per recipient that carries
//   the recipient's Shamir share of the dealer's contribution AND
//   the full dealer-contribution-to-the-joint-seed. Combining N
//   such per-dealer contributions at Round 2 lets each party
//   compute the joint master public key locally.
//
// v0.1 ships the envelope IN PLAINTEXT for KAT determinism;
// production deployments wrap it under ML-KEM-768 per the same
// pattern Pulsar uses. The honest v0.1 trust caveat (reveal-and-
// aggregate aggregator-as-TCB) is unaffected by this choice; both
// modes equally reveal the seed at Combine time. See SPEC.md
// "Trust model" for full disclosure.
type DKGRound1Msg struct {
	NodeID    NodeID
	Envelopes map[NodeID]DKGShareEnvelope
}

// DKGShareEnvelope is the v0.1 plaintext envelope carrying one
// recipient's per-byte Shamir share of the dealer's seed
// contribution AND the full dealer contribution.
//
// Wire layout (v0.1 plaintext): Share || Contribution where
//   - Share is seed_size × uint16 big-endian (2 × seed_size bytes)
//   - Contribution is seed_size bytes (the dealer's contribution
//     to the joint seed, used at Round 2 to compute the master
//     public key).
//
// v0.2 wraps Sealed under ML-KEM-768 to the recipient's long-term
// identity public key, matching the BLOCKERS.md CR-8 pattern Pulsar
// adopted. v0.2 wire layout: KEMCiphertext || Sealed.
type DKGShareEnvelope struct {
	Share        []byte // 2 × seed_size bytes (GF(257) Shamir share, big-endian uint16 per byte position)
	Contribution []byte // seed_size bytes (dealer's contribution to the joint seed)
}

// DKGRound2Msg is the broadcast emitted by DKGSession.Round2: the
// per-party transcript-digest agreement digest. Used to bind every
// party's view of the ordered Round-1 envelope set so equivocation
// is detectable.
type DKGRound2Msg struct {
	NodeID NodeID
	Digest [32]byte
}

// DKGOutput is the result of a successful DKG.
//
// On success, GroupPubkey is the joint FIPS 205 SLH-DSA public
// key, SecretShare is the calling party's Shamir share of the
// group seed, TranscriptHash is the 48-byte transcript digest that
// the chain can pin in its validator-set commitment, and
// AbortEvidence is nil.
type DKGOutput struct {
	GroupPubkey    *PublicKey
	SecretShare    *KeyShare
	TranscriptHash [48]byte
	AbortEvidence  *AbortEvidence
}

// AbortEvidence is a signed complaint emitted by an honest party
// when it detects deviation. The protocol family commits to
// identifiable abort: every detected deviation produces verifiable
// evidence suitable for slashing.
type AbortEvidence struct {
	Kind     ComplaintKind
	Accuser  NodeID
	Accused  NodeID
	Epoch    uint64
	Evidence []byte
	Signature []byte
}

// ComplaintKind is the taxonomy of identifiable-abort complaint
// types. Values are wire-stable (do not renumber).
type ComplaintKind uint8

const (
	// ComplaintEquivocation: a dealer broadcast distinct envelopes
	// or commit vectors to distinct recipients.
	ComplaintEquivocation ComplaintKind = 1

	// ComplaintBadDelivery: the share delivered to the accuser
	// fails verification against the dealer's contribution.
	ComplaintBadDelivery ComplaintKind = 2

	// ComplaintMACFailure: a MAC from the accused failed
	// verification. Reserved for v0.2 where per-pair MACs are
	// added; v0.1 has no MAC layer.
	ComplaintMACFailure ComplaintKind = 3
)

// String returns the canonical name of the complaint kind.
func (k ComplaintKind) String() string {
	switch k {
	case ComplaintEquivocation:
		return "equivocation"
	case ComplaintBadDelivery:
		return "bad-delivery"
	case ComplaintMACFailure:
		return "mac-failure"
	default:
		return "unknown"
	}
}

// Round1Message and Round2Message in threshold signing have a
// different shape from DKG. The threshold protocol's Round-1
// emits a commit + per-peer MAC; Round-2 reveals (mask,
// masked_share). The v0.1 reveal-and-aggregate model collapses
// the per-signature ceremony into a single Sign on the
// reconstructed seed.

// Round1Message is the broadcast emitted by ThresholdSigner.Round1.
//
// v0.1 protocol shape: each signer commits to a masked version of
// their seed share via a cSHAKE256 commit digest D_i. Round-2
// reveals (mask, masked_share) so peers can re-derive D_i and the
// aggregator can recover the share via XOR.
//
// MACs are intentionally omitted from v0.1: the reveal-and-
// aggregate model already TRUSTS the aggregator (it sees the
// reconstructed seed). Adding MACs would close a session-bind
// hole that doesn't matter under the v0.1 trust caveat; v0.2
// adds them when the trust model tightens. See SPEC.md.
type Round1Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32
	Commit    [32]byte // D_i = cSHAKE256(mask || masked || tau_1)
}

// Round2Message carries the (mask, masked_share) reveal. The
// aggregator combines this with the matching Round1Message to
// recover the underlying share, then Lagrange-reconstructs the
// master seed.
//
// PartialSig wire layout: mask || masked_share (each is 2 ×
// seed_size bytes). The aggregator parses these per share.
type Round2Message struct {
	NodeID     NodeID
	SessionID  [16]byte
	Attempt    uint32
	PartialSig []byte
}

// shareWireSize returns the byte length of one Shamir share's
// wire representation for a given seed size.
func shareWireSize(seedSize int) int {
	return seedSize * 2
}
