// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// thbsse.go — THBS-SE (Threshold Hash-Based Signatures with
// Selected-Element Reconstruction).
//
// THBS-SE is the ONE permissionless threshold construction
// shipped by Magnetar v1.0. It is the architectural counterpart of
// the per-validator standalone primitive (standalone.go): both produce
// FIPS 205 wire bytes that any unmodified verifier accepts, but
// THBS-SE produces a SINGLE signature from a t-of-n committee and
// has NO privileged aggregator role.
//
// =====================================================================
//  CONSTRUCTION SHAPE
// =====================================================================
//
//   1. PUBLIC COMBINER. Combine is a pure function of its inputs.
//      Anyone — a validator, a block proposer, an RPC node, a
//      passive watcher — can run it. There is no "designated
//      aggregator" role. The output is the FIPS 205 wire-format
//      signature bytes.
//
//   2. SLOT BINDING. Every signature is bound to a slot tuple
//      (chain_id, epoch, slot, height, committee_id, message_domain).
//      The binding flows into the cSHAKE256 commit transcript AND
//      into the FIPS 205 context string at sign time, so the same
//      committee cannot reuse the same share material on a different
//      slot, and any verifier holding the slot tuple can derive
//      ctx and call FIPS 205 Verify directly.
//
//   3. LOCAL ONE-TIME SLOT ENFORCEMENT. Each party tracks the set
//      of slots it has already signed at via ThbsSeSlotGuard. A
//      second signature attempt at the same slot under a different
//      message hash is REFUSED locally, and produces a slashable
//      ThbsSeEquivocationError carrying public-form
//      ThbsSeEvidence the consensus layer consumes.
//
//   4. SLASHING EVIDENCE. Malformed shares (failed share-commit
//      re-derivation, wrong wire size, slot mismatch) produce a
//      typed ThbsSeShareEvidence blob from Combine. Any third
//      party verifies the evidence against the committee's
//      published commitment material via
//      VerifyThbsSeShareEvidence / VerifyThbsSeEvidence. Both are
//      pure functions, but not self-contained: the equivocation
//      check anchors both reveals to the accused's dealt share, so
//      fabricated bytes naming a victim who never signed are refused.
//
//   5. OVER-SELECTED COMMITTEE. (n, t) with n > t tolerates up to
//      n-t silent withholders. Combine picks any t valid
//      Round-2 reveals; the Lagrange interpolation is determined
//      by any t evaluation points, so disjoint sub-quora of size
//      t produce byte-equal signatures (deterministic public
//      combiner).
//
// =====================================================================
//  HARD INVARIANT (user spec, verbatim)
// =====================================================================
//
//   "A revealed value is allowed only if it is also present in the
//    final SLH-DSA signature."
//
// Allowed reveals (in the canonical wire shape Magnetar v1.0
// emits):
//   - The per-round mask r_i and masked share s'_i. Both flow into
//     the Round-2 PartialSig payload. Mask + masked_share are the
//     party's per-slot one-time reveal — they let any combiner
//     recover share_i = mask XOR masked_share via byte-wise XOR,
//     and the share itself is one party's Shamir leaf at evaluation
//     point x_i. The leaf alone is uniform-random to anyone
//     holding fewer than t leaves (Shamir information-theoretic
//     property over GF(257)).
//   - The reconstructed FIPS 205 signature randomizer R and the
//     FIPS 205 signature payload bytes themselves. These are the
//     PUBLIC output of Combine and are byte-identical to what a
//     centralised FIPS 205 SignDeterministic would produce on the
//     same (seed, message, ctx) tuple — see Combine for the byte-
//     identity argument.
//
// Forbidden reveals (enforced by Combine input validation +
// slot-guard pre-check + FIPS 205 verifier semantics):
//   - SK.seed in any party-local persistent form. Each party
//     holds ONLY its Shamir leaf, never the seed.
//   - SK.prf in any form. Derived from the seed and shared the
//     same way.
//   - Future-slot share material. The slot guard refuses any
//     same-slot re-emission and the share envelope is per-slot.
//
// =====================================================================
//  v1.0 SHIP STATE — HONEST OPEN ITEM
// =====================================================================
//
// The user's strictest formulation of the invariant — "no party or
// combiner EVER reconstructs SK.seed, even transiently in memory"
// — requires assembling the FIPS 205 signature directly from
// per-atom share reconstructions of the message-selected FORS
// leaves and WOTS+ chain bases, bypassing the canonical
// slh_sign_internal procedure entirely. That requires a Magnetar-
// internal re-implementation of FIPS 205 §5 (WOTS+ chain), §6.2
// (FORS sign), §7 (XMSS), and §8 (hypertree) operations from
// per-atom share reconstructions; cloudflare/circl's
// implementation does not expose these as public APIs.
//
// Magnetar v1.0 routes the final FIPS 205 byte production via
// circl/slhdsa.SignDeterministic on a seed reconstructed by the
// PUBLIC COMBINER (not a privileged aggregator). The seed is
// briefly present in the public combiner's memory for one Sign
// call and is zeroized before return. The combiner role is
// PUBLIC — anyone can be the combiner — and there is no long-lived
// secret material outside party-local Shamir leaves.
//
// This is materially stronger than a TEE-attested
// privileged-aggregator model (no host is in the TCB; the combiner
// is a pure function any peer can run on its own substrate) and
// is materially weaker than the strict invariant (a peer-local
// memory-disclosure adversary at exactly the combine moment could
// observe the seed). The strict-atom-assembly path is the
// Magnetar v1.1 work item tracked at
// BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11 and the open item flagged
// in the v1.0 sign-off; the wire format, share format, slot-guard
// state, and protocol round structure are all forward-compatible
// with that lift — only the Combine internals change.
//
// =====================================================================
//  PROTOCOL SHAPE (v1.0 wire)
// =====================================================================
//
// Setup (one ceremony, off-chain; v1.0 reference uses a
// deterministic dealer pattern; production deployments run the
// leaderless PVSS path):
//
//   - Sample SLH-DSA seed S.
//   - Derive (PK, SK) = slhdsa.Scheme().DeriveKey(S).
//   - Byte-wise Shamir-share S across (n, t) committee via
//     GF(257) (shamir.go).
//   - Publish PK + committee + (n, t).
//   - Erase S (the dealer is in the TCB FOR SETUP ONLY; once
//     NewThbsSeKey returns, no party including the dealer holds S).
//
// Sign Round 1 (party p_i, in parallel):
//   - Sample per-round mask r_i.
//   - Compute D_i = cSHAKE256(r_i || s'_i || tau) where
//     s'_i = share_i XOR r_i and
//     tau = SlotBinding.Encode() || msg || party_id.
//   - Broadcast (party_id, slot_id, D_i, availability_bit).
//   - Persist (slot_id, H(slot_id || msg)) in local SlotGuard.
//     Refuse if the same slot_id is already used for a different
//     digest.
//
// Sign Round 2 (party p_i, after Round-1 quorum is observable):
//   - Reveal PartialSig = r_i || s'_i.
//   - Idempotent replay: re-issuing Round 1+2 for the same
//     (slot_id, msg) returns the persisted (R1, R2). A genuine
//     equivocation attempt (same slot_id, different msg) raises
//     *ThbsSeEquivocationError without emitting the second R1.
//
// Combine (anyone, public):
//   - Collect >= t Round-2 reveals.
//   - For each, re-derive D_i from PartialSig + slot_binding +
//     msg + party_id. Mismatch produces ThbsSeShareEvidence with
//     reason=ThbsSeShareCommitMismatch.
//   - Recover share_i = mask XOR masked_share via byte-wise XOR.
//   - Lagrange-interpolate the seed via shamirReconstructGF over
//     GF(257) — v1.0 transient reveal.
//   - Bind to slot via FIPS 205 ctx =
//     tagThbsSeCtxPrefix || slot_id (32 bytes); total <= 255B per
//     FIPS 205 §10.2.
//   - Call slhdsa.SignDeterministic(seed, msg, ctx).
//   - Zeroize seed + intermediate buffers.
//   - Return Signature{Mode, FIPS 205 wire bytes}.
//
// Verify (anyone, public): standard FIPS 205
// slhdsa.Verify(pk, msg, sig, ctx). The v1.0 reference exposes
// this as VerifyBytesCtx (wire.go) for stateless dispatch — no
// Magnetar code path on the verifier side.
//
// =====================================================================
//  DECOMPLECTING DISCIPLINE
// =====================================================================
//
//   - The setup primitive (NewThbsSeKey) takes ONE slot-local seed
//     and produces ONE share set plus ONE public key. It does NOT
//     touch the network, the bus, or any aggregator. The seed is
//     consumed within one function call; the function never
//     returns the seed.
//
//   - The Round-1 primitive (ThbsSeRound1) takes ONE party's
//     share + the slot binding + the message and produces ONE
//     Round-1 message and ONE Round-2 reveal. No cross-party
//     coupling.
//
//   - The Combine primitive takes >= t Round-1/Round-2 message
//     pairs and produces ONE signature. It is a PURE function —
//     no internal state, no mutation of inputs.
//
//   - The slot-guard primitive (ThbsSeSlotGuard) tracks per-party
//     used slots. It is the LOCAL state defense; the protocol-
//     layer on-chain slot binding (commit-reveal of slot-burn
//     proofs) is a separate consumer concern.
//
//   - Slashing evidence is emitted by Combine when it detects
//     malformed shares or equivocation; the consensus layer
//     consumes the evidence via VerifyThbsSeShareEvidence /
//     VerifyThbsSeEvidence.

import (
	"crypto/subtle"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Customisation tags for THBS-SE. Distinct from every other
// Magnetar tag so a cross-protocol replay deterministically fails
// commit reconstruction at the first byte.
const (
	tagThbsSeSlot      = "MAGNETAR-THBSSE-SLOT-V1"
	tagThbsSeR1Commit  = "MAGNETAR-THBSSE-R1-COMMIT-V1"
	tagThbsSeShareMAC  = "MAGNETAR-THBSSE-SHARE-MAC-V1"
	tagThbsSeCtxPrefix = "lux-magnetar-thbsse-v1"
)

// Errors returned by the THBS-SE construction.
var (
	// ErrInsufficientQuor is returned by Combine when fewer than
	// threshold Round-2 reveals pass the commit re-derivation
	// check.
	ErrInsufficientQuor = errors.New("magnetar/thbsse: insufficient quorum after dropping invalid shares")

	// ErrPubkeyMismatch is returned by Combine when the
	// reconstructed seed derives a public key that does not match
	// the committee's published ThbsSeKey.PublicKey. Indicates a
	// tampered share set or a mismatched setup transcript.
	ErrPubkeyMismatch = errors.New("magnetar/thbsse: reconstructed seed does not derive to committee public key")
)

// ThbsSeSlotBinding is the on-chain slot-binding tuple. Every
// signature is bound to (chain_id, epoch, slot, height,
// committee_id, message_domain). The binding hashes into the
// commit transcript so the same committee cannot reuse the same
// share material on a different message, and into the FIPS 205
// ctx so any verifier that holds the binding can derive ctx
// independently.
//
// Wire layout (canonical, big-endian throughout):
//
//	chain_id_len(4) || chain_id ||
//	epoch(8) || slot(8) || height(8) ||
//	committee_id_len(4) || committee_id ||
//	message_domain_len(4) || message_domain
type ThbsSeSlotBinding struct {
	ChainID       []byte
	Epoch         uint64
	Slot          uint64
	Height        uint64
	CommitteeID   []byte
	MessageDomain []byte
}

// Encode serializes the slot binding into the canonical wire form.
// Used in transcript hashing and as the ctx prefix for FIPS 205
// SignDeterministic.
func (b *ThbsSeSlotBinding) Encode() []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, 0, 4+len(b.ChainID)+24+4+len(b.CommitteeID)+4+len(b.MessageDomain))
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.ChainID)))
	out = append(out, b.ChainID...)
	out = binary.BigEndian.AppendUint64(out, b.Epoch)
	out = binary.BigEndian.AppendUint64(out, b.Slot)
	out = binary.BigEndian.AppendUint64(out, b.Height)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.CommitteeID)))
	out = append(out, b.CommitteeID...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.MessageDomain)))
	out = append(out, b.MessageDomain...)
	return out
}

// SlotID returns the canonical 32-byte slot identifier hash of the
// binding. Used as the key in the local slot-guard and as the
// payload of the FIPS 205 ctx string.
func (b *ThbsSeSlotBinding) SlotID() [32]byte {
	digest := cshake256(b.Encode(), 32, tagThbsSeSlot)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// ctxFromSlot returns the FIPS 205 context string for this slot
// binding. The format is tagThbsSeCtxPrefix || slot_id (32 bytes),
// keeping the total length <= 255 bytes per FIPS 205 §10.2 limit.
// Any verifier holding the slot binding can derive ctx
// independently and pass it to slhdsa.Verify.
func ctxFromSlot(binding *ThbsSeSlotBinding) []byte {
	slotID := binding.SlotID()
	ctx := make([]byte, 0, len(tagThbsSeCtxPrefix)+32)
	ctx = append(ctx, []byte(tagThbsSeCtxPrefix)...)
	ctx = append(ctx, slotID[:]...)
	return ctx
}

// ThbsSeKey is the (public key, per-party share set, setup
// transcript) tuple produced by NewThbsSeKey.
//
// PublicKey is the FIPS 205 SLH-DSA public key under which the
// combined signature verifies. Shares are the per-party Shamir
// leaves; in a production deployment, ONLY the party's own share
// is distributed to the party, and the dealer erases all other
// shares + the master seed at end of setup.
//
// Once NewThbsSeKey returns, the master seed has been zeroized
// inside the function and is not recoverable from the returned
// struct.
type ThbsSeKey struct {
	Params          *Params
	PublicKey       *PublicKey
	Shares          []*KeyShare // length = n
	SetupTranscript [32]byte    // commits (PublicKey, committee, params, n, t)
	Threshold       int
	N               int
}

// KeyShare is one party's portion of a THBS-SE key. Each share is
// a (NodeID, GF(257) byte-vector) tuple where the byte-vector is
// the Shamir share of the underlying SLH-DSA seed at the party's
// Shamir evaluation point.
//
// The Share field carries seed_size × uint16 lanes (big-endian),
// giving the Shamir share value in GF(257) at every byte position
// of the underlying seed.
//
// The evaluation point must be non-zero and distinct across the
// committee. NewThbsSeKey derives it from the 1-indexed committee
// position; callers that want an ID-stable point can use
// EvalPointFromID.
type KeyShare struct {
	NodeID    NodeID
	EvalPoint uint32 // Shamir x-coordinate in [1, 257); distinct per party
	Share     []byte // seed_size × uint16 big-endian GF(257) share values
	Pub       *PublicKey
	Mode      Mode
}

// NewThbsSeKey runs the THBS-SE setup ceremony.
//
// For Magnetar v1.0 reference this is a DETERMINISTIC dealer
// pattern: a master seed is sampled, expanded into per-party
// Shamir shares over GF(257), the public key is derived, and the
// master seed is zeroized before return. The dealer machine is in
// the TCB FOR SETUP ONLY — once the function returns, no party
// (including the dealer) holds the seed.
//
// Production deployments should run the leaderless PVSS DKG; the
// wire shape of ThbsSeKey is forward-compatible (only the Shares
// assignment changes — each party computes its own share via PVSS
// instead of receiving it from a dealer).
//
// committee must be sorted ascending by NodeID and contain
// distinct non-zero NodeIDs. Each party's EvalPoint is
// (committee_index + 1) for KAT determinism; production
// deployments may prefer EvalPointFromID for ID-stable points.
//
// rng may be nil; crypto/rand.Reader is used. Pass a deterministic
// reader for KAT reproducibility.
func NewThbsSeKey(params *Params, threshold int, committee []NodeID, rng io.Reader) (*ThbsSeKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(committee[i-1][:], committee[i][:]) >= 0 {
			return nil, errors.New("magnetar/thbsse: committee not sorted ascending or contains duplicates")
		}
	}
	if rng == nil {
		rng = rand.Reader
	}

	seed := make([]byte, params.SeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, ErrShortRand
	}

	sk, err := KeyFromSeed(params, seed)
	if err != nil {
		zeroizeBytes(seed)
		return nil, err
	}

	// Coefficient stream for Shamir. Distinct tag from any other
	// share derivation so the stream cannot be cross-replayed.
	coeffBytes := make([]byte, (threshold-1)*params.SeedSize*2)
	if threshold > 1 {
		if _, err := io.ReadFull(rng, coeffBytes); err != nil {
			zeroizeBytes(seed)
			zeroizePrivateKey(sk)
			return nil, ErrShortRand
		}
	}
	shamShares, err := thbsseDealRandom(seed, n, threshold, coeffBytes)
	if err != nil {
		zeroizeBytes(seed)
		zeroizeBytes(coeffBytes)
		zeroizePrivateKey(sk)
		return nil, err
	}

	shares := make([]*KeyShare, n)
	for i := 0; i < n; i++ {
		shares[i] = &KeyShare{
			NodeID:    committee[i],
			EvalPoint: shamShares[i].X,
			Share:     thbsseShareToBytes(shamShares[i]),
			Pub:       sk.Pub,
			Mode:      params.Mode,
		}
	}

	// Setup transcript — commits everything an auditor needs to
	// bind the public key to the share set without learning any
	// secret.
	tr := make([]byte, 0, 256)
	tr = append(tr, sk.Pub.Bytes...)
	tr = binary.BigEndian.AppendUint32(tr, uint32(n))
	tr = binary.BigEndian.AppendUint32(tr, uint32(threshold))
	for _, c := range committee {
		tr = append(tr, c[:]...)
	}
	var setupTr [32]byte
	copy(setupTr[:], cshake256(tr, 32, tagThbsSeR1Commit))

	out := &ThbsSeKey{
		Params:          params,
		PublicKey:       sk.Pub,
		Shares:          shares,
		SetupTranscript: setupTr,
		Threshold:       threshold,
		N:               n,
	}

	// Erase every secret-bearing buffer before return.
	zeroizeBytes(seed)
	zeroizeBytes(coeffBytes)
	zeroizePrivateKey(sk)

	return out, nil
}

// ThbsSeRound1Msg is one party's Round-1 broadcast. It commits to
// the party's per-round mask plus its masked share; the commit is
// bound to the slot binding so the same Round-1 message cannot be
// replayed at a different slot.
type ThbsSeRound1Msg struct {
	NodeID    NodeID
	SlotID    [32]byte
	Commit    [32]byte // D_i = cSHAKE256(r_i || s'_i || tau)
	Available bool
}

// ThbsSeRound2Msg is one party's Round-2 reveal. The combiner uses
// (Round1, Round2) to re-derive the commit, check it matches, then
// recover the share via byte-wise XOR.
//
// PartialSig wire layout: mask || masked_share. Each block is
// (params.SeedSize * 2) bytes — the Shamir share wire size.
type ThbsSeRound2Msg struct {
	NodeID     NodeID
	SlotID     [32]byte
	PartialSig []byte
}

// ThbsSeSlotGuard is the per-party persistent record of used slots.
// It is the local-state defense against equivocation. The protocol-
// layer on-chain slot binding (commit-reveal of slot-burn proofs)
// is a separate consumer concern.
type ThbsSeSlotGuard struct {
	mu   sync.Mutex
	used map[[32]byte]ThbsSeSlotRecord
}

// ThbsSeSlotRecord persists the message digest the party committed
// to at a given slot, plus the Round-1 envelope it broadcast. The
// envelope is REQUIRED for evidence verification across restarts —
// digest-only persistence breaks the slashing chain.
type ThbsSeSlotRecord struct {
	MessageDigest [32]byte
	Round1        ThbsSeRound1Msg
	Round2        ThbsSeRound2Msg
}

// NewThbsSeSlotGuard returns a fresh slot guard.
func NewThbsSeSlotGuard() *ThbsSeSlotGuard {
	return &ThbsSeSlotGuard{used: make(map[[32]byte]ThbsSeSlotRecord)}
}

// Record inserts (slot, digest, r1, r2) into the guard. Returns
// *ThbsSeEquivocationError carrying slashable evidence if the slot
// is already used under a different digest.
func (g *ThbsSeSlotGuard) Record(slotID [32]byte, digest [32]byte, r1 ThbsSeRound1Msg, r2 ThbsSeRound2Msg) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if prior, ok := g.used[slotID]; ok {
		if prior.MessageDigest != digest {
			return &ThbsSeEquivocationError{
				SlotID:      slotID,
				PartyID:     r1.NodeID,
				PriorDigest: prior.MessageDigest,
				PriorR1:     prior.Round1,
				PriorR2:     prior.Round2,
				NewDigest:   digest,
				NewR1:       r1,
				NewR2:       r2,
			}
		}
		return nil
	}
	g.used[slotID] = ThbsSeSlotRecord{
		MessageDigest: digest,
		Round1:        r1,
		Round2:        r2,
	}
	return nil
}

// Has reports whether the guard has already recorded slotID.
func (g *ThbsSeSlotGuard) Has(slotID [32]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.used[slotID]
	return ok
}

// lookup is the slot-guard's read-only check.
func (g *ThbsSeSlotGuard) lookup(slotID [32]byte) (ThbsSeSlotRecord, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.used[slotID]
	return rec, ok
}

// ThbsSeEquivocationError carries identifiable double-signing
// evidence. Returned by Record and (independently) emitted by
// Combine when two distinct messages are presented under the same
// slot via the same committee.
type ThbsSeEquivocationError struct {
	SlotID      [32]byte
	PartyID     NodeID
	PriorDigest [32]byte
	PriorR1     ThbsSeRound1Msg
	PriorR2     ThbsSeRound2Msg
	NewDigest   [32]byte
	NewR1       ThbsSeRound1Msg
	NewR2       ThbsSeRound2Msg
}

// Error implements error.
func (e *ThbsSeEquivocationError) Error() string {
	return fmt.Sprintf("magnetar/thbsse: equivocation by party %x at slot %x", e.PartyID[:8], e.SlotID[:8])
}

// ThbsSeEvidence is the public-form slashing-evidence blob. It is
// the wire-shaped variant of ThbsSeEquivocationError suitable for
// on-chain transmission via the consensus layer's evidence channel.
type ThbsSeEvidence struct {
	SlotID      [32]byte
	PartyID     NodeID
	PriorDigest [32]byte
	PriorR1     ThbsSeRound1Msg
	PriorR2     ThbsSeRound2Msg
	NewDigest   [32]byte
	NewR1       ThbsSeRound1Msg
	NewR2       ThbsSeRound2Msg
}

// Evidence converts an EquivocationError into a wire-shaped
// Evidence blob.
func (e *ThbsSeEquivocationError) Evidence() ThbsSeEvidence {
	return ThbsSeEvidence{
		SlotID:      e.SlotID,
		PartyID:     e.PartyID,
		PriorDigest: e.PriorDigest,
		PriorR1:     e.PriorR1,
		PriorR2:     e.PriorR2,
		NewDigest:   e.NewDigest,
		NewR1:       e.NewR1,
		NewR2:       e.NewR2,
	}
}

// VerifyThbsSeEvidence is the third-party check that the evidence blob is a
// genuine equivocation by the accused: both Round-1 commits re-derive from the
// matching Round-2 reveals + slot binding, the two digests differ, AND both
// reveals unmask to the accused's real committee share. The caller passes that
// share (`share`) from the published committee, never from the evidence.
//
// The share anchor is what makes the check sound. Without it the commit is only
// a hash the accuser recomputes over bytes it supplies, so the structural
// checks pass for fabricated reveals naming any victim — a byte string of one's
// choosing would slash an honest validator that never signed. Requiring both
// reveals to unmask to the dealt share ties the evidence to a party that holds
// it: a forger who lacks the share cannot produce a mask/masked pair that
// unmasks to it. This surface is the research-only THBS-SE reconstruct path
// where the share is available to the combiner; production finality slashes via
// verified cert-equivocation (luxfi/consensus core/slashing), not this.
func VerifyThbsSeEvidence(params *Params, ev ThbsSeEvidence, share []byte, msgPrior, msgNew []byte, bindingPrior, bindingNew *ThbsSeSlotBinding) bool {
	if err := params.Validate(); err != nil {
		return false
	}
	if bindingPrior == nil || bindingNew == nil {
		return false
	}
	if ev.PriorR1.NodeID != ev.PartyID || ev.PriorR2.NodeID != ev.PartyID {
		return false
	}
	if ev.NewR1.NodeID != ev.PartyID || ev.NewR2.NodeID != ev.PartyID {
		return false
	}
	if ev.PriorR1.SlotID != ev.SlotID || ev.PriorR2.SlotID != ev.SlotID {
		return false
	}
	if ev.NewR1.SlotID != ev.SlotID || ev.NewR2.SlotID != ev.SlotID {
		return false
	}
	if ev.PriorDigest == ev.NewDigest {
		return false
	}
	maskLen := params.SeedSize * 2
	if len(ev.PriorR2.PartialSig) != 2*maskLen {
		return false
	}
	if len(ev.NewR2.PartialSig) != 2*maskLen {
		return false
	}
	priorCommit := deriveThbsSeCommit(params, ev.PriorR2.PartialSig, bindingPrior, msgPrior, ev.PartyID)
	if priorCommit != ev.PriorR1.Commit {
		return false
	}
	newCommit := deriveThbsSeCommit(params, ev.NewR2.PartialSig, bindingNew, msgNew, ev.PartyID)
	if newCommit != ev.NewR1.Commit {
		return false
	}
	// The authenticity gate, last: both reveals must unmask to the accused's real
	// committee share. Everything above is self-consistency the accuser can also
	// compute — fabricated bytes naming a victim satisfy it. Only this ties the
	// blob to a party that holds the share; a forger who lacks it cannot produce a
	// mask/masked pair that unmasks to it.
	if !thbsSeUnmasksToShare(ev.PriorR2.PartialSig, maskLen, share) {
		return false
	}
	return thbsSeUnmasksToShare(ev.NewR2.PartialSig, maskLen, share)
}

// thbsSeUnmasksToShare reports whether partialSig (mask || masked_share)
// unmasks to share. Constant-time in the share bytes so the verifier cannot be
// turned into an oracle that recovers the share one guess at a time.
func thbsSeUnmasksToShare(partialSig []byte, maskLen int, share []byte) bool {
	if len(partialSig) != 2*maskLen || len(share) != maskLen {
		return false
	}
	recovered := make([]byte, maskLen)
	mask := partialSig[:maskLen]
	masked := partialSig[maskLen:]
	for i := 0; i < maskLen; i++ {
		recovered[i] = mask[i] ^ masked[i]
	}
	return subtle.ConstantTimeCompare(recovered, share) == 1
}

// deriveThbsSeCommit computes the Round-1 commit
// D_i = cSHAKE256(mask || masked_share || tau)
// where tau = (slot_binding, msg, party_id). The mask and masked
// share are read from r2.PartialSig as the wire codec defines.
//
// Used by both Round1 and Combine; tests call it via the
// package's test boundary.
func deriveThbsSeCommit(params *Params, partialSig []byte, binding *ThbsSeSlotBinding, msg []byte, party NodeID) [32]byte {
	tau := make([]byte, 0, 256)
	tau = append(tau, binding.Encode()...)
	tau = append(tau, msg...)
	tau = append(tau, party[:]...)
	input := make([]byte, 0, len(partialSig)+len(tau))
	input = append(input, partialSig...)
	input = append(input, tau...)
	digest := cshake256(input, 32, tagThbsSeR1Commit)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// thbsSeMessageDigest is the canonical message digest used by the
// slot guard. Binds (slot_id, msg) so the same msg at distinct
// slots is a distinct digest.
func thbsSeMessageDigest(slotID [32]byte, msg []byte) [32]byte {
	input := make([]byte, 0, 32+len(msg))
	input = append(input, slotID[:]...)
	input = append(input, msg...)
	digest := cshake256(input, 32, tagThbsSeSlot)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// ThbsSeRound1 produces party p_i's Round-1 broadcast given its
// share and the slot binding. The Round-2 reveal state needed for
// downstream Combine is returned alongside.
//
// rng may be nil; crypto/rand.Reader is used. Pass a deterministic
// reader for KAT reproducibility.
//
// The slot guard is checked AFTER the mask is sampled but BEFORE
// the function returns: if the slot is already used under a
// different message digest, the function returns
// *ThbsSeEquivocationError and the party's Round-1 broadcast is
// NOT emitted. An idempotent replay of the same (slot_id, msg)
// returns the persisted (R1, R2).
func ThbsSeRound1(
	params *Params,
	share *KeyShare,
	binding *ThbsSeSlotBinding,
	msg []byte,
	guard *ThbsSeSlotGuard,
	rng io.Reader,
) (ThbsSeRound1Msg, ThbsSeRound2Msg, error) {
	if err := params.Validate(); err != nil {
		return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, err
	}
	if share == nil {
		return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, ErrNilKey
	}
	if binding == nil {
		return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, errors.New("magnetar/thbsse: nil slot binding")
	}
	if rng == nil {
		rng = rand.Reader
	}

	maskLen := params.SeedSize * 2

	// Pre-check slot guard for idempotent replay.
	slotID := binding.SlotID()
	digest := thbsSeMessageDigest(slotID, msg)
	if guard != nil {
		if prior, ok := guard.lookup(slotID); ok {
			if prior.MessageDigest == digest {
				// Idempotent replay of the same slot+msg returns
				// the persisted Round1 / Round2.
				return prior.Round1, prior.Round2, nil
			}
			// Equivocation detected. Fall through into the commit
			// construction so the evidence carries a cryptographically
			// valid NewR1.Commit / NewR2.PartialSig for the
			// conflicting message. The "new" emission is NEVER
			// returned to the caller — it goes into the evidence
			// only via the slot-guard Record path below.
		}
	}

	// Sample mask.
	mask := make([]byte, maskLen)
	if _, err := io.ReadFull(rng, mask); err != nil {
		zeroizeBytes(mask)
		return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, ErrShortRand
	}
	if len(share.Share) != maskLen {
		zeroizeBytes(mask)
		return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, ErrShareWireSize
	}
	masked := make([]byte, maskLen)
	for i := 0; i < maskLen; i++ {
		masked[i] = share.Share[i] ^ mask[i]
	}

	// Build the wire-shape PartialSig.
	partial := make([]byte, 0, 2*maskLen)
	partial = append(partial, mask...)
	partial = append(partial, masked...)

	r1 := ThbsSeRound1Msg{
		NodeID:    share.NodeID,
		SlotID:    slotID,
		Commit:    deriveThbsSeCommit(params, partial, binding, msg, share.NodeID),
		Available: true,
	}
	r2 := ThbsSeRound2Msg{
		NodeID:     share.NodeID,
		SlotID:     slotID,
		PartialSig: partial,
	}

	if guard != nil {
		if err := guard.Record(slotID, digest, r1, r2); err != nil {
			// Equivocation: r1.Commit and r2.PartialSig are now
			// public evidence (persisted in the EquivocationError
			// for third-party slashing verification). The `mask`
			// and `masked` local slices were copied into `partial`
			// which is the r2.PartialSig reference; we MUST NOT
			// zeroize `partial` because that would wipe the
			// evidence in-flight. The per-round mask `mask` is
			// also legitimately published as part of the Round-2
			// reveal, so it does not need wiping either. `masked`
			// aliases bytes inside `partial`.
			return ThbsSeRound1Msg{}, ThbsSeRound2Msg{}, err
		}
	}

	// Honest emission path: mask and masked are LEGITIMATELY
	// PUBLIC as the Round-2 reveal payload. They are not wiped
	// because the caller will broadcast them as part of
	// r2.PartialSig.
	return r1, r2, nil
}

// ThbsSeCombineInput bundles the inputs to the public Combine
// call. Anyone can construct this from observed Round-1 and
// Round-2 broadcasts plus the published committee's public
// ThbsSeKey.
type ThbsSeCombineInput struct {
	Key     *ThbsSeKey
	Binding *ThbsSeSlotBinding
	Message []byte
	Round1  []ThbsSeRound1Msg
	Round2  []ThbsSeRound2Msg
}

// ThbsSeReconstructAck is the explicit hazard acknowledgement required by
// Combine. The THBS-SE combine path reconstructs the FIPS 205 master seed at
// the public combiner — it is RESEARCH-ONLY; production finality uses the
// standalone per-validator leg aggregated via STARK-QC (no seed ever formed).
// This is a RUNTIME barrier (no build tags — one native binary), greppable in
// review (grep for IUnderstandThisReconstructsTheSeed).
type ThbsSeReconstructAck struct{ ack string }

// AckThbsSeReconstructsSeed is the only value Combine accepts; its single
// field documents the hazard at the call site.
var AckThbsSeReconstructsSeed = ThbsSeReconstructAck{ack: "IUnderstandThisReconstructsTheSeed"}

// ErrThbsSeResearchOnly is returned when Combine is invoked without the
// explicit AckThbsSeReconstructsSeed acknowledgement.
var ErrThbsSeResearchOnly = errors.New(
	"magnetar/thbsse: seed-reconstructing Combine is RESEARCH-ONLY (it " +
		"reconstructs the FIPS 205 master seed at the combiner); pass " +
		"AckThbsSeReconstructsSeed to confirm, or use the standalone " +
		"per-validator leg aggregated via STARK-QC for production")

// Combine is the PUBLIC combiner. It is a pure function of its
// inputs — anyone with the public ThbsSeKey, the slot binding, the
// message, and >= t valid Round-1/Round-2 pairs can produce the
// FIPS 205 signature.
//
// Validation order:
//
//  1. Every Round-2 reveal must have a matching Round-1 commit
//     under the SAME (party, slot). Non-matching reveals are
//     silently dropped — the protocol-layer transcript records
//     them, the combiner returns the signature for the largest
//     consistent set.
//
//  2. The Round-1 commit must re-derive correctly from
//     (Round-2 reveal, slot binding, message, party). A failed
//     re-derivation drops the reveal and emits a ThbsSeShareEvidence
//     blob in the output.
//
//  3. The party's NodeID must appear in the committee. Unknown
//     parties' reveals are dropped silently — the protocol-layer
//     registry binding lives at the consumer.
//
//  4. The party's share-wire-size must match params.SeedSize * 2.
//     Wrong-size reveals emit ThbsSeShareWireSize evidence.
//
//  5. After dropping the above, the set of validated shares must
//     have size >= threshold. If not, returns ErrInsufficientQuor
//     plus the collected evidence so the consensus layer can
//     slash the malformed shares before retrying.
//
//  6. The first `threshold` validated shares (ordered by ascending
//     EvalPoint for canonical Lagrange basis) are used for
//     interpolation. Any t shares produce the same signature
//     (deterministic public combiner).
//
// The Combine function ZEROIZES the reconstructed seed before
// return. The returned Signature is the FIPS 205 wire-format
// bytes; it verifies under unmodified slhdsa.Verify against
// (key.PublicKey, msg, ctx=ctxFromSlot(binding)).
func Combine(ack ThbsSeReconstructAck, input ThbsSeCombineInput) (*Signature, []ThbsSeShareEvidence, error) {
	// Runtime research-only barrier (mirrors OpenRevealAck; NO build tags —
	// one native binary). The THBS-SE combiner reconstructs the FIPS 205
	// master seed; refuse unless the caller explicitly acknowledges it.
	if ack != AckThbsSeReconstructsSeed {
		return nil, nil, ErrThbsSeResearchOnly
	}
	if input.Key == nil {
		return nil, nil, errors.New("magnetar/thbsse: nil key")
	}
	if input.Binding == nil {
		return nil, nil, errors.New("magnetar/thbsse: nil slot binding")
	}
	params := input.Key.Params
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	threshold := input.Key.Threshold

	// Index Round-1 by (PartyID, SlotID).
	type r1key struct {
		party  NodeID
		slotID [32]byte
	}
	r1ByKey := make(map[r1key]ThbsSeRound1Msg, len(input.Round1))
	for _, r1 := range input.Round1 {
		k := r1key{party: r1.NodeID, slotID: r1.SlotID}
		r1ByKey[k] = r1
	}

	// Index committee shares by NodeID.
	shareByID := make(map[NodeID]*KeyShare, input.Key.N)
	for _, ks := range input.Key.Shares {
		shareByID[ks.NodeID] = ks
	}

	bindingSlotID := input.Binding.SlotID()

	maskLen := params.SeedSize * 2
	var evidences []ThbsSeShareEvidence
	// Validated shares --- keyed by NodeID to preserve dedupe.
	validated := make(map[NodeID]thbsseShare, threshold)
	for _, r2 := range input.Round2 {
		if r2.SlotID != bindingSlotID {
			evidences = append(evidences, ThbsSeShareEvidence{
				PartyID: r2.NodeID,
				Reason:  ThbsSeShareSlotMismatch,
			})
			continue
		}
		if len(r2.PartialSig) != 2*maskLen {
			evidences = append(evidences, ThbsSeShareEvidence{
				PartyID: r2.NodeID,
				Reason:  ThbsSeShareWireSize,
			})
			continue
		}
		k := r1key{party: r2.NodeID, slotID: r2.SlotID}
		r1, ok := r1ByKey[k]
		if !ok {
			// No Round1 — drop silently; the protocol-layer
			// reliability trail records this.
			continue
		}
		ks, ok := shareByID[r2.NodeID]
		if !ok {
			// Unknown party — drop silently; the registry binding
			// is the consumer's responsibility.
			continue
		}
		expected := deriveThbsSeCommit(params, r2.PartialSig, input.Binding, input.Message, r2.NodeID)
		if expected != r1.Commit {
			evidences = append(evidences, ThbsSeShareEvidence{
				PartyID:    r2.NodeID,
				Reason:     ThbsSeShareCommitMismatch,
				ExpectedD:  expected,
				ObservedD:  r1.Commit,
				PartialSig: append([]byte(nil), r2.PartialSig...),
			})
			continue
		}
		mask := r2.PartialSig[:maskLen]
		masked := r2.PartialSig[maskLen:]
		shareWire := make([]byte, maskLen)
		for i := 0; i < maskLen; i++ {
			shareWire[i] = mask[i] ^ masked[i]
		}
		if _, dup := validated[r2.NodeID]; !dup {
			validated[r2.NodeID] = thbsseShareFromBytes(ks.EvalPoint, shareWire)
		}
	}

	if len(validated) < threshold {
		return nil, evidences, ErrInsufficientQuor
	}

	// Stable order: select the first `threshold` shares by
	// ascending EvalPoint so the Lagrange basis is canonical.
	ordered := make([]thbsseShare, 0, len(validated))
	for _, s := range validated {
		ordered = append(ordered, s)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].X < ordered[j].X })
	pick := ordered[:threshold]

	// Emit FIPS 205 wire bytes from the validated quorum shares via
	// the Magnetar-internal sec 5-8 path (slhdsa_internal.go +
	// thbsse_assemble.go). NOTE: assembleSignatureBytes RECONSTRUCTS
	// THE FIPS 205 MASTER at this public combiner (into
	// `derivedMaterial`). The permissionless THBS-SE path is
	// research-grade, not no-leak -- the master is resident in this
	// process for one Sign call. See ASSEMBLE-INVARIANT.md and
	// BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11 (OPEN).
	ctx := ctxFromSlot(input.Binding)
	if len(ctx) > 255 {
		return nil, evidences, ErrCtxTooLong
	}
	sigBytes, err := assembleSignatureBytes(params, pick, input.Key.PublicKey.Bytes, input.Message, ctx)
	if err != nil {
		return nil, evidences, err
	}

	return &Signature{Mode: params.Mode, Bytes: sigBytes}, evidences, nil
}

// ThbsSeShareEvidence enumerates the malformed-share cases the
// public combiner emits. The consensus layer slashes parties
// named in these payloads.
type ThbsSeShareEvidence struct {
	PartyID    NodeID
	Reason     ThbsSeShareEvidenceReason
	ExpectedD  [32]byte // for commit-mismatch
	ObservedD  [32]byte // for commit-mismatch
	PartialSig []byte   // for commit-mismatch / wire-size
}

// ThbsSeShareEvidenceReason classifies the kind of malformation.
type ThbsSeShareEvidenceReason uint8

const (
	ThbsSeShareSlotMismatch   ThbsSeShareEvidenceReason = 1
	ThbsSeShareWireSize       ThbsSeShareEvidenceReason = 2
	ThbsSeShareCommitMismatch ThbsSeShareEvidenceReason = 3
)

// String returns the canonical name of the reason.
func (r ThbsSeShareEvidenceReason) String() string {
	switch r {
	case ThbsSeShareSlotMismatch:
		return "slot-mismatch"
	case ThbsSeShareWireSize:
		return "wire-size"
	case ThbsSeShareCommitMismatch:
		return "commit-mismatch"
	default:
		return "unknown"
	}
}

// VerifyThbsSeShareEvidence is the third-party verifier of a
// ShareEvidence blob. For ThbsSeShareCommitMismatch the verifier
// recomputes the expected commit from (party, slot, partial_sig,
// message) and checks it matches ExpectedD. ObservedD is
// informational (it's what the party broadcast).
func VerifyThbsSeShareEvidence(params *Params, ev ThbsSeShareEvidence, binding *ThbsSeSlotBinding, msg []byte) bool {
	if err := params.Validate(); err != nil {
		return false
	}
	if binding == nil {
		return false
	}
	switch ev.Reason {
	case ThbsSeShareCommitMismatch:
		expected := deriveThbsSeCommit(params, ev.PartialSig, binding, msg, ev.PartyID)
		return expected == ev.ExpectedD && ev.ExpectedD != ev.ObservedD
	case ThbsSeShareWireSize:
		return len(ev.PartialSig) != 2*params.SeedSize*2 || len(ev.PartialSig) == 0
	case ThbsSeShareSlotMismatch:
		// The blob carries only (PartyID, Reason): no reveal, no
		// offending slot, no broadcast from the accused. There is
		// nothing to recompute and nothing that ties the named party
		// to a fault, so it is not proof — refuse it. A slot-mismatch
		// a third party can slash on requires the accused's own signed
		// Round-2 reveal carrying the foreign slot; verifying that is
		// the identity-key evidence-signing lift (AXIOM-INVENTORY.md),
		// not a recomputation any observer can run against a name.
		return false
	default:
		return false
	}
}
