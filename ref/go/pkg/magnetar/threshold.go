// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// threshold.go — two-round threshold signing (reveal-and-aggregate).
//
// Protocol shape (v0.1):
//
//   Round 1 (party i): sample per-round mask r_i (seed_size×2
//     bytes). Compute the masked share s'_i = share_i XOR r_i.
//     Compute the commit
//       D_i = cSHAKE256(r_i || s'_i || tau_1)
//     where tau_1 = (sid, kappa, T, i, pk, msg). Broadcast (D_i).
//
//   Round 2 (party i): reveal (r_i, masked_share_i) so peers can
//     re-derive D_i and the aggregator can XOR them to recover
//     share_i.
//
//   Combine: aggregator gathers t Round-2 reveals, re-derives
//     each party's D_i and checks it equals the Round-1 commit,
//     then Lagrange-interpolates the byte-sum at x=0, applies
//     the same cSHAKE256 mix as DKG to recover the master seed,
//     calls FIPS 205 SignDeterministic. Returns the resulting
//     signature.
//
// The byte-equality theorem (Magnetar analog of Pulsar Class N1):
// the returned signature is byte-identical to what
//   slhdsa.SignDeterministic(KeyFromSeed(master_seed), msg, ctx)
// would produce, because Combine literally calls that path on
// the same reconstructed master seed.
//
// The honest v0.1 trust caveat: the aggregator process holds the
// reconstructed master seed for the duration of one Sign call,
// then zeroizes it. See SPEC.md "Trust model" and
// DEPLOYMENT-RUNBOOK.md for the operator-facing disclosure.

import (
	"crypto/rand"
	"errors"
	"io"
)

// Errors returned by threshold signing.
var (
	ErrNilSession       = errors.New("magnetar: nil ThresholdSigner")
	ErrEmptyQuorum      = errors.New("magnetar: empty signing quorum")
	ErrInsufficientQuor = errors.New("magnetar: quorum smaller than threshold")
	ErrRound2CommitBad  = errors.New("magnetar: Round-2 reveal does not match Round-1 commit")
	ErrSessionMismatch  = errors.New("magnetar: round messages from different sessions")
	ErrAttemptMismatch  = errors.New("magnetar: round messages from different rejection-restart attempts")
	ErrPubkeyMismatch   = errors.New("magnetar: KeyShare public-key does not match")
)

// ThresholdSigner holds one party's state for a 2-round threshold
// sign ceremony.
//
// A ThresholdSigner is single-use: one (sid, attempt) pair per
// instance. The protocol-layer driver allocates a fresh signer
// for each attempt.
type ThresholdSigner struct {
	Params      *Params
	NodeID      NodeID
	SecretShare *KeyShare

	// SessionID uniquely identifies this signature attempt across
	// the network.
	SessionID [16]byte

	// Attempt is a counter that distinguishes retries; for v0.1
	// reveal-and-aggregate it's a transcript-bind only (FIPS 205
	// SLH-DSA has no rejection-restart, so Attempt is documentary
	// in v0.1; it's wired through for parity with Pulsar and to
	// support future MPC-style restarts).
	Attempt uint32

	// Quorum is the t-element signing committee, sorted ascending
	// by NodeID.
	Quorum []NodeID

	// Message is the FIPS 205 message being signed.
	Message []byte

	// rng is the entropy source for per-round mask r_i.
	rng io.Reader

	// Internal Round-1 state.
	myMask        []byte // r_i — 2 × seed_size bytes
	myMaskedShare []byte // s'_i = share_i XOR r_i (per byte)
	myCommit      [32]byte
}

// NewThresholdSigner constructs a new ThresholdSigner for a
// (sessionID, attempt, quorum, message) tuple.
//
// quorum must contain myShare.NodeID. All parties in the quorum
// must share the same group public key (i.e. they completed the
// same DKG).
//
// rng may be nil — crypto/rand is used. Pass a deterministic
// reader for KAT runs.
func NewThresholdSigner(
	params *Params,
	sessionID [16]byte,
	attempt uint32,
	quorum []NodeID,
	myShare *KeyShare,
	message []byte,
	rng io.Reader,
) (*ThresholdSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if myShare == nil {
		return nil, ErrNilKey
	}
	if myShare.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	found := false
	for _, q := range quorum {
		if q == myShare.NodeID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotInQuorum
	}
	if rng == nil {
		rng = rand.Reader
	}
	return &ThresholdSigner{
		Params:      params,
		NodeID:      myShare.NodeID,
		SecretShare: myShare,
		SessionID:   sessionID,
		Attempt:     attempt,
		Quorum:      append([]NodeID{}, quorum...),
		Message:     append([]byte{}, message...),
		rng:         rng,
	}, nil
}

// Round1 samples the per-round mask, computes the commit, and
// emits the Round-1 broadcast.
func (s *ThresholdSigner) Round1() (*Round1Message, error) {
	maskLen := s.Params.SeedSize * 2
	if len(s.SecretShare.Share) != maskLen {
		return nil, ErrShareWireSize
	}
	// Sample raw entropy and derive the per-attempt mask via
	// cSHAKE256(rngBytes || sid || attempt || NodeID, tagSignMask).
	// This way a deterministic RNG that produces the same output
	// across two attempts still yields DISTINCT masks per attempt.
	rngBytes := make([]byte, maskLen)
	if _, err := io.ReadFull(s.rng, rngBytes); err != nil {
		return nil, ErrShortRand
	}
	maskMix := make([]byte, 0, len(rngBytes)+16+4+len(s.NodeID))
	maskMix = append(maskMix, rngBytes...)
	maskMix = append(maskMix, s.SessionID[:]...)
	maskMix = append(maskMix,
		byte(s.Attempt>>24), byte(s.Attempt>>16),
		byte(s.Attempt>>8), byte(s.Attempt))
	maskMix = append(maskMix, s.NodeID[:]...)
	s.myMask = cshake256(maskMix, maskLen, tagSignMask)
	zeroizeBytes(rngBytes)
	zeroizeBytes(maskMix)

	// Mask the share byte-by-byte XOR.
	s.myMaskedShare = make([]byte, maskLen)
	for i := 0; i < maskLen; i++ {
		s.myMaskedShare[i] = s.SecretShare.Share[i] ^ s.myMask[i]
	}

	// Commit D_i = cSHAKE256(mask || masked || tau_1).
	tau := transcriptTau1Bytes(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.SecretShare.Pub, s.Message)
	commitInput := make([]byte, 0, len(s.myMask)+len(s.myMaskedShare)+len(tau))
	commitInput = append(commitInput, s.myMask...)
	commitInput = append(commitInput, s.myMaskedShare...)
	commitInput = append(commitInput, tau...)
	s.myCommit = transcriptHash32(tagSignR1, commitInput)

	return &Round1Message{
		NodeID:    s.NodeID,
		SessionID: s.SessionID,
		Attempt:   s.Attempt,
		Commit:    s.myCommit,
	}, nil
}

// Round2 ingests Round-1 messages and emits the Round-2 reveal
// carrying (r_i, masked_share_i).
func (s *ThresholdSigner) Round2(round1Msgs []*Round1Message) (*Round2Message, *AbortEvidence, error) {
	if len(round1Msgs) < 1 {
		return nil, nil, ErrEmptyQuorum
	}
	// Verify session and attempt consistency.
	for _, m := range round1Msgs {
		if m.SessionID != s.SessionID {
			return nil, nil, ErrSessionMismatch
		}
		if m.Attempt != s.Attempt {
			return nil, nil, ErrAttemptMismatch
		}
	}

	// Round-2 reveal: (r_i, masked_share_i). Pack into PartialSig.
	revealed := make([]byte, 0, len(s.myMask)+len(s.myMaskedShare))
	revealed = append(revealed, s.myMask...)
	revealed = append(revealed, s.myMaskedShare...)

	return &Round2Message{
		NodeID:     s.NodeID,
		SessionID:  s.SessionID,
		Attempt:    s.Attempt,
		PartialSig: revealed,
	}, nil, nil
}

// Combine is implemented in combine.go.

// transcriptTau1Bytes builds the Round-1 transcript tau_1 = (sid,
// kappa, T, i, pk, mu). tau_1 is bound into every commit so a
// cross-session replay becomes a transcript mismatch.
func transcriptTau1Bytes(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message []byte) []byte {
	parts := [][]byte{}
	parts = append(parts, sid[:])
	parts = append(parts, []byte{byte(attempt >> 24), byte(attempt >> 16), byte(attempt >> 8), byte(attempt)})
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}
