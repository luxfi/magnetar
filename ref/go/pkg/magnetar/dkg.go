// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// dkg.go — Threshold DKG via byte-wise Shamir VSS over the SLH-DSA
// scheme seed.
//
// Protocol shape (v0.1 reveal-and-aggregate, Shamir+sum):
//
//   Round 1 (dealer P_i):
//     Sample a random contribution c_i ∈ {0,1}^{seed_size}.
//     Shamir-share c_i across the committee at threshold t.
//     For each recipient P_j, broadcast Envelope_{i,j} =
//       (Share_{i,j}, c_i)
//     where Share_{i,j} is P_j's per-byte Shamir share of c_i and
//     c_i is the full contribution (duplicated into every envelope
//     so each party can sum contributions at Round 2).
//
//   Round 2 (party P_i):
//     Verify all received envelopes are well-formed. Compute the
//     digest D_i = cSHAKE256(ordered envelope set || tau_dkg)
//     where tau_dkg = (mode, committee, threshold). Broadcast
//     (NodeID_i, D_i).
//
//   Round 3 (party P_i):
//     Verify all received digests match. Sum the per-byte Shamir
//     shares: my_share = Σ_j Share_{j,i} (mod 257). Sum the
//     contributions: master_byteSum = Σ_j c_j (per byte, mod 257).
//     Mix master_byteSum with the committee root via cSHAKE256 to
//     get the master seed; derive the group public key via
//     KeyFromSeed. The (NodeID, EvalPoint, my_share, GroupPubkey)
//     tuple becomes the party's KeyShare.
//
// The v0.1 trust caveat: the aggregator process at sign time
// reconstructs the master seed in memory. See SPEC.md "Trust
// model" and DEPLOYMENT-RUNBOOK.md.
//
// Round-1 envelopes are PLAINTEXT in v0.1 (committee members trust
// each other already since each will see the reconstructed seed
// at sign time). v0.2 wraps envelopes under ML-KEM-768 to close
// the network-observer channel while keeping the same trust model
// vis-a-vis committee members.

import (
	"crypto/rand"
	"errors"
	"io"
)

// Errors returned by DKG.
var (
	ErrDKGUnexpectedRound = errors.New("magnetar: DKG message from unexpected round")
	ErrDKGCommitteeMismatch = errors.New("magnetar: DKG message committee mismatch")
	ErrDKGMissingEnvelope = errors.New("magnetar: DKG missing envelope for this party")
	ErrDKGShareSize       = errors.New("magnetar: DKG envelope share has wrong size")
	ErrDKGContribSize     = errors.New("magnetar: DKG envelope contribution has wrong size")
	ErrDKGDigestMismatch  = errors.New("magnetar: DKG Round-2 digest mismatch — equivocation suspected")
	ErrDKGShareTooShort   = errors.New("magnetar: DKG share count below threshold")
)

// DKGSession holds one party's state for a Magnetar DKG ceremony.
type DKGSession struct {
	Params    *Params
	Committee []NodeID // canonical-ordered committee, indexed 1..n
	Threshold int
	MyID      NodeID

	rng io.Reader

	// myIndex is myID's position in committee (0-indexed).
	myIndex int

	// myContribution is THIS party's c_i. Held across rounds.
	myContribution []byte

	// myShares[j] is P_j's Shamir share of myContribution, for
	// j ∈ 0..n-1.
	myShares []shamirShare

	// myEvalPoint is the party's Shamir x-coordinate (1-indexed).
	myEvalPoint uint32

	// receivedR1 caches Round-1 messages by sender for use in Round 2/3.
	receivedR1 map[NodeID]*DKGRound1Msg

	// receivedR2 caches Round-2 digests by sender.
	receivedR2 map[NodeID]*DKGRound2Msg
}

// NewDKGSession constructs a fresh DKG session for committee C
// with threshold t. myID must be a member of C. rng may be nil
// (crypto/rand is used).
//
// Committee ordering: caller passes the canonical sorted committee.
// EvalPoints are derived as (committee_index + 1), matching the
// Pulsar pattern.
func NewDKGSession(params *Params, committee []NodeID, threshold int, myID NodeID, rng io.Reader) (*DKGSession, error) {
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
	myIndex := -1
	for i, id := range committee {
		if id == myID {
			myIndex = i
			break
		}
	}
	if myIndex < 0 {
		return nil, ErrNotInQuorum
	}
	if rng == nil {
		rng = rand.Reader
	}
	return &DKGSession{
		Params:      params,
		Committee:   append([]NodeID{}, committee...),
		Threshold:   threshold,
		MyID:        myID,
		rng:         rng,
		myIndex:     myIndex,
		myEvalPoint: uint32(myIndex + 1),
		receivedR1:  make(map[NodeID]*DKGRound1Msg, n),
		receivedR2:  make(map[NodeID]*DKGRound2Msg, n),
	}, nil
}

// Round1 samples this party's contribution and emits the per-
// recipient envelope broadcast.
func (s *DKGSession) Round1() (*DKGRound1Msg, error) {
	if s.myContribution != nil {
		return nil, ErrDKGUnexpectedRound
	}
	n := len(s.Committee)
	t := s.Threshold

	// Sample the contribution.
	s.myContribution = make([]byte, s.Params.SeedSize)
	if _, err := io.ReadFull(s.rng, s.myContribution); err != nil {
		return nil, ErrShortRand
	}

	// Sample the polynomial coefficient stream from rng — enough
	// bytes to feed (t-1) × seed_size × 2 bytes of coefficient
	// material. cshake256 will be used as a fallback inside shamirDealRandomGF
	// when the stream is short.
	needed := (t - 1) * s.Params.SeedSize * 2
	if needed < 2 {
		needed = 2
	}
	coeffStream := make([]byte, needed)
	if _, err := io.ReadFull(s.rng, coeffStream); err != nil {
		return nil, ErrShortRand
	}

	shares, err := shamirDealRandom(s.myContribution, n, t, coeffStream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	// Build per-recipient envelopes.
	envs := make(map[NodeID]DKGShareEnvelope, n)
	for j := 0; j < n; j++ {
		envs[s.Committee[j]] = DKGShareEnvelope{
			Share:        shareToBytes(shares[j]),
			Contribution: append([]byte{}, s.myContribution...),
		}
	}
	return &DKGRound1Msg{
		NodeID:    s.MyID,
		Envelopes: envs,
	}, nil
}

// Round2 ingests every party's Round-1 envelopes, validates them,
// and emits this party's transcript-digest broadcast.
func (s *DKGSession) Round2(round1 []*DKGRound1Msg) (*DKGRound2Msg, error) {
	if s.myContribution == nil {
		return nil, ErrDKGUnexpectedRound
	}
	n := len(s.Committee)
	expectShareLen := s.Params.SeedSize * 2
	expectContribLen := s.Params.SeedSize

	committeeSet := make(map[NodeID]struct{}, n)
	for _, id := range s.Committee {
		committeeSet[id] = struct{}{}
	}

	for _, m := range round1 {
		if _, ok := committeeSet[m.NodeID]; !ok {
			return nil, ErrDKGCommitteeMismatch
		}
		// Must contain an envelope for this party.
		env, ok := m.Envelopes[s.MyID]
		if !ok {
			return nil, ErrDKGMissingEnvelope
		}
		if len(env.Share) != expectShareLen {
			return nil, ErrDKGShareSize
		}
		if len(env.Contribution) != expectContribLen {
			return nil, ErrDKGContribSize
		}
		// Must contain an envelope for every committee member.
		for _, peer := range s.Committee {
			if _, has := m.Envelopes[peer]; !has {
				return nil, ErrDKGMissingEnvelope
			}
		}
		s.receivedR1[m.NodeID] = m
	}
	if len(s.receivedR1) != n {
		return nil, ErrDKGCommitteeMismatch
	}

	// Compute the transcript digest. The digest binds:
	//   - tau_dkg = (mode, committee, threshold, domain-sep)
	//   - the ordered envelope-set: for each dealer in committee
	//     order, for each recipient in committee order, the
	//     envelope bytes.
	//
	// Both this party and every honest peer compute the same
	// digest from the same envelope set — equivocation by a
	// dealer who broadcasts distinct envelopes to distinct
	// recipients is detected at Round 3 as a digest mismatch.
	digest := s.computeR2Digest()
	return &DKGRound2Msg{
		NodeID: s.MyID,
		Digest: digest,
	}, nil
}

// computeR2Digest computes the transcript digest used in Round 2.
// Pure function of (params, committee, threshold, receivedR1).
func (s *DKGSession) computeR2Digest() [32]byte {
	parts := [][]byte{
		[]byte(tagDomainSep),
		{byte(s.Params.Mode)},
		intLE(uint32(s.Threshold)),
		intLE(uint32(len(s.Committee))),
	}
	for _, id := range s.Committee {
		parts = append(parts, id[:])
	}
	// For each dealer (committee order), for each recipient
	// (committee order), the envelope's share+contribution.
	for _, dealerID := range s.Committee {
		m := s.receivedR1[dealerID]
		if m == nil {
			parts = append(parts, []byte("MISSING"))
			continue
		}
		for _, recipientID := range s.Committee {
			env := m.Envelopes[recipientID]
			parts = append(parts, env.Share)
			parts = append(parts, env.Contribution)
		}
	}
	return transcriptHash32(tagDKGTranscript, parts...)
}

// Round3 ingests Round-1 envelopes (cached in Round 2) and Round-2
// digests. Produces the party's KeyShare and the joint group
// public key.
//
// Returns DKGOutput with AbortEvidence != nil on detected
// misbehavior (digest mismatch). The caller is expected to
// broadcast the AbortEvidence for slashing.
func (s *DKGSession) Round3(round2 []*DKGRound2Msg) (*DKGOutput, error) {
	if len(s.receivedR1) == 0 {
		return nil, ErrDKGUnexpectedRound
	}
	n := len(s.Committee)
	if len(round2) < n {
		return nil, ErrDKGShareTooShort
	}

	// Index round2 by sender; verify all match my digest.
	myDigest := s.computeR2Digest()
	committeeSet := make(map[NodeID]struct{}, n)
	for _, id := range s.Committee {
		committeeSet[id] = struct{}{}
	}
	for _, m := range round2 {
		if _, ok := committeeSet[m.NodeID]; !ok {
			return nil, ErrDKGCommitteeMismatch
		}
		s.receivedR2[m.NodeID] = m
	}
	for _, id := range s.Committee {
		m, ok := s.receivedR2[id]
		if !ok {
			return nil, ErrDKGCommitteeMismatch
		}
		if !ctEqual32(m.Digest, myDigest) {
			// Identifiable abort: digest mismatch indicates either
			// the accused dealer equivocated or this party's view
			// of the envelope set differs. Build a complaint with
			// the conflicting digest pair as evidence.
			return &DKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintEquivocation,
					Accuser: s.MyID,
					Accused: m.NodeID,
					Evidence: append(append([]byte{}, myDigest[:]...), m.Digest[:]...),
				},
			}, nil
		}
	}

	// Sum the per-byte shares received from each dealer to get
	// THIS party's share of the joint master byte-sum.
	seedSize := s.Params.SeedSize
	mySumShare := make([]uint16, seedSize)
	for _, dealerID := range s.Committee {
		env := s.receivedR1[dealerID].Envelopes[s.MyID]
		// Deserialize the envelope's share for this party.
		share := shareFromBytes(s.myEvalPoint, env.Share)
		for b := 0; b < seedSize; b++ {
			mySumShare[b] = uint16((uint32(mySumShare[b]) + uint32(share.Y[b])) % shamirPrime)
		}
	}

	// Sum the contributions to get the master byte-sum (this is
	// the same value mySumShare would Lagrange-interpolate to at
	// x=0 when combined with a threshold of other parties).
	masterByteSum := make([]uint16, seedSize)
	for _, dealerID := range s.Committee {
		env := s.receivedR1[dealerID].Envelopes[s.MyID]
		for b := 0; b < seedSize; b++ {
			masterByteSum[b] = uint16((uint32(masterByteSum[b]) + uint32(env.Contribution[b])) % shamirPrime)
		}
	}

	// Mix the byteSum with the committee root to get the master
	// seed. This step domain-separates the seed from the raw
	// Shamir reconstruction and gives constant-length output
	// regardless of how many parties contributed.
	committeeRoot := committeeRootFromIDs(s.Committee)
	byteSumBytes := make([]byte, seedSize*2)
	for b := 0; b < seedSize; b++ {
		byteSumBytes[2*b] = byte(masterByteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(masterByteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	masterSeed := cshake256(mixInput, seedSize, tagSeedShare)

	// Derive the group key.
	sk, err := KeyFromSeed(s.Params, masterSeed)
	if err != nil {
		zeroizeBytes(masterSeed)
		zeroizeBytes(mixInput)
		zeroizeBytes(byteSumBytes)
		zeroizeU16Slice(masterByteSum)
		return nil, err
	}
	groupPub := sk.Pub
	// We DON'T retain sk — only the public part is published.
	// Wipe sk before continuing.
	zeroizePrivateKey(sk)

	// Compute the transcript hash for chain pinning. 48-byte
	// digest binding (committee_root, group_pubkey, threshold).
	transcript := transcriptHash(tagDKGTranscript,
		[]byte(tagDomainSep),
		committeeRoot[:],
		groupPub.Bytes,
		intLE(uint32(s.Threshold)),
	)

	// Construct THIS party's KeyShare. The share field carries
	// the per-byte Shamir share of the master byte-sum. The
	// aggregator at Combine reconstructs the byte-sum from t
	// such shares via Lagrange interpolation, then mixes with
	// committee_root via cSHAKE256 — bit-for-bit matching the
	// DKG mix above.
	shareBytes := make([]byte, seedSize*2)
	for b := 0; b < seedSize; b++ {
		shareBytes[2*b] = byte(mySumShare[b] >> 8)
		shareBytes[2*b+1] = byte(mySumShare[b])
	}

	out := &DKGOutput{
		GroupPubkey: groupPub,
		SecretShare: &KeyShare{
			NodeID:    s.MyID,
			EvalPoint: s.myEvalPoint,
			Share:     shareBytes,
			Pub:       groupPub,
			Mode:      s.Params.Mode,
		},
		TranscriptHash: transcript,
	}

	// Wipe intermediate buffers.
	zeroizeBytes(masterSeed)
	zeroizeBytes(mixInput)
	zeroizeBytes(byteSumBytes)
	zeroizeU16Slice(masterByteSum)
	zeroizeU16Slice(mySumShare)
	zeroizeBytes(s.myContribution)
	for _, sh := range s.myShares {
		zeroizeU16Slice(sh.Y)
	}
	s.myContribution = nil
	s.myShares = nil

	return out, nil
}

// committeeRootFromIDs computes the canonical 32-byte digest of
// the sorted committee. Used by DKG and Combine to bind the share
// reconstruction to the exact committee that the DKG installed.
func committeeRootFromIDs(ids []NodeID) [32]byte {
	sorted := append([]NodeID{}, ids...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && nodeIDLess(sorted[j], sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	parts := make([][]byte, 0, len(sorted)+1)
	parts = append(parts, []byte("MAGNETAR-COMMITTEE-V1"))
	for _, id := range sorted {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

// committeeRootFromShares is the KeyShare-keyed variant used by
// Combine when the aggregator only has the directory of shares.
func committeeRootFromShares(shares []*KeyShare) [32]byte {
	ids := make([]NodeID, 0, len(shares))
	for _, s := range shares {
		ids = append(ids, s.NodeID)
	}
	return committeeRootFromIDs(ids)
}

// intLE returns x as a 4-byte little-endian slice. Used in
// transcript binding.
func intLE(x uint32) []byte {
	return []byte{byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24)}
}

// ErrNotInQuorum is reused from the threshold layer; declared
// here to avoid forward-declaration issues at first compilation.
var ErrNotInQuorum = errors.New("magnetar: party not in committee/quorum")
