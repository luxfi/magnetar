// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// combine.go — aggregator-side reconstruction and single-party
// FIPS 205 Sign on the reconstructed master seed.
//
// This file IS the v0.1 reveal-and-aggregate trust caveat: the
// master seed lives in this process's memory for the duration of
// one Combine call. Every reconstructed-seed code path explicitly
// zeroizes the seed before return. No defer: the call-tree is
// short, and explicit zeroization at each return site keeps the
// secret lifetime locally legible.
//
// Class-N1-analog: this function produces a signature byte-
// identical to single-party FIPS 205 SignDeterministic on the
// reconstructed master seed. Any FIPS 205 verifier accepts the
// output with no code change.

import (
	"crypto/rand"
)

// Combine produces a FIPS 205 SLH-DSA signature from a quorum of
// Round-2 reveals.
//
// Parameters:
//   - params, groupPubkey, message, ctx: match what was passed to
//     NewThresholdSigner.
//   - randomized: when false, uses SLH-DSA deterministic signing
//     (Class-N1-analog reproducible output). When true, uses
//     randomized signing with the supplied rng.
//   - sessionID, attempt, quorum: match the signing session.
//   - threshold: minimum number of Round-2 reveals required.
//   - round1, round2: messages from the signing committee.
//   - allShares: directory of KeyShares (used to map NodeID →
//     EvalPoint for Lagrange interpolation).
//
// Combine is a pure function — it does not require ThresholdSigner
// state. Any honest party in the quorum (or an external
// aggregator) can call Combine after Round 2 completes.
//
// The returned Signature, when passed to Verify(params,
// groupPubkey, message, sig), returns nil (i.e. the signature is
// FIPS 205 valid).
func Combine(
	params *Params,
	groupPubkey *PublicKey,
	message []byte,
	ctx []byte,
	randomized bool,
	sessionID [16]byte,
	attempt uint32,
	quorum []NodeID,
	threshold int,
	round1 []*Round1Message,
	round2 []*Round2Message,
	allShares []*KeyShare,
) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if groupPubkey == nil {
		return nil, ErrNilPublicKey
	}
	if len(round1) < threshold || len(round2) < threshold {
		return nil, ErrInsufficientQuor
	}

	maskLen := params.SeedSize * 2

	// Index Round-1 messages by sender.
	r1ByID := make(map[NodeID]*Round1Message, len(round1))
	for _, m := range round1 {
		if m.SessionID != sessionID || m.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1ByID[m.NodeID] = m
	}

	// For each Round-2 reveal: re-derive D_i and compare against
	// the matching Round-1 commit.
	revealedShares := make(map[NodeID][]byte, threshold)
	for _, r2 := range round2 {
		r1, ok := r1ByID[r2.NodeID]
		if !ok {
			continue
		}
		if r2.SessionID != sessionID || r2.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		if len(r2.PartialSig) != 2*maskLen {
			return nil, ErrRound2CommitBad
		}
		mask := r2.PartialSig[:maskLen]
		masked := r2.PartialSig[maskLen:]

		// Re-derive D_i = cSHAKE256(mask || masked || tau_1).
		tau := transcriptTau1Bytes(sessionID, attempt, quorum, r2.NodeID, groupPubkey, message)
		commitInput := make([]byte, 0, len(mask)+len(masked)+len(tau))
		commitInput = append(commitInput, mask...)
		commitInput = append(commitInput, masked...)
		commitInput = append(commitInput, tau...)
		recomputed := transcriptHash32(tagSignR1, commitInput)
		if !ctEqual32(recomputed, r1.Commit) {
			return nil, ErrRound2CommitBad
		}

		// Recover share = masked XOR mask.
		share := make([]byte, maskLen)
		for i := 0; i < maskLen; i++ {
			share[i] = masked[i] ^ mask[i]
		}
		revealedShares[r2.NodeID] = share
	}

	if len(revealedShares) < threshold {
		return nil, ErrInsufficientQuor
	}

	// Pair each revealed share with its KeyShare entry to recover
	// the EvalPoint. The aggregator gets allShares as a directory
	// so it can map NodeID → EvalPoint.
	keyShareByID := make(map[NodeID]*KeyShare, len(allShares))
	for _, ks := range allShares {
		keyShareByID[ks.NodeID] = ks
	}

	shares := make([]shamirShare, 0, threshold)
	for id, sBytes := range revealedShares {
		ks, ok := keyShareByID[id]
		if !ok {
			return nil, ErrNotInQuorum
		}
		if len(sBytes) != params.SeedSize*2 {
			return nil, ErrShareWireSize
		}
		shares = append(shares, shareFromBytes(ks.EvalPoint, sBytes))
		if len(shares) == threshold {
			break
		}
	}

	// Lagrange-reconstruct the GF(257) byte-sum. The committee
	// root is canonical given allShares.
	byteSum, err := shamirReconstructGF(shares, params.SeedSize)
	if err != nil {
		return nil, err
	}
	committeeRoot := committeeRootFromShares(allShares)
	byteSumBytes := make([]byte, params.SeedSize*2)
	for b := 0; b < params.SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	masterSeed := cshake256(mixInput, params.SeedSize, tagSeedShare)

	// Derive the centralized FIPS 205 SK from the master seed.
	// Every error path AND the success path below MUST explicitly
	// zeroize the reconstructed secret material before return.
	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		zeroizeBytes(masterSeed)
		zeroizeBytes(mixInput)
		zeroizeBytes(byteSumBytes)
		zeroizeU16Slice(byteSum)
		return nil, err
	}

	// Sanity: the reconstructed pubkey MUST match groupPubkey,
	// else the aggregator's share set is wrong / tampered.
	if !sk.Pub.Equal(groupPubkey) {
		zeroizePrivateKey(sk)
		zeroizeBytes(masterSeed)
		zeroizeBytes(mixInput)
		zeroizeBytes(byteSumBytes)
		zeroizeU16Slice(byteSum)
		return nil, ErrPubkeyMismatch
	}

	// FIPS 205 sign with the reconstructed seed-derived key.
	// randomized=false → SignDeterministic (Class-N1-analog
	// reproducible output). randomized=true uses the caller's rng.
	signRng := rand.Reader
	sigBytes, err := slhSign(params.ID, sk.Bytes, message, ctx, randomized, signRng)
	if err != nil {
		zeroizePrivateKey(sk)
		zeroizeBytes(masterSeed)
		zeroizeBytes(mixInput)
		zeroizeBytes(byteSumBytes)
		zeroizeU16Slice(byteSum)
		return nil, err
	}

	// Success path: signature is OK; wipe every secret-bearing
	// buffer before returning.
	zeroizePrivateKey(sk)
	zeroizeBytes(masterSeed)
	zeroizeBytes(mixInput)
	zeroizeBytes(byteSumBytes)
	zeroizeU16Slice(byteSum)

	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}
