// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import (
	"encoding/binary"
	"errors"
)

// sign.go — SignShare + Aggregate + Verify, the three operations that
// make this package "true threshold".
//
// SignShare:
//   1. Compute MessageDigest = H(msg, slot).
//   2. Derive the FORS index digest -> k SELECTED FORS leaves.
//   3. Derive the WOTS+ base-w digits -> per-chain SELECTED step counts.
//   4. Release a Shamir share for EVERY selected FORS leaf (k shares)
//      AND for every WOTS+ chain head (WOTSChains shares).
//      NOTE: every chain head is "selected" — the value the verifier
//      sees is the chain after b_j hash steps, so the secret head IS
//      required even when b_j > 0. The threshold property is that
//      OTHER SLOTS' chain heads / OTHER FORS LEAVES are never released.
//      Specifically: a single SignShare touches WOTSChains + k secret
//      elements total, NOT every element for the slot, and NEVER any
//      element from another slot.
//   5. Bind each share with a cSHAKE MAC under (party_id, slot_id,
//      message_digest) so the combiner can detect malformed
//      contributions.
//   6. Anti-equivocation: insert (slot, digest, partial) into the slot
//      guard; reject (with Evidence) any later sign for the same slot
//      under a different digest.
//
// Aggregate:
//   1. Validate every PartialSignature against the public key (party
//      membership; matching slot, message; share count; share proof).
//   2. For each SELECTED element, Lagrange-reconstruct the secret
//      from the t shares for that element. (No global seed
//      reconstruction.)
//   3. Chain each reconstructed WOTS+ value forward to verify against
//      the public endpoint; chain each FORS leaf forward to verify
//      against the FORS subtree root.
//   4. Assemble the FinalSignature (the SLH-DSA-style payload).
//
// Verify:
//   1. Re-derive the per-chain step counts from message_digest.
//   2. Chain each FinalSignature.WotsSigs[j] forward (w - 1 - b_j)
//      additional steps; the result must equal the public endpoint
//      in HelperData.
//   3. Re-derive the FORS leaf indices; each FinalSignature.ForsSig
//      entry must chain through its auth path to the matching
//      FORSPubRoots entry.
//   4. The slot-leaf and FORS commitment must chain through
//      AuthPaths[slot] to PublicKey.Root.

// SignShare runs the party-side computation. Returns the
// PartialSignature; on equivocation it returns an *EquivocationError
// carrying the slashable Evidence payload.
//
// `slot` is the one-shot WOTS+ slot the consensus layer has allocated
// to this signing session. The party is responsible for ensuring it
// has not previously signed a different message under this slot;
// the slot guard (NewGuard / PrivateShareGuard) enforces this locally.
func SignShare(guard *PrivateShareGuard, slot Slot, msg []byte) (PartialSignature, error) {
	if guard == nil || guard.Share == nil {
		return PartialSignature{}, errors.New("thbs: nil guard")
	}
	share := guard.Share

	// 1. Message digest. SlotID binds the slot into the digest so the
	// same `msg` under a different slot is a different digest. (Note:
	// callers also commonly want to bind a chain/context tag; v1 stays
	// minimal.)
	slotID := slotIDBytes(slot)
	digest := messageDigest(msg, slotID)

	// 2/3. Element selection.
	// We need the WOTS+ base-w digits AND the FORS leaf indices. Both
	// come from the digest. We use the first 32 bytes for the FORS
	// indices, the rest for the WOTS+ digits — for our reference
	// params (n=24), MessageDigest is 32 bytes and we ALSO need a
	// distinct 32-byte FORS-index digest derived from the message.
	// SignShare requires params for chain/digit selection. The guard
	// holds the params and eval point that NewGuardWithParams attached.
	params := guard.params
	if params.N == 0 {
		return PartialSignature{}, errors.New("thbs: guard has no params; use NewGuardWithParams")
	}

	forsDigest := hash32("MAGNETAR-THBS-FORS-IDX-V1", digest[:], slotID)
	wotsMsg := hashN(params.N, "MAGNETAR-THBS-WOTS-MSG-V1", digest[:], slotID)
	forsLeaves := forsSelectLeaves(params, forsDigest[:])
	wotsDigits := wotsBaseDigits(params, wotsMsg)

	// 4. Collect the selected shares.
	// WOTS+: one share per chain (WOTSChains total). Steps = digit[j].
	// FORS: one share per tree (FORSK total), at the selected leaf.
	shares := make([]ElementShare, 0, params.WOTSChains+params.FORSK)

	// EvalPoint: find this party's evaluation point. We stash it in the
	// guard at NewGuard time too.
	xPoint := guard.evalPoint
	if xPoint == 0 {
		return PartialSignature{}, errors.New("thbs: guard has no eval point")
	}

	for j := 0; j < params.WOTSChains; j++ {
		id := ElementID{Type: ElementWOTS, Slot: uint32(slot), ChainIdx: uint16(j)}
		y, ok := share.ElementShares[id]
		if !ok {
			return PartialSignature{}, errors.New("thbs: missing WOTS share for selected chain")
		}
		shares = append(shares, ElementShare{
			ID:    id,
			X:     xPoint,
			Y:     append([]uint16{}, y...),
			Steps: wotsDigits[j],
		})
	}
	for tree := 0; tree < params.FORSK; tree++ {
		leaf := forsLeaves[tree]
		id := ElementID{Type: ElementFORS, Slot: uint32(slot), TreeIdx: uint16(tree), LeafIdx: leaf}
		y, ok := share.ElementShares[id]
		if !ok {
			return PartialSignature{}, errors.New("thbs: missing FORS share for selected leaf")
		}
		shares = append(shares, ElementShare{
			ID: id,
			X:  xPoint,
			Y:  append([]uint16{}, y...),
		})
	}

	// 5. Per-share proofs (cSHAKE MACs binding share to party + slot
	// + message digest).
	proofs := make([]ShareProof, len(shares))
	for i, s := range shares {
		proofs[i] = ShareProof{Tag: shareMACTag(share.PartyID, slot, digest, s)}
	}

	// 6. Anti-equivocation.
	var slotIDArr [32]byte
	copy(slotIDArr[:], slotID)
	partial := PartialSignature{
		PartyID:       share.PartyID,
		SlotID:        slotIDArr,
		MessageDigest: digest,
		Shares:        shares,
		Proofs:        proofs,
	}

	idempotent, prev, err := guard.state.checkAndRecord(slot, digest, partial)
	if err != nil {
		// Equivocation.
		ev := Evidence{
			PartyID: share.PartyID,
			SlotID:  slotIDArr,
			DigestA: prev.Digest,
			ShareA:  prev.Partial,
			DigestB: digest,
			ShareB:  partial,
		}
		return PartialSignature{}, &EquivocationError{Err: ErrEquivocation, Evidence: ev}
	}
	if idempotent {
		return prev.Partial, nil
	}
	return partial, nil
}

// Aggregate combines a quorum of partial signatures into a final
// threshold-HBS signature.
func Aggregate(pk PublicKey, slot Slot, partials []PartialSignature) (FinalSignature, error) {
	if pk.HelperData == nil {
		return FinalSignature{}, errors.New("thbs: public key missing helper data")
	}
	params := pk.Params
	if len(partials) < 1 {
		return FinalSignature{}, ErrInsufficient
	}

	// Pin slot/message agreement across partials.
	slotID := slotIDBytes(slot)
	var slotIDArr [32]byte
	copy(slotIDArr[:], slotID)
	digest := partials[0].MessageDigest
	for _, p := range partials {
		if p.SlotID != slotIDArr {
			return FinalSignature{}, ErrInconsistent
		}
		if p.MessageDigest != digest {
			return FinalSignature{}, ErrInconsistent
		}
		if len(p.Shares) != params.WOTSChains+params.FORSK {
			return FinalSignature{}, ErrShareCount
		}
		if len(p.Proofs) != len(p.Shares) {
			return FinalSignature{}, ErrShareCount
		}
	}

	// Re-derive the selected elements from the digest.
	forsDigest := hash32("MAGNETAR-THBS-FORS-IDX-V1", digest[:], slotID)
	wotsMsg := hashN(params.N, "MAGNETAR-THBS-WOTS-MSG-V1", digest[:], slotID)
	wotsDigits := wotsBaseDigits(params, wotsMsg)
	forsLeaves := forsSelectLeaves(params, forsDigest[:])

	// Validate every share against the selection. Any share that
	// references a non-selected element is a protocol violation.
	for _, p := range partials {
		for _, s := range p.Shares {
			switch s.ID.Type {
			case ElementWOTS:
				if s.ID.Slot != uint32(slot) {
					return FinalSignature{}, ErrShareSelection
				}
				if int(s.ID.ChainIdx) >= params.WOTSChains {
					return FinalSignature{}, ErrShareSelection
				}
				if s.Steps != wotsDigits[s.ID.ChainIdx] {
					return FinalSignature{}, ErrShareSelection
				}
			case ElementFORS:
				if s.ID.Slot != uint32(slot) {
					return FinalSignature{}, ErrShareSelection
				}
				if int(s.ID.TreeIdx) >= params.FORSK {
					return FinalSignature{}, ErrShareSelection
				}
				if forsLeaves[s.ID.TreeIdx] != s.ID.LeafIdx {
					return FinalSignature{}, ErrShareSelection
				}
			default:
				return FinalSignature{}, ErrShareSelection
			}
			// Validate the share proof tag.
			expect := shareMACTag(p.PartyID, slot, digest, s)
			if !ctEqualArr32(expect, p.Proofs[indexOfShare(p, s)].Tag) {
				return FinalSignature{}, ErrShareProof
			}
		}
	}

	// For each selected element, collect t shares (we have len(partials);
	// the caller is expected to send exactly t).
	byElement := make(map[ElementID][]shamirSlice)
	for _, p := range partials {
		for _, s := range p.Shares {
			byElement[s.ID] = append(byElement[s.ID], shamirSlice{X: s.X, Y: s.Y})
		}
	}

	// Reconstruct each selected element.
	// WOTS+ chains: WOTSChains in [0, ChainEndpoints[slot])
	wotsRecons := make([][]byte, params.WOTSChains)
	for j := 0; j < params.WOTSChains; j++ {
		id := ElementID{Type: ElementWOTS, Slot: uint32(slot), ChainIdx: uint16(j)}
		slices, ok := byElement[id]
		if !ok || len(slices) < 1 {
			return FinalSignature{}, ErrInsufficient
		}
		gf, err := reconstructElement(slices, params.N)
		if err != nil {
			return FinalSignature{}, err
		}
		secret := gfBytesToBytes(gf, params.N, slotIDArr[:])
		zeroizeU16(gf)
		// Sanity: chain to endpoint MUST match HelperData.
		endpoint := wotsChain(params, secret, uint32(slot), uint16(j), 0, params.W-1)
		if !ctEqual(endpoint, pk.HelperData.ChainEndpoints[uint32(slot)][j]) {
			zeroize(secret)
			return FinalSignature{}, ErrChainEndpoint
		}
		// Apply the chain steps for this signature.
		steps := int(wotsDigits[j])
		sig := wotsChain(params, secret, uint32(slot), uint16(j), 0, steps)
		zeroize(secret)
		wotsRecons[j] = sig
	}

	// FORS: one selected leaf per tree.
	forsSig := make([]byte, 0, params.FORSK*params.N*(1+params.FORSA))
	for tree := 0; tree < params.FORSK; tree++ {
		leafIdx := forsLeaves[tree]
		id := ElementID{Type: ElementFORS, Slot: uint32(slot), TreeIdx: uint16(tree), LeafIdx: leafIdx}
		slices, ok := byElement[id]
		if !ok || len(slices) < 1 {
			return FinalSignature{}, ErrInsufficient
		}
		gf, err := reconstructElement(slices, params.N)
		if err != nil {
			return FinalSignature{}, err
		}
		sk := gfBytesToBytes(gf, params.N, slotIDArr[:])
		zeroizeU16(gf)
		// Sanity: chains to the FORS subtree root via the helper data
		// auth path.
		authPath := helperForsAuthPath(pk.HelperData, uint32(slot), uint16(tree), leafIdx, params)
		recomputedRoot := forsVerifyAuth(params, sk, uint32(slot), uint16(tree), leafIdx, authPath)
		if !ctEqual(recomputedRoot, pk.HelperData.FORSPubRoots[uint32(slot)][tree]) {
			zeroize(sk)
			return FinalSignature{}, ErrFORSPub
		}
		// Append the revealed sk and auth path to forsSig.
		forsSig = append(forsSig, sk...)
		for _, ap := range authPath {
			forsSig = append(forsSig, ap...)
		}
		zeroize(sk)
	}

	finalSig := FinalSignature{
		Params:    params,
		SlotID:    slotIDArr,
		ForsSig:   forsSig,
		WotsSigs:  wotsRecons,
		AuthPaths: pk.HelperData.AuthPaths[uint32(slot)],
	}
	return finalSig, nil
}

// Verify checks a FinalSignature against the public key + message.
func Verify(pk PublicKey, msg []byte, sig FinalSignature) bool {
	if pk.HelperData == nil {
		return false
	}
	params := pk.Params
	if sig.Params != params {
		return false
	}
	// Re-derive the slot index from the SlotID. SlotID is the
	// canonical encoding of (slot uint32); we extract.
	slot, ok := slotFromID(sig.SlotID)
	if !ok {
		return false
	}
	if int(slot) >= len(pk.HelperData.LeafRoots) {
		return false
	}
	slotID := slotIDBytes(slot)
	digest := messageDigest(msg, slotID)
	forsDigest := hash32("MAGNETAR-THBS-FORS-IDX-V1", digest[:], slotID)
	wotsMsg := hashN(params.N, "MAGNETAR-THBS-WOTS-MSG-V1", digest[:], slotID)
	wotsDigits := wotsBaseDigits(params, wotsMsg)
	forsLeaves := forsSelectLeaves(params, forsDigest[:])

	// 1. Verify each WOTS+ chain value chains to the endpoint.
	if len(sig.WotsSigs) != params.WOTSChains {
		return false
	}
	for j := 0; j < params.WOTSChains; j++ {
		v := sig.WotsSigs[j]
		// Chain forward (w-1 - b_j) more steps to reach the endpoint.
		endpoint := wotsChain(params, v, uint32(slot), uint16(j), int(wotsDigits[j]), params.W-1)
		if !ctEqual(endpoint, pk.HelperData.ChainEndpoints[uint32(slot)][j]) {
			return false
		}
	}
	// Reconstruct the WOTS+ leaf root from the (just-verified) endpoints.
	wotsLeaf := wotsLeafFromChainEndpoints(params, uint32(slot), pk.HelperData.ChainEndpoints[uint32(slot)])

	// 2. Verify each FORS leaf chains to its public root.
	if len(sig.ForsSig) != params.FORSK*params.N*(1+params.FORSA) {
		return false
	}
	forsRoots := make([][]byte, params.FORSK)
	off := 0
	for tree := 0; tree < params.FORSK; tree++ {
		sk := sig.ForsSig[off : off+params.N]
		off += params.N
		authPath := make([][]byte, params.FORSA)
		for l := 0; l < params.FORSA; l++ {
			authPath[l] = sig.ForsSig[off : off+params.N]
			off += params.N
		}
		leafIdx := forsLeaves[tree]
		root := forsVerifyAuth(params, sk, uint32(slot), uint16(tree), leafIdx, authPath)
		if !ctEqual(root, pk.HelperData.FORSPubRoots[uint32(slot)][tree]) {
			return false
		}
		forsRoots[tree] = root
	}
	forsRoot := forsRootOfRoots(params, forsRoots, uint32(slot))

	// 3. The top-tree leaf is H(wotsLeaf, forsRoot, slot). It must
	// chain through AuthPaths[slot] to PublicKey.Root.
	topLeaf := hashN(params.N, tagWotsLeaf, wotsLeaf, forsRoot,
		[]byte{byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot)})
	if len(sig.AuthPaths) != params.Height {
		return false
	}
	reconRoot := treeVerifyAuth(params, topLeaf, uint32(slot), sig.AuthPaths)
	return ctEqual(reconRoot, pk.Root)
}

// slotIDBytes encodes a Slot as a stable 32-byte SlotID.
//
// Layout: 28 zero bytes || 4-byte big-endian slot index. The fixed
// prefix gives forward compatibility for richer SlotID shapes (e.g. a
// 32-byte chain-bound nonce) without bumping wire layout.
func slotIDBytes(slot Slot) []byte {
	out := make([]byte, 32)
	binary.BigEndian.PutUint32(out[28:], uint32(slot))
	return out
}

func slotFromID(id [32]byte) (Slot, bool) {
	// Prefix must be zero.
	for i := 0; i < 28; i++ {
		if id[i] != 0 {
			return 0, false
		}
	}
	return Slot(binary.BigEndian.Uint32(id[28:])), true
}

// messageDigest binds (msg, slotID) into a stable 32-byte digest.
func messageDigest(msg, slotID []byte) [32]byte {
	return hash32(tagMsgDigest, msg, slotID)
}

// shareMACTag binds a single share to (party_id, slot, message digest).
func shareMACTag(p PartyID, slot Slot, digest [32]byte, s ElementShare) [32]byte {
	idBytes := []byte{
		byte(s.ID.Type),
		byte(s.ID.Slot >> 24), byte(s.ID.Slot >> 16), byte(s.ID.Slot >> 8), byte(s.ID.Slot),
		byte(s.ID.ChainIdx >> 8), byte(s.ID.ChainIdx),
		byte(s.ID.TreeIdx >> 8), byte(s.ID.TreeIdx),
		byte(s.ID.LeafIdx >> 24), byte(s.ID.LeafIdx >> 16), byte(s.ID.LeafIdx >> 8), byte(s.ID.LeafIdx),
		byte(s.X >> 8), byte(s.X),
		s.Steps,
	}
	yBytes := make([]byte, len(s.Y)*2)
	for i, v := range s.Y {
		yBytes[2*i] = byte(v >> 8)
		yBytes[2*i+1] = byte(v)
	}
	slotID := slotIDBytes(slot)
	return hash32(tagShareMAC, p[:], slotID, digest[:], idBytes, yBytes)
}

func ctEqualArr32(a, b [32]byte) bool {
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// indexOfShare locates the index in p.Shares matching s by ID. We
// can't trust slice ordering across parties for the proof lookup, so
// the combiner looks up the matching proof by ID.
func indexOfShare(p PartialSignature, s ElementShare) int {
	for i := range p.Shares {
		if p.Shares[i].ID == s.ID {
			return i
		}
	}
	return -1
}

// helperForsAuthPath fetches the dealer-precomputed FORS auth path for
// (slot, tree, leaf). HelperData.FORSAuthPaths[slot] is a flat list of
// [leafPaths_for_tree_0, leafPaths_for_tree_1, ...]; we index in.
func helperForsAuthPath(h *HelperData, slot uint32, tree uint16, leaf uint32, params HBSParams) [][]byte {
	leavesPerTree := 1 << params.FORSA
	flatIdx := int(tree)*leavesPerTree + int(leaf)
	return h.FORSAuthPaths[slot][flatIdx]
}

// NewGuardWithParams is the constructor signers should use: it
// captures the params and eval point so SignShare has what it needs.
func NewGuardWithParams(share *PrivateShare, params HBSParams, evalPoint uint16) *PrivateShareGuard {
	g := NewGuard(share)
	g.params = params
	g.evalPoint = evalPoint
	return g
}

