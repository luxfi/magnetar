// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sort"
)

// dealer.go — v1 dealer-backed DKG.
//
// HONEST TRUST CAVEAT: a single party (the dealer) generates a master
// seed, expands it into per-element secrets, shares each secret via
// per-byte Shamir over GF(257), and distributes shares. The dealer
// learns every secret element at setup time; the dealer MUST erase
// the seed before going live. This is the McGrew et al. v1 setup
// pattern.
//
// v2 replaces this with a public DKG (PVSS-based) so no single party
// learns the secret elements. The wire shape of PrivateShare /
// PublicKey is forward-compatible with the v2 DKG output.
//
// What the dealer DOES emit publicly:
//   - PublicKey.Root (the top-tree root)
//   - HelperData (LeafRoots, AuthPaths, ChainEndpoints, FORS roots
//     and FORS auth paths)
//   - DKGTranscript (a hash binding committee + params + epoch +
//     chainID + the helper data)
//
// What the dealer NEVER emits publicly:
//   - The dealer seed (zeroized before return)
//   - Any secret WOTS+ chain head x_{slot, j}
//   - Any secret FORS leaf sk_{slot, tree, leaf}
//
// What each party RECEIVES (their PrivateShare.ElementShares):
//   - A Shamir share at their EvalPoint of every secret element:
//       (slot, ElementWOTS, chain_idx) -> N bytes share
//       (slot, ElementFORS, tree_idx, leaf_idx) -> N bytes share
//   - NO seed, NO future-signing key derivation path.

// DKGOptions extends DKGConfig with optional plumbing.
type DKGOptions struct {
	// Rng is the randomness source used by the dealer to generate the
	// secret material. If nil, crypto/rand.Reader is used.
	Rng io.Reader

	// DealerSeed, if non-nil, replaces the random dealer seed with a
	// deterministic value. ONLY for test vectors. Production deployments
	// MUST leave this nil.
	DealerSeed []byte
}

// DKG runs the v1 dealer-backed DKG.
//
// Returns the threshold public key, the calling party's PrivateShare,
// and any error.
//
// IMPORTANT — call site responsibility: in v1 the dealer machine
// generates EVERY party's PrivateShare. The function is wired to
// produce ALL shares; in a real deployment the dealer would split
// the returned share-set across parties and zeroise the rest before
// the dealer-host shuts down. See DKGAll for that path.
//
// This helper signature returns the PrivateShare for the FIRST
// participant only, to match the user-spec signature. To obtain every
// party's share, call DKGAll.
func DKG(config DKGConfig) (PublicKey, PrivateShare, error) {
	pk, shares, err := DKGAll(config, DKGOptions{})
	if err != nil {
		return PublicKey{}, PrivateShare{}, err
	}
	if len(shares) == 0 {
		return PublicKey{}, PrivateShare{}, errors.New("thbs: empty committee")
	}
	return pk, shares[0], nil
}

// DKGAll is the same as DKG but returns one PrivateShare per
// participant (indexed by position in config.Participants). Use this in
// tests and in a real dealer host where the dealer process needs all
// shares to distribute them.
func DKGAll(config DKGConfig, opts DKGOptions) (PublicKey, []PrivateShare, error) {
	if err := validateDKGConfig(config); err != nil {
		return PublicKey{}, nil, err
	}
	rng := opts.Rng
	if rng == nil {
		rng = rand.Reader
	}

	params := config.Params
	n := params.N
	nSlots := 1 << params.Height

	// Deterministic transcript-binding tag for the dealer's per-element
	// PRF expansion. Includes everything in the DKGConfig so the
	// resulting shares are pinned to this exact ceremony.
	tagPrefix := transcriptPrefix(config)

	// Dealer seed. Either supplied (test-vector mode) or freshly
	// drawn from rng.
	dealerSeed := make([]byte, 64)
	if opts.DealerSeed != nil {
		dealerSeed = append(dealerSeed[:0], opts.DealerSeed...)
		if len(dealerSeed) < 32 {
			return PublicKey{}, nil, errors.New("thbs: DealerSeed too short (need >= 32 bytes)")
		}
	} else {
		if _, err := io.ReadFull(rng, dealerSeed); err != nil {
			return PublicKey{}, nil, err
		}
	}
	defer zeroize(dealerSeed)

	// Collect per-participant evaluation points.
	points := make([]uint16, len(config.Participants))
	for i, p := range config.Participants {
		points[i] = p.EvalPoint
	}

	// Per-party share stores.
	stores := make([]ShareStore, len(config.Participants))
	for i := range stores {
		stores[i] = make(ShareStore)
	}

	// Helper data structures we'll populate.
	helper := &HelperData{
		LeafRoots:      make([][]byte, nSlots),
		AuthPaths:      make([][][]byte, nSlots),
		ChainEndpoints: make([][][]byte, nSlots),
		FORSPubRoots:   make([][][]byte, nSlots),
		FORSAuthPaths:  make([][][][]byte, nSlots),
	}

	// For each slot we:
	//   1. derive WOTS+ secret chain heads x_{slot, j}
	//   2. share each across the committee (per-byte Shamir GF(257))
	//   3. compute the public endpoint W_{slot, j} = H^{w-1}(x_{slot, j})
	//      [for the dealer's bookkeeping; same can be done from the
	//      reconstructed value when w-1 - 0 == w-1 steps are applied
	//      at sign time, but we materialise it here for HelperData]
	//   4. derive FORS secret leaves sk_{slot, tree, leaf}
	//   5. share each
	//   6. build per-tree FORS authentication paths
	//   7. compute the WOTS+ leaf-root and stash it for the top tree.
	//
	// After every slot, the dealer zeroises the secret material.
	for slot := uint32(0); slot < uint32(nSlots); slot++ {
		// 1. WOTS+ secret heads.
		secrets := make([][]byte, params.WOTSChains)
		endpoints := make([][]byte, params.WOTSChains)
		for j := 0; j < params.WOTSChains; j++ {
			secrets[j] = dealerPRF(dealerSeed, tagPrefix,
				byte(ElementWOTS), slot, uint16(j), 0, 0, n)
			// 2. share.
			slices, err := shareElement(secrets[j], points, int(config.Threshold),
				dealerPRFRaw(dealerSeed, tagPrefix, byte(ElementWOTS), slot, uint16(j), 0, 0, (int(config.Threshold)-1)*n*2+2))
			if err != nil {
				zeroizeMatrix(secrets)
				return PublicKey{}, nil, err
			}
			for i := range stores {
				id := ElementID{Type: ElementWOTS, Slot: slot, ChainIdx: uint16(j)}
				stores[i][id] = append([]uint16{}, slices[i].Y...)
			}
			// 3. public endpoint.
			endpoints[j] = wotsChain(params, secrets[j], slot, uint16(j), 0, params.W-1)
		}
		helper.ChainEndpoints[slot] = endpoints

		// 7a. WOTS+ leaf root.
		wotsLeaf := wotsLeafFromChainEndpoints(params, slot, endpoints)

		// 4-6. FORS.
		forsRoots := make([][]byte, params.FORSK)
		nLeaves := 1 << params.FORSA
		for tree := 0; tree < params.FORSK; tree++ {
			leafImages := make([][]byte, nLeaves)
			for leaf := 0; leaf < nLeaves; leaf++ {
				sk := dealerPRF(dealerSeed, tagPrefix,
					byte(ElementFORS), slot, uint16(tree), uint32(leaf), 0, n)
				// share each leaf
				slices, err := shareElement(sk, points, int(config.Threshold),
					dealerPRFRaw(dealerSeed, tagPrefix, byte(ElementFORS), slot, uint16(tree), uint32(leaf), 0, (int(config.Threshold)-1)*n*2+2))
				if err != nil {
					zeroize(sk)
					return PublicKey{}, nil, err
				}
				for i := range stores {
					id := ElementID{Type: ElementFORS, Slot: slot,
						TreeIdx: uint16(tree), LeafIdx: uint32(leaf)}
					stores[i][id] = append([]uint16{}, slices[i].Y...)
				}
				// public image
				leafImages[leaf] = forsLeafImage(params, sk, slot, uint16(tree), uint32(leaf))
				zeroize(sk)
			}
			// Build FORS tree.
			root, levels := forsBuildTree(params, leafImages, slot, uint16(tree))
			forsRoots[tree] = root
			// Materialise EVERY leaf's auth path (combiner only uses
			// one per signature, but the helper data is public).
			// We flatten by tree: helper.FORSAuthPaths[slot] becomes
			// a list of `FORSK * 2^FORSA` paths, indexed as
			// [tree * 2^FORSA + leaf].
			for leaf := 0; leaf < nLeaves; leaf++ {
				helper.FORSAuthPaths[slot] = append(
					helper.FORSAuthPaths[slot],
					forsAuthPath(levels, uint32(leaf), params.FORSA),
				)
			}
		}
		helper.FORSPubRoots[slot] = forsRoots

		// 7b. The WOTS+ leaf root and the FORS commitment combine into
		// the top-tree leaf for this slot. We bind them together so a
		// single Merkle path covers both.
		forsRoot := forsRootOfRoots(params, forsRoots, slot)
		topLeaf := hashN(params.N, tagWotsLeaf, wotsLeaf, forsRoot,
			[]byte{byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot)})
		helper.LeafRoots[slot] = topLeaf

		zeroizeMatrix(secrets)
	}

	// Build the top tree.
	root, levels := treeBuild(params, helper.LeafRoots)
	for slot := uint32(0); slot < uint32(nSlots); slot++ {
		helper.AuthPaths[slot] = treeAuthPath(levels, slot, params.Height)
	}

	// DKG transcript binding.
	transcript := computeDKGTranscript(config, helper, root)

	// Qualified set = all parties for v1 (no complaint rounds).
	qs := NewBitmap(len(config.Participants))
	for i := range config.Participants {
		qs.Set(i)
	}

	pk := PublicKey{
		Params:        params,
		Root:          root,
		DKGTranscript: transcript,
		QualifiedSet:  qs,
		HelperData:    helper,
	}

	out := make([]PrivateShare, len(config.Participants))
	for i, p := range config.Participants {
		out[i] = PrivateShare{
			PartyID:        p.ID,
			Epoch:          config.Epoch,
			ElementShares:  stores[i],
			AntiEquivState: make(StateStore),
		}
	}

	// Defensive: zero dealerSeed (the only "global secret" alive in this
	// function). Per-element secrets were zeroised inline.
	zeroize(dealerSeed)

	return pk, out, nil
}

// validateDKGConfig sanity-checks the DKG inputs.
func validateDKGConfig(c DKGConfig) error {
	if c.Threshold < 1 || int(c.Threshold) > len(c.Participants) {
		return ErrInvalidThreshold
	}
	if len(c.Participants) > maxParties {
		return ErrTooManyParties
	}
	if c.Params.N <= 0 || c.Params.W <= 1 || c.Params.LogW < 1 ||
		c.Params.WOTSChains < 1 || c.Params.FORSK < 1 || c.Params.FORSA < 1 ||
		c.Params.Height < 1 {
		return ErrInvalidParams
	}
	// Distinct evaluation points, all non-zero.
	seen := make(map[uint16]struct{}, len(c.Participants))
	for _, p := range c.Participants {
		if p.EvalPoint == 0 {
			return ErrZeroEvalPoint
		}
		if _, ok := seen[p.EvalPoint]; ok {
			return ErrDuplicateParty
		}
		seen[p.EvalPoint] = struct{}{}
	}
	return nil
}

// dealerPRF expands the dealer seed into a per-element secret of length
// `n` bytes. The PRF input is fully bound to (elementType, slot,
// chain/tree, leaf, byteOffset) so distinct elements get independent
// outputs and shares cannot be cross-domain-confused.
func dealerPRF(seed, tagPrefix []byte, elemType byte, slot uint32, idx16 uint16, idx32 uint32, off uint8, n int) []byte {
	bind := dealerPRFBind(elemType, slot, idx16, idx32, off)
	return hashN(n, tagDealerPRF, seed, tagPrefix, bind)
}

// dealerPRFRaw is dealerPRF with a caller-chosen output length, used to
// supply the coefficient stream for Shamir splitting.
func dealerPRFRaw(seed, tagPrefix []byte, elemType byte, slot uint32, idx16 uint16, idx32 uint32, off uint8, n int) []byte {
	bind := dealerPRFBind(elemType, slot, idx16, idx32, off|0x80) // distinct off bit so secret PRF != coeff PRF
	return hashN(n, tagDealerPRF, seed, tagPrefix, bind)
}

func dealerPRFBind(elemType byte, slot uint32, idx16 uint16, idx32 uint32, off uint8) []byte {
	var buf [13]byte
	buf[0] = elemType
	binary.BigEndian.PutUint32(buf[1:5], slot)
	binary.BigEndian.PutUint16(buf[5:7], idx16)
	binary.BigEndian.PutUint32(buf[7:11], idx32)
	buf[11] = off
	buf[12] = 0xA1 // domain literal
	return buf[:]
}

// transcriptPrefix binds DKG identity to a stable byte string for use
// in the dealer PRF.
func transcriptPrefix(c DKGConfig) []byte {
	parts := make([][]byte, 0, 8+len(c.Participants))
	parts = append(parts, c.ChainID)
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], c.Epoch)
	parts = append(parts, epochBuf[:])
	var thrBuf [2]byte
	binary.BigEndian.PutUint16(thrBuf[:], c.Threshold)
	parts = append(parts, thrBuf[:])
	// Participants, sorted by EvalPoint for canonicality.
	sorted := append([]Participant{}, c.Participants...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].EvalPoint < sorted[j].EvalPoint })
	for _, p := range sorted {
		parts = append(parts, p.ID[:])
		var xb [2]byte
		binary.BigEndian.PutUint16(xb[:], p.EvalPoint)
		parts = append(parts, xb[:])
	}
	// Params.
	parts = append(parts, paramsBytes(c.Params))
	// Returns 64-byte transcript prefix.
	return hashN(64, tagTranscript, parts...)
}

// computeDKGTranscript binds the helper data into the transcript so the
// public key fully commits to everything the dealer emitted.
func computeDKGTranscript(c DKGConfig, h *HelperData, root []byte) []byte {
	prefix := transcriptPrefix(c)
	parts := make([][]byte, 0, 2+len(h.LeafRoots))
	parts = append(parts, prefix, root)
	for _, lr := range h.LeafRoots {
		parts = append(parts, lr)
	}
	return hashN(48, tagTranscript, parts...)
}

func paramsBytes(p HBSParams) []byte {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:4], uint32(p.N))
	binary.BigEndian.PutUint32(buf[4:8], uint32(p.W))
	binary.BigEndian.PutUint32(buf[8:12], uint32(p.LogW))
	binary.BigEndian.PutUint32(buf[12:16], uint32(p.WOTSChains))
	binary.BigEndian.PutUint32(buf[16:20], uint32(p.FORSK))
	binary.BigEndian.PutUint32(buf[20:24], uint32(p.FORSA))
	binary.BigEndian.PutUint32(buf[24:28], uint32(p.Height))
	return buf
}

func zeroizeMatrix(m [][]byte) {
	for i := range m {
		zeroize(m[i])
		m[i] = nil
	}
}

