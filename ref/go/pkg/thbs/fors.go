// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

// fors.go — FORS (Forest of Random Subsets) primitive used by THBS v1.
//
// FORS is the few-time signature scheme inside FIPS 205 SLH-DSA. In this
// reference impl we keep just enough FORS to demonstrate the threshold
// property: for each slot we have k FORS trees, each of height a, so
// each tree has 2^a leaves. A signature reveals one leaf per tree
// (the leaf selected by the message digest) plus its authentication
// path inside the tree.
//
// THRESHOLD GLUE: the SECRET LEAVES sk_{slot, tree, leaf} are Shamir-
// shared in dealer.go. The PUBLIC authentication paths and per-tree
// roots are emitted as HelperData. For each message, the protocol
// reveals shares for ONLY the k SELECTED leaves (one per tree) and
// NEVER for the other 2^a - 1 leaves per tree. That is the true
// threshold property.

// forsSelectLeaves extracts the per-tree leaf indices from a 32-byte
// message-derived FORS index digest. Returns k indices, each in
// [0, 2^a).
func forsSelectLeaves(params HBSParams, forsIdxDigest []byte) []uint32 {
	leaves := make([]uint32, params.FORSK)
	// Treat forsIdxDigest as a bitstream; pop a-bit chunks.
	// We need k*a bits of entropy; for k=14 a=12 that's 168 bits, which
	// fits in 21 bytes (we have 32 bytes — plenty).
	bitOff := 0
	a := params.FORSA
	for t := 0; t < params.FORSK; t++ {
		// Extract bits [bitOff, bitOff+a) from forsIdxDigest.
		var idx uint32
		for k := 0; k < a; k++ {
			bytePos := (bitOff + k) >> 3
			bitInByte := 7 - ((bitOff + k) & 7)
			bit := (forsIdxDigest[bytePos] >> uint(bitInByte)) & 1
			idx = (idx << 1) | uint32(bit)
		}
		leaves[t] = idx
		bitOff += a
	}
	return leaves
}

// forsLeafImage hashes a FORS secret leaf into its public leaf image.
// pk_{slot, tree, leaf} = H(sk_{slot, tree, leaf} || slot || tree ||
// leaf).
func forsLeafImage(params HBSParams, sk []byte, slot uint32, tree uint16, leaf uint32) []byte {
	bind := []byte{
		byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot),
		byte(tree >> 8), byte(tree),
		byte(leaf >> 24), byte(leaf >> 16), byte(leaf >> 8), byte(leaf),
	}
	return hashN(params.N, tagForsLeaf, sk, bind)
}

// forsTreeNode hashes two child nodes into a parent. Standard binary
// tree (left || right || slot || tree || level || pos).
func forsTreeNode(params HBSParams, left, right []byte, slot uint32, tree uint16, level, pos int) []byte {
	bind := []byte{
		byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot),
		byte(tree >> 8), byte(tree),
		byte(level),
		byte(pos >> 24), byte(pos >> 16), byte(pos >> 8), byte(pos),
	}
	return hashN(params.N, tagForsNode, left, right, bind)
}

// forsBuildTree computes the Merkle tree over 2^a leaf images. Returns
// (root, levels) where levels[l][i] is the node at level l index i.
// levels[0] = leaves, levels[a] = [root].
func forsBuildTree(params HBSParams, leafImages [][]byte, slot uint32, tree uint16) ([]byte, [][][]byte) {
	a := params.FORSA
	levels := make([][][]byte, a+1)
	levels[0] = leafImages
	for l := 1; l <= a; l++ {
		prev := levels[l-1]
		next := make([][]byte, len(prev)/2)
		for i := 0; i < len(next); i++ {
			next[i] = forsTreeNode(params, prev[2*i], prev[2*i+1], slot, tree, l, i)
		}
		levels[l] = next
	}
	return levels[a][0], levels
}

// forsAuthPath extracts the authentication path for leaf index `leaf`
// from a built FORS tree. Returns FORSA hashes top-down level-1 to
// level-a sibling.
func forsAuthPath(levels [][][]byte, leaf uint32, a int) [][]byte {
	path := make([][]byte, a)
	idx := leaf
	for l := 0; l < a; l++ {
		sibling := idx ^ 1 // flip last bit
		path[l] = append([]byte{}, levels[l][sibling]...)
		idx >>= 1
	}
	return path
}

// forsVerifyAuth reconstructs the FORS subtree root given a revealed
// secret leaf and the auth path. The caller compares the result to the
// HelperData FORSPubRoots[slot][tree].
func forsVerifyAuth(params HBSParams, sk []byte, slot uint32, tree uint16, leaf uint32, authPath [][]byte) []byte {
	cur := forsLeafImage(params, sk, slot, tree, leaf)
	idx := leaf
	for l := 0; l < params.FORSA; l++ {
		sibling := authPath[l]
		var left, right []byte
		if idx&1 == 0 {
			left = cur
			right = sibling
		} else {
			left = sibling
			right = cur
		}
		cur = forsTreeNode(params, left, right, slot, tree, l+1, int(idx>>1))
		idx >>= 1
	}
	return cur
}

// forsRootOfRoots binds k FORS subtree roots into a single FORS
// commitment for the slot. This is the value the WOTS+ message digest
// chains-into; in the v1 spec we treat this as part of the message
// the WOTS+ chains sign (cf. SLH-DSA where it is similar but the
// commitment is over an XMSS path).
func forsRootOfRoots(params HBSParams, roots [][]byte, slot uint32) []byte {
	parts := make([][]byte, 0, len(roots)+1)
	parts = append(parts, []byte{
		byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot),
	})
	parts = append(parts, roots...)
	return hashN(params.N, tagForsRoot, parts...)
}
