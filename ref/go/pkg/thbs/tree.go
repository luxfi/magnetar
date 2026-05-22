// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

// tree.go — top-level Merkle tree over WOTS+ leaf-roots.
//
// This is the analog of the XMSS hypertree in FIPS 205 SLH-DSA. v1
// uses a single tree of height Height (1024 leaves); v3 will stack
// trees XMSS_MT-style. There are NO secrets in this file: the tree
// is built over PUBLIC WOTS+ leaf roots (the per-slot commitments
// to the WOTSChains public chain endpoints).

// treeBuild constructs the top Merkle tree over leafRoots. Returns
// (root, levels). levels[0] = leafRoots, levels[Height] = [root].
func treeBuild(params HBSParams, leafRoots [][]byte) ([]byte, [][][]byte) {
	h := params.Height
	levels := make([][][]byte, h+1)
	levels[0] = leafRoots
	for l := 1; l <= h; l++ {
		prev := levels[l-1]
		next := make([][]byte, len(prev)/2)
		for i := 0; i < len(next); i++ {
			next[i] = treeNode(params, prev[2*i], prev[2*i+1], l, i)
		}
		levels[l] = next
	}
	return levels[h][0], levels
}

// treeNode hashes two child nodes into a parent. Level and position
// bound prevents inter-tree collisions.
func treeNode(params HBSParams, left, right []byte, level, pos int) []byte {
	bind := []byte{
		byte(level),
		byte(pos >> 24), byte(pos >> 16), byte(pos >> 8), byte(pos),
	}
	return hashN(params.N, tagTreeNode, left, right, bind)
}

// treeAuthPath extracts the authentication path for leaf `slot` from a
// built tree. Returns Height entries top-down.
func treeAuthPath(levels [][][]byte, slot uint32, height int) [][]byte {
	path := make([][]byte, height)
	idx := slot
	for l := 0; l < height; l++ {
		sibling := idx ^ 1
		path[l] = append([]byte{}, levels[l][sibling]...)
		idx >>= 1
	}
	return path
}

// treeVerifyAuth reconstructs the top-tree root given a leaf root, the
// slot index, and the authentication path.
func treeVerifyAuth(params HBSParams, leafRoot []byte, slot uint32, authPath [][]byte) []byte {
	cur := append([]byte{}, leafRoot...)
	idx := slot
	for l := 0; l < params.Height; l++ {
		sibling := authPath[l]
		var left, right []byte
		if idx&1 == 0 {
			left = cur
			right = sibling
		} else {
			left = sibling
			right = cur
		}
		cur = treeNode(params, left, right, l+1, int(idx>>1))
		idx >>= 1
	}
	return cur
}
