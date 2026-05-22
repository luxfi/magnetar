// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// hash.go — cSHAKE-256 hash primitives for THBS v1.
//
// Domain-separated outputs of length N bytes. Every internal hash
// goes through `hashN` with a tag string. Direct sha3 calls outside
// this file are a CI failure.

const (
	tagWotsChain  = "MAGNETAR-THBS-WOTS-CHAIN-V1"
	tagWotsLeaf   = "MAGNETAR-THBS-WOTS-LEAF-V1"
	tagForsLeaf   = "MAGNETAR-THBS-FORS-LEAF-V1"
	tagForsNode   = "MAGNETAR-THBS-FORS-NODE-V1"
	tagForsRoot   = "MAGNETAR-THBS-FORS-ROOT-V1"
	tagTreeNode   = "MAGNETAR-THBS-TREE-NODE-V1"
	tagMsgDigest  = "MAGNETAR-THBS-MSG-DIGEST-V1"
	tagShareMAC   = "MAGNETAR-THBS-SHARE-MAC-V1"
	tagDealerPRF  = "MAGNETAR-THBS-DEALER-PRF-V1"
	tagSlotMix    = "MAGNETAR-THBS-SLOT-MIX-V1"
	tagTranscript = "MAGNETAR-THBS-TRANSCRIPT-V1"
	tagShamir     = "MAGNETAR-THBS-SHAMIR-V1"
)

// hashN returns the first n bytes of cSHAKE-256(input, "Magnetar-THBS",
// customisation).
func hashN(n int, customisation string, parts ...[]byte) []byte {
	h := sha3.NewCShake256([]byte("Magnetar-THBS"), []byte(customisation))
	for _, p := range parts {
		// Length-prefix each part so concatenation is unambiguous.
		var lp [8]byte
		binary.BigEndian.PutUint64(lp[:], uint64(len(p)))
		_, _ = h.Write(lp[:])
		_, _ = h.Write(p)
	}
	out := make([]byte, n)
	_, _ = h.Read(out)
	return out
}

// hash32 is the 32-byte fast path used for tags and digests.
func hash32(customisation string, parts ...[]byte) [32]byte {
	out := hashN(32, customisation, parts...)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

// ctEqual is a constant-time byte-slice equality check.
func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// zeroize wipes a byte slice.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeU16 wipes a uint16 slice.
func zeroizeU16(b []uint16) {
	for i := range b {
		b[i] = 0
	}
}
