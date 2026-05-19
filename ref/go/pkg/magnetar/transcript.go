// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// transcript.go — FIPS 202 / SP 800-185 transcript primitives used
// by every Magnetar protocol round.
//
// All hashing in Magnetar routes through this file. Direct use of
// stdlib hashes anywhere else in the package is a CI failure.
//
// The two primitives we vend are:
//
//   - cSHAKE256(K, X, L, S)         — FIPS 202 §6.3 + SP 800-185 §3
//   - KMAC256  (K, X, L, S)         — SP 800-185 §4
//
// All Magnetar customisation strings live in this file as named
// constants so the audit footprint of the hash layer is one file.

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Customisation tags for cSHAKE256/KMAC256. Rotating a tag
// invalidates every test vector pinned at that tag.
const (
	tagDKGCommit     = "MAGNETAR-DKG-COMMIT-V1"
	tagDKGTranscript = "MAGNETAR-DKG-TRANSCRIPT-V1"
	tagSignR1        = "MAGNETAR-SIGN-R1-V1"
	tagSignR1MAC     = "MAGNETAR-SIGN-R1-MAC-V1"
	tagSignMask      = "MAGNETAR-SIGN-MASK-V1"
	tagSeedShare     = "MAGNETAR-SEED-SHARE-V1"
	tagDomainSep     = "lux-magnetar-v0.1"
)

// functionName is the SP 800-185 cSHAKE function-name parameter.
// All Magnetar cSHAKE calls pin N to "Magnetar" so that an
// integrator who mistakenly fed Magnetar cSHAKE bytes into a
// non-Magnetar cSHAKE engine would get a deterministic mismatch.
const functionName = "Magnetar"

// cshake256 returns the first outLen bytes of cSHAKE256(input, N,
// customisation) per SP 800-185 §3.
func cshake256(input []byte, outLen int, customisation string) []byte {
	h := sha3.NewCShake256([]byte(functionName), []byte(customisation))
	_, _ = h.Write(input)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// kmac256 returns KMAC256(key, msg, outLen, customisation) per
// SP 800-185 §4.
func kmac256(key, msg []byte, outLen int, customisation string) []byte {
	preamble := bytepad(encodeString(key), 136)
	body := append(append([]byte{}, preamble...), msg...)
	body = append(body, rightEncode(uint64(outLen)*8)...)
	h := sha3.NewCShake256([]byte("KMAC"), []byte(customisation))
	_, _ = h.Write(body)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// SP 800-185 §2.3 encoders.

// leftEncode returns left_encode(x) per SP 800-185 §2.3.1.
// Operates on the BIT length: callers pre-multiply by 8 when
// encoding a byte-length.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// rightEncode returns right_encode(x) per SP 800-185 §2.3.1.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00, 0x01}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, buf[i:]...)
	out = append(out, byte(8-i))
	return out
}

// encodeString returns encode_string(s) = left_encode(bit_len(s))
// || s per SP 800-185 §2.3.2.
func encodeString(s []byte) []byte {
	out := leftEncode(uint64(len(s)) * 8)
	out = append(out, s...)
	return out
}

// bytepad returns bytepad(x, w) = left_encode(w) || x ||
// pad-to-w-bytes per SP 800-185 §2.3.3.
func bytepad(x []byte, w int) []byte {
	prefix := leftEncode(uint64(w))
	out := make([]byte, 0, len(prefix)+len(x)+w)
	out = append(out, prefix...)
	out = append(out, x...)
	for len(out)%w != 0 {
		out = append(out, 0x00)
	}
	return out
}

// transcriptHash binds an ordered tuple of byte-strings into a
// single 48-byte digest under the named customisation tag.
//
// Encoding is SP 800-185 TupleHash256-style: for each part, prepend
// left_encode(bit_len(part)) so the boundary between parts is
// unambiguous regardless of part lengths.
func transcriptHash(customisation string, parts ...[]byte) [48]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, encodeString(p)...)
	}
	out := cshake256(buf, 48, customisation)
	var ret [48]byte
	copy(ret[:], out)
	return ret
}

// transcriptHash32 is the 32-byte counterpart used where a shorter
// digest is sufficient (commit digests, MAC tags).
func transcriptHash32(customisation string, parts ...[]byte) [32]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, encodeString(p)...)
	}
	out := cshake256(buf, 32, customisation)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

// ctEqualSlice is a constant-time byte-slice equality check.
// Returns false if lengths differ; otherwise scans every byte
// regardless of where the first mismatch occurs.
func ctEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ctEqual32 is the 32-byte fast path for ctEqualSlice.
func ctEqual32(a, b [32]byte) bool {
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// nodeIDLess returns true if a < b in canonical big-endian byte
// order. Used for sorting committee membership canonically.
func nodeIDLess(a, b NodeID) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
