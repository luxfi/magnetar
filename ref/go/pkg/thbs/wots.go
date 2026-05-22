// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thbs

// wots.go — Winternitz one-time signatures (WOTS+) primitive used by
// THBS v1. This is a teaching-grade reference impl that captures the
// only WOTS+ behaviours we threshold:
//
//   1. Each chain x_j has w-1 = 15 hash steps from secret head to
//      public endpoint. The signature reveals x_j after b_j hash
//      steps, where b_j is the j-th base-w digit of the message digest
//      (with the standard FIPS 205 checksum appended).
//   2. The combiner verifies a signature by chaining each revealed
//      value (w-1 - b_j) more steps and comparing to the public
//      endpoint.
//
// THRESHOLD GLUE: the SECRET CHAIN HEADS x_{slot, j} are Shamir-shared
// in dealer.go; the public endpoints W_{slot, j} = H^{w-1}(x_{slot, j})
// are emitted as helper data (HelperData.ChainEndpoints[slot]).
//
// The selected-elements property (the user's hard invariant) is exactly:
// for each chain j the threshold protocol reveals shares ONLY for the
// chain head x_{slot, j}, AND only when b_j > 0 (when b_j == 0 the
// signature is the chain head itself, which still needs reconstruction).
// All OTHER chain values x_{slot, *} for unrelated chains are NEVER
// reconstructed. That is what makes this true threshold.

// wotsBaseDigits decomposes msg into WOTSChains base-w digits with
// the standard FIPS 205 / RFC 8391 checksum appended. Returns a
// slice of length params.WOTSChains.
func wotsBaseDigits(params HBSParams, msg []byte) []uint8 {
	// FIPS 205 / RFC 8391 algorithm 1: base_w decomposition.
	// Each LogW bits of msg becomes one digit in [0, w).
	logW := params.LogW
	w := uint32(params.W)
	wMask := uint8(w - 1)

	// Number of message digits.
	totalMsgBits := 8 * params.N
	numMsgDigits := totalMsgBits / logW
	// (totalMsgBits is a multiple of logW for w in {4, 16, 256}.)

	// Number of checksum digits per FIPS 205 §5.1 / RFC 8391 §3.1.5.
	numChkDigits := params.WOTSChains - numMsgDigits

	digits := make([]uint8, params.WOTSChains)

	// Message digits.
	bitsRem := 0
	bitBuf := uint32(0)
	srcIdx := 0
	for d := 0; d < numMsgDigits; d++ {
		if bitsRem < logW {
			bitBuf = (bitBuf << 8) | uint32(msg[srcIdx])
			srcIdx++
			bitsRem += 8
		}
		shift := bitsRem - logW
		digits[d] = uint8(bitBuf>>uint(shift)) & wMask
		bitBuf &= (1 << uint(shift)) - 1
		bitsRem -= logW
	}

	// Checksum.
	var csum uint32
	for d := 0; d < numMsgDigits; d++ {
		csum += w - 1 - uint32(digits[d])
	}
	// FIPS 205 §5.1: left-shift csum so the high bits land in the
	// MSB of the first checksum digit. shift = 8 - ((numChkDigits *
	// logW) mod 8) when that mod is nonzero; else 0.
	totalChkBits := numChkDigits * logW
	pad := (8 - (totalChkBits % 8)) % 8
	csum <<= uint(pad)

	// Encode checksum into the remaining digits (big-endian).
	for d := 0; d < numChkDigits; d++ {
		shift := totalChkBits - (d+1)*logW + pad
		// shift may overshoot when csum is small; we just want the
		// requested chunk.
		// We need the (d-th from the left) logW-bit chunk of csum.
		// chunk_count = ceil(totalChkBits / 8) bytes; here we
		// re-derive bit position directly.
		_ = shift
		// Simpler: extract from csum bit-by-bit.
		hi := uint32(numChkDigits - d - 1)
		digits[numMsgDigits+d] = uint8((csum >> (hi * uint32(logW))) & uint32(wMask))
	}
	return digits
}

// wotsChain applies (end - start) hash steps to x along chain index
// chainIdx, slot, returning the value at chain position end.
// Position 0 = secret head, position w-1 = public endpoint.
//
// Each step is H(prevValue || slot || chainIdx || position) under the
// cSHAKE chain tag. This is the standard FIPS 205-style chained hash;
// the slot+chain+position binding prevents leaf-pinning attacks.
func wotsChain(params HBSParams, x []byte, slot uint32, chainIdx uint16, start, end int) []byte {
	if end < start {
		panic("thbs/wots: end < start")
	}
	cur := append([]byte{}, x...)
	for pos := start; pos < end; pos++ {
		bind := []byte{
			byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot),
			byte(chainIdx >> 8), byte(chainIdx),
			byte(pos),
		}
		next := hashN(params.N, tagWotsChain, cur, bind)
		zeroize(cur)
		cur = next
	}
	return cur
}

// wotsLeafFromChainEndpoints hashes the WOTSChains public endpoints
// into a single N-byte WOTS+ leaf value. This is the Merkle leaf for
// the top tree.
func wotsLeafFromChainEndpoints(params HBSParams, slot uint32, endpoints [][]byte) []byte {
	// Concatenate every chain endpoint (length-prefixed via hashN)
	// with the slot binding.
	parts := make([][]byte, 0, len(endpoints)+1)
	parts = append(parts, []byte{
		byte(slot >> 24), byte(slot >> 16), byte(slot >> 8), byte(slot),
	})
	parts = append(parts, endpoints...)
	return hashN(params.N, tagWotsLeaf, parts...)
}
