// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// zeroize.go --- best-effort secret-buffer zeroization.
//
// Threat model: a Magnetar process holding transient secret material
// (the THBS-SE public combiner's reconstructed seed; a per-validator
// PrivateKey buffer at standalone-sign time) is at risk of coredump,
// /proc/self/mem, or swap-file exfiltration if the secret is left
// live on the heap or stack after use. Go provides no native
// runtime.Memzero and the GC may copy buffers around; zeroize is a
// defense-in-depth measure, not a guarantee.
//
// We deliberately do NOT use `defer` for zeroize calls --- the
// hot-path callers are short, and explicit zeroization at the
// return site keeps the secret-handling code path locally legible.
//
// THBS-SE v1.0 honest open item: the strict invariant ("no party or
// combiner EVER reconstructs SK.seed, even transiently in memory")
// requires the v1.1 strict-atom-assembly path tracked at
// BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11. v1.0 ships a PUBLIC
// COMBINER (anyone-can-combine) that holds the seed for the duration
// of one circl SignDeterministic call and then zeroizes; this is
// materially stronger than a TEE-attested privileged-aggregator
// model (no host in TCB) and materially weaker than the strict
// invariant (a peer-local memory-disclosure adversary at the combine
// moment could observe the seed). See thbsse.go for the open-item
// discussion.

// zeroizeBytes overwrites every byte of b with 0.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeU16Slice overwrites every uint16 element with 0.
func zeroizeU16Slice(s []uint16) {
	for i := range s {
		s[i] = 0
	}
}

// zeroizePrivateKey wipes the secret-bearing fields of a
// PrivateKey (Bytes and Seed). Sets references to nil where
// possible so the underlying backing arrays can be GC'd; before
// they are, the bytes have been overwritten in place so a
// concurrent coredump captures zeros.
func zeroizePrivateKey(sk *PrivateKey) {
	if sk == nil {
		return
	}
	zeroizeBytes(sk.Bytes)
	zeroizeBytes(sk.Seed)
}
