// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// zeroize.go — best-effort secret-buffer zeroization.
//
// Threat model: a Magnetar process holding reconstructed secret
// material (e.g. the Combine aggregator's master seed) is at risk
// of coredump / /proc/self/mem / swap-file exfiltration if the
// secret is left live on the heap or stack after use. Go provides
// no native `runtime.Memzero` and the GC may copy buffers around;
// zeroize is a defense-in-depth measure, not a guarantee.
//
// We deliberately do NOT use `defer` for zeroize calls — the
// hot-path callers are short, and explicit zeroization at the
// return site keeps the secret-handling code path locally legible.
//
// The v0.1 reveal-and-aggregate trust caveat: even with perfect
// zeroization the aggregator process has a non-zero secret
// lifetime window. See SPEC.md "Trust model" and
// DEPLOYMENT-RUNBOOK.md for operational mitigations (mlock,
// ptrace-off, etc).

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
