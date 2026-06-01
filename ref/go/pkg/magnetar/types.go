// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// types.go — public data types used across the Magnetar reference
// implementation.

// NodeID is the canonical party identifier used in all Magnetar
// protocols. The 32-byte width matches the Lux validator-ID format
// and is wide enough to host an arbitrary external identifier
// (e.g. a Hanzo IAM subject hash). Index 0 is forbidden because
// the Shamir evaluation point at x=0 holds the master secret; any
// party with nominal index 0 is rejected.
type NodeID [32]byte

// PublicKey wraps a FIPS 205 SLH-DSA public key. The byte layout
// is exactly what circl's slhdsa.PublicKey.MarshalBinary emits —
// (seed, root) concatenation per FIPS 205 §10.1 (Algorithm 21).
//
// The headline byte-identity claim of Magnetar is that a Magnetar
// signature (per-validator standalone or THBS-SE) against this
// PublicKey verifies under unmodified FIPS 205 slhdsa.Verify
// (see Verify in verify.go).
type PublicKey struct {
	Mode  Mode
	Bytes []byte
}

// PrivateKey wraps a FIPS 205 SLH-DSA private key. Held only by
// the per-validator standalone path (each validator holds its own
// PrivateKey locally); the THBS-SE threshold path holds KeyShare
// values produced by setup, never the full PrivateKey.
//
// PrivateKey carries the seed it was derived from so determinism
// across re-load is preserved. Seed is variable-length (4n bytes
// per FIPS 205 §10.1).
type PrivateKey struct {
	Mode  Mode
	Bytes []byte
	Seed  []byte
	Pub   *PublicKey
}

// Signature is a FIPS 205 SLH-DSA signature in its standard byte
// layout per FIPS 205 §10.2 (Algorithm 22). No Magnetar envelope
// is applied to the inner bytes; the canonical MAGS wire frame
// (wire.go) wraps them for transport but a relying party that
// strips the 11-byte header obtains the unmodified FIPS 205 bytes
// that cloudflare/circl's slhdsa.Verify accepts.
type Signature struct {
	Mode  Mode
	Bytes []byte
}

// GroupKey is the public key produced by THBS-SE setup
// (NewThbsSeKey). The distinction between GroupKey and PublicKey
// is documentary only: they carry the same bytes. A *GroupKey is
// a *PublicKey under a renamed alias that signals "this is the
// permissionless-threshold-committee output."
type GroupKey = PublicKey
