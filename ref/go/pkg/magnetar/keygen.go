// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// keygen.go --- single-party key generation. This is the FIPS 205
// keygen path consumed by both:
//
//   - the per-validator standalone primitive (standalone.go), where
//     every validator runs GenerateKey once and persists (sk, pk); and
//
//   - the THBS-SE setup (thbsse.go::NewThbsSeKey), where a single
//     scheme seed is sampled, Shamir-shared via thbsseDealRandom, and
//     the master seed is zeroized before the ThbsSeKey struct is
//     returned.
//
// Output: a FIPS 205 SLH-DSA key pair. The public key is byte-equal
// to what circl's slhdsa.Scheme().DeriveKey would emit on the same
// seed; the private key carries the seed alongside the packed key.
//
// The seed is the variable-length (4n bytes) scheme-seed used by
// circl's DeriveKey --- for the recommended SHAKE-192s mode that's
// 96 bytes.

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Errors returned by keygen and the surrounding key-handling layer.
var (
	ErrShortRand     = errors.New("magnetar: short read from entropy source")
	ErrSeedSize      = errors.New("magnetar: seed-derived keygen requires correct seed length")
	ErrModeMismatch  = errors.New("magnetar: mode mismatch")
	ErrInvalidPubKey = errors.New("magnetar: invalid public-key length")
	ErrInvalidPriv   = errors.New("magnetar: invalid private-key length")
)

// GenerateKey produces a fresh single-party Magnetar key pair. The
// generated key is a FIPS 205 SLH-DSA key pair: the public key
// verifies under unmodified slhdsa.Verify.
//
// rng may be nil; if so crypto/rand.Reader is used. Pass a
// deterministic reader (e.g. bytes.NewReader of a fixed seed) for
// KAT-reproducible key generation.
func GenerateKey(params *Params, rng io.Reader) (*PrivateKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	seed := make([]byte, params.SeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, ErrShortRand
	}
	return KeyFromSeed(params, seed)
}

// KeyFromSeed deterministically derives a Magnetar key pair from a
// params.SeedSize-byte seed. This is the canonical seed-based
// keygen path used by every KAT and by the DKG aggregation step.
//
// The seed is copied into the returned PrivateKey so callers can
// zeroize their input buffer immediately on return.
func KeyFromSeed(params *Params, seed []byte) (*PrivateKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(seed) != params.SeedSize {
		return nil, ErrSeedSize
	}
	pubBytes, privBytes, err := slhDSAKeyFromSeed(params.ID, seed)
	if err != nil {
		return nil, err
	}
	pub := &PublicKey{Mode: params.Mode, Bytes: pubBytes}
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)
	return &PrivateKey{
		Mode:  params.Mode,
		Bytes: privBytes,
		Seed:  seedCopy,
		Pub:   pub,
	}, nil
}

// slhDSAKeyFromSeed dispatches to circl's SLH-DSA scheme.DeriveKey
// for the given ID and returns packed (pub, priv). This is the
// only place in the package that touches circl's FIPS 205
// implementation for key generation.
func slhDSAKeyFromSeed(id slhdsa.ID, seed []byte) ([]byte, []byte, error) {
	scheme := id.Scheme()
	if len(seed) != scheme.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pubKey, privKey := scheme.DeriveKey(seed)
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

// Public returns this key's public companion.
func (sk *PrivateKey) Public() *PublicKey {
	return sk.Pub
}

// Equal reports whether two public keys are byte-equal under the
// same mode. Constant-time per byte.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	if p.Mode != other.Mode {
		return false
	}
	if len(p.Bytes) != len(other.Bytes) {
		return false
	}
	var diff byte
	for i := range p.Bytes {
		diff |= p.Bytes[i] ^ other.Bytes[i]
	}
	return diff == 0
}
