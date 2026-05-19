// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// params.go — concrete parameter sets for Magnetar and the canonical
// Mode -> Params resolution. Magnetar instantiates threshold SLH-DSA
// over the FIPS 205 parameter sets defined in NIST FIPS 205 §10.1
// Table 2.
//
// The v0.1 reveal-and-aggregate construction shares the 4n-byte
// SLH-DSA scheme seed (the input to slhdsa.Scheme().DeriveKey) via
// byte-wise Shamir secret sharing over GF(257). On Combine the seed
// is reconstructed in aggregator memory, fed to the single-party
// FIPS 205 SignDeterministic, and zeroized. The resulting signature
// is byte-identical to single-party SLH-DSA on the same (seed, msg,
// ctx) — this is the Magnetar analog of Pulsar's Class N1 claim.
//
// The v0.1 honest trust caveat: the aggregator process is TCB for
// the brief window the master seed is reconstructed. See SPEC.md
// "Trust model" and DEPLOYMENT-RUNBOOK.md.

import (
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Mode identifies which FIPS 205 parameter set a Magnetar instance
// targets. The v0.1 implementation ships the SHAKE-family small and
// fast variants at NIST PQ category 3 (≥192-bit security) and
// category 5 (≥256-bit security).
//
// The SHAKE family is preferred over the SHA-2 family for two
// reasons: (i) FIPS 202 SHA-3 + cSHAKE is the same hash family used
// by every other Magnetar transcript hash, keeping the audit
// footprint single-suite; (ii) the FIPS 205 SHAKE primitive permits
// constant-time implementations on the same SHA-3 core that Pulsar
// uses, sharing the side-channel analysis.
type Mode uint8

const (
	// ModeUnspecified rejects every operation; included so the zero
	// Mode is invalid (forces explicit initialization).
	ModeUnspecified Mode = 0

	// ModeM192s targets FIPS 205 SLH-DSA-SHAKE-192s (NIST PQ
	// Category 3, ≥192-bit classical security). 48-byte pk,
	// 96-byte sk, 16224-byte signature. RECOMMENDED production
	// target.
	ModeM192s Mode = 1

	// ModeM192f targets FIPS 205 SLH-DSA-SHAKE-192f (Category 3,
	// "fast" variant: smaller hypertree → larger signature, faster
	// signing). 48-byte pk, 96-byte sk, 35664-byte signature.
	ModeM192f Mode = 2

	// ModeM256s targets FIPS 205 SLH-DSA-SHAKE-256s (NIST PQ
	// Category 5, ≥256-bit classical security). 64-byte pk,
	// 128-byte sk, 29792-byte signature.
	ModeM256s Mode = 3
)

// String returns the canonical mode name.
func (m Mode) String() string {
	switch m {
	case ModeM192s:
		return "Magnetar-SHAKE-192s"
	case ModeM192f:
		return "Magnetar-SHAKE-192f"
	case ModeM256s:
		return "Magnetar-SHAKE-256s"
	default:
		return "Magnetar-unspecified"
	}
}

// Params captures the concrete parameters of a Magnetar instance.
// The values are derived from FIPS 205 §10.1 Table 2.
type Params struct {
	Mode Mode

	// FIPS 205 hash-tree shape. n is the WOTS+ message length (per
	// FIPS 205 §10.1); seed size = 4n bytes (3n internal seeds +
	// the public-key root absorbs the same width).
	N int // WOTS+ message length in bytes (16 / 24 / 32)

	// Wire sizes. Match circl/slhdsa byte-for-byte.
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int

	// SeedSize is the byte length of the SLH-DSA scheme seed used by
	// circl's DeriveKey. Equal to PrivateKeySize for every FIPS 205
	// parameter set.
	SeedSize int

	// ID is the circl/slhdsa identifier this Mode dispatches to.
	// Centralising the mapping makes the dispatch table auditable.
	ID slhdsa.ID

	// ShamirPrime is the small prime over which per-byte Shamir
	// shares of the SLH-DSA seed are computed. 257 matches the
	// Pulsar choice: smallest prime > 255, admits every byte as a
	// distinct GF element, gives 9-bit shares packed as one uint16
	// per byte.
	ShamirPrime uint32
}

// SeedSize is the byte length of an SLH-DSA scheme seed for the
// recommended SHAKE-192s mode. Other modes have different seed
// sizes — callers MUST use params.SeedSize, not this constant, for
// non-192s code paths. Provided as a const for KAT generators that
// pin to the recommended mode.
const SeedSize = 96

// MaxCommittee257 is the maximum committee size under byte-wise
// Shamir over GF(257). 256 is exactly q-1 = 257-1, the upper bound
// on distinct non-zero evaluation points.
const MaxCommittee257 = 256

// Hard-coded parameter tables per FIPS 205 §10.1 Table 2.

// ParamsM192s is the Magnetar SHAKE-192s parameter set (recommended).
var ParamsM192s = &Params{
	Mode:           ModeM192s,
	N:              24,
	PublicKeySize:  48,
	PrivateKeySize: 96,
	SignatureSize:  16224,
	SeedSize:       96,
	ID:             slhdsa.SHAKE_192s,
	ShamirPrime:    257,
}

// ParamsM192f is the Magnetar SHAKE-192f parameter set.
var ParamsM192f = &Params{
	Mode:           ModeM192f,
	N:              24,
	PublicKeySize:  48,
	PrivateKeySize: 96,
	SignatureSize:  35664,
	SeedSize:       96,
	ID:             slhdsa.SHAKE_192f,
	ShamirPrime:    257,
}

// ParamsM256s is the Magnetar SHAKE-256s parameter set.
var ParamsM256s = &Params{
	Mode:           ModeM256s,
	N:              32,
	PublicKeySize:  64,
	PrivateKeySize: 128,
	SignatureSize:  29792,
	SeedSize:       128,
	ID:             slhdsa.SHAKE_256s,
	ShamirPrime:    257,
}

// ParamsFor returns the canonical Params for the given Mode.
func ParamsFor(mode Mode) (*Params, error) {
	switch mode {
	case ModeM192s:
		return ParamsM192s, nil
	case ModeM192f:
		return ParamsM192f, nil
	case ModeM256s:
		return ParamsM256s, nil
	default:
		return nil, ErrUnknownMode
	}
}

// MustParamsFor is the panic-on-error variant of ParamsFor for use
// in constants and tests. Production code must use ParamsFor.
func MustParamsFor(mode Mode) *Params {
	p, err := ParamsFor(mode)
	if err != nil {
		panic(err)
	}
	return p
}

// Validate checks that a Params struct is internally consistent and
// matches one of the registered parameter sets.
func (p *Params) Validate() error {
	if p == nil {
		return ErrNilParams
	}
	canonical, err := ParamsFor(p.Mode)
	if err != nil {
		return err
	}
	if *p != *canonical {
		return ErrParamsTampered
	}
	return nil
}

// Errors returned by params operations.
var (
	ErrUnknownMode    = errors.New("magnetar: unknown mode")
	ErrNilParams      = errors.New("magnetar: nil params")
	ErrParamsTampered = errors.New("magnetar: params do not match canonical set")
)
