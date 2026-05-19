// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"bytes"
	"testing"
)

func TestKeyFromSeed_Deterministic(t *testing.T) {
	skipUnderRace(t)
	modes := []Mode{ModeM192s, ModeM192f, ModeM256s}
	if testing.Short() {
		modes = []Mode{ModeM192s}
	}
	for _, mode := range modes {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			seed := make([]byte, params.SeedSize)
			for i := range seed {
				seed[i] = byte(i)
			}
			sk1, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatalf("KeyFromSeed#1: %v", err)
			}
			sk2, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatalf("KeyFromSeed#2: %v", err)
			}
			if !bytes.Equal(sk1.Bytes, sk2.Bytes) {
				t.Fatalf("private keys differ across deterministic calls")
			}
			if !bytes.Equal(sk1.Pub.Bytes, sk2.Pub.Bytes) {
				t.Fatalf("public keys differ across deterministic calls")
			}
			if !sk1.Pub.Equal(sk2.Pub) {
				t.Fatalf("PublicKey.Equal disagrees with byte equality")
			}
			if len(sk1.Pub.Bytes) != params.PublicKeySize {
				t.Fatalf("public key size: got %d want %d", len(sk1.Pub.Bytes), params.PublicKeySize)
			}
			if len(sk1.Bytes) != params.PrivateKeySize {
				t.Fatalf("private key size: got %d want %d", len(sk1.Bytes), params.PrivateKeySize)
			}
		})
	}
}

func TestKeyFromSeed_WrongSize(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	short := make([]byte, params.SeedSize-1)
	if _, err := KeyFromSeed(params, short); err == nil {
		t.Fatalf("expected error for short seed")
	}
	long := make([]byte, params.SeedSize+1)
	if _, err := KeyFromSeed(params, long); err == nil {
		t.Fatalf("expected error for long seed")
	}
}

func TestGenerateKey_FromRNG(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	rng := deterministicReader([]byte("magnetar-generatekey-test"))
	sk, err := GenerateKey(params, rng)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(sk.Pub.Bytes) != params.PublicKeySize {
		t.Fatalf("public key size: got %d want %d", len(sk.Pub.Bytes), params.PublicKeySize)
	}
	if len(sk.Seed) != params.SeedSize {
		t.Fatalf("seed length: got %d want %d", len(sk.Seed), params.SeedSize)
	}
}

func TestParams_Validate(t *testing.T) {
	for _, mode := range []Mode{ModeM192s, ModeM192f, ModeM256s} {
		p := MustParamsFor(mode)
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	// Tampered params should fail.
	tampered := *MustParamsFor(ModeM192s)
	tampered.SeedSize = 1
	if err := tampered.Validate(); err == nil {
		t.Fatalf("expected tampered params to fail validation")
	}
	if err := (*Params)(nil).Validate(); err == nil {
		t.Fatalf("expected nil params to fail validation")
	}
	bogus := &Params{Mode: ModeUnspecified}
	if err := bogus.Validate(); err == nil {
		t.Fatalf("expected unspecified mode to fail validation")
	}
}
