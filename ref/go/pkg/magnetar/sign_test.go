// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"bytes"
	"testing"
)

func TestSign_Verify_RoundTrip(t *testing.T) {
	skipUnderRace(t)
	modes := []Mode{ModeM192s, ModeM192f, ModeM256s}
	if testing.Short() {
		// 192f signatures are large (35664 bytes) and 256s
		// keygen/sign is the slowest variant; keep only the
		// recommended 192s mode under -short.
		modes = []Mode{ModeM192s}
	}
	for _, mode := range modes {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			seed := bytes.Repeat([]byte{0xA5}, params.SeedSize)
			sk, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			msg := []byte("Magnetar single-party Sign-Verify round trip")
			sig, err := Sign(params, sk, msg, nil, false, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig.Bytes) != params.SignatureSize {
				t.Fatalf("signature size: got %d want %d", len(sig.Bytes), params.SignatureSize)
			}
			if err := Verify(params, sk.Pub, msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// Tampered: flip a byte in the middle.
			bad := append([]byte{}, sig.Bytes...)
			bad[len(bad)/2] ^= 0x01
			badSig := &Signature{Mode: mode, Bytes: bad}
			if err := Verify(params, sk.Pub, msg, badSig); err == nil {
				t.Fatalf("Verify accepted tampered signature")
			}
			// Tampered message.
			if err := Verify(params, sk.Pub, []byte("different"), sig); err == nil {
				t.Fatalf("Verify accepted on different message")
			}
		})
	}
}

func TestSign_Deterministic_ByteEqual(t *testing.T) {
	skipUnderRace(t)
	// For randomized=false (SignDeterministic), two calls on the
	// same (sk, msg, ctx) MUST produce byte-identical output.
	// This is the FIPS 205 invariant Magnetar's threshold path
	// rides on top of.
	params := MustParamsFor(ModeM192s)
	seed := bytes.Repeat([]byte{0x42}, params.SeedSize)
	sk, _ := KeyFromSeed(params, seed)
	msg := []byte("Magnetar determinism test")
	sig1, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatalf("Sign#1: %v", err)
	}
	sig2, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatalf("Sign#2: %v", err)
	}
	if !bytes.Equal(sig1.Bytes, sig2.Bytes) {
		t.Fatalf("deterministic SignDeterministic produced different bytes on repeat call")
	}
}

func TestSign_WithContext(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	seed := bytes.Repeat([]byte{0xC7}, params.SeedSize)
	sk, _ := KeyFromSeed(params, seed)
	msg := []byte("Magnetar context test")
	ctx := []byte("lux-magnetar-ctx-v0.1")
	sig, err := SignCtx(params, sk, msg, ctx, false, nil)
	if err != nil {
		t.Fatalf("SignCtx: %v", err)
	}
	if err := VerifyCtx(params, sk.Pub, msg, ctx, sig); err != nil {
		t.Fatalf("VerifyCtx: %v", err)
	}
	// Verify under a different context must fail.
	if err := VerifyCtx(params, sk.Pub, msg, []byte("wrong-ctx"), sig); err == nil {
		t.Fatalf("VerifyCtx accepted wrong context")
	}
	// Verify with NO context must fail (context binding).
	if err := Verify(params, sk.Pub, msg, sig); err == nil {
		t.Fatalf("Verify (no ctx) accepted ctx-bound signature")
	}
}

func TestSign_TooLongCtx(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	seed := bytes.Repeat([]byte{0x33}, params.SeedSize)
	sk, _ := KeyFromSeed(params, seed)
	msg := []byte("x")
	ctx := make([]byte, 256)
	if _, err := SignCtx(params, sk, msg, ctx, false, nil); err == nil {
		t.Fatalf("expected ErrCtxTooLong")
	}
}
