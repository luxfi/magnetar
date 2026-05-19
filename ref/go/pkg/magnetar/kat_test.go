// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// kat_test.go — KAT replay tests. Loads the JSON vectors emitted
// by cmd/genkat and checks that the package implementation
// reproduces the bytes verbatim.
//
// On a clean checkout: re-running cmd/genkat must produce the
// same JSON output, and these tests must continue to pass.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type katKeygen struct {
	Mode       string `json:"mode"`
	Seed       string `json:"seed"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type katSign struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type katVerify struct {
	Mode      string `json:"mode"`
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
	Valid     bool   `json:"valid"`
}

type katThreshold struct {
	Mode      string   `json:"mode"`
	N         int      `json:"n"`
	T         int      `json:"t"`
	Message   string   `json:"message"`
	PublicKey string   `json:"public_key"`
	Signature string   `json:"signature"`
	Quorum    []string `json:"quorum"`
	SessionID string   `json:"session_id"`
	Attempt   uint32   `json:"attempt"`
}

type katDKG struct {
	Mode           string   `json:"mode"`
	N              int      `json:"n"`
	T              int      `json:"t"`
	Committee      []string `json:"committee"`
	PublicKey      string   `json:"public_key"`
	TranscriptHash string   `json:"transcript_hash"`
	Shares         []string `json:"shares"`
}

// vectorsDir returns the path to the KAT vectors directory.
// Resolved relative to the package directory.
func vectorsDir() string {
	return filepath.Join("..", "..", "..", "..", "vectors")
}

// modeFromName converts a KAT mode string back to the Mode enum.
func modeFromName(name string) Mode {
	switch name {
	case "Magnetar-SHAKE-192s":
		return ModeM192s
	case "Magnetar-SHAKE-192f":
		return ModeM192f
	case "Magnetar-SHAKE-256s":
		return ModeM256s
	default:
		return ModeUnspecified
	}
}

// hexDecode is a test-side hex.DecodeString that fatals on error.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// loadVectors reads a JSON KAT file into v. Skips the test (with
// a message) if the file does not exist — vectors are checked in
// via cmd/genkat and may be absent on a fresh checkout before
// genkat is run.
func loadVectors(t *testing.T, path string, v any) bool {
	t.Helper()
	full := filepath.Join(vectorsDir(), path)
	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("vectors file not present (%s); run cmd/genkat first", full)
			return false
		}
		t.Fatalf("read %s: %v", full, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", full, err)
	}
	return true
}

func TestKAT_Keygen(t *testing.T) {
	skipUnderRace(t)
	var katsArr []katKeygen
	if !loadVectors(t, "keygen.json", &katsArr) {
		return
	}
	if len(katsArr) == 0 {
		t.Fatalf("no keygen vectors")
	}
	for _, k := range katsArr {
		k := k
		if testing.Short() && k.Mode != "Magnetar-SHAKE-192s" {
			continue // skip non-recommended modes under -short -race
		}
		t.Run(k.Mode+"_seed_"+k.Seed[:8], func(t *testing.T) {
			mode := modeFromName(k.Mode)
			params := MustParamsFor(mode)
			seed := hexDecode(t, k.Seed)
			sk, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			expectPub := hexDecode(t, k.PublicKey)
			if !bytes.Equal(sk.Pub.Bytes, expectPub) {
				t.Errorf("public key bytes differ\nexpected: %x\ngot:      %x", expectPub, sk.Pub.Bytes)
			}
			expectPriv := hexDecode(t, k.PrivateKey)
			if !bytes.Equal(sk.Bytes, expectPriv) {
				t.Errorf("private key bytes differ\nexpected: %x\ngot:      %x", expectPriv, sk.Bytes)
			}
		})
	}
}

func TestKAT_Sign(t *testing.T) {
	skipUnderRace(t)
	var katsArr []katSign
	if !loadVectors(t, "sign.json", &katsArr) {
		return
	}
	for _, k := range katsArr {
		k := k
		if testing.Short() && k.Mode != "Magnetar-SHAKE-192s" {
			continue
		}
		t.Run(k.Mode+"_seed_"+k.Seed[:8], func(t *testing.T) {
			mode := modeFromName(k.Mode)
			params := MustParamsFor(mode)
			seed := hexDecode(t, k.Seed)
			sk, _ := KeyFromSeed(params, seed)
			msg := hexDecode(t, k.Message)
			ctx := hexDecode(t, k.Context)
			sig, err := Sign(params, sk, msg, ctx, false, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			expect := hexDecode(t, k.Signature)
			if !bytes.Equal(sig.Bytes, expect) {
				// Show first divergence.
				for i := 0; i < len(sig.Bytes) && i < len(expect); i++ {
					if sig.Bytes[i] != expect[i] {
						t.Errorf("first divergent byte at offset %d: got 0x%02x expected 0x%02x", i, sig.Bytes[i], expect[i])
						break
					}
				}
				t.Fatalf("signature bytes differ from KAT")
			}
		})
	}
}

func TestKAT_Verify(t *testing.T) {
	skipUnderRace(t)
	var katsArr []katVerify
	if !loadVectors(t, "verify.json", &katsArr) {
		return
	}
	for i, k := range katsArr {
		k := k
		if testing.Short() && k.Mode != "Magnetar-SHAKE-192s" {
			continue
		}
		t.Run(k.Mode+"_case"+itoa(i), func(t *testing.T) {
			mode := modeFromName(k.Mode)
			params := MustParamsFor(mode)
			pub := &PublicKey{Mode: mode, Bytes: hexDecode(t, k.PublicKey)}
			msg := hexDecode(t, k.Message)
			ctx := hexDecode(t, k.Context)
			sig := &Signature{Mode: mode, Bytes: hexDecode(t, k.Signature)}
			err := VerifyCtx(params, pub, msg, ctx, sig)
			if k.Valid {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected invalid, got nil error")
				}
			}
		})
	}
}
