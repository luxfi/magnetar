// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// kat_test.go — KAT replay tests. Loads the JSON vectors emitted
// by cmd/genkat and checks that the package implementation
// reproduces the bytes verbatim.
//
// v1.0 KAT scope: single-party FIPS 205 keygen / sign / verify and
// THBS-SE permissionless threshold sign. Per-validator standalone
// sign is exercised by standalone_test.go +
// TestMagnetar_Wire_FIPS205Verifiable; THBS-SE byte-identity to
// FIPS 205 is exercised by thbsse_test.go.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
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

// katThbsSe captures the v1.0 THBS-SE KAT shape: a deterministic
// (n, t) committee, slot binding tuple, message, and the
// resulting (group public key, signature) pair. Byte-equal to
// what stock FIPS 205 SignDeterministic emits on the master seed
// under ctx = ctxFromSlot(binding).
type katThbsSe struct {
	Mode          string   `json:"mode"`
	N             int      `json:"n"`
	T             int      `json:"t"`
	SetupSeed     string   `json:"setup_seed"`
	Committee     []string `json:"committee"` // hex 32-byte NodeIDs
	ChainID       string   `json:"chain_id"`
	Epoch         uint64   `json:"epoch"`
	Slot          uint64   `json:"slot"`
	Height        uint64   `json:"height"`
	CommitteeID   string   `json:"committee_id"`
	MessageDomain string   `json:"message_domain"`
	Message       string   `json:"message"`
	PublicKey     string   `json:"public_key"` // FIPS 205 wire bytes (raw, no MAGG)
	Signature     string   `json:"signature"`  // FIPS 205 wire bytes (raw, no MAGS)
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

// itoa is a test-local small-int formatter.
func itoa(v int) string { return strconv.Itoa(v) }

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

// TestKAT_ThbsSe replays the THBS-SE permissionless threshold
// vectors. For each (n, t) × Mode × slot tuple in
// vectors/thbsse-sign.json, the test:
//
//  1. Rebuilds the deterministic committee from SetupSeed.
//  2. Runs NewThbsSeKey with a SeedReader pinned to the same
//     SetupSeed.
//  3. Asserts the recovered FIPS 205 public-key bytes match the
//     KAT.
//  4. Runs Round1 for the first t committee members under a
//     deterministic mask RNG.
//  5. Runs Combine.
//  6. Asserts the FIPS 205 signature bytes match the KAT.
//  7. Asserts unmodified circl.slhdsa.Verify accepts the
//     signature under ctx = ctxFromSlot(binding).
//
// The KAT vectors live at vectors/thbsse-sign.json and are
// regenerated by cmd/genkat. The vectors are deterministic over
// (SetupSeed, slot tuple, message).
func TestKAT_ThbsSe(t *testing.T) {
	skipUnderRace(t)
	var katsArr []katThbsSe
	if !loadVectors(t, "thbsse-sign.json", &katsArr) {
		return
	}
	if len(katsArr) == 0 {
		t.Fatalf("no thbsse vectors")
	}
	for _, k := range katsArr {
		k := k
		if testing.Short() && k.Mode != "Magnetar-SHAKE-192s" {
			continue
		}
		t.Run(k.Mode+"_n"+itoa(k.N)+"t"+itoa(k.T)+"_slot"+strconv.FormatUint(k.Slot, 10), func(t *testing.T) {
			mode := modeFromName(k.Mode)
			params := MustParamsFor(mode)

			// Rebuild the committee from the KAT NodeID hex list.
			committee := make([]NodeID, k.N)
			for i := 0; i < k.N; i++ {
				idBytes := hexDecode(t, k.Committee[i])
				if len(idBytes) != len(committee[i]) {
					t.Fatalf("kat committee[%d] wrong length: %d", i, len(idBytes))
				}
				copy(committee[i][:], idBytes)
			}

			// Build setup RNG from the KAT setup seed.
			setupSeed := hexDecode(t, k.SetupSeed)
			setupRng := newDetReader(setupSeed)

			key, err := NewThbsSeKey(params, k.T, committee, setupRng)
			if err != nil {
				t.Fatalf("NewThbsSeKey: %v", err)
			}
			expectPK := hexDecode(t, k.PublicKey)
			if !bytes.Equal(key.PublicKey.Bytes, expectPK) {
				t.Fatalf("public key bytes differ\nexpected: %x\ngot:      %x", expectPK, key.PublicKey.Bytes)
			}

			binding := &ThbsSeSlotBinding{
				ChainID:       hexDecode(t, k.ChainID),
				Epoch:         k.Epoch,
				Slot:          k.Slot,
				Height:        k.Height,
				CommitteeID:   hexDecode(t, k.CommitteeID),
				MessageDomain: hexDecode(t, k.MessageDomain),
			}
			msg := hexDecode(t, k.Message)

			// Round 1 for the first t signers. Each signer pulls a
			// deterministic mask RNG keyed by (setupSeed, party_index).
			r1s := make([]ThbsSeRound1Msg, k.T)
			r2s := make([]ThbsSeRound2Msg, k.T)
			for i := 0; i < k.T; i++ {
				guard := NewThbsSeSlotGuard()
				maskSeed := append([]byte("thbsse-kat-mask-"), append(setupSeed, byte(i))...)
				maskRng := newDetReader(maskSeed)
				r1, r2, err := ThbsSeRound1(params, key.Shares[i], binding, msg, guard, maskRng)
				if err != nil {
					t.Fatalf("Round1[%d]: %v", i, err)
				}
				r1s[i] = r1
				r2s[i] = r2
			}

			sig, evidences, err := Combine(ThbsSeCombineInput{
				Key:     key,
				Binding: binding,
				Message: msg,
				Round1:  r1s,
				Round2:  r2s,
			})
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if len(evidences) != 0 {
				t.Fatalf("Combine emitted %d evidences on honest replay: %+v", len(evidences), evidences)
			}

			expectSig := hexDecode(t, k.Signature)
			if !bytes.Equal(sig.Bytes, expectSig) {
				for i := 0; i < len(sig.Bytes) && i < len(expectSig); i++ {
					if sig.Bytes[i] != expectSig[i] {
						t.Errorf("first divergent byte at offset %d: got 0x%02x expected 0x%02x", i, sig.Bytes[i], expectSig[i])
						break
					}
				}
				t.Fatalf("thbsse signature bytes differ from KAT")
			}

			// Byte-identity end-stop: unmodified circl verify.
			id := slhdsaIDForMode(mode)
			pk := slhdsa.PublicKey{ID: id}
			if err := pk.UnmarshalBinary(key.PublicKey.Bytes); err != nil {
				t.Fatalf("UnmarshalBinary(pk): %v", err)
			}
			ctx := ctxFromSlot(binding)
			if !slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig.Bytes, ctx) {
				t.Fatalf("circl FIPS 205 Verify rejected the THBS-SE KAT signature")
			}
		})
	}
}
