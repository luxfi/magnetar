// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// genkat is the canonical KAT (Known Answer Test) generator for
// Magnetar v1.0. It produces the JSON vector files committed
// under vectors/:
//
//   - keygen.json   — FIPS 205 single-party keypair derivation
//   - sign.json     — FIPS 205 single-party SignDeterministic
//   - verify.json   — FIPS 205 verify (positive + negative)
//   - thbsse-sign.json — THBS-SE permissionless threshold sign
//
// Re-running genkat on a clean checkout MUST produce byte-
// identical output. Drift is a CI failure.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	pm "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// masterSeedHex is the head-of-file 48-byte seed from which every
// KAT in the file is reproducible.
const masterSeedHex = "f1a5c98e2d40e9b7a3f87216d4ca09fbb6e51d75c7e3a920" +
	"4f3c1aab83de2f08e1d5b4a1c8f6b9e6743a298e7062a5c4"

type KeygenKAT struct {
	Mode       string `json:"mode"`
	Seed       string `json:"seed"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type SignKAT struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type VerifyKAT struct {
	Mode      string `json:"mode"`
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
	Valid     bool   `json:"valid"`
}

// ThbsSeSignKAT mirrors the kat_test.go katThbsSe shape: a
// (n, t) committee deterministically derived from SetupSeed, a
// slot binding, a message, and the resulting (group pk, σ)
// pair. Byte-identical to what stock FIPS 205 SignDeterministic
// emits on the master seed under ctx = ctxFromSlot(binding).
type ThbsSeSignKAT struct {
	Mode          string   `json:"mode"`
	N             int      `json:"n"`
	T             int      `json:"t"`
	SetupSeed     string   `json:"setup_seed"`
	Committee     []string `json:"committee"`
	ChainID       string   `json:"chain_id"`
	Epoch         uint64   `json:"epoch"`
	Slot          uint64   `json:"slot"`
	Height        uint64   `json:"height"`
	CommitteeID   string   `json:"committee_id"`
	MessageDomain string   `json:"message_domain"`
	Message       string   `json:"message"`
	PublicKey     string   `json:"public_key"`
	Signature     string   `json:"signature"`
}

// detReader is a deterministic byte stream from a seed via
// SHA-256 chaining. Layout matches the magnetar package test
// helper so KATs reproduce across the cmd/test boundary.
type detReader struct {
	seed []byte
	buf  []byte
	off  int
}

func newDetReader(seed []byte) *detReader {
	return &detReader{seed: seed}
}

func (r *detReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			ctr := uint32(len(r.buf) / 32)
			r.buf = nil
			for i := 0; i < 128; i++ {
				h := sha256.New()
				h.Write(r.seed)
				h.Write([]byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)})
				r.buf = append(r.buf, h.Sum(nil)...)
				ctr++
			}
			r.off = 0
		}
		c := copy(p[n:], r.buf[r.off:])
		n += c
		r.off += c
	}
	return len(p), nil
}

func main() {
	outDir := flag.String("out", "vectors", "output directory for KAT JSON files")
	flag.Parse()

	masterSeed, err := hex.DecodeString(masterSeedHex)
	if err != nil {
		fail(err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}

	modes := []pm.Mode{pm.ModeM192s, pm.ModeM192f, pm.ModeM256s}

	// ---- keygen ----
	keygenKATs := []KeygenKAT{}
	for _, mode := range modes {
		params := pm.MustParamsFor(mode)
		for i := 0; i < 3; i++ {
			seedReader := newDetReader(append(masterSeed, []byte{0x00, byte(mode), byte(i)}...))
			seed := make([]byte, params.SeedSize)
			_, _ = seedReader.Read(seed)
			sk, err := pm.KeyFromSeed(params, seed)
			if err != nil {
				fail(err)
			}
			keygenKATs = append(keygenKATs, KeygenKAT{
				Mode:       mode.String(),
				Seed:       hex.EncodeToString(seed),
				PublicKey:  hex.EncodeToString(sk.Pub.Bytes),
				PrivateKey: hex.EncodeToString(sk.Bytes),
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "keygen.json"), keygenKATs)

	// ---- sign ----
	signKATs := []SignKAT{}
	for _, mode := range modes {
		params := pm.MustParamsFor(mode)
		for i := 0; i < 3; i++ {
			seedReader := newDetReader(append(masterSeed, []byte{0x10, byte(mode), byte(i)}...))
			seed := make([]byte, params.SeedSize)
			_, _ = seedReader.Read(seed)
			sk, _ := pm.KeyFromSeed(params, seed)
			msg := []byte(fmt.Sprintf("Magnetar KAT message %s #%d", mode.String(), i))
			sig, err := pm.Sign(params, sk, msg, nil, false, nil)
			if err != nil {
				fail(err)
			}
			signKATs = append(signKATs, SignKAT{
				Mode:      mode.String(),
				Seed:      hex.EncodeToString(seed),
				Message:   hex.EncodeToString(msg),
				Context:   "",
				Signature: hex.EncodeToString(sig.Bytes),
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "sign.json"), signKATs)

	// ---- verify ----
	verifyKATs := []VerifyKAT{}
	for _, mode := range modes {
		params := pm.MustParamsFor(mode)
		seedReader := newDetReader(append(masterSeed, []byte{0x20, byte(mode)}...))
		seed := make([]byte, params.SeedSize)
		_, _ = seedReader.Read(seed)
		sk, _ := pm.KeyFromSeed(params, seed)
		msg := []byte(fmt.Sprintf("Magnetar Verify KAT %s", mode.String()))
		sig, _ := pm.Sign(params, sk, msg, nil, false, nil)
		verifyKATs = append(verifyKATs, VerifyKAT{
			Mode:      mode.String(),
			PublicKey: hex.EncodeToString(sk.Pub.Bytes),
			Message:   hex.EncodeToString(msg),
			Context:   "",
			Signature: hex.EncodeToString(sig.Bytes),
			Valid:     true,
		})
		// Negative: flip a byte.
		badSig := make([]byte, len(sig.Bytes))
		copy(badSig, sig.Bytes)
		badSig[len(badSig)/2] ^= 0x01
		verifyKATs = append(verifyKATs, VerifyKAT{
			Mode:      mode.String(),
			PublicKey: hex.EncodeToString(sk.Pub.Bytes),
			Message:   hex.EncodeToString(msg),
			Context:   "",
			Signature: hex.EncodeToString(badSig),
			Valid:     false,
		})
	}
	writeJSON(filepath.Join(*outDir, "verify.json"), verifyKATs)

	// ---- THBS-SE ----
	//
	// Spec requirement (user prompt): (n=7, t=4) × 3 SLH-DSA modes
	// (192s/192f/256s) × 3 distinct messages. Deterministic over
	// (SetupSeed, slot tuple, message).
	thbsseKATs := []ThbsSeSignKAT{}
	for _, mode := range modes {
		params := pm.MustParamsFor(mode)
		const N = 7
		const T = 4
		committee := makeKATCommittee(N)
		committeeHex := make([]string, N)
		for i, c := range committee {
			committeeHex[i] = hex.EncodeToString(c[:])
		}
		for msgIdx := 0; msgIdx < 3; msgIdx++ {
			// SetupSeed pinned per (mode, msgIdx) so KAT
			// regeneration is deterministic.
			setupSeed := sha256.Sum256(append(masterSeed,
				[]byte{0x40, byte(mode), byte(N), byte(T), byte(msgIdx)}...))
			setupRng := newDetReader(setupSeed[:])

			key, err := pm.NewThbsSeKey(params, T, committee, setupRng)
			if err != nil {
				fail(fmt.Errorf("NewThbsSeKey mode=%s msg=%d: %w", mode, msgIdx, err))
			}

			binding := &pm.ThbsSeSlotBinding{
				ChainID:       []byte(fmt.Sprintf("lux-magnetar-kat-%s", mode.String())),
				Epoch:         uint64(7 + msgIdx),
				Slot:          uint64(101 + 10*msgIdx),
				Height:        uint64(900 + msgIdx),
				CommitteeID:   []byte(fmt.Sprintf("kat-ctte-%d", msgIdx)),
				MessageDomain: []byte("polaris-cert"),
			}
			msg := []byte(fmt.Sprintf(
				"Magnetar THBS-SE KAT %s n=%d t=%d msg#%d", mode.String(), N, T, msgIdx))

			r1s := make([]pm.ThbsSeRound1Msg, T)
			r2s := make([]pm.ThbsSeRound2Msg, T)
			for i := 0; i < T; i++ {
				guard := pm.NewThbsSeSlotGuard()
				maskSeed := append([]byte("thbsse-kat-mask-"), append(setupSeed[:], byte(i))...)
				maskRng := newDetReader(maskSeed)
				r1, r2, err := pm.ThbsSeRound1(params, key.Shares[i], binding, msg, guard, maskRng)
				if err != nil {
					fail(fmt.Errorf("ThbsSeRound1 mode=%s msg=%d i=%d: %w", mode, msgIdx, i, err))
				}
				r1s[i] = r1
				r2s[i] = r2
			}
			sig, evidences, err := pm.Combine(pm.ThbsSeCombineInput{
				Key:     key,
				Binding: binding,
				Message: msg,
				Round1:  r1s,
				Round2:  r2s,
			})
			if err != nil {
				fail(fmt.Errorf("Combine mode=%s msg=%d: %w", mode, msgIdx, err))
			}
			if len(evidences) != 0 {
				fail(fmt.Errorf("Combine emitted evidences on honest KAT mode=%s msg=%d: %+v",
					mode, msgIdx, evidences))
			}

			thbsseKATs = append(thbsseKATs, ThbsSeSignKAT{
				Mode:          mode.String(),
				N:             N,
				T:             T,
				SetupSeed:     hex.EncodeToString(setupSeed[:]),
				Committee:     committeeHex,
				ChainID:       hex.EncodeToString(binding.ChainID),
				Epoch:         binding.Epoch,
				Slot:          binding.Slot,
				Height:        binding.Height,
				CommitteeID:   hex.EncodeToString(binding.CommitteeID),
				MessageDomain: hex.EncodeToString(binding.MessageDomain),
				Message:       hex.EncodeToString(msg),
				PublicKey:     hex.EncodeToString(key.PublicKey.Bytes),
				Signature:     hex.EncodeToString(sig.Bytes),
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "thbsse-sign.json"), thbsseKATs)

	fmt.Println("KAT vectors written to", *outDir)
}

func makeKATCommittee(n int) []pm.NodeID {
	out := make([]pm.NodeID, n)
	for i := 0; i < n; i++ {
		out[i][0] = byte(i + 1)
		copy(out[i][1:], []byte("MAGNETAR-KAT"))
	}
	return out
}

func writeJSON(path string, v any) {
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genkat: error:", err)
	os.Exit(1)
}
