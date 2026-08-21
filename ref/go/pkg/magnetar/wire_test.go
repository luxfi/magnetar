// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// TestMagnetar_Wire_Roundtrip checks the Signature wire codec
// round-trips byte-equal for every magnetar mode and that the
// parsed Mode + Bytes match the input exactly. A second marshal
// MUST produce the same bytes as the first (strict canonical
// encoding). Mirrors TestPulsar_Wire_SigRoundtrip in scope.
func TestMagnetar_Wire_Roundtrip(t *testing.T) {
	for _, mode := range []Mode{ModeM192s, ModeM192f, ModeM256s} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			body := make([]byte, params.SignatureSize)
			if _, err := rand.Read(body); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			sig := &Signature{Mode: mode, Bytes: append([]byte{}, body...)}

			wire1, err := sig.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := len(wire1); got != wireFixedSigHeader+params.SignatureSize {
				t.Fatalf("wire length %d != header(%d) + payload(%d)",
					got, wireFixedSigHeader, params.SignatureSize)
			}

			var parsed Signature
			if err := parsed.UnmarshalBinary(wire1); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if parsed.Mode != mode {
				t.Fatalf("parsed.Mode = %v want %v", parsed.Mode, mode)
			}
			if !bytes.Equal(parsed.Bytes, body) {
				t.Fatalf("parsed.Bytes diverged from input")
			}

			wire2, err := parsed.MarshalBinary()
			if err != nil {
				t.Fatalf("re-MarshalBinary: %v", err)
			}
			if !bytes.Equal(wire1, wire2) {
				t.Fatalf("re-marshal not byte-equal: %d vs %d", len(wire1), len(wire2))
			}
		})
	}
}

// TestMagnetar_Wire_GroupKeyRoundtrip mirrors the signature
// round-trip for the group-key (MAGG) frame.
func TestMagnetar_Wire_GroupKeyRoundtrip(t *testing.T) {
	for _, mode := range []Mode{ModeM192s, ModeM192f, ModeM256s} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			body := make([]byte, params.PublicKeySize)
			if _, err := rand.Read(body); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			pk := &PublicKey{Mode: mode, Bytes: append([]byte{}, body...)}

			wire1, err := MarshalGroupKey(pk)
			if err != nil {
				t.Fatalf("MarshalGroupKey: %v", err)
			}
			if got := len(wire1); got != wireFixedGroupKeyHeader+params.PublicKeySize {
				t.Fatalf("wire length %d != header(%d) + payload(%d)",
					got, wireFixedGroupKeyHeader, params.PublicKeySize)
			}

			parsed, err := UnmarshalGroupKey(wire1)
			if err != nil {
				t.Fatalf("UnmarshalGroupKey: %v", err)
			}
			if parsed.Mode != mode {
				t.Fatalf("parsed.Mode = %v want %v", parsed.Mode, mode)
			}
			if !bytes.Equal(parsed.Bytes, body) {
				t.Fatalf("parsed.Bytes diverged from input")
			}

			wire2, err := MarshalGroupKey(parsed)
			if err != nil {
				t.Fatalf("re-MarshalGroupKey: %v", err)
			}
			if !bytes.Equal(wire1, wire2) {
				t.Fatalf("re-marshal not byte-equal: %d vs %d", len(wire1), len(wire2))
			}
		})
	}
}

// TestMagnetar_Wire_FIPS205Verifiable is THE HEADLINE
// cryptographic claim of the wire codec: a Magnetar Signature
// produced by the v0.5 per-validator standalone primary path
// (ValidatorSign), after MarshalBinary + payload extraction,
// verifies under cloudflare/circl's FIPS 205 slhdsa.Verify with NO
// magnetar code path involved on the verifier side.
//
// This is the Class N1 analog in test form: the threshold
// orchestration layer can hand wire bytes to a relying party that
// has never heard of Magnetar, and that party — with only a FIPS
// 205 SLH-DSA verifier and the documented MAGS / MAGG frame —
// verifies the signature.
//
// For every magnetar mode we run the v0.5 per-validator standalone
// primary path: PerValidatorKeypair + ValidatorSign. The output is
// FIPS 205 SignDeterministic when rng is nil (sign.go:91; see
// magnetar README §"FIPS 205 byte-identity").
//
// We DO NOT silently fall back to slhdsa.GenerateKey + priv.SignCtx
// here — if magnetar's v0.5 primary path failed to produce a
// byte-identical FIPS 205 signature, that would be a real finding
// for the cryptographer, not something to mask.
func TestMagnetar_Wire_FIPS205Verifiable(t *testing.T) {
	skipUnderRace(t)
	for _, mode := range []Mode{ModeM192s, ModeM192f, ModeM256s} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)

			// 1. Generate via the v0.5 per-validator standalone primary
			//    path — this is the MPC code path the magnetar audit
			//    cares about, even though "MPC" here is the public-BFT
			//    per-validator-standalone shape (each validator runs
			//    PerValidatorKeypair independently; the consensus layer
			//    aggregates N signatures separately via
			//    ValidatorAggregateCert).
			seed := []byte("magnetar-wire-fips205-test")
			seed = append(seed, byte(mode))
			sk, pk, err := PerValidatorKeypair(params, newDetReader(seed))
			if err != nil {
				t.Fatalf("PerValidatorKeypair: %v", err)
			}

			msg := []byte("magnetar wire codec — FIPS 205 byte-identity claim")

			// 2. Sign via the v0.5 ValidatorSign primary primitive.
			//    rng=nil → SignDeterministic (deterministic, byte-
			//    identical across calls). This is the magnetar entry
			//    point the consensus layer hits.
			sigBytes, err := ValidatorSign(sk, nil, msg)
			if err != nil {
				t.Fatalf("ValidatorSign: %v", err)
			}
			if len(sigBytes) != params.SignatureSize {
				t.Fatalf("sig length = %d, want %d", len(sigBytes), params.SignatureSize)
			}

			sig := &Signature{Mode: mode, Bytes: sigBytes}

			// 3. Sanity: magnetar's own Verify accepts it (the same
			//    FIPS 205 verifier, but routed through magnetar's
			//    dispatch).
			if err := Verify(params, pk, msg, sig); err != nil {
				t.Fatalf("baseline magnetar Verify failed before wire: %v", err)
			}

			// 4. Frame both via the wire codec.
			gkWire, err := MarshalGroupKey(pk)
			if err != nil {
				t.Fatalf("MarshalGroupKey: %v", err)
			}
			sigWire, err := sig.MarshalBinary()
			if err != nil {
				t.Fatalf("sig.MarshalBinary: %v", err)
			}

			// 5. Extract the FIPS 205 payload from each frame by
			//    skipping the 11-byte header. NO magnetar package code
			//    touches the payload — this is exactly what an external
			//    relying party with a FIPS 205 verifier would do.
			fipsPK := extractFIPS205Payload(t, gkWire, wireMagicMagnetarGroupKey)
			fipsSig := extractFIPS205Payload(t, sigWire, wireMagicMagnetarSig)

			if !bytes.Equal(fipsPK, pk.Bytes) {
				t.Fatalf("MAGG payload != raw FIPS 205 pk bytes — wire codec injected envelope")
			}
			if !bytes.Equal(fipsSig, sigBytes) {
				t.Fatalf("MAGS payload != raw FIPS 205 sig bytes — wire codec injected envelope")
			}

			// 6. Verify under cloudflare/circl directly. No magnetar
			//    code path is hit on the verify side. This is the
			//    load-bearing assertion of byte-identity.
			if !verifyDirectCircl(mode, fipsPK, msg, fipsSig) {
				t.Fatalf("cloudflare/circl FIPS 205 Verify rejected the unwrapped Magnetar bytes — wire codec broke byte-identity")
			}

			// 7. Stateless VerifyBytes path used by thresholdd accepts
			//    the same wire bytes.
			if !VerifyBytes(gkWire, msg, sigWire) {
				t.Fatalf("VerifyBytes rejected a valid signature")
			}

			// 8. Tamper resistance: flip a byte in the sig payload —
			//    direct circl Verify MUST reject, and VerifyBytes must
			//    reject.
			tamperedSig := append([]byte{}, sigWire...)
			tamperedSig[len(tamperedSig)-1] ^= 0x01
			if VerifyBytes(gkWire, msg, tamperedSig) {
				t.Fatalf("VerifyBytes accepted a tampered signature")
			}
			tamperedFIPS := append([]byte{}, fipsSig...)
			tamperedFIPS[len(tamperedFIPS)-1] ^= 0x01
			if verifyDirectCircl(mode, fipsPK, msg, tamperedFIPS) {
				t.Fatalf("circl FIPS 205 Verify accepted a tampered signature")
			}
		})
	}
}

// extractFIPS205Payload strips the wire header from a MAGS or MAGG
// frame and returns the FIPS 205 payload bytes. Asserts the magic
// matches the expected one. Test-only — production wire callers go
// through Signature.UnmarshalBinary / UnmarshalGroupKey.
func extractFIPS205Payload(t *testing.T, wire []byte, wantMagic uint32) []byte {
	t.Helper()
	if len(wire) < wireFixedSigHeader {
		t.Fatalf("wire frame too short: %d", len(wire))
	}
	gotMagic := binary.BigEndian.Uint32(wire[0:4])
	if gotMagic != wantMagic {
		t.Fatalf("magic mismatch: got 0x%08x want 0x%08x", gotMagic, wantMagic)
	}
	version := binary.BigEndian.Uint16(wire[4:6])
	if version != wireVersionV1 {
		t.Fatalf("version mismatch: got %d want %d", version, wireVersionV1)
	}
	declared := binary.BigEndian.Uint32(wire[7:11])
	if int(declared) != len(wire)-wireFixedSigHeader {
		t.Fatalf("declared length %d != payload length %d",
			declared, len(wire)-wireFixedSigHeader)
	}
	return wire[wireFixedSigHeader:]
}

// verifyDirectCircl bypasses every magnetar code path and calls
// cloudflare/circl's FIPS 205 Verify directly. This proves the
// wire codec's body bytes are valid FIPS 205 bytes.
func verifyDirectCircl(mode Mode, pkBytes, msg, sigBytes []byte) bool {
	var id slhdsa.ID
	switch mode {
	case ModeM192s:
		id = slhdsa.SHAKE_192s
	case ModeM192f:
		id = slhdsa.SHAKE_192f
	case ModeM256s:
		id = slhdsa.SHAKE_256s
	default:
		return false
	}
	pk := slhdsa.PublicKey{ID: id}
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return false
	}
	return slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sigBytes, nil)
}

// TestMagnetar_Wire_RejectMalformed exercises every negative path
// the signature parser must catch. Each malformed input must
// surface a typed error from the wire package; no panic, no
// oversized allocation, no payload buffer for invalid magic /
// version / mode / length.
func TestMagnetar_Wire_RejectMalformed(t *testing.T) {
	validSig := func(t *testing.T) []byte {
		t.Helper()
		mode := ModeM192s
		params := MustParamsFor(mode)
		body := make([]byte, params.SignatureSize)
		s := &Signature{Mode: mode, Bytes: body}
		w, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("setup MarshalBinary: %v", err)
		}
		return w
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []byte
		want  error
	}{
		{
			name:  "empty",
			build: func(t *testing.T) []byte { return nil },
			want:  ErrWireFrameTooShort,
		},
		{
			name: "header-only-minus-one",
			build: func(t *testing.T) []byte {
				return make([]byte, wireFixedSigHeader-1)
			},
			want: ErrWireFrameTooShort,
		},
		{
			name: "wrong-magic",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				w[0] = 0xDE
				w[1] = 0xAD
				w[2] = 0xBE
				w[3] = 0xEF
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "group-key-magic-into-sig",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Replace MAGS with MAGG.
				binary.BigEndian.PutUint32(w[0:4], wireMagicMagnetarGroupKey)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "pulsar-sig-magic-rejected",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// PULS = 0x50554C53 — pulsar's signature magic.
				binary.BigEndian.PutUint32(w[0:4], 0x50554C53)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "corona-sig-magic-rejected",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// CORS = 0x434F5253 — corona's signature magic.
				binary.BigEndian.PutUint32(w[0:4], 0x434F5253)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "wrong-version",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				binary.BigEndian.PutUint16(w[4:6], 0xFFFF)
				return w
			},
			want: ErrWireVersionMismatch,
		},
		{
			name: "unknown-mode",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				w[6] = 0xAA // not in {ModeM192s, ModeM192f, ModeM256s}
				return w
			},
			want: ErrWireModeUnknown,
		},
		{
			name: "length-mismatch-mode-192s",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Declared length 999 for ModeM192s — not the canonical 16224.
				binary.BigEndian.PutUint32(w[7:11], 999)
				return w
			},
			want: ErrWireLengthMismatch,
		},
		{
			name: "length-oversized-vs-buffer",
			build: func(t *testing.T) []byte {
				// Manually craft: MAGS, v1, mode=M192s, declared=4 GiB.
				w := make([]byte, wireFixedSigHeader)
				binary.BigEndian.PutUint32(w[0:4], wireMagicMagnetarSig)
				binary.BigEndian.PutUint16(w[4:6], wireVersionV1)
				w[6] = byte(ModeM192s)
				binary.BigEndian.PutUint32(w[7:11], 0xFFFFFFFF)
				return w
			},
			// 4 GiB is not equal to FIPS 205 ModeM192s size; the length
			// mismatch fires before the buffer-bounds check.
			want: ErrWireLengthMismatch,
		},
		{
			name: "trailing-bytes",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				return append(w, 0x00, 0x00, 0x00)
			},
			want: ErrWireTrailingBytes,
		},
		{
			name: "truncated-payload",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Drop the trailing 3 bytes of the payload. The declared
				// length still matches the canonical FIPS 205 size so
				// length-against-mode check passes; the bounded-reader
				// check fires because declared > remaining buffer.
				return w[:len(w)-3]
			},
			want: ErrWireFrameRejected,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var sig Signature
			err := sig.UnmarshalBinary(tc.build(t))
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestMagnetar_Wire_RejectTrailingBytes pins the strict-canonical
// property as a standalone test: exactly one well-formed encoding
// of any (mode, bytes) pair exists.
func TestMagnetar_Wire_RejectTrailingBytes(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	body := make([]byte, params.SignatureSize)
	s := &Signature{Mode: ModeM192s, Bytes: body}
	w, err := s.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// One trailing zero byte must be rejected.
	withTrailing := append(append([]byte{}, w...), 0x00)
	var parsed Signature
	if err := parsed.UnmarshalBinary(withTrailing); !errors.Is(err, ErrWireTrailingBytes) {
		t.Fatalf("expected ErrWireTrailingBytes, got %v", err)
	}

	// Same for GroupKey.
	pkBody := make([]byte, params.PublicKeySize)
	pk := &PublicKey{Mode: ModeM192s, Bytes: pkBody}
	gw, err := MarshalGroupKey(pk)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	gwTrailing := append(append([]byte{}, gw...), 0xFF)
	if _, err := UnmarshalGroupKey(gwTrailing); !errors.Is(err, ErrWireTrailingBytes) {
		t.Fatalf("expected ErrWireTrailingBytes on GroupKey, got %v", err)
	}
}

// TestMagnetar_Wire_GroupKeyRejectMalformed mirrors the signature
// rejection suite for GroupKey. Crucially, a SIGNATURE frame fed
// into the GroupKey parser must be rejected at the magic check —
// domain separation between MAGS and MAGG must be effective.
func TestMagnetar_Wire_GroupKeyRejectMalformed(t *testing.T) {
	validGk := func(t *testing.T) []byte {
		t.Helper()
		mode := ModeM192s
		params := MustParamsFor(mode)
		body := make([]byte, params.PublicKeySize)
		p := &PublicKey{Mode: mode, Bytes: body}
		w, err := MarshalGroupKey(p)
		if err != nil {
			t.Fatalf("setup MarshalGroupKey: %v", err)
		}
		return w
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []byte
		want  error
	}{
		{
			name:  "empty",
			build: func(t *testing.T) []byte { return nil },
			want:  ErrWireFrameTooShort,
		},
		{
			name: "sig-magic-into-groupkey",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint32(w[0:4], wireMagicMagnetarSig)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "pulsar-groupkey-magic-rejected",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				// PULG = 0x50554C47 — pulsar's GroupKey magic.
				binary.BigEndian.PutUint32(w[0:4], 0x50554C47)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "corona-groupkey-magic-rejected",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				// CORG = 0x434F5247 — corona's GroupKey magic.
				binary.BigEndian.PutUint32(w[0:4], 0x434F5247)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "wrong-version",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint16(w[4:6], 0xFFFF)
				return w
			},
			want: ErrWireVersionMismatch,
		},
		{
			name: "unknown-mode",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				w[6] = 0xAA
				return w
			},
			want: ErrWireModeUnknown,
		},
		{
			name: "length-mismatch",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint32(w[7:11], 7)
				return w
			},
			want: ErrWireLengthMismatch,
		},
		{
			name: "trailing-bytes",
			build: func(t *testing.T) []byte {
				return append(validGk(t), 0x00)
			},
			want: ErrWireTrailingBytes,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalGroupKey(tc.build(t))
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestMagnetar_Wire_RejectCrossWire pins the cross-protocol
// rejection contract: feeding pulsar's PULS / PULG bytes or
// corona's CORS / CORG bytes into magnetar's parser must fail at
// the first magic check. This is the audit-load-bearing property
// that the four-byte magic acts as a protocol-family domain
// separator.
func TestMagnetar_Wire_RejectCrossWire(t *testing.T) {
	t.Run("pulsar-PULS-frame-into-magnetar-sig", func(t *testing.T) {
		// Synthesise the smallest valid-looking PULS frame: PULS
		// magic + version=1 + mode=0x41 (P65) + declared FIPS 204
		// ML-DSA-65 sig size 3309 + 3309 zero bytes.
		const pulsarP65SigSize = 3309
		buf := make([]byte, 0, wireFixedSigHeader+pulsarP65SigSize)
		buf = binary.BigEndian.AppendUint32(buf, 0x50554C53) // PULS
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = append(buf, 0x41) // pulsar ModeP65
		buf = binary.BigEndian.AppendUint32(buf, pulsarP65SigSize)
		buf = append(buf, make([]byte, pulsarP65SigSize)...)

		var sig Signature
		err := sig.UnmarshalBinary(buf)
		if !errors.Is(err, ErrWireMagicMismatch) {
			t.Fatalf("expected ErrWireMagicMismatch on PULS frame, got %v", err)
		}
		// VerifyBytes must also reject in the signature slot.
		if VerifyBytes(nil, []byte("msg"), buf) {
			t.Fatalf("VerifyBytes accepted PULS frame in sig slot")
		}
	})

	t.Run("corona-CORS-frame-into-magnetar-sig", func(t *testing.T) {
		// Corona's signature has nested length-prefixed polynomial
		// fields; we don't need a perfectly-formed corona frame, just
		// the canonical four-byte magic + version. Magnetar must
		// reject at the first byte check.
		buf := make([]byte, 0, wireFixedSigHeader+32)
		buf = binary.BigEndian.AppendUint32(buf, 0x434F5253) // CORS
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = append(buf, 0x00)
		buf = binary.BigEndian.AppendUint32(buf, 32)
		buf = append(buf, make([]byte, 32)...)

		var sig Signature
		err := sig.UnmarshalBinary(buf)
		if !errors.Is(err, ErrWireMagicMismatch) {
			t.Fatalf("expected ErrWireMagicMismatch on CORS frame, got %v", err)
		}
	})

	t.Run("pulsar-PULG-frame-into-magnetar-groupkey", func(t *testing.T) {
		const pulsarP65PkSize = 1952
		buf := make([]byte, 0, wireFixedGroupKeyHeader+pulsarP65PkSize)
		buf = binary.BigEndian.AppendUint32(buf, 0x50554C47) // PULG
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = append(buf, 0x41)
		buf = binary.BigEndian.AppendUint32(buf, pulsarP65PkSize)
		buf = append(buf, make([]byte, pulsarP65PkSize)...)

		_, err := UnmarshalGroupKey(buf)
		if !errors.Is(err, ErrWireMagicMismatch) {
			t.Fatalf("expected ErrWireMagicMismatch on PULG frame, got %v", err)
		}
	})

	t.Run("corona-CORG-frame-into-magnetar-groupkey", func(t *testing.T) {
		buf := make([]byte, 0, wireFixedGroupKeyHeader+32)
		buf = binary.BigEndian.AppendUint32(buf, 0x434F5247) // CORG
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = append(buf, 0x00)
		buf = binary.BigEndian.AppendUint32(buf, 32)
		buf = append(buf, make([]byte, 32)...)

		_, err := UnmarshalGroupKey(buf)
		if !errors.Is(err, ErrWireMagicMismatch) {
			t.Fatalf("expected ErrWireMagicMismatch on CORG frame, got %v", err)
		}
	})
}

// TestMagnetar_Wire_VerifyBytes_RejectsCrossSlot exercises the
// dispatcher's contract that wire bytes cannot be swapped between
// slots: a GroupKey-magic frame fed into the signature slot of
// VerifyBytes must produce false. Same for a Signature-magic frame
// fed into the GroupKey slot.
func TestMagnetar_Wire_VerifyBytes_RejectsCrossSlot(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte("magnetar-wire-cross-slot")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair: %v", err)
	}
	msg := []byte("cross-slot rejection")
	sigBytes, err := ValidatorSign(sk, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign: %v", err)
	}
	sig := &Signature{Mode: params.Mode, Bytes: sigBytes}

	gkWire, err := MarshalGroupKey(pk)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	sigWire, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("sig.MarshalBinary: %v", err)
	}

	if !VerifyBytes(gkWire, msg, sigWire) {
		t.Fatalf("baseline VerifyBytes failed")
	}
	// Swap: gkWire in the signature slot. Must reject.
	if VerifyBytes(gkWire, msg, gkWire) {
		t.Fatalf("VerifyBytes accepted GroupKey-magic bytes in signature slot")
	}
	// Swap: sigWire in the group-key slot. Must reject.
	if VerifyBytes(sigWire, msg, sigWire) {
		t.Fatalf("VerifyBytes accepted Signature-magic bytes in group-key slot")
	}
	// nil bytes — must reject without panic.
	if VerifyBytes(nil, msg, sigWire) {
		t.Fatalf("VerifyBytes accepted nil group-key bytes")
	}
	if VerifyBytes(gkWire, msg, nil) {
		t.Fatalf("VerifyBytes accepted nil signature bytes")
	}
	// Wrong message — must reject.
	if VerifyBytes(gkWire, []byte("different message"), sigWire) {
		t.Fatalf("VerifyBytes accepted a wrong message")
	}
}

// TestMagnetar_Wire_ModeMismatch_Rejected ensures the dispatcher's
// VerifyBytes returns false when the parsed GroupKey and Signature
// declare different modes — a relying party must never witness a
// ModeM256s signature verifying under a ModeM192s group key.
func TestMagnetar_Wire_ModeMismatch_Rejected(t *testing.T) {
	skipUnderRace(t)
	// Build a valid sig (ModeM192s) and a valid gk (ModeM256s).
	params192 := MustParamsFor(ModeM192s)
	params256 := MustParamsFor(ModeM256s)

	sk192, _, err := PerValidatorKeypair(params192, newDetReader([]byte("mm-192")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair 192: %v", err)
	}
	_, pk256, err := PerValidatorKeypair(params256, newDetReader([]byte("mm-256")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair 256: %v", err)
	}

	msg := []byte("mode mismatch test")
	sig192Bytes, err := ValidatorSign(sk192, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign 192: %v", err)
	}
	sig192 := &Signature{Mode: params192.Mode, Bytes: sig192Bytes}

	gk256Wire, err := MarshalGroupKey(pk256)
	if err != nil {
		t.Fatalf("MarshalGroupKey 256: %v", err)
	}
	sig192Wire, err := sig192.MarshalBinary()
	if err != nil {
		t.Fatalf("sig192.MarshalBinary: %v", err)
	}
	if VerifyBytes(gk256Wire, msg, sig192Wire) {
		t.Fatalf("VerifyBytes accepted cross-mode (gk=M256s, sig=M192s)")
	}
}

// TestMagnetar_Wire_MarshalSafetyChecks ensures Marshal refuses
// inputs that would emit malformed frames: nil receiver, unknown
// mode, length-vs-mode mismatch.
func TestMagnetar_Wire_MarshalSafetyChecks(t *testing.T) {
	t.Run("nil-signature", func(t *testing.T) {
		var s *Signature
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("nil Signature.MarshalBinary did not return error")
		}
	})
	t.Run("nil-publickey", func(t *testing.T) {
		if _, err := MarshalGroupKey(nil); err == nil {
			t.Fatal("nil MarshalGroupKey did not return error")
		}
	})
	t.Run("sig-unknown-mode", func(t *testing.T) {
		s := &Signature{Mode: Mode(0xAA), Bytes: make([]byte, 16224)}
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("unknown-mode Signature.MarshalBinary did not return error")
		}
	})
	t.Run("sig-wrong-length", func(t *testing.T) {
		s := &Signature{Mode: ModeM192s, Bytes: make([]byte, 999)}
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("wrong-length Signature.MarshalBinary did not return error")
		}
	})
	t.Run("gk-wrong-length", func(t *testing.T) {
		p := &PublicKey{Mode: ModeM192s, Bytes: make([]byte, 99)}
		if _, err := MarshalGroupKey(p); err == nil {
			t.Fatal("wrong-length MarshalGroupKey did not return error")
		}
	})
}

// TestMagnetar_Wire_VerifyBytesCtx_RoundTrip exercises the
// context-aware verifier with a non-nil ctx, the path the EVM
// precompile takes. Same sign-vs-verify ctx → accept; different
// ctx → reject.
func TestMagnetar_Wire_VerifyBytesCtx_RoundTrip(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte("magnetar-wire-ctx")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair: %v", err)
	}
	msg := []byte("ctx-aware verify")
	ctx := []byte("lux-evm-precompile-magnetar-v1")

	// Sign with explicit ctx via the package-level Sign (the entry
	// point ValidatorSign documents for the ctx case).
	sig, err := Sign(params, sk, msg, ctx, false, nil)
	if err != nil {
		t.Fatalf("Sign with ctx: %v", err)
	}

	gkWire, err := MarshalGroupKey(pk)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	sigWire, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("sig.MarshalBinary: %v", err)
	}

	if !VerifyBytesCtx(gkWire, msg, ctx, sigWire) {
		t.Fatalf("VerifyBytesCtx rejected a valid ctx-bound signature")
	}
	// Empty ctx must NOT verify (the sign used a non-empty ctx).
	if VerifyBytes(gkWire, msg, sigWire) {
		t.Fatalf("VerifyBytes (empty ctx) accepted a ctx-bound signature")
	}
	// Different ctx must NOT verify.
	if VerifyBytesCtx(gkWire, msg, []byte("different ctx"), sigWire) {
		t.Fatalf("VerifyBytesCtx accepted a wrong ctx")
	}
	// Over-long ctx must NOT verify (≤255 bytes per FIPS 205).
	if VerifyBytesCtx(gkWire, msg, make([]byte, 256), sigWire) {
		t.Fatalf("VerifyBytesCtx accepted an over-long ctx")
	}
}

// TestSlhVerify_TotalOverUnknownMode pins that verification is total over its
// mode input: an unknown mode resolves to the zero (invalid) id, and slhVerify
// under it returns false rather than handing a non-scheme to circl, which panics.
func TestSlhVerify_TotalOverUnknownMode(t *testing.T) {
	if slhdsaIDForMode(Mode(0x7F)) != 0 {
		t.Fatal("an unknown mode must resolve to the zero (invalid) id")
	}
	if slhVerify(slhdsaIDForMode(Mode(0x7F)), make([]byte, 48), nil, nil, make([]byte, 16224)) {
		t.Fatal("verification under an unknown scheme must return false")
	}
}
