// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// wire.go — canonical wire codec for Signature and PublicKey (the
// group public key, in a MAGG frame) plus a stateless VerifyBytes
// helper that any independent peer can call given only:
//
//   - the wire bytes of the group public key (MAGG-framed),
//   - the bytes of the message that was signed,
//   - the wire bytes of the signature (MAGS-framed),
//
// and obtain a bool answer with no additional state. This is the
// surface luxfi/threshold/pkg/thresholdd consumes to publish
// Magnetar outputs over a JSON-RPC bus — and the surface independent
// verifiers (other mpcd, bridge nodes, L1 verifier contracts) must
// satisfy.
//
// The Class N1 analog of Magnetar (see verify.go, README §"FIPS 205
// byte-identity") is that a Magnetar Signature is bit-identical to a
// single-party FIPS 205 SLH-DSA signature on the same (message,
// group public key) tuple. The wire codec preserves this property
// by transporting the FIPS 205 bytes verbatim inside a small
// domain-separated frame. A relying party that strips the MAGS /
// MAGG frame obtains the FIPS 205 wire bytes that
// cloudflare/circl's slhdsa.Verify accepts unmodified — this is
// what TestMagnetar_Wire_FIPS205Verifiable asserts.
//
// Wire frame layout (big-endian throughout):
//
//	Signature:
//	  magic(4) = 'M' 'A' 'G' 'S' = 0x4D414753
//	  version(2) = 0x0001
//	  mode(1)    = 0x01 | 0x02 | 0x03   (M192s | M192f | M256s)
//	  len(4)     = FIPS 205 SignatureSize for mode
//	               (16224 | 35664 | 29792)
//	  payload    = len bytes — the FIPS 205 sigEncode output
//
//	GroupKey:
//	  magic(4) = 'M' 'A' 'G' 'G' = 0x4D414747
//	  version(2) = 0x0001
//	  mode(1)    = 0x01 | 0x02 | 0x03
//	  len(4)     = FIPS 205 PublicKeySize for mode (48 | 48 | 64)
//	  payload    = len bytes — the FIPS 205 (PK.seed || PK.root) bytes
//
// Domain separation: the four-byte magic is distinct from pulsar's
// PULS / PULG (0x50554C53 / 0x50554C47) and corona's CORS / CORG
// (0x434F5253 / 0x434F5247), so a frame from any sibling protocol
// fed into the magnetar parser is rejected at the first dispatch
// and vice versa. Distinct magic per type within magnetar means a
// GroupKey frame fed into the signature slot is rejected before any
// length-decode is attempted.
//
// Bounded reads: every length-prefix read is checked against the
// remaining bytes in the reader BEFORE any allocation. Beyond that,
// the wire codec also pins the declared FIPS 205 length to the
// canonical value for the Mode — a malformed frame that claims a
// 4 GiB signature for ModeM192s is rejected without allocating any
// buffer. Any wire-format change (additional field, version flip)
// bumps wireVersionV1.
//
// Trailing garbage policy: STRICT — UnmarshalBinary returns an
// error if any byte remains after the declared frame. Mirrors
// pulsar/wire.go and corona/wire.go.
//
// Version-bump rule: any byte-level change to the layout (new
// field, reordered fields, bigger length prefix, additional FIPS
// 205 mode beyond the magnetar canonical set) requires bumping
// wireVersionV1. The Mode byte is independent — adding ModeM192s /
// ModeM192f / ModeM256s alternates does NOT bump the version
// because Mode is a structural payload selector, not a format
// change.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Wire-format identifiers. Distinct from pulsar's PULS / PULG and
// corona's CORS / CORG so the parsers cannot cross-accept and a
// passive observer can tell from the first four bytes which
// protocol the payload belongs to.
const (
	wireMagicMagnetarSig      uint32 = 0x4D414753 // "MAGS" Magnetar Signature
	wireMagicMagnetarGroupKey uint32 = 0x4D414747 // "MAGG" Magnetar GroupKey
	wireVersionV1             uint16 = 1
)

// Errors returned by the wire codec. Typed for errors.Is matching
// in callers (the dispatcher, downstream relying parties, fuzzers).
var (
	ErrWireMagicMismatch   = errors.New("magnetar/wire: magic mismatch")
	ErrWireVersionMismatch = errors.New("magnetar/wire: version mismatch")
	ErrWireFrameTooShort   = errors.New("magnetar/wire: frame too short")
	ErrWireFrameRejected   = errors.New("magnetar/wire: frame rejected by bounded reader")
	ErrWireModeUnknown     = errors.New("magnetar/wire: unknown mode byte")
	ErrWireLengthMismatch  = errors.New("magnetar/wire: declared length does not match FIPS 205 size for mode")
	ErrWireTrailingBytes   = errors.New("magnetar/wire: trailing bytes after frame")
)

// wireFixedSigHeader is magic(4) + version(2) + mode(1) + len(4).
const wireFixedSigHeader = 4 + 2 + 1 + 4

// wireFixedGroupKeyHeader has the same shape as wireFixedSigHeader.
const wireFixedGroupKeyHeader = wireFixedSigHeader

// MarshalBinary serialises a Signature into the canonical MAGS frame.
//
// The body bytes are the FIPS 205 sigEncode output verbatim —
// Magnetar adds NO envelope around them. Stripping the 11-byte
// header recovers the unmodified FIPS 205 bytes that
// cloudflare/circl's slhdsa.Verify accepts. This is the
// load-bearing property TestMagnetar_Wire_FIPS205Verifiable pins.
//
// Returns an error if the Signature's Mode is unknown, its Bytes
// field does not match the FIPS 205 size for the Mode, or the
// Signature receiver is nil.
func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil {
		return nil, errors.New("magnetar: nil Signature")
	}
	sigSize, err := wireSigSizeForMode(s.Mode)
	if err != nil {
		return nil, fmt.Errorf("magnetar/wire: %w", err)
	}
	if len(s.Bytes) != sigSize {
		return nil, fmt.Errorf("magnetar/wire: Signature.Bytes length %d != FIPS 205 size %d for %s",
			len(s.Bytes), sigSize, s.Mode)
	}

	out := make([]byte, 0, wireFixedSigHeader+sigSize)
	out = binary.BigEndian.AppendUint32(out, wireMagicMagnetarSig)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = append(out, byte(s.Mode))
	out = binary.BigEndian.AppendUint32(out, uint32(sigSize))
	out = append(out, s.Bytes...)
	return out, nil
}

// UnmarshalBinary parses a Signature from canonical MAGS frame.
//
// Validation order is strict: magic, version, mode, length-against-
// FIPS 205-size are all checked BEFORE any payload bytes are read.
// The codec never allocates a payload buffer larger than the canonical
// FIPS 205 signature size for the declared mode, so a malformed length
// header cannot trigger an oversized allocation.
//
// Trailing bytes after the frame are rejected (ErrWireTrailingBytes)
// to keep the format strictly canonical — there is exactly one
// well-formed encoding of any (mode, bytes) pair.
func (s *Signature) UnmarshalBinary(b []byte) error {
	if s == nil {
		return errors.New("magnetar: nil Signature receiver")
	}
	if len(b) < wireFixedSigHeader {
		return ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("magnetar/wire: read magic: %w", err)
	}
	if magic != wireMagicMagnetarSig {
		return fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicMagnetarSig)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("magnetar/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	modeByte, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("magnetar/wire: read mode: %w", err)
	}
	mode := Mode(modeByte)
	sigSize, err := wireSigSizeForMode(mode)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWireModeUnknown, err)
	}

	var declared uint32
	if err := binary.Read(r, binary.BigEndian, &declared); err != nil {
		return fmt.Errorf("magnetar/wire: read length: %w", err)
	}
	// Bounded read: declared length must equal the canonical FIPS 205
	// size for the mode AND must not exceed the remaining buffer.
	// Both checks happen BEFORE the payload allocation.
	if int(declared) != sigSize {
		return fmt.Errorf("%w: declared %d, FIPS 205 size for %s is %d",
			ErrWireLengthMismatch, declared, mode, sigSize)
	}
	if int(declared) > r.Len() {
		return fmt.Errorf("%w: declared length %d exceeds remaining %d",
			ErrWireFrameRejected, declared, r.Len())
	}

	payload := make([]byte, declared)
	if _, err := r.Read(payload); err != nil {
		return fmt.Errorf("magnetar/wire: read payload: %w", err)
	}
	if r.Len() != 0 {
		return fmt.Errorf("%w: %d bytes remaining", ErrWireTrailingBytes, r.Len())
	}

	s.Mode = mode
	s.Bytes = payload
	return nil
}

// MarshalGroupKey serialises a PublicKey (used on the wire as the
// group public key) into the canonical MAGG frame.
//
// The body bytes are the FIPS 205 public-key encoding (PK.seed ||
// PK.root, per §10.1) verbatim — Magnetar adds NO envelope around
// them. Stripping the 11-byte header recovers the unmodified FIPS
// 205 public-key bytes that cloudflare/circl's
// slhdsa.PublicKey.UnmarshalBinary accepts.
//
// A method on *PublicKey would collide with potential SDK-side
// MarshalBinary on the same type, so the canonical group-key wire
// emitter is a package-level function. This mirrors how the
// distinction between PublicKey-as-validator-pk and
// PublicKey-as-group-pk is documentary only (types.go: GroupKey =
// PublicKey alias) — the wire emitter encodes the intent.
//
// Returns an error if the PublicKey's Mode is unknown, its Bytes
// field does not match the FIPS 205 size for the Mode, or the
// PublicKey is nil.
func MarshalGroupKey(p *PublicKey) ([]byte, error) {
	if p == nil {
		return nil, errors.New("magnetar: nil GroupKey")
	}
	pkSize, err := wirePubKeySizeForMode(p.Mode)
	if err != nil {
		return nil, fmt.Errorf("magnetar/wire: %w", err)
	}
	if len(p.Bytes) != pkSize {
		return nil, fmt.Errorf("magnetar/wire: GroupKey.Bytes length %d != FIPS 205 size %d for %s",
			len(p.Bytes), pkSize, p.Mode)
	}

	out := make([]byte, 0, wireFixedGroupKeyHeader+pkSize)
	out = binary.BigEndian.AppendUint32(out, wireMagicMagnetarGroupKey)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = append(out, byte(p.Mode))
	out = binary.BigEndian.AppendUint32(out, uint32(pkSize))
	out = append(out, p.Bytes...)
	return out, nil
}

// UnmarshalGroupKey parses a PublicKey from canonical MAGG frame.
//
// Validation order matches Signature.UnmarshalBinary: magic,
// version, mode, length-against-FIPS 205-size are all checked
// BEFORE any payload bytes are read. Trailing bytes after the
// frame are rejected.
func UnmarshalGroupKey(b []byte) (*PublicKey, error) {
	if len(b) < wireFixedGroupKeyHeader {
		return nil, ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("magnetar/wire: read magic: %w", err)
	}
	if magic != wireMagicMagnetarGroupKey {
		return nil, fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicMagnetarGroupKey)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("magnetar/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	modeByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("magnetar/wire: read mode: %w", err)
	}
	mode := Mode(modeByte)
	pkSize, err := wirePubKeySizeForMode(mode)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWireModeUnknown, err)
	}

	var declared uint32
	if err := binary.Read(r, binary.BigEndian, &declared); err != nil {
		return nil, fmt.Errorf("magnetar/wire: read length: %w", err)
	}
	if int(declared) != pkSize {
		return nil, fmt.Errorf("%w: declared %d, FIPS 205 size for %s is %d",
			ErrWireLengthMismatch, declared, mode, pkSize)
	}
	if int(declared) > r.Len() {
		return nil, fmt.Errorf("%w: declared length %d exceeds remaining %d",
			ErrWireFrameRejected, declared, r.Len())
	}

	payload := make([]byte, declared)
	if _, err := r.Read(payload); err != nil {
		return nil, fmt.Errorf("magnetar/wire: read payload: %w", err)
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("%w: %d bytes remaining", ErrWireTrailingBytes, r.Len())
	}

	return &PublicKey{Mode: mode, Bytes: payload}, nil
}

// VerifyBytes is the stateless verifier the threshold orchestration
// layer (luxfi/threshold/pkg/thresholdd) needs to publish a
// signature over a JSON-RPC bus: it accepts the canonical wire
// bytes of a GroupKey (MAGG frame) and a Signature (MAGS frame)
// plus the message that was signed, and returns true iff the
// signature verifies under the group key.
//
// Rejection of any malformed input returns false (NOT an error) —
// the dispatcher distinguishes "no valid signature" from
// "infrastructure error" via its JSON-RPC envelope; bytes-in,
// bool-out keeps this helper pure. The signature MUST verify under
// the FIPS 205 verifier verbatim (no Magnetar envelope) — this
// matches the Class N1 analog.
//
// Mode mismatch between the parsed Signature and parsed GroupKey
// is treated as verification failure (returns false). This keeps
// the helper allocation-free of any cross-mode dispatch surprises.
//
// Empty context: VerifyBytes calls FIPS 205 Verify with an empty
// context string. Callers needing the FIPS 205 §10.3 context
// binding (e.g. the EVM precompile's
// "lux-evm-precompile-magnetar-v1" tag) must use VerifyBytesCtx.
// The unbound helper stays narrow so the dispatcher remains a thin
// proxy.
func VerifyBytes(gpkBytes, message, sigBytes []byte) bool {
	return VerifyBytesCtx(gpkBytes, message, nil, sigBytes)
}

// VerifyBytesCtx is the context-aware variant of VerifyBytes. The
// FIPS 205 context string ctx (≤255 bytes) is included in the
// verification transcript per FIPS 205 §10.3. Callers MUST pass the
// SAME ctx that was supplied at Sign time; a different ctx (or nil
// where the signer used non-nil) returns false.
//
// This is the path the on-chain precompile and any contextual
// verifier (consensus block-binding tags, validator-set epoch tags)
// take.
func VerifyBytesCtx(gpkBytes, message, ctx, sigBytes []byte) bool {
	gk, err := UnmarshalGroupKey(gpkBytes)
	if err != nil {
		return false
	}
	var sig Signature
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return false
	}
	if gk.Mode != sig.Mode {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	return slhVerify(slhdsaIDForMode(gk.Mode), gk.Bytes, message, ctx, sig.Bytes)
}

// slhdsaIDForMode returns the circl/slhdsa.ID for a magnetar Mode.
// Centralised here so the wire codec does not transitively depend
// on the params.go table — the codec carries its own canonical
// mapping so a corrupted Params can never confuse the parser.
func slhdsaIDForMode(mode Mode) slhdsa.ID {
	switch mode {
	case ModeM192s:
		return slhdsa.SHAKE_192s
	case ModeM192f:
		return slhdsa.SHAKE_192f
	case ModeM256s:
		return slhdsa.SHAKE_256s
	default:
		return 0
	}
}

// wireSigSizeForMode returns the FIPS 205 signature size for the
// declared mode, or an error if the mode is unrecognised.
// Centralising this here means the wire codec does not depend on
// params.go's table — the codec carries its own canonical numbers
// so a corrupted Params can never confuse the parser.
func wireSigSizeForMode(mode Mode) (int, error) {
	switch mode {
	case ModeM192s:
		return 16224, nil
	case ModeM192f:
		return 35664, nil
	case ModeM256s:
		return 29792, nil
	default:
		return 0, fmt.Errorf("mode 0x%02x", byte(mode))
	}
}

// wirePubKeySizeForMode returns the FIPS 205 public-key size for
// the declared mode.
func wirePubKeySizeForMode(mode Mode) (int, error) {
	switch mode {
	case ModeM192s:
		return 48, nil
	case ModeM192f:
		return 48, nil
	case ModeM256s:
		return 64, nil
	default:
		return 0, fmt.Errorf("mode 0x%02x", byte(mode))
	}
}
