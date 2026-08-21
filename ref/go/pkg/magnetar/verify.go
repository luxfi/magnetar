// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// verify.go --- the canonical consensus-consumer entry point.
//
// Verify literally dispatches to circl/slhdsa.Verify, the FIPS 205
// sec 10.3 verifier verbatim. No Magnetar-specific logic; no
// threshold-specific extension fields; no envelope. A signature
// produced by ValidatorSign (per-validator standalone, standalone.go),
// by Combine (THBS-SE public combiner, thbsse.go), or by a sibling
// single-party FIPS 205 toolchain flows through the SAME Verify code
// path and produces the same accept/reject result.
//
// Any change to Verify breaks the wire-identity claim that ties
// Magnetar to unmodified FIPS 205.

import (
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Verification errors. Returning a typed error rather than a panic
// is mandated by the no-panic-in-verify-path discipline.
var (
	// ErrInvalidSignature is returned when the signature does not
	// verify under FIPS 205 SLH-DSA.Verify(pk, message, signature).
	ErrInvalidSignature = errors.New("magnetar: signature verification failed")

	// ErrSignatureWrongSize is returned when the signature byte
	// length does not match the expected FIPS 205 signature size
	// for the params.Mode.
	ErrSignatureWrongSize = errors.New("magnetar: signature wrong size")

	// ErrPublicKeyWrongSize is returned when the public-key byte
	// length does not match the expected FIPS 205 public-key size.
	ErrPublicKeyWrongSize = errors.New("magnetar: public-key wrong size")

	// ErrNilSignature is returned when sig is nil.
	ErrNilSignature = errors.New("magnetar: nil signature")

	// ErrNilPublicKey is returned when groupPubkey is nil.
	ErrNilPublicKey = errors.New("magnetar: nil public key")
)

// Verify is the canonical consensus-consumer entry point for
// Magnetar signature verification.
//
// Returns nil if the signature is valid under FIPS 205 SLH-DSA.Verify;
// a typed error otherwise. Never panics: caller code in the consensus
// path can call Verify in a hot loop without a recover() shroud.
//
// ctx is the FIPS 205 context string (≤255 bytes); pass nil for the
// empty context. Match this to whatever was passed at Sign time.
//
// This function MUST remain a thin dispatch over the FIPS 205
// verifier. Adding logic here breaks output interchangeability with
// unmodified FIPS 205 verifiers (cloudflare/circl, NIST FIPS 205
// reference, openssl-pq) --- the wire-identity claim that lets any
// peer verify Magnetar signatures without a Magnetar dependency.
func Verify(params *Params, groupPubkey *PublicKey, message []byte, sig *Signature) error {
	return VerifyCtx(params, groupPubkey, message, nil, sig)
}

// VerifyCtx is the context-aware variant of Verify. The FIPS 205
// context string ctx (≤255 bytes) is included in the verification
// transcript per FIPS 205 §10.3.
func VerifyCtx(params *Params, groupPubkey *PublicKey, message, ctx []byte, sig *Signature) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if groupPubkey == nil {
		return ErrNilPublicKey
	}
	if sig == nil {
		return ErrNilSignature
	}
	if groupPubkey.Mode != params.Mode {
		return ErrModeMismatch
	}
	if sig.Mode != params.Mode {
		return ErrModeMismatch
	}
	if len(groupPubkey.Bytes) != params.PublicKeySize {
		return ErrPublicKeyWrongSize
	}
	if len(sig.Bytes) != params.SignatureSize {
		return ErrSignatureWrongSize
	}
	if len(ctx) > 255 {
		return ErrCtxTooLong
	}

	if !slhVerify(params.ID, groupPubkey.Bytes, message, ctx, sig.Bytes) {
		return ErrInvalidSignature
	}
	return nil
}

// slhVerify dispatches to circl/slhdsa.Verify for the given
// parameter ID. This is the only place outside keygen/sign/Combine
// that touches the FIPS 205 implementation; centralising it makes
// the wire-identity dispatch auditable as a single function.
func slhVerify(id slhdsa.ID, packedPk, message, ctx, sig []byte) bool {
	// id 0 is the sentinel slhdsaIDForMode returns for an unknown mode; it is not
	// a scheme, and handing it to circl panics. A verifier must be total over its
	// inputs — an unrecognised mode is a failed verification, not a crash.
	if id == 0 {
		return false
	}
	pk := slhdsa.PublicKey{ID: id}
	if err := pk.UnmarshalBinary(packedPk); err != nil {
		return false
	}
	return slhdsa.Verify(&pk, slhdsa.NewMessage(message), sig, ctx)
}
