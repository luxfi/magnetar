// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// sign.go --- single-party signing. The single-party path is consumed
// by both the per-validator standalone primitive (ValidatorSign in
// standalone.go) and by the THBS-SE PUBLIC COMBINER (Combine in
// thbsse.go), via slhSignDeterministic. Each consumer routes through
// circl/slhdsa as the FIPS 205 signing primitive.
//
// The THBS-SE byte-identity claim rides on FIPS 205 SignDeterministic
// being a pure function of (sk, message, ctx): a public combiner that
// reconstructs the same scheme seed and routes through this Sign call
// emits the same wire bytes any FIPS 205 verifier accepts.

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Errors returned by signing.
var (
	ErrCtxTooLong  = errors.New("magnetar: context string longer than 255 bytes")
	ErrSignFailure = errors.New("magnetar: FIPS 205 signing failed")
	ErrNilKey      = errors.New("magnetar: nil key")
)

// Sign produces a FIPS 205 SLH-DSA signature on message under the
// supplied private key.
//
// ctx is the FIPS 205 §10.2 context string (0..255 bytes); pass
// nil for the empty context. randomized chooses between the hedged
// and deterministic signing variants — deterministic (false) is
// the KAT-reproducible variant.
//
// If rng is nil and randomized is true, crypto/rand.Reader is used.
// Pass a deterministic reader for KAT reproducibility.
func Sign(params *Params, sk *PrivateKey, message, ctx []byte, randomized bool, rng io.Reader) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, ErrNilKey
	}
	if sk.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(ctx) > 255 {
		return nil, ErrCtxTooLong
	}
	if rng == nil {
		rng = rand.Reader
	}
	sigBytes, err := slhSign(params.ID, sk.Bytes, message, ctx, randomized, rng)
	if err != nil {
		return nil, err
	}
	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

// SignCtx is the FIPS 205 context-aware Sign convenience wrapper.
// Equivalent to Sign with ctx != nil.
func SignCtx(params *Params, sk *PrivateKey, message, ctx []byte, randomized bool, rng io.Reader) (*Signature, error) {
	return Sign(params, sk, message, ctx, randomized, rng)
}

// slhSign dispatches to circl/slhdsa for the given parameter ID
// and returns the packed signature.
//
// circl's slhdsa.SignDeterministic produces signatures that are
// byte-identical across calls for the same (sk, message, ctx).
// SignRandomized adds a fresh n-byte randomness from the supplied
// reader; with a deterministic reader it remains reproducible.
//
// THBS-SE always uses randomized=false (via slhSignDeterministic in
// thbsse.go) to guarantee byte-identity: any t valid Round-2 reveals
// produce the same final signature, so the PUBLIC COMBINER is a pure
// function of its inputs and disjoint sub-quora produce the same wire
// bytes.
func slhSign(id slhdsa.ID, packedSk, message, ctx []byte, randomized bool, rng io.Reader) ([]byte, error) {
	priv := slhdsa.PrivateKey{ID: id}
	if err := priv.UnmarshalBinary(packedSk); err != nil {
		return nil, err
	}
	msg := slhdsa.NewMessage(message)
	if randomized {
		return slhdsa.SignRandomized(&priv, rng, msg, ctx)
	}
	return slhdsa.SignDeterministic(&priv, msg, ctx)
}
