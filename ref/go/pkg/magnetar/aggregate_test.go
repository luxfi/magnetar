// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// aggregate_test.go — tests for the public-BFT-safe N-of-N
// collected-signatures API.
//
// These tests exercise the AggregateSignatures path:
//
//   - GenerateValidatorKey: per-validator standalone keypair
//     production (no DKG).
//   - SignBundle / VerifyBundle: single-validator round-trip.
//   - AggregateSignatures: dedupe + shape-check the N-bundle wire
//     envelope.
//   - VerifyAggregated: per-bundle Verify with parallel-CPU
//     dispatch, returns the COUNT of valid signers.
//   - Provenance: confirm the parallel goroutine path is exercised
//     above verifyAggregatedConcurrentThreshold, mirroring
//     luxfi/crypto/slhdsa.GetProvenance() in spirit.

import (
	"bytes"
	"testing"
)

func TestSignBundle_RoundTrip(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	sk, pk, err := GenerateValidatorKey(params, newDetReader([]byte("aggregate-rt-1")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey: %v", err)
	}
	var vid NodeID
	copy(vid[:], []byte("VALIDATOR-ALPHA"))

	msg := []byte("Magnetar aggregate-mode single-validator round-trip")
	bundle, err := SignBundle(params, sk, vid, msg)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if bundle.ValidatorID != vid {
		t.Fatalf("bundle.ValidatorID = %x, want %x", bundle.ValidatorID[:], vid[:])
	}
	if len(bundle.PublicKey) != params.PublicKeySize {
		t.Fatalf("bundle.PublicKey len = %d, want %d", len(bundle.PublicKey), params.PublicKeySize)
	}
	if !bytes.Equal(bundle.PublicKey, pk.Bytes) {
		t.Fatalf("bundle.PublicKey does not match generated pk")
	}
	if len(bundle.Signature) != params.SignatureSize {
		t.Fatalf("bundle.Signature len = %d, want %d", len(bundle.Signature), params.SignatureSize)
	}
	if !VerifyBundle(params, bundle, msg) {
		t.Fatalf("VerifyBundle failed on freshly-signed bundle")
	}
	// Negative: flip a byte.
	bad := *bundle
	badSig := make([]byte, len(bundle.Signature))
	copy(badSig, bundle.Signature)
	badSig[len(badSig)/2] ^= 0x01
	bad.Signature = badSig
	if VerifyBundle(params, &bad, msg) {
		t.Fatalf("VerifyBundle accepted tampered signature")
	}
	// Negative: wrong message.
	if VerifyBundle(params, bundle, []byte("different message")) {
		t.Fatalf("VerifyBundle accepted signature against wrong message")
	}
}

func TestAggregateSignatures_5of5(t *testing.T) {
	skipUnderRace(t)
	// 5 validators sign the same message under their OWN keypairs;
	// AggregateSignatures collects them; VerifyAggregated returns
	// count=5.
	params := MustParamsFor(ModeM192s)
	const N = 5

	type validator struct {
		id NodeID
		sk *PrivateKey
		pk *PublicKey
	}
	vs := make([]validator, N)
	known := make(map[NodeID][]byte, N)
	for i := 0; i < N; i++ {
		sk, pk, err := GenerateValidatorKey(params, newDetReader([]byte{byte(i), 'A', 'G', 'G'}))
		if err != nil {
			t.Fatalf("GenerateValidatorKey[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("VALIDATOR"))
		vs[i] = validator{id: id, sk: sk, pk: pk}
		known[id] = pk.Bytes
	}

	msg := []byte("Magnetar aggregate-mode 5-of-5 public-BFT scenario")
	bundles := make([]*SignedBundle, N)
	for i, v := range vs {
		b, err := SignBundle(params, v.sk, v.id, msg)
		if err != nil {
			t.Fatalf("SignBundle[%d]: %v", i, err)
		}
		bundles[i] = b
	}

	agg, err := AggregateSignatures(params, bundles, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}
	if len(agg.Bundles) != N {
		t.Fatalf("agg.Bundles len = %d, want %d", len(agg.Bundles), N)
	}
	if !bytes.Equal(agg.Message, msg) {
		t.Fatalf("agg.Message does not match input")
	}

	count, err := VerifyAggregated(params, agg, known)
	if err != nil {
		t.Fatalf("VerifyAggregated: %v", err)
	}
	if count != N {
		t.Fatalf("VerifyAggregated count = %d, want %d", count, N)
	}
}

func TestVerifyAggregated_BadSig_Counted_Out(t *testing.T) {
	skipUnderRace(t)
	// 5 validators sign; corrupt ONE bundle's signature; verify
	// returns count=4 (not 5) but does NOT error — the bad
	// signature is counted out, not fatal.
	params := MustParamsFor(ModeM192s)
	const N = 5

	type validator struct {
		id NodeID
		sk *PrivateKey
		pk *PublicKey
	}
	vs := make([]validator, N)
	known := make(map[NodeID][]byte, N)
	for i := 0; i < N; i++ {
		sk, pk, err := GenerateValidatorKey(params, newDetReader([]byte{byte(i), 'B', 'A', 'D'}))
		if err != nil {
			t.Fatalf("GenerateValidatorKey[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("BAD-SIG-TEST"))
		vs[i] = validator{id: id, sk: sk, pk: pk}
		known[id] = pk.Bytes
	}

	msg := []byte("Magnetar aggregate-mode bad-sig-counted-out scenario")
	bundles := make([]*SignedBundle, N)
	for i, v := range vs {
		b, err := SignBundle(params, v.sk, v.id, msg)
		if err != nil {
			t.Fatalf("SignBundle[%d]: %v", i, err)
		}
		bundles[i] = b
	}
	// Corrupt bundles[2]'s signature.
	corruptIdx := 2
	bundles[corruptIdx].Signature[len(bundles[corruptIdx].Signature)/2] ^= 0x01

	agg, err := AggregateSignatures(params, bundles, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	count, err := VerifyAggregated(params, agg, known)
	if err != nil {
		t.Fatalf("VerifyAggregated returned error on counted-out bundle: %v", err)
	}
	if count != N-1 {
		t.Fatalf("VerifyAggregated count = %d, want %d (one bad sig counted out)", count, N-1)
	}
}

func TestVerifyAggregated_UnknownValidator(t *testing.T) {
	skipUnderRace(t)
	// A bundle from a validator not in knownValidators must cause
	// VerifyAggregated to return ErrUnknownValidator.
	params := MustParamsFor(ModeM192s)

	sk1, pk1, err := GenerateValidatorKey(params, newDetReader([]byte("unk-1")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[1]: %v", err)
	}
	sk2, _, err := GenerateValidatorKey(params, newDetReader([]byte("unk-2")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[2]: %v", err)
	}

	var id1, id2 NodeID
	id1[0] = 1
	copy(id1[1:], []byte("KNOWN"))
	id2[0] = 2
	copy(id2[1:], []byte("UNKNOWN"))

	known := map[NodeID][]byte{
		id1: pk1.Bytes,
	}

	msg := []byte("Magnetar aggregate unknown-validator rejection")
	b1, err := SignBundle(params, sk1, id1, msg)
	if err != nil {
		t.Fatalf("SignBundle[1]: %v", err)
	}
	b2, err := SignBundle(params, sk2, id2, msg)
	if err != nil {
		t.Fatalf("SignBundle[2]: %v", err)
	}

	agg, err := AggregateSignatures(params, []*SignedBundle{b1, b2}, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	_, err = VerifyAggregated(params, agg, known)
	if err != ErrUnknownValidator {
		t.Fatalf("VerifyAggregated err = %v, want ErrUnknownValidator", err)
	}
}

func TestVerifyAggregated_DuplicateValidator(t *testing.T) {
	skipUnderRace(t)
	// Same validator appears twice in the bundle list; dedupe at
	// AggregateSignatures (first occurrence wins) AND at
	// VerifyAggregated. Count must reflect one valid signer.
	params := MustParamsFor(ModeM192s)

	sk, pk, err := GenerateValidatorKey(params, newDetReader([]byte("dup-validator")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey: %v", err)
	}
	var id NodeID
	id[0] = 1
	copy(id[1:], []byte("DUPE"))
	known := map[NodeID][]byte{id: pk.Bytes}

	msg := []byte("Magnetar aggregate duplicate-validator dedupe")
	b, err := SignBundle(params, sk, id, msg)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Two identical bundles in the list.
	agg, err := AggregateSignatures(params, []*SignedBundle{b, b}, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}
	if len(agg.Bundles) != 1 {
		t.Fatalf("AggregateSignatures: dedupe failed, got %d bundles, want 1", len(agg.Bundles))
	}

	count, err := VerifyAggregated(params, agg, known)
	if err != nil {
		t.Fatalf("VerifyAggregated: %v", err)
	}
	if count != 1 {
		t.Fatalf("VerifyAggregated count = %d, want 1", count)
	}

	// And a SECOND form: two DIFFERENT but-valid bundles for the
	// same ValidatorID (e.g. same validator signed twice with
	// different randomness in a hypothetical randomized variant).
	// VerifyAggregated dedupes those too.
	b2, err := SignBundle(params, sk, id, msg)
	if err != nil {
		t.Fatalf("SignBundle (second): %v", err)
	}
	// SignBundle is deterministic so b and b2 are byte-equal; we
	// still exercise the dedupe path here.
	agg2 := &AggregatedSignature{
		Message: msg,
		Bundles: []*SignedBundle{b, b2},
	}
	count2, err := VerifyAggregated(params, agg2, known)
	if err != nil {
		t.Fatalf("VerifyAggregated (manual agg): %v", err)
	}
	if count2 != 1 {
		t.Fatalf("VerifyAggregated count = %d, want 1 (dedupe at verify)", count2)
	}
}

func TestVerifyAggregated_PubkeyMismatch(t *testing.T) {
	skipUnderRace(t)
	// A bundle whose embedded PublicKey does NOT match the
	// known-validators registry must trigger
	// ErrValidatorPubkeyMismatch. Protects against a malicious
	// validator binding a different pk to its NodeID mid-quorum.
	params := MustParamsFor(ModeM192s)

	sk1, pk1, err := GenerateValidatorKey(params, newDetReader([]byte("pkmis-1")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[1]: %v", err)
	}
	_, pk2, err := GenerateValidatorKey(params, newDetReader([]byte("pkmis-2")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[2]: %v", err)
	}

	var id NodeID
	id[0] = 1
	copy(id[1:], []byte("PKMISMATCH"))

	// Registry binds id -> pk1, but the bundle (signed with sk1)
	// embeds pk2 — a malicious validator trying to rebind.
	known := map[NodeID][]byte{id: pk1.Bytes}
	msg := []byte("Magnetar aggregate pubkey-mismatch rejection")
	b, err := SignBundle(params, sk1, id, msg)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Overwrite the bundle's embedded pubkey to a DIFFERENT
	// pubkey. The signature is still valid under sk1, but the
	// bundle's pk now lies.
	b.PublicKey = make([]byte, len(pk2.Bytes))
	copy(b.PublicKey, pk2.Bytes)

	agg, err := AggregateSignatures(params, []*SignedBundle{b}, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	_, err = VerifyAggregated(params, agg, known)
	if err != ErrValidatorPubkeyMismatch {
		t.Fatalf("VerifyAggregated err = %v, want ErrValidatorPubkeyMismatch", err)
	}
}

func TestAggregateSignatures_BatchVerify(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: -short does not run the batch-verify provenance check (5 SLH-DSA verifies)")
	}
	// Confirm the per-bundle verify path is parallel-CPU
	// (verifyAggregatedConcurrent) for a batch above the
	// threshold. Mirrors the BatchVerify provenance assertion in
	// luxfi/crypto/slhdsa.GetProvenance — magnetar exposes the
	// same observable via LastVerifyAggregatedTier.
	params := MustParamsFor(ModeM192s)
	const N = 5

	type validator struct {
		id NodeID
		sk *PrivateKey
		pk *PublicKey
	}
	vs := make([]validator, N)
	known := make(map[NodeID][]byte, N)
	for i := 0; i < N; i++ {
		sk, pk, err := GenerateValidatorKey(params, newDetReader([]byte{byte(i), 'B', 'V'}))
		if err != nil {
			t.Fatalf("GenerateValidatorKey[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("BATCH-VERIFY"))
		vs[i] = validator{id: id, sk: sk, pk: pk}
		known[id] = pk.Bytes
	}

	msg := []byte("Magnetar batch-verify provenance scenario")
	bundles := make([]*SignedBundle, N)
	for i, v := range vs {
		b, err := SignBundle(params, v.sk, v.id, msg)
		if err != nil {
			t.Fatalf("SignBundle[%d]: %v", i, err)
		}
		bundles[i] = b
	}

	agg, err := AggregateSignatures(params, bundles, msg)
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	count, err := VerifyAggregated(params, agg, known)
	if err != nil {
		t.Fatalf("VerifyAggregated: %v", err)
	}
	if count != N {
		t.Fatalf("VerifyAggregated count = %d, want %d", count, N)
	}

	// Provenance: a 5-bundle agg above the concurrent threshold
	// MUST have taken the parallel-CPU dispatch tier. This is the
	// observable evidence that the per-bundle verify is using the
	// goroutine fork-join pattern (the slhdsa.VerifyBatch
	// parallel path). If a future change accidentally drops the
	// parallel dispatch, this test catches the regression.
	tier := LastVerifyAggregatedTier()
	if tier != verifyAggregatedConcurrent {
		t.Fatalf("LastVerifyAggregatedTier = %s, want %s — parallel dispatch did not engage",
			tier, verifyAggregatedConcurrent)
	}

	// Also exercise the serial path: a 1-bundle agg should take
	// the serial tier (below threshold).
	agg1, err := AggregateSignatures(params, bundles[:1], msg)
	if err != nil {
		t.Fatalf("AggregateSignatures (1-bundle): %v", err)
	}
	if _, err := VerifyAggregated(params, agg1, known); err != nil {
		t.Fatalf("VerifyAggregated (1-bundle): %v", err)
	}
	tier1 := LastVerifyAggregatedTier()
	if tier1 != verifyAggregatedSerial {
		t.Fatalf("LastVerifyAggregatedTier (1-bundle) = %s, want %s",
			tier1, verifyAggregatedSerial)
	}
}

func TestAggregateSignatures_EmptyBundles(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	_, err := AggregateSignatures(params, nil, []byte("msg"))
	if err != ErrEmptyBundle {
		t.Fatalf("AggregateSignatures nil err = %v, want ErrEmptyBundle", err)
	}
	_, err = AggregateSignatures(params, []*SignedBundle{}, []byte("msg"))
	if err != ErrEmptyBundle {
		t.Fatalf("AggregateSignatures empty err = %v, want ErrEmptyBundle", err)
	}
}

func TestAggregateSignatures_ShapeCheck(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	var id NodeID
	id[0] = 1
	// Bundle with wrong PublicKey length.
	badPk := &SignedBundle{
		ValidatorID: id,
		PublicKey:   make([]byte, params.PublicKeySize-1),
		Signature:   make([]byte, params.SignatureSize),
	}
	if _, err := AggregateSignatures(params, []*SignedBundle{badPk}, []byte("msg")); err != ErrBundleMismatch {
		t.Fatalf("AggregateSignatures bad-pk err = %v, want ErrBundleMismatch", err)
	}
	// Bundle with wrong Signature length.
	badSig := &SignedBundle{
		ValidatorID: id,
		PublicKey:   make([]byte, params.PublicKeySize),
		Signature:   make([]byte, params.SignatureSize-1),
	}
	if _, err := AggregateSignatures(params, []*SignedBundle{badSig}, []byte("msg")); err != ErrBundleMismatch {
		t.Fatalf("AggregateSignatures bad-sig err = %v, want ErrBundleMismatch", err)
	}
	// Nil bundle.
	if _, err := AggregateSignatures(params, []*SignedBundle{nil}, []byte("msg")); err != ErrBundleMismatch {
		t.Fatalf("AggregateSignatures nil-bundle err = %v, want ErrBundleMismatch", err)
	}
}

func TestGenerateValidatorKey_Independent(t *testing.T) {
	skipUnderRace(t)
	// Two GenerateValidatorKey calls with DIFFERENT seeds MUST
	// produce distinct (sk, pk) — confirms "no shared seed" /
	// "no DKG" property.
	params := MustParamsFor(ModeM192s)
	sk1, pk1, err := GenerateValidatorKey(params, newDetReader([]byte("indep-1")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[1]: %v", err)
	}
	sk2, pk2, err := GenerateValidatorKey(params, newDetReader([]byte("indep-2")))
	if err != nil {
		t.Fatalf("GenerateValidatorKey[2]: %v", err)
	}
	if bytes.Equal(sk1.Bytes, sk2.Bytes) {
		t.Fatalf("two independent GenerateValidatorKey calls produced identical sk")
	}
	if bytes.Equal(pk1.Bytes, pk2.Bytes) {
		t.Fatalf("two independent GenerateValidatorKey calls produced identical pk")
	}
}
