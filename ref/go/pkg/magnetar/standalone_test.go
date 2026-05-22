// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// standalone_test.go — Tests for the public-BFT-safe per-validator
// standalone primitive (standalone.go).
//
// These tests pin the canonical public-BFT path: each validator
// holds its OWN SLH-DSA keypair, signs independently, and the
// consensus layer collects N signatures into a
// ValidatorAggregateCert. No DKG. No dealer. No shared seed.

import (
	"bytes"
	"testing"
)

// TestPerValidatorKeypair_RoundTrip pins the round-trip:
//   - PerValidatorKeypair produces a fresh standalone keypair.
//   - ValidatorSign over the message produces a valid signature.
//   - That signature verifies under the validator's pk via stock
//     FIPS 205 Verify (the byte-equality claim).
//   - Two independent calls with distinct seeds produce DISTINCT
//     keypairs (no shared seed, no DKG).
func TestPerValidatorKeypair_RoundTrip(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)

	sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte("standalone-rt-1")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair: %v", err)
	}
	if sk == nil || pk == nil {
		t.Fatalf("PerValidatorKeypair returned nil (sk=%v pk=%v)", sk, pk)
	}
	if sk.Mode != params.Mode || pk.Mode != params.Mode {
		t.Fatalf("mode mismatch: sk=%v pk=%v want=%v", sk.Mode, pk.Mode, params.Mode)
	}
	if !sk.Pub.Equal(pk) {
		t.Fatalf("PerValidatorKeypair: sk.Pub != returned pk")
	}

	msg := []byte("Magnetar standalone-mode per-validator round-trip")
	sig, err := ValidatorSign(sk, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign: %v", err)
	}
	if len(sig) != params.SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), params.SignatureSize)
	}

	// Round-trip under stock FIPS 205 dispatch.
	if !slhVerify(params.ID, pk.Bytes, msg, nil, sig) {
		t.Fatalf("slhVerify rejected ValidatorSign output")
	}

	// Determinism: two ValidatorSign calls under the same (sk, msg)
	// must be byte-identical when rng is nil (FIPS 205
	// SignDeterministic).
	sig2, err := ValidatorSign(sk, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign (2nd): %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Fatalf("ValidatorSign nil-rng output is non-deterministic")
	}

	// Independence: a second PerValidatorKeypair call with a
	// DIFFERENT seed produces a distinct keypair. "No DKG, no shared
	// seed" property.
	sk2, pk2, err := PerValidatorKeypair(params, newDetReader([]byte("standalone-rt-2")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair (2nd): %v", err)
	}
	if bytes.Equal(sk.Bytes, sk2.Bytes) {
		t.Fatalf("two PerValidatorKeypair calls produced identical sk")
	}
	if pk.Equal(pk2) {
		t.Fatalf("two PerValidatorKeypair calls produced identical pk")
	}
}

// TestValidatorBatchVerify_5of5_AllValid pins the parallel-CPU
// batch-verify path. Five validators sign the same message under
// their own keypairs; ValidatorBatchVerify returns true for every
// signer.
func TestValidatorBatchVerify_5of5_AllValid(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	const N = 5
	pubs, msgs, sigs := buildStandaloneFixture(t, params, N, []byte("standalone-batch-5"))
	bitmap, err := ValidatorBatchVerify(params, pubs, msgs, sigs)
	if err != nil {
		t.Fatalf("ValidatorBatchVerify: %v", err)
	}
	if len(bitmap) != N {
		t.Fatalf("bitmap len = %d, want %d", len(bitmap), N)
	}
	for i, ok := range bitmap {
		if !ok {
			t.Fatalf("ValidatorBatchVerify[%d] = false, want true", i)
		}
	}
}

// TestValidatorBatchVerify_BadSig_Counted pins the
// "counted-out, not fatal" property for tampered signatures.
func TestValidatorBatchVerify_BadSig_Counted(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	const N = 5
	pubs, msgs, sigs := buildStandaloneFixture(t, params, N, []byte("standalone-batch-bad"))
	// Tamper bitmap[2].
	sigs[2] = append([]byte(nil), sigs[2]...)
	sigs[2][len(sigs[2])/2] ^= 0x01
	bitmap, err := ValidatorBatchVerify(params, pubs, msgs, sigs)
	if err != nil {
		t.Fatalf("ValidatorBatchVerify: %v", err)
	}
	if len(bitmap) != N {
		t.Fatalf("bitmap len = %d, want %d", len(bitmap), N)
	}
	for i, ok := range bitmap {
		if i == 2 {
			if ok {
				t.Fatalf("ValidatorBatchVerify[%d] = true, want false (tampered)", i)
			}
			continue
		}
		if !ok {
			t.Fatalf("ValidatorBatchVerify[%d] = false, want true", i)
		}
	}
}

// TestVerifyAggregateCert_UnknownValidator_Rejected pins the
// known-validator allowlist defense. A signer whose ValidatorID is
// not in knownValidators is COUNTED AS INVALID (not fatal, by
// standalone.go contract).
func TestVerifyAggregateCert_UnknownValidator_Rejected(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	const N = 3
	known := make(map[NodeID][]byte, N)
	signers := make([]NodeID, N)
	pubKeys := make([][]byte, N)
	sigs := make([][]byte, N)
	msg := []byte("standalone-cert-unknown-validator")
	for i := 0; i < N; i++ {
		sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte{byte(i), 'U', 'N'}))
		if err != nil {
			t.Fatalf("PerValidatorKeypair[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("CERT-UNKNOWN"))
		signers[i] = id
		pubKeys[i] = pk.Bytes
		s, err := ValidatorSign(sk, nil, msg)
		if err != nil {
			t.Fatalf("ValidatorSign[%d]: %v", i, err)
		}
		sigs[i] = s
		// Only register the first two validators in knownValidators.
		// The third signer is "unknown" to the registry.
		if i < 2 {
			known[id] = pk.Bytes
		}
	}
	cert, err := BuildAggregateCert(params, signers, pubKeys, sigs)
	if err != nil {
		t.Fatalf("BuildAggregateCert: %v", err)
	}
	count, err := VerifyAggregateCert(cert, msg, known)
	if err != nil {
		t.Fatalf("VerifyAggregateCert: %v", err)
	}
	if count != 2 {
		t.Fatalf("VerifyAggregateCert count = %d, want 2 (one unknown signer)", count)
	}
}

// TestVerifyAggregateCert_DuplicateValidator_DedupedAndCountedOnce
// pins dedupe-by-ValidatorID semantics. The same signer appearing
// twice in the cert is counted ONCE.
func TestVerifyAggregateCert_DuplicateValidator_DedupedAndCountedOnce(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	known := make(map[NodeID][]byte, 2)
	signers := make([]NodeID, 0, 3)
	pubKeys := make([][]byte, 0, 3)
	sigs := make([][]byte, 0, 3)
	msg := []byte("standalone-cert-duplicate")

	// Validator A.
	skA, pkA, err := PerValidatorKeypair(params, newDetReader([]byte("dup-A")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair[A]: %v", err)
	}
	var idA NodeID
	idA[0] = 1
	copy(idA[1:], []byte("DUP-A"))
	known[idA] = pkA.Bytes

	// Validator B.
	skB, pkB, err := PerValidatorKeypair(params, newDetReader([]byte("dup-B")))
	if err != nil {
		t.Fatalf("PerValidatorKeypair[B]: %v", err)
	}
	var idB NodeID
	idB[0] = 2
	copy(idB[1:], []byte("DUP-B"))
	known[idB] = pkB.Bytes

	sigA, err := ValidatorSign(skA, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign[A]: %v", err)
	}
	sigB, err := ValidatorSign(skB, nil, msg)
	if err != nil {
		t.Fatalf("ValidatorSign[B]: %v", err)
	}

	// Build a cert with A appearing TWICE plus B once.
	signers = append(signers, idA, idA, idB)
	pubKeys = append(pubKeys, pkA.Bytes, pkA.Bytes, pkB.Bytes)
	sigs = append(sigs, sigA, sigA, sigB)
	cert, err := BuildAggregateCert(params, signers, pubKeys, sigs)
	if err != nil {
		t.Fatalf("BuildAggregateCert: %v", err)
	}
	count, err := VerifyAggregateCert(cert, msg, known)
	if err != nil {
		t.Fatalf("VerifyAggregateCert: %v", err)
	}
	if count != 2 {
		t.Fatalf("VerifyAggregateCert count = %d, want 2 (A deduped, B counted once)", count)
	}
}

// TestVerifyAggregateCert_GPU_Provenance pins that the cert
// verification path routes through the parallel-CPU dispatch
// (the goroutine fork-join that mirrors
// luxfi/crypto/slhdsa.VerifyBatch). Confirms a batch above the
// concurrent threshold takes the parallel tier.
func TestVerifyAggregateCert_GPU_Provenance(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: -short does not run the cert-provenance check (5 SLH-DSA verifies)")
	}
	params := MustParamsFor(ModeM192s)
	const N = 5
	known := make(map[NodeID][]byte, N)
	signers := make([]NodeID, N)
	pubKeys := make([][]byte, N)
	sigs := make([][]byte, N)
	msg := []byte("standalone-cert-provenance")
	for i := 0; i < N; i++ {
		sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte{byte(i), 'P', 'V'}))
		if err != nil {
			t.Fatalf("PerValidatorKeypair[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("PROV"))
		signers[i] = id
		pubKeys[i] = pk.Bytes
		known[id] = pk.Bytes
		s, err := ValidatorSign(sk, nil, msg)
		if err != nil {
			t.Fatalf("ValidatorSign[%d]: %v", i, err)
		}
		sigs[i] = s
	}
	cert, err := BuildAggregateCert(params, signers, pubKeys, sigs)
	if err != nil {
		t.Fatalf("BuildAggregateCert: %v", err)
	}
	count, err := VerifyAggregateCert(cert, msg, known)
	if err != nil {
		t.Fatalf("VerifyAggregateCert: %v", err)
	}
	if count != N {
		t.Fatalf("VerifyAggregateCert count = %d, want %d", count, N)
	}
	// Provenance: above the concurrent threshold the parallel tier
	// MUST engage. This is the standalone analog of the
	// aggregate.go BatchVerify provenance test — observable
	// evidence that the per-bundle verify uses the goroutine
	// fork-join pattern (the slhdsa.VerifyBatch parallel path).
	tier := LastVerifyAggregatedTier()
	if tier != verifyAggregatedConcurrent {
		t.Fatalf("LastVerifyAggregatedTier = %s, want %s — cert verify did not dispatch parallel",
			tier, verifyAggregatedConcurrent)
	}
}

// TestValidatorBatchVerify_ShapeChecks pins the fail-fast structural
// errors. Bad inputs do NOT silently produce a half-validated
// bitmap.
func TestValidatorBatchVerify_ShapeChecks(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	const N = 3
	pubs, msgs, sigs := buildStandaloneFixture(t, params, N, []byte("standalone-shape"))

	// Mismatched slice lengths.
	if _, err := ValidatorBatchVerify(params, pubs, msgs[:N-1], sigs); err != ErrAggregateCertShape {
		t.Fatalf("ValidatorBatchVerify msgs-short err = %v, want ErrAggregateCertShape", err)
	}

	// Wrong signature byte length.
	badSigs := make([][]byte, N)
	for i := range badSigs {
		badSigs[i] = sigs[i]
	}
	badSigs[1] = make([]byte, params.SignatureSize-1)
	if _, err := ValidatorBatchVerify(params, pubs, msgs, badSigs); err != ErrSignatureWrongSize {
		t.Fatalf("ValidatorBatchVerify wrong-sig-size err = %v, want ErrSignatureWrongSize", err)
	}

	// Wrong pubkey byte length.
	badPub := *pubs[1]
	badPub.Bytes = make([]byte, params.PublicKeySize-1)
	badPubs := append([]*PublicKey(nil), pubs...)
	badPubs[1] = &badPub
	if _, err := ValidatorBatchVerify(params, badPubs, msgs, sigs); err != ErrPublicKeyWrongSize {
		t.Fatalf("ValidatorBatchVerify wrong-pk-size err = %v, want ErrPublicKeyWrongSize", err)
	}

	// Mode mismatch.
	wrongMode := *pubs[1]
	wrongMode.Mode = ModeM256s
	wrongModePubs := append([]*PublicKey(nil), pubs...)
	wrongModePubs[1] = &wrongMode
	if _, err := ValidatorBatchVerify(params, wrongModePubs, msgs, sigs); err != ErrModeMismatch {
		t.Fatalf("ValidatorBatchVerify wrong-mode err = %v, want ErrModeMismatch", err)
	}
}

// TestVerifyAggregateCert_AllInvalid_ReturnsZero pins the "fact-
// reporting" property: when no signer is valid, the count is 0
// and the error is nil (the caller's quorum threshold check will
// reject; that is not this primitive's job).
func TestVerifyAggregateCert_AllInvalid_ReturnsZero(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	const N = 3
	known := make(map[NodeID][]byte, N)
	signers := make([]NodeID, N)
	pubKeys := make([][]byte, N)
	sigs := make([][]byte, N)
	msg := []byte("standalone-cert-all-invalid")
	for i := 0; i < N; i++ {
		sk, pk, err := PerValidatorKeypair(params, newDetReader([]byte{byte(i), 'I', 'V'}))
		if err != nil {
			t.Fatalf("PerValidatorKeypair[%d]: %v", i, err)
		}
		var id NodeID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("ALL-INVALID"))
		signers[i] = id
		pubKeys[i] = pk.Bytes
		known[id] = pk.Bytes
		s, err := ValidatorSign(sk, nil, msg)
		if err != nil {
			t.Fatalf("ValidatorSign[%d]: %v", i, err)
		}
		// Corrupt every signature.
		s[len(s)/2] ^= 0x01
		sigs[i] = s
	}
	cert, err := BuildAggregateCert(params, signers, pubKeys, sigs)
	if err != nil {
		t.Fatalf("BuildAggregateCert: %v", err)
	}
	count, err := VerifyAggregateCert(cert, msg, known)
	if err != nil {
		t.Fatalf("VerifyAggregateCert: %v", err)
	}
	if count != 0 {
		t.Fatalf("VerifyAggregateCert count = %d, want 0 (all invalid)", count)
	}
}

// TestBuildAggregateCert_EmptyAndShape pins the BuildAggregateCert
// shape checks.
func TestBuildAggregateCert_EmptyAndShape(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)

	if _, err := BuildAggregateCert(params, nil, nil, nil); err != ErrAggregateCertEmpty {
		t.Fatalf("BuildAggregateCert empty err = %v, want ErrAggregateCertEmpty", err)
	}
	// Mismatched lengths.
	signers := []NodeID{{1}, {2}}
	pubs := [][]byte{make([]byte, params.PublicKeySize)}
	sigs := [][]byte{make([]byte, params.SignatureSize), make([]byte, params.SignatureSize)}
	if _, err := BuildAggregateCert(params, signers, pubs, sigs); err != ErrAggregateCertShape {
		t.Fatalf("BuildAggregateCert mismatch err = %v, want ErrAggregateCertShape", err)
	}
}

// buildStandaloneFixture is a test helper that produces N valid
// (pk, msg, sig) triples under deterministic per-validator
// keypairs. Returns parallel slices ready to feed into
// ValidatorBatchVerify or BuildAggregateCert.
func buildStandaloneFixture(t *testing.T, params *Params, n int, seed []byte) ([]*PublicKey, [][]byte, [][]byte) {
	t.Helper()
	pubs := make([]*PublicKey, n)
	msgs := make([][]byte, n)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		mix := append([]byte{byte(i)}, seed...)
		sk, pk, err := PerValidatorKeypair(params, newDetReader(mix))
		if err != nil {
			t.Fatalf("PerValidatorKeypair[%d]: %v", i, err)
		}
		pubs[i] = pk
		msgs[i] = append([]byte{}, seed...)
		s, err := ValidatorSign(sk, nil, msgs[i])
		if err != nil {
			t.Fatalf("ValidatorSign[%d]: %v", i, err)
		}
		sigs[i] = s
	}
	return pubs, msgs, sigs
}
