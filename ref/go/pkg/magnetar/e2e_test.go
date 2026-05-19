// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// e2e_test.go — end-to-end Magnetar threshold-signing scenarios.
//
// These tests exercise the FULL protocol path (DKG -> threshold sign
// -> Verify) under realistic configurations, including:
//
//   - All three Magnetar parameter modes (M192s, M192f, M256s).
//   - Multiple (n, t) threshold configurations.
//   - Cross-implementation byte-equality against single-party circl
//     SLH-DSA on the reconstructed seed.
//   - Quorum-rotation: signing with two distinct quorums must produce
//     the SAME signature (deterministic SLH-DSA byte-equality).
//   - Long messages + context strings (boundary cases).
//   - Repeat signing: signing the same (m, ctx) twice produces
//     byte-identical output.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func TestE2E_AllModes_BasicCeremony(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: -short does not run multi-mode e2e")
	}
	modes := []Mode{ModeM192s, ModeM192f, ModeM256s}
	for _, mode := range modes {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			committee := makeCommittee(3)
			pub, shares, _ := runDKG(t, params, committee, 2)

			msg := []byte("Magnetar e2e " + mode.String())
			sig, err := signWithQuorum(t, params, pub, shares, 2, msg)
			if err != nil {
				t.Fatalf("signWithQuorum: %v", err)
			}
			if err := Verify(params, pub, msg, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(sig.Bytes) != params.SignatureSize {
				t.Fatalf("sig size %d != expected %d", len(sig.Bytes), params.SignatureSize)
			}
		})
	}
}

func TestE2E_CrossImpl_ThresholdMatchesCirclSingleParty(t *testing.T) {
	skipUnderRace(t)
	// Run the threshold protocol AND a centralized circl
	// SignDeterministic on the reconstructed seed; assert
	// byte-equality.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)

	msg := []byte("e2e: threshold ≡ centralised circl SignDeterministic")
	var ctx []byte

	thresholdSig, err := signWithQuorum(t, params, pub, shares, 2, msg)
	if err != nil {
		t.Fatalf("signWithQuorum: %v", err)
	}

	// Centralized path: reconstruct seed, sk = circl.DeriveKey(seed),
	// sig = circl.SignDeterministic(sk, msg, ctx).
	quorumShares := make([]*KeyShare, 2)
	for i := 0; i < 2; i++ {
		quorumShares[i] = shares[i]
	}
	masterSeed := reconstructMasterSeed(t, params, quorumShares, shares)
	scheme := params.ID.Scheme()
	pkCircl, skCircl := scheme.DeriveKey(masterSeed)
	// circl returns sign.PrivateKey / sign.PublicKey interfaces;
	// SignDeterministic takes *slhdsa.PrivateKey concretely. Marshal
	// and re-unmarshal to get the concrete type (the same path
	// Magnetar's own keygen.go uses).
	skBytes, err := skCircl.MarshalBinary()
	if err != nil {
		t.Fatalf("skCircl.MarshalBinary: %v", err)
	}
	priv := slhdsa.PrivateKey{ID: params.ID}
	if err := priv.UnmarshalBinary(skBytes); err != nil {
		t.Fatalf("priv.UnmarshalBinary: %v", err)
	}
	circlSig, err := slhdsa.SignDeterministic(&priv, slhdsa.NewMessage(msg), ctx)
	if err != nil {
		t.Fatalf("circl SignDeterministic: %v", err)
	}
	// Sanity: the circl-derived public key must match the DKG pub.
	pkBytes, err := pkCircl.MarshalBinary()
	if err != nil {
		t.Fatalf("pkCircl.MarshalBinary: %v", err)
	}
	if !bytes.Equal(pkBytes, pub.Bytes) {
		t.Fatalf("circl pk does not match DKG pub")
	}

	if !bytes.Equal(thresholdSig.Bytes, circlSig) {
		t.Errorf("threshold and circl signature bytes differ")
		for i := 0; i < len(thresholdSig.Bytes) && i < len(circlSig); i++ {
			if thresholdSig.Bytes[i] != circlSig[i] {
				t.Errorf("first divergent byte at offset %d: threshold=0x%02x circl=0x%02x",
					i, thresholdSig.Bytes[i], circlSig[i])
				break
			}
		}
		t.Fatalf("cross-impl byte-equality violated")
	}
}

func TestE2E_DistinctQuorums_SameSignature(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: -short does not run distinct-quorum e2e")
	}
	// Two distinct quorums on the same (msg, ctx) MUST produce the
	// same byte-identical signature (reveal-and-aggregate
	// reconstructs to the same master seed regardless of quorum).
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(5)
	pub, shares, _ := runDKG(t, params, committee, 3)

	msg := []byte("e2e: distinct quorums must agree on signature")

	sign := func(idxs []int) []byte {
		t.Helper()
		quorumShares := make([]*KeyShare, len(idxs))
		quorum := make([]NodeID, len(idxs))
		for i, j := range idxs {
			quorumShares[i] = shares[j]
			quorum[i] = shares[j].NodeID
		}
		var sid [16]byte
		copy(sid[:], "magnetar-e2e-qrm")
		signers := make([]*ThresholdSigner, len(idxs))
		for i, j := range idxs {
			s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[j], msg,
				newDetReader([]byte{byte(j), 0x5A}))
			signers[i] = s
		}
		r1 := make([]*Round1Message, len(idxs))
		for i, s := range signers {
			r1[i], _ = s.Round1()
		}
		r2 := make([]*Round2Message, len(idxs))
		for i, s := range signers {
			r2[i], _, _ = s.Round2(r1)
		}
		sig, err := Combine(params, pub, msg, nil, false, sid, 1, quorum, len(idxs), r1, r2, shares)
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}
		return sig.Bytes
	}

	sigA := sign([]int{0, 1, 2})
	sigB := sign([]int{2, 3, 4})
	if !bytes.Equal(sigA, sigB) {
		t.Errorf("distinct quorums produced different signatures")
		t.Fatalf("quorum-independence violated")
	}
}

func TestE2E_RepeatSign_DeterministicByteIdentical(t *testing.T) {
	skipUnderRace(t)
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)

	msg := []byte("e2e: repeat sign must be byte-identical")
	sig1, err := signWithQuorum(t, params, pub, shares, 2, msg)
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}
	sig2, err := signWithQuorum(t, params, pub, shares, 2, msg)
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if !bytes.Equal(sig1.Bytes, sig2.Bytes) {
		t.Fatalf("repeat sign produced different signatures (SignDeterministic should be byte-identical)")
	}
}

func TestE2E_LargeMessage_BoundaryOK(t *testing.T) {
	skipUnderRace(t)
	if testing.Short() {
		t.Skip("skip: -short does not run large-message e2e")
	}
	// Long messages (1 MB) and the FIPS 205 §10.2 max-context (255
	// bytes) must work end-to-end.
	params := MustParamsFor(ModeM192s)
	committee := makeCommittee(3)
	pub, shares, _ := runDKG(t, params, committee, 2)

	msg := make([]byte, 1<<20) // 1 MB
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	ctx := make([]byte, 255)
	for i := range ctx {
		ctx[i] = byte(i)
	}

	// Run Combine with explicit ctx.
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID}
	var sid [16]byte
	copy(sid[:], "e2e-large-msg-01")
	signers := make([]*ThresholdSigner, 2)
	for i := 0; i < 2; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, nil)
		signers[i] = s
	}
	r1 := make([]*Round1Message, 2)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*Round2Message, 2)
	for i, s := range signers {
		r2[i], _, _ = s.Round2(r1)
	}
	sig, err := Combine(params, pub, msg, ctx, false, sid, 1, quorum, 2, r1, r2, shares)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if err := VerifyCtx(params, pub, msg, ctx, sig); err != nil {
		t.Fatalf("VerifyCtx: %v", err)
	}
}

func TestE2E_KATReplay_Deterministic(t *testing.T) {
	skipUnderRace(t)
	// Run the same ceremony twice with the SAME deterministic seeds;
	// both runs MUST produce byte-identical artifacts (DKG pubkey,
	// shares, threshold sig). This is the KAT-determinism invariant.
	runOnce := func() (pubBytes []byte, shareBytes []byte, sigBytes []byte) {
		params := MustParamsFor(ModeM192s)
		committee := makeCommittee(3)
		pub, shares, _ := runDKG(t, params, committee, 2)
		msg := []byte("e2e: KAT replay determinism")
		sig, err := signWithQuorum(t, params, pub, shares, 2, msg)
		if err != nil {
			t.Fatalf("signWithQuorum: %v", err)
		}
		pubBytes = append(pubBytes, pub.Bytes...)
		shareBytes = append(shareBytes, shares[0].Share...)
		sigBytes = append(sigBytes, sig.Bytes...)
		return
	}

	p1, s1, sig1 := runOnce()
	p2, s2, sig2 := runOnce()
	if !bytes.Equal(p1, p2) {
		t.Fatalf("KAT replay: DKG pub differs")
	}
	if !bytes.Equal(s1, s2) {
		t.Fatalf("KAT replay: party-0 share differs")
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("KAT replay: threshold sig differs")
	}
}
