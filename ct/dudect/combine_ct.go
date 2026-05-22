// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build magnetar_combine_ct

// combine_ct.go — cgo bridge exposing magnetar.CombineWithSeedReconstruction
// to the C dudect harness in dudect_combine.c.
//
// CT POPULATION (operational framing, NOT a standards mandate):
// both dudect classes are VALID CombineWithSeedReconstruction inputs —
// independently randomized threshold ceremonies over the SAME shares.
// The bridge pre-builds a pool of K full (Round1, Round2) tapes by
// running the threshold protocol K times with different per-party
// RNG seeds. All K ceremonies produce the SAME final FIPS 205 SLH-DSA
// signature (the reveal-and-aggregate CombineWithSeedReconstruction
// collapses through the same master seed via Lagrange reconstruction),
// but the intermediate Round-1 commits + Round-2 (mask, masked)
// reveals vary across tapes.
//
// dudect class assignment:
//   class A: always tape[0]      (byte-identical Combine inputs)
//   class B: tape[rand % K]      (varying-but-valid Combine inputs)
//
// Both classes pass every internal CombineWithSeedReconstruction
// check (commit re-derive, Lagrange reconstruct, mix-to-seed,
// KeyFromSeed pk match, FIPS 205 SignDeterministic). Any timing
// difference between classes is a real signature-content-dependent
// timing in the CombineWithSeedReconstruction pipeline, not a
// rejection-path artifact.
//
// Build (Linux):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmagnetar_combine.so ./combine_ct.go
// Build (macOS):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libmagnetar_combine.dylib ./combine_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// Pool size — K independent valid threshold ceremonies over the
// SAME shares. SLH-DSA signing in Combine is heavier than ML-DSA so
// we use a smaller pool than Pulsar's 16 to keep setup time bounded.
const kCombineValidPool = 8

// Per-tape fixture: one full (Round1, Round2) tape from an
// independent threshold ceremony.
type combineTape struct {
	round1 []*magnetar.Round1Message
	round2 []*magnetar.Round2Message
}

// Long-lived fixture: a real (n=3, t=2) threshold setup at ModeM192s,
// plus a pool of kCombineValidPool valid (Round1, Round2) tapes.
var (
	cFixtureParams    *magnetar.Params
	cFixturePub       *magnetar.PublicKey
	cFixtureMsg       []byte
	cFixtureSessionID [16]byte
	cFixtureAttempt   uint32
	cFixtureQuorum    []magnetar.NodeID
	cFixtureThreshold int
	cFixtureShares    []*magnetar.KeyShare
	cFixtureTapes     [kCombineValidPool]combineTape
)

//export magnetar_combine_ct_setup
//
// Build a real threshold ceremony fixture once. Returns 0 on success,
// non-zero on failure.
//
// Topology: n=3 parties, t=2 threshold, ModeM192s. This is the
// smallest non-trivial threshold ceremony — keeps the dudect run
// time per sample bounded.
func magnetar_combine_ct_setup() C.int {
	params := magnetar.MustParamsFor(magnetar.ModeM192s)
	n, t := 3, 2

	committee := make([]magnetar.NodeID, n)
	for i := 0; i < n; i++ {
		committee[i] = magnetar.NodeID{byte(i + 1)}
	}

	// DKG ceremony.
	dkgSessions := make([]*magnetar.DKGSession, n)
	for i := 0; i < n; i++ {
		s, err := magnetar.NewDKGSession(params, committee, t, committee[i], rand.Reader)
		if err != nil {
			return 1
		}
		dkgSessions[i] = s
	}
	r1 := make([]*magnetar.DKGRound1Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round1()
		if err != nil {
			return 2
		}
		r1[i] = m
	}
	r2 := make([]*magnetar.DKGRound2Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round2(r1)
		if err != nil {
			return 3
		}
		r2[i] = m
	}
	outputs := make([]*magnetar.DKGOutput, n)
	for i, s := range dkgSessions {
		out, err := s.Round3(r2)
		if err != nil {
			return 4
		}
		outputs[i] = out
	}

	pub := outputs[0].GroupPubkey
	shares := make([]*magnetar.KeyShare, n)
	for i := range outputs {
		shares[i] = outputs[i].SecretShare
	}

	// Threshold sign.
	msg := []byte("dudect constant-time smoke: Magnetar Combine class N1-analog")
	quorum := make([]magnetar.NodeID, t)
	for i := 0; i < t; i++ {
		quorum[i] = shares[i].NodeID
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return 5
	}

	// Build the K-entry valid-tape pool. Each tape is an independent
	// run of (Round1, Round2) over the SAME shares + sid + attempt +
	// message — only the per-party RNG (hence masks + commits +
	// reveals) differs. Every tape is sanity-checked: Combine must
	// succeed before the tape is admitted to the pool. All tapes
	// produce the SAME final signature (deterministic SLH-DSA on the
	// SAME reconstructed seed); any timing difference dudect detects
	// is a real data-dependent signal in the Combine pipeline.
	for k := 0; k < kCombineValidPool; k++ {
		signers := make([]*magnetar.ThresholdSigner, t)
		for i := 0; i < t; i++ {
			s, err := magnetar.NewThresholdSigner(params, sid, 1, quorum, shares[i],
				msg, rand.Reader)
			if err != nil {
				return 6
			}
			signers[i] = s
		}
		sr1 := make([]*magnetar.Round1Message, t)
		for i, s := range signers {
			m, err := s.Round1()
			if err != nil {
				return 7
			}
			sr1[i] = m
		}
		sr2 := make([]*magnetar.Round2Message, t)
		for i, s := range signers {
			m, _, err := s.Round2(sr1)
			if err != nil {
				return 8
			}
			sr2[i] = m
		}
		// Sanity: this tape's CombineWithSeedReconstruction must succeed.
		if _, err := magnetar.CombineWithSeedReconstruction(params, pub, msg, nil, false, sid, 1, quorum, t, sr1, sr2, shares); err != nil {
			return 9
		}
		cFixtureTapes[k] = combineTape{round1: sr1, round2: sr2}
	}

	cFixtureParams = params
	cFixturePub = pub
	cFixtureMsg = msg
	cFixtureSessionID = sid
	cFixtureAttempt = 1
	cFixtureQuorum = quorum
	cFixtureThreshold = t
	cFixtureShares = shares
	return 0
}

//export magnetar_combine_ct_pool_size
//
// Returns the number of valid tapes in the per-startup pool.
func magnetar_combine_ct_pool_size() C.size_t {
	return C.size_t(kCombineValidPool)
}

//export magnetar_combine_ct_input_size
//
// Returns the per-sample input width: 4 bytes (a big-endian uint32
// tape index, mod kCombineValidPool). The C harness sizes its
// dudect chunk to this width.
func magnetar_combine_ct_input_size() C.size_t {
	return C.size_t(4)
}

//export magnetar_combine_ct
//
// One dudect measurement sample.
//
// `data` points to a 4-byte big-endian uint32 tape index; the
// bridge reduces it mod kCombineValidPool and runs
// CombineWithSeedReconstruction on the indexed (Round1, Round2)
// tape. Both classes (A: fixed index 0, B: caller-supplied index)
// drive CombineWithSeedReconstruction through the SAME code path
// on VALID inputs — any timing difference is a real data-dependent
// signal, not a rejection-path artifact.
func magnetar_combine_ct(data *C.uint8_t) {
	if cFixtureParams == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 4)
	idx := (uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])) %
		uint32(kCombineValidPool)
	tape := cFixtureTapes[idx]

	_, _ = magnetar.CombineWithSeedReconstruction(
		cFixtureParams,
		cFixturePub,
		cFixtureMsg,
		nil,
		false,
		cFixtureSessionID,
		cFixtureAttempt,
		cFixtureQuorum,
		cFixtureThreshold,
		tape.round1,
		tape.round2,
		cFixtureShares,
	)
}

func main() {}
