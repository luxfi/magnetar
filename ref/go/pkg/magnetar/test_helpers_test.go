// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// test_helpers_test.go — shared test utilities for deterministic
// RNG and committee construction. Lives under *_test.go so it is
// not compiled into the production binary.

import (
	"crypto/sha256"
	"io"
	"testing"
)

// skipUnderRace is a self-skip guard for tests that wrap heavy
// SLH-DSA computation. Race-detector runs add 5-10× overhead on
// SHAKE-heavy code; these tests carry no inter-goroutine
// concurrency so they cannot trigger a race condition regardless.
// Race-detector runs cover the cheap unit tests (shamir,
// transcript, types) — see CONTRIBUTING.md "Testing under race".
func skipUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("skip: SLH-DSA-heavy test under race detector (see CONTRIBUTING.md)")
	}
}

// detReader is a deterministic SHA-256-counter byte stream from a
// seed. Used by tests + KAT generator to produce reproducible
// "random" input. NOT a CSPRNG suitable for production.
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

// deterministicReader is a thin alias for newDetReader for test
// code that wants a one-liner.
func deterministicReader(seed []byte) io.Reader {
	return newDetReader(seed)
}
