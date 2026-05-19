// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !race

package magnetar

// race_off_test.go — race-detector-OFF constant. When the binary is
// built without the race detector, this constant is true; otherwise
// the race_on_test.go counterpart sets it to false.
//
// Tests that wrap heavy SLH-DSA computation (DeriveKey,
// SignDeterministic) skip themselves when raceEnabled is true because
// the race detector adds 5-10× overhead, and these tests carry no
// inter-goroutine concurrency — they cannot trigger a race condition
// regardless. Race-detector runs cover the cheap unit tests
// (shamir, transcript, types).

const raceEnabled = false
