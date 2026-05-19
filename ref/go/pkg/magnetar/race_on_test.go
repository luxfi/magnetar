// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build race

package magnetar

// race_on_test.go — race-detector-ON counterpart of
// race_off_test.go. Sets raceEnabled = true so SLH-DSA-heavy tests
// can self-skip with a one-line t.Skip(skipUnderRace) gate.

const raceEnabled = true
