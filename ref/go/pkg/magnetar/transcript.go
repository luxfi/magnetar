// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// transcript.go --- FIPS 202 / SP 800-185 transcript primitive used
// by the THBS-SE construction.
//
// Magnetar v1.0 ships ONE hashing surface: cSHAKE256 from FIPS 202
// sec 6.3 + SP 800-185 sec 3, pinned to function-name "Magnetar". All
// other Magnetar cSHAKE calls route through this file so the audit
// footprint of the hash layer is one function.
//
// Per-validator standalone (standalone.go) uses NO cSHAKE; it is FIPS
// 205 SLH-DSA top-to-bottom. THBS-SE (thbsse.go + thbsse_field.go) is
// the only consumer of cshake256, for the commit transcript
// (R1-commit, slot-id derivation, share-deal coefficient stretch) and
// the share-MAC. The customisation tags are pinned in their
// respective files as named constants so any cross-protocol replay
// deterministically fails commit reconstruction at the first byte.

import (
	"golang.org/x/crypto/sha3"
)

// functionName is the SP 800-185 cSHAKE function-name parameter. All
// Magnetar cSHAKE calls pin N to "Magnetar" so that an integrator who
// mistakenly fed Magnetar cSHAKE bytes into a non-Magnetar cSHAKE
// engine would get a deterministic mismatch.
const functionName = "Magnetar"

// Customisation tags for cSHAKE256. Rotating a tag invalidates every
// test vector pinned at that tag.
//
// THBS-SE-specific tags live in thbsse.go (tagThbsSeSlot,
// tagThbsSeR1Commit, tagThbsSeShareMAC, tagThbsSeCtxPrefix). The
// share-deal tag below is consumed by thbsse_field.go and by
// EvalPointFromID.
const (
	tagThbsSeShareDeal = "MAGNETAR-THBSSE-SHARE-DEAL-V1"
	tagDomainSep       = "lux-magnetar-v1"
)

// cshake256 returns the first outLen bytes of cSHAKE256(input, N,
// customisation) per SP 800-185 sec 3.
func cshake256(input []byte, outLen int, customisation string) []byte {
	h := sha3.NewCShake256([]byte(functionName), []byte(customisation))
	_, _ = h.Write(input)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}
