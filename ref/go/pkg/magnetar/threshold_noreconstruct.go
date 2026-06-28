// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// threshold_noreconstruct.go --- Magnetar Track B: the NO-RECONSTRUCT
// threshold SLH-DSA interface, FAIL CLOSED.
//
// =====================================================================
//  WHY THIS FILE EXISTS
// =====================================================================
//
// The Magnetar trustless-by-default law (owner-authoritative) splits
// threshold hash-based signing into two tracks:
//
//   Track A --- Magnetar-Quorum (PRODUCTION, trustless TODAY).
//     Validators hold INDEPENDENT ordinary FIPS 205 SLH-DSA keys; each
//     signs the same Quasar subject; a P3Q STARK proves a >= policy
//     weighted quorum of stock SLH-DSA signatures verified. No dealer,
//     no DKG, no shared secret, no threshold SLH-DSA at all. Lives in
//     the Track-A surface (sibling work), evidence kind
//     "magnetar-p3q-slhdsa-rollup".
//
//   Track B --- Magnetar-Threshold (RESEARCH ONLY, THIS FILE).
//     A genuine t-of-n threshold SLH-DSA that emits ONE stock FIPS 205
//     signature WITHOUT any party or aggregator ever reconstructing the
//     global SLH-DSA seed / full secret key, even transiently. This is
//     an OPEN research problem. Until no-reconstruct signing is proven,
//     Track B MUST NOT be admitted to the POLARIS_MAX cert tier.
//
// This file encodes the Track-B INTERFACE and the FAIL-CLOSED gate. The
// signing entry returns ErrNoReconstructUnproven. NoReconstructProven()
// is hard-wired false. AdmitMagnetarThresholdToPolarisMax() refuses.
// Track B can therefore NEVER be silently admitted to POLARIS_MAX: a
// consumer that wires Track B into a strict cert tier gets an explicit
// error, not a degraded-trust signature.
//
// The ONE concretely-buildable, stock-FIPS-205-verifiable, genuinely
// no-reconstruct sub-protocol that DOES exist --- distributed FORS-leaf
// threshold opening --- lives in fors_threshold_open.go. It is a proven
// COMPONENT of a FORS-bottom signature, NOT a full SLH-DSA signature.
// It is deliberately NOT wired into Sign() below, because a full
// signature additionally needs the hypertree (d WOTS+ signatures + XMSS
// authentication paths), whose authentication-path siblings are
// secret-derived WOTS+ public keys over a 2^h-leaf tree --- the
// materialisation wall + keygen-MPC wall documented in the companion
// paper (papers/lp-magnetar-threshold-slhdsa).
//
// =====================================================================
//  THE THREE HARD CONSTRAINTS (the acceptance gates)
// =====================================================================
//
//   1. NO-RECONSTRUCT. No aggregator or party ever reconstructs the
//      global seed or full secret key, even transiently. (Contrast: the
//      existing THBS-SE Combine path --- thbsse_assemble.go --- DOES
//      reconstruct the full seed, into a buffer named derivedExpandInput
//      / derivedMaterial; its "strict-atom" grep gate forbids the
//      variable NAME "seed", not the reconstruction. THBS-SE is Track-A-
//      adjacent reveal-and-aggregate, NOT a strict no-reconstruct lane.)
//
//   2. STOCK VERIFY. The final output verifies under ordinary FIPS 205
//      SLH-DSA Verify (cloudflare/circl, unmodified). No verifier-side
//      Magnetar code.
//
//   3. ONE-TIME SAFETY. Any revealed WOTS+/FORS one-time material is
//      burned forever; no reusable secret leaks. Hash-based signatures
//      are FRAGILE: a single WOTS+ chain-base reuse under two distinct
//      message digits is a full WOTS+ key recovery, hence a hypertree
//      forgery; FORS is few-time and degrades with reuse. The burn
//      discipline is enforced by BurnLedger below + the per-leaf slot
//      guard in fors_threshold_open.go.
//
// Constraint 1 draws the no-reconstruct line at the GLOBAL SEED, not at
// individual leaves: constraint 3 EXPECTS one-time leaf material to be
// revealed ("any revealed WOTS+/FORS one-time material..."). Opening a
// single one-time leaf secret is therefore permitted; assembling the
// global seed is not.

import "errors"

// ErrNoReconstructUnproven is the fail-closed sentinel returned by the
// Track-B signing entry and the POLARIS_MAX admission gate. It signals
// that no-reconstruct threshold SLH-DSA signing has not been proven for
// the full FIPS 205 signature, so the construction must not be admitted
// to a strict trustless cert tier.
var ErrNoReconstructUnproven = errors.New(
	"magnetar/threshold: no-reconstruct threshold SLH-DSA signing is unproven for the full FIPS 205 signature " +
		"(only the distributed FORS-leaf opening component is proven); Track B is NOT admitted to POLARIS_MAX")

// ErrLeafWidthViolation is returned (and is a fail-closed guard) when a
// no-reconstruct opening is asked to reconstruct a secret buffer wider
// than a single one-time leaf. It is the runtime expression of
// constraint 1: the open path may interpolate at most ONE leaf-width
// secret at a time, never the SeedSize-byte master.
var ErrLeafWidthViolation = errors.New(
	"magnetar/threshold: no-reconstruct opening attempted to interpolate a buffer wider than one one-time leaf " +
		"(this would be a global-seed/secret-key reconstruction --- refused)")

// NoReconstructProven reports whether the FULL no-reconstruct threshold
// SLH-DSA signing construction (a stock FIPS 205 signature with NO
// global-seed reconstruction anywhere in the path) has been proven and
// is therefore eligible for the POLARIS_MAX strict cert tier.
//
// It is HARD-WIRED false. Flipping it to true is a deliberate, reviewed
// act that MUST be accompanied by:
//
//   - A no-reconstruct producer for the COMPLETE signature (FORS +
//     hypertree), not just the FORS component.
//   - A proof, under stock FIPS 205 Verify, that the producer's output
//     is byte-accepted by an unmodified verifier.
//   - A Byzantine-safe distributed BURN-STATE that guarantees WOTS+
//     one-time and FORS few-time discipline across a live committee
//     (the open obstruction --- see BurnLedger and the paper).
//
// Until then, every strict-tier consumer fails closed.
func NoReconstructProven() bool { return false }

// MagnetarTrack identifies which Magnetar threshold track a cert
// references. The admission gate dispatches on it.
type MagnetarTrack uint8

const (
	// TrackUnspecified rejects every admission decision; the zero value
	// is invalid by construction.
	TrackUnspecified MagnetarTrack = 0

	// TrackAQuorum is Magnetar-Quorum: P3Q rollup of independent
	// validator SLH-DSA signatures. Trustless today; admitted to its
	// own tiers by the Track-A surface, NOT by this gate.
	TrackAQuorum MagnetarTrack = 1

	// TrackBThreshold is Magnetar-Threshold: no-reconstruct threshold
	// SLH-DSA. Research only. Refused by AdmitMagnetarThresholdToPolarisMax
	// until NoReconstructProven().
	TrackBThreshold MagnetarTrack = 2
)

// String returns the canonical track name.
func (t MagnetarTrack) String() string {
	switch t {
	case TrackAQuorum:
		return "Magnetar-Quorum (Track A)"
	case TrackBThreshold:
		return "Magnetar-Threshold (Track B)"
	default:
		return "Magnetar-unspecified-track"
	}
}

// AdmitMagnetarThresholdToPolarisMax is the SINGLE admission authority
// for whether a Magnetar-Threshold (Track B) lane may contribute to the
// POLARIS_MAX strict cert tier. It is the one-function gate (Hickey
// discipline: policy enforcement in ONE place, never braided into the
// crypto).
//
// It refuses Track B unconditionally until NoReconstructProven() is
// true. Track A is NOT this gate's concern --- a TrackAQuorum argument
// returns ErrWrongTrackForGate so callers cannot accidentally route the
// production lane through the research gate.
func AdmitMagnetarThresholdToPolarisMax(track MagnetarTrack) error {
	switch track {
	case TrackBThreshold:
		if !NoReconstructProven() {
			return ErrNoReconstructUnproven
		}
		return nil
	case TrackAQuorum:
		return ErrWrongTrackForGate
	default:
		return ErrUnknownTrack
	}
}

// ErrWrongTrackForGate is returned when Track A is passed to the
// Track-B POLARIS_MAX admission gate. Track A is admitted by its own
// (P3Q-rollup) surface; routing it here is a wiring bug.
var ErrWrongTrackForGate = errors.New(
	"magnetar/threshold: Track A (Magnetar-Quorum) is not admitted by the Track-B gate; use the P3Q-rollup surface")

// ErrUnknownTrack is returned for an unspecified / unknown track.
var ErrUnknownTrack = errors.New("magnetar/threshold: unknown Magnetar track")

// =====================================================================
//  THE NO-RECONSTRUCT SIGNER INTERFACE
// =====================================================================

// NoReconstructThresholdSigner is the Track-B signing contract. A
// conforming implementation produces ONE stock FIPS 205 SLH-DSA
// signature from a t-of-n committee such that NO party or aggregator
// ever holds the global seed / full secret key, even transiently.
//
// No such implementation exists for the COMPLETE signature. The
// fail-closed implementation below returns ErrNoReconstructUnproven.
// The proven COMPONENT (distributed FORS-leaf opening) implements only
// the FORS-bottom of this contract and is exposed separately in
// fors_threshold_open.go --- it is intentionally NOT a
// NoReconstructThresholdSigner, because it does not emit a complete
// signature.
type NoReconstructThresholdSigner interface {
	// SignNoReconstruct produces a stock FIPS 205 signature on message
	// under ctx from >= threshold partial openings, with no global-seed
	// reconstruction. Returns ErrNoReconstructUnproven until the
	// construction is proven.
	SignNoReconstruct(message, ctx []byte, openings [][]byte) (*Signature, error)

	// Mode reports the FIPS 205 parameter set this signer targets.
	Mode() Mode
}

// failClosedThresholdSigner is the only NoReconstructThresholdSigner
// Magnetar ships. Every signing call fails closed. It exists so that
// consumers can wire the Track-B interface end-to-end TODAY and observe
// the explicit refusal, rather than discovering at integration time
// that the lane silently degraded to a reconstructing combiner.
type failClosedThresholdSigner struct {
	params *Params
}

// NewFailClosedThresholdSigner returns the fail-closed Track-B signer
// for the given mode. Its SignNoReconstruct always returns
// ErrNoReconstructUnproven.
func NewFailClosedThresholdSigner(params *Params) (NoReconstructThresholdSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return &failClosedThresholdSigner{params: params}, nil
}

// SignNoReconstruct fails closed.
func (s *failClosedThresholdSigner) SignNoReconstruct(_, _ []byte, _ [][]byte) (*Signature, error) {
	return nil, ErrNoReconstructUnproven
}

// Mode reports the target parameter set.
func (s *failClosedThresholdSigner) Mode() Mode { return s.params.Mode }

// =====================================================================
//  CONSTRAINT-1 RUNTIME GUARD (leaf-width invariant)
// =====================================================================

// maxOpenWidth is the maximum secret-buffer width a no-reconstruct
// opening may interpolate at once: exactly ONE one-time leaf secret,
// which in FIPS 205 is n bytes (params.N). This is strictly less than
// SeedSize (= PrivateKeySize = 4n for every FIPS 205 set), so an
// interpolation at this width can never assemble the master seed.
func maxOpenWidth(params *Params) int { return params.N }

// assertLeafWidth is the fail-closed expression of constraint 1. Every
// no-reconstruct interpolation in fors_threshold_open.go passes its
// target width through this guard. A width > one leaf (i.e. anything
// approaching SeedSize) is refused with ErrLeafWidthViolation: the open
// path is structurally incapable of reconstructing the global seed.
//
// This is a CONSTRUCTIVE guard, not merely a test assertion --- it sits
// on the live open path so a future refactor that tried to widen an
// interpolation to seed size would fault immediately.
func assertLeafWidth(params *Params, width int) error {
	if width <= 0 || width > maxOpenWidth(params) {
		return ErrLeafWidthViolation
	}
	return nil
}

// =====================================================================
//
//	THE ONE-TIME / FEW-TIME BURN LEDGER (constraint 3; the crux)
//
// =====================================================================
//
// The deepest obstruction to no-reconstruct threshold SLH-DSA is NOT
// the no-reconstruct property of a single opening --- the FORS component
// achieves that. It is GLOBAL one-time/few-time discipline across a
// live, possibly-Byzantine committee:
//
//   - WOTS+ keypairs are STRICTLY ONE-TIME. Signing two distinct
//     message digests with one WOTS+ keypair reveals chain values at
//     two different chain lengths; the shorter one lets an adversary
//     extend to forge the other --- full WOTS+ key recovery, hence a
//     hypertree forgery. A threshold protocol MUST guarantee that for
//     every (layer, tree, leaf) WOTS+ address, the committee opens chain
//     material for AT MOST ONE message digest, forever.
//
//   - FORS keypairs are FEW-TIME. Opening leaf secrets of one FORS
//     keypair for multiple messages degrades security as roughly
//     (reuse)^k; the few-time margin must not be exceeded.
//
// In stateless SLH-DSA the keypair selection (idxTree, idxLeaf) is a
// pseudo-random function of R = PRF_msg(SK.prf, PK.seed, M'), and the
// huge hypertree (2^63..2^68 leaves) makes collisions negligible for a
// single signer. In a THRESHOLD setting SK.prf is itself shared, so R
// must be produced by the committee, and the committee must DETECT and
// REFUSE any second opening of an already-burned one-time address.
//
// BurnLedger is the durable, fault-tolerant state that enforces this.
// It is the "stateful subprotocol under a stateless-looking cert
// boundary" (cf. NIST Haystack, threshold/distributed stateful HBS).
// The in-memory ledger below is the LOCAL-state reference; a production
// deployment lifts it to Byzantine-fault-tolerant replicated state
// (consensus-anchored burn proofs). The Byzantine-safe lift is the open
// obstruction --- see the paper. NoReconstructProven() cannot return
// true until that lift is proven.
type BurnLedger struct {
	// burned maps a one-time address key to the message digest it was
	// burned for. A second open at the same address under a different
	// digest is an equivocation: refused, and the (address, two digests)
	// tuple is slashable evidence.
	burned map[OneTimeAddr][32]byte
}

// OneTimeAddr canonically identifies a one-time/few-time signing slot in
// the SLH-DSA forest: the FIPS 205 hypertree coordinates plus the
// component kind. It is the burn-ledger key. Values, not places: the
// address is defined by what it IS (a coordinate in the forest), not by
// who holds it.
type OneTimeAddr struct {
	// Kind distinguishes WOTS+ (strictly one-time) from FORS (few-time)
	// addresses so the ledger can apply the correct reuse budget.
	Kind OneTimeKind
	// Layer is the hypertree layer (0 = bottom). FORS lives below layer 0.
	Layer uint32
	// Tree is the XMSS tree index within the layer (low 32 bits; the
	// full FIPS 205 tree address is 3 words --- the reference ledger keys
	// on the low word, sufficient for the bounded test forests; a
	// production ledger keys on the full 3-word address).
	Tree uint32
	// Leaf is the keypair (XMSS leaf / FORS keypair) index within the
	// tree.
	Leaf uint32
	// ForsTree is the FORS sub-tree index in [0, k) for FORS addresses;
	// zero for WOTS+ addresses.
	ForsTree uint32
}

// OneTimeKind classifies the reuse budget of a one-time address.
type OneTimeKind uint8

const (
	// KindWotsOneTime is a WOTS+ keypair: STRICTLY one message, ever.
	KindWotsOneTime OneTimeKind = 1
	// KindForsFewTime is a FORS keypair: few-time, budget enforced by
	// the few-time parameters (k, a). The reference ledger applies a
	// strict one-message default; a production ledger may widen to the
	// proven few-time budget.
	KindForsFewTime OneTimeKind = 2
)

// NewBurnLedger returns an empty local burn ledger.
func NewBurnLedger() *BurnLedger {
	return &BurnLedger{burned: make(map[OneTimeAddr][32]byte)}
}

// Burn records that addr is consumed for digest. It returns
// ErrOneTimeReuse (carrying the conflicting prior digest via
// BurnConflict) if addr was already burned for a DIFFERENT digest.
// Re-burning the SAME (addr, digest) is idempotent (a benign retry).
//
// This is the fail-closed enforcement of constraint 3: the open path
// MUST call Burn before releasing one-time material, and abort on
// conflict. A production committee replaces the local map with
// consensus-anchored burn proofs so the guarantee survives crashes,
// restarts, and Byzantine equivocation.
func (l *BurnLedger) Burn(addr OneTimeAddr, digest [32]byte) error {
	if prior, ok := l.burned[addr]; ok {
		if prior != digest {
			return &BurnConflict{Addr: addr, Prior: prior, New: digest}
		}
		return nil // idempotent retry
	}
	l.burned[addr] = digest
	return nil
}

// IsBurned reports whether addr has been consumed.
func (l *BurnLedger) IsBurned(addr OneTimeAddr) bool {
	_, ok := l.burned[addr]
	return ok
}

// BurnConflict is the slashable evidence of a one-time-address reuse
// attempt: the same one-time slot opened for two distinct messages.
type BurnConflict struct {
	Addr  OneTimeAddr
	Prior [32]byte
	New   [32]byte
}

// Error implements error.
func (e *BurnConflict) Error() string {
	return "magnetar/threshold: one-time address reuse --- a WOTS+/FORS slot was opened for two distinct message digests (slashable)"
}

// ErrOneTimeReuse is a sentinel for errors.Is matching against a
// BurnConflict.
var ErrOneTimeReuse = errors.New("magnetar/threshold: one-time address reuse")

// Is lets errors.Is(err, ErrOneTimeReuse) match a *BurnConflict.
func (e *BurnConflict) Is(target error) bool { return target == ErrOneTimeReuse }
