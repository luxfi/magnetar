// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// pvss_dkg.go --- PVSS-DKG for the THBS-SE setup.
//
// =====================================================================
//  HONEST SUMMARY: TWO PATHS, ONE HARD BARRIER
// =====================================================================
//
// This file provides a dealerless setup for THBS-SE share material.
// There are TWO entry points, and they differ in exactly one property:
// whether the transcript reveals the master.
//
//   - RunDKG (PRODUCTION): the transcript carries NO constant-term
//     reveals (Reveals == nil; tr.RevealsMaster() == false). An
//     observer of the transcript CANNOT reconstruct M = sum_i m_i from
//     polynomial reveals. This is the no-leak setup path.
//
//   - RunDKGSimulationOpenRevealTestOnly (TEST/KAT): every party
//     publishes its full RevealMsg, so the transcript REVEALS the
//     master. It exists for deterministic KAT replay and for
//     exercising the verification logic in tests. It requires an
//     explicit hazard acknowledgement and MUST NOT run in production.
//
// THE HARD BARRIER (read before trusting the no-leak claim):
//
//   Deriving the SLH-DSA group public key needs the master.
//   pk = SLH-DSA.PK(M) is a hash tree over M; there is no way to
//   compute it from shares without reconstructing M at some party (or
//   full MPC over the SHAKE hash tree --- open research). So
//   deriveDKGPublicKey RECONSTRUCTS M transiently to compute pk and
//   zeroizes it. That reconstruction is the inherent cost of producing
//   any SLH-DSA-shaped artifact from a shared seed. It is NOT
//   published, but it does mean SOME party (whoever derives pk) holds M
//   for an instant. "No party EVER holds M" is achievable only via the
//   TEE path or the dealer path. Do not over-claim it.
//
// The earlier banner here claimed "NO PARTY HOLDS THE MASTER ... ever"
// and described a "NO-MASTER-IN-MEMORY DISCIPLINE" whose only content
// was naming a buffer `lagrangeScratch` instead of `seed`. That was
// the same proof-by-rename used on the SIGN side: a variable name is
// not a security property, and the pk-derivation reconstruction is
// real. Both claims are corrected here and in BLOCKERS.md.
//
// Wire compatibility: the emitted *ThbsSeKey is byte-shape identical to
// the dealer-path output (TestPVSS_DKG_ByteCompatWithDealerPath uses
// the open-reveal path because it inspects the polynomial reveals).
//
// =====================================================================
//  CONSTRUCTION
// =====================================================================
//
// We use a Schoenmakers-style PVSS-DKG over GF(257), the same small-
// prime byte-share field the dealer path lives in. The classical
// Schoenmakers (CRYPTO 1999) construction publishes Feldman group
// commitments over a prime-order group with a DDH assumption. We
// re-cast the same algebraic shape over GF(257) using a hash-based
// commitment construction (no DDH; commitments are binding by
// collision-resistance of cSHAKE256 and hiding by the secret blinding
// randomness mixed into the cSHAKE256 absorb). IMPORTANT: hash
// commitments are NOT homomorphic, so unlike Feldman/Schoenmakers a
// recipient CANNOT verify its share against the commitments without the
// dealer's opening — and the opening includes the constant term m_i.
// This is why the production path defers share verification (see the
// VERIFIABILITY and SECURITY sections below); the "publicly verifiable"
// property holds in full only on the open-reveal (test) path.
//
// Round structure (n parties, t-of-n threshold, seed_size L = 96 or
// 128 bytes):
//
//   Round 1 — every party i ∈ [1..n]:
//     - Sample contribution m_i ∈ GF(257)^L uniformly. m_i is the
//       byte-vector of party i's masked contribution to the master M.
//     - For each b ∈ [0..L), sample (t-1) coefficients c_{i,b,d} for
//       d ∈ [1..t-1] uniformly in GF(257). Set f_{i,b}(x) = m_i[b] +
//       Σ_d c_{i,b,d}·x^d.
//     - For each coefficient (including the constant term m_i[b]),
//       sample 16 bytes of blinding randomness ρ_{i,b,d}. Compute the
//       Pedersen-style hash commitment:
//         C_{i,b,d} = cSHAKE256(setup_tr || node_i || b || d ||
//                               ρ_{i,b,d} || coeff_value)[:32]
//       Publish {C_{i,b,d}} for every b ∈ [0..L), d ∈ [0..t).
//     - For each j ∈ [1..n], compute share value σ_{i→j}[b] =
//       f_{i,b}(j) mod 257 for each b. Send σ_{i→j} to party j over
//       an authenticated channel (in our reference: a function call
//       carrying the per-recipient blob).
//
//   Round 2 — every party j ∈ [1..n]:
//     - Aggregate: party j's final Shamir share is
//       σ_j[b] = Σ_{i ∈ Q} σ_{i→j}[b] mod 257 for each b.
//     - The aggregate share σ_j is the Lagrange evaluation at j of the
//       implicit master polynomial F_b(x) = Σ_{i ∈ Q} f_{i,b}(x), whose
//       constant term is M[b] = Σ_{i ∈ Q} m_i[b].
//     - SHARE VERIFICATION: with hash commitments, a recipient CANNOT
//       non-interactively check σ_{i→j} against {C_{i,b,d}} without i's
//       opening, and the opening includes the constant term m_i. So the
//       PRODUCTION path (RunDKG) does NOT verify shares at DKG time and
//       does NOT publish reveals; malformed shares are caught at sign
//       time (THBS-SE commit binding) and via a complaint that reveals
//       only the disputed recipient's share value. The OPEN-REVEAL test
//       path verifies fully against published reveals (and thereby
//       reveals the master). See RunDKG's HONEST LIMITATIONS.
//
//   PK derivation (whoever calls VerifyDKGTranscript):
//     - pk is derived from a Lagrange reconstruction of the master:
//         M[b] = Σ_{j ∈ R} λ_j · σ_j[b] mod 257, R a t-subset of Q.
//       Per FIPS 205 §10.1, KeyFromSeed(M) is deterministic. Computing
//       pk REQUIRES reconstructing M (a hash tree over M); there is no
//       way around it without TEE/MPC. The reconstruction is transient,
//       internal, and not published — but it IS a reconstruction.
//
// =====================================================================
//  ON "NO MASTER IN MEMORY" (the earlier claim, corrected)
// =====================================================================
//
// The production transcript hides the master from OBSERVERS (no
// reveals). It does NOT make it true that "no party ever holds M":
// deriveDKGPublicKey reconstructs M to compute pk. The earlier banner's
// "NO-MASTER-IN-MEMORY DISCIPLINE" rested on naming a buffer
// `lagrangeScratch` instead of `seed` — a naming convention, not a
// security property. The buffer name is incidental. What is real:
//
//   - RunDKG's transcript carries no constant-term reveals, so M is not
//     reconstructible from the wire (this IS a real improvement over
//     the old open-reveal-only design).
//   - pk derivation reconstructs M transiently at one party and
//     zeroizes it (inherent SLH-DSA cost; not eliminated by naming).
//
// To guarantee no party holds M even for pk derivation, use the TEE
// path (sibling primitive at luxfi/threshold/protocols/slhdsa-tee) or
// the dealer path (NewThbsSeKey, dealer-in-TCB-for-setup-only). A
// multi-party SHAKE evaluation that derives pk without reconstructing M
// is open research (multi-second per setup).
//
// =====================================================================
//  VERIFIABILITY
// =====================================================================
//
//   VerifyDKGTranscript(transcript) -> (qualifiedSet, pk, error)
//
// dispatches on transcript type:
//
//   - PRODUCTION transcript (no reveals): verifies commitment shape +
//     setup binding + received-share shape, qualifies every well-shaped
//     party (it CANNOT verify shares against hash commitments without
//     the reveals), and derives pk. Malformed-share detection is
//     deferred to sign-time commit binding + the complaint flow.
//
//   - OPEN-REVEAL transcript (TEST/KAT): additionally re-derives every
//     commitment from the published reveals and checks every received
//     share against the revealed polynomial, dropping inconsistent
//     parties. This path reveals the master.
//
// =====================================================================
//  SECURITY ARGUMENT (informal) --- and its limits
// =====================================================================
//
// Adversary controls T = {i : party_i is corrupt} with |T| ≤ t-1.
//
//   - Secrecy (PRODUCTION path only): if no honest party publishes its
//     constant term (RunDKG: nobody publishes reveals), the adversary's
//     view of an honest party h consists of the ≤(t-1) shares σ_{h→i}
//     for i ∈ T. These are uniform Shamir leaves of f_{h,b}, giving
//     zero information about m_h = f_{h,b}(0) by Shamir info-theoretic
//     security over GF(257). Hence M = Σ_i m_i is uniform in the
//     adversary's view. THIS ARGUMENT FAILS for the open-reveal path,
//     where every m_i is published and M is trivially reconstructible.
//     (It is also NOT mechanized; see PROOF-CLAIMS.md.)
//
//   - Correctness: Each f_{i,b} has constant term m_i[b]. Aggregating,
//     F_b(x) = Σ_{i ∈ Q} f_{i,b}(x) has constant term M[b], so the
//     aggregate shares σ_j = F_b(j) Lagrange-interpolate to M at x=0.
//
//   - Robustness against malicious dealers: DELIVERED ONLY on the
//     open-reveal path (which detects a non-opening commitment at
//     verify time). The PRODUCTION path does NOT deliver it: hash
//     commitments are not openable without revealing m_i, so a
//     malicious dealer's bad share is caught only later, at THBS-SE
//     sign time (commit binding) or via a complaint. For adversarial
//     committees, prefer the dealer path or the TEE pool. This limit is
//     stated in RunDKG's HONEST LIMITATIONS, not hidden.
//
//   - Equivalence to dealer: the aggregate shares σ_j byte-equal the
//     dealer-path shares for the same implicit master + coefficient
//     distribution (TestPVSS_DKG_ByteCompatWithDealerPath, open-reveal
//     path). The two paths are wire-indistinguishable; they differ in
//     who holds M and in robustness.
//
// =====================================================================
//  CITATIONS
// =====================================================================
//
//   - Schoenmakers, B. (1999). A simple publicly verifiable secret
//     sharing scheme and its application to electronic voting. CRYPTO.
//   - Feldman, P. (1987). A practical scheme for non-interactive
//     verifiable secret sharing. FOCS.
//   - Pedersen, T. (1991). Non-interactive and information-theoretic
//     secure verifiable secret sharing. CRYPTO.
//   - Gennaro, Jarecki, Krawczyk, Rabin (1999). Secure distributed
//     key generation for discrete-log based cryptosystems. EUROCRYPT.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Tag constants for the PVSS-DKG transcript hashing. Each tag is
// distinct from every other Magnetar tag so a cross-protocol replay
// deterministically mismatches at the first byte.
const (
	tagPVSSCommit     = "MAGNETAR-PVSS-DKG-COMMIT-V1"
	tagPVSSTranscript = "MAGNETAR-PVSS-DKG-TRANSCRIPT-V1"
	tagPVSSComplaint  = "MAGNETAR-PVSS-DKG-COMPLAINT-V1"
)

// pvssBlindingSize is the per-coefficient blinding randomness width
// in bytes. 16 bytes (128 bits) gives a 2^-128 collision bound on the
// commitment, matching SLH-DSA category 3 / category 5 security.
const pvssBlindingSize = 16

// Errors emitted by the PVSS-DKG path.
var (
	// ErrPVSSCommitMismatch indicates a party's Round-2 reveal does
	// not re-derive the Round-1 commitment for a given coefficient.
	ErrPVSSCommitMismatch = errors.New("magnetar/pvss-dkg: Round-2 reveal does not re-derive Round-1 commitment")

	// ErrPVSSShareInconsistent indicates a party's distributed share
	// to a recipient does not match the polynomial evaluation at the
	// recipient's index.
	ErrPVSSShareInconsistent = errors.New("magnetar/pvss-dkg: distributed share does not match polynomial evaluation")

	// ErrPVSSQuorumLost indicates fewer than t parties survived the
	// Round-2 verification step. The DKG cannot proceed.
	ErrPVSSQuorumLost = errors.New("magnetar/pvss-dkg: fewer than threshold parties survived verification")

	// ErrPVSSWrongShape indicates a transcript payload has the wrong
	// dimensions (n × n shares; n × L × t commitments).
	ErrPVSSWrongShape = errors.New("magnetar/pvss-dkg: transcript payload has wrong shape")

	// ErrPVSSEmptyContribution indicates a party submitted no
	// contribution (all-zero m_i + all-zero coefficients) and is
	// trivially detectable as a non-participant.
	ErrPVSSEmptyContribution = errors.New("magnetar/pvss-dkg: party submitted an empty contribution")
)

// PVSSPartyState is one party's complete per-party state at the end
// of Round 1. The dealing party owns this; remote parties see only
// (Commits, Share-To-Me, Blindings via the public transcript).
//
// Internally:
//   - polyCoeffs[b][d] is party i's coefficient for byte b at degree d.
//     polyCoeffs[b][0] = m_i[b] is the contribution; polyCoeffs[b][d]
//     for d > 0 are the polynomial coefficients of f_{i,b}.
//   - blindings[b][d] is the 16-byte blinding randomness paired with
//     polyCoeffs[b][d] in the hash commitment.
//   - commits[b][d] is the 32-byte cSHAKE256 commitment.
//
// distributedShares[j-1][b] is the share value σ_{i→j}[b] that party
// i delivers to party j over a private channel. In our reference
// harness this is simply a slice; in production it is encrypted under
// j's transport key.
type PVSSPartyState struct {
	// NodeID is this party's committee identifier (32 bytes).
	NodeID NodeID

	// PartyIndex is the 1-indexed committee position. Equal to
	// committee_index + 1.
	PartyIndex uint32

	// SeedSize is the byte width of the master vector (96 for
	// SHAKE-192*, 128 for SHAKE-256s).
	SeedSize int

	// Threshold is the t parameter; polynomials are degree-(t-1).
	Threshold int

	// N is the committee size.
	N int

	// polyCoeffs[b][d] is the GF(257) coefficient for byte b at degree
	// d. polyCoeffs[b][0] is the contribution m_i[b]. This is the
	// SECRET STATE of party i; it never leaves the party's process
	// except as Round-2 reveals (and even then only to verifiers
	// who already received the corresponding shares).
	polyCoeffs [][]uint16

	// blindings[b][d] is the 16-byte cSHAKE256 commitment blinding
	// paired with polyCoeffs[b][d]. Also SECRET in Round 1; revealed
	// in Round 2.
	blindings [][]byte

	// commits[b][d] is the 32-byte public commitment for
	// polyCoeffs[b][d]. PUBLIC at Round 1.
	commits [][][]byte

	// distributedShares[j-1][b] is σ_{i→j}[b]: the share value party
	// i sends to party j. Party i computes all n entries, then
	// delivers each row to its recipient via the private-channel.
	// In the dealing party's memory this row is SECRET (party i
	// knows every other party's share); the recipient sees only
	// its own row.
	distributedShares [][]uint16
}

// PVSSPublicContribution is the public per-party payload broadcast at
// Round 1. It carries the commitments only (no secret data). Anyone
// can verify a party's Round-2 reveal against this payload.
type PVSSPublicContribution struct {
	NodeID     NodeID
	PartyIndex uint32

	// Commits[b][d] is the 32-byte commitment for polyCoeffs[b][d].
	Commits [][][]byte
}

// PVSSRevealMsg is one party's Round-2 broadcast. It opens every
// commitment by revealing (blinding, coefficient) pairs. Recipients
// use these openings to verify their privately-received shares.
type PVSSRevealMsg struct {
	NodeID     NodeID
	PartyIndex uint32

	// PolyCoeffs[b][d] is the revealed coefficient. The verifier
	// recomputes cSHAKE256(setup_tr || node || b || d || ρ || coeff)
	// and checks byte-equality with the party's published
	// Commits[b][d].
	PolyCoeffs [][]uint16

	// Blindings[b][d] is the 16-byte blinding randomness.
	Blindings [][][]byte
}

// PVSSComplaint is the structured slashable-evidence blob a verifier
// emits when a party's Round-2 reveal fails. Any third party verifies
// it via VerifyPVSSComplaint without holding committee state.
type PVSSComplaint struct {
	// Accuser is the verifier that detected the inconsistency.
	Accuser NodeID

	// Accused is the party whose reveal or share was malformed.
	Accused NodeID

	// Reason classifies the malformation.
	Reason PVSSComplaintReason

	// ByteIndex, Degree, and Recipient pin the specific coefficient
	// or share the malformation concerns. Unused fields are zero.
	ByteIndex uint32
	Degree    uint32
	Recipient uint32

	// PublishedCommit is the byte-equal Round-1 commit the accused
	// party broadcast. RecomputedCommit is what the accuser derived
	// from the accused's Round-2 reveal. The two MUST differ for the
	// complaint to be valid.
	PublishedCommit  []byte
	RecomputedCommit []byte
}

// PVSSComplaintReason classifies the kind of malformation.
type PVSSComplaintReason uint8

const (
	// PVSSComplaintCommitMismatch indicates a Round-2 (blinding, coeff)
	// opening does not re-derive the Round-1 commitment.
	PVSSComplaintCommitMismatch PVSSComplaintReason = 1

	// PVSSComplaintShareInconsistent indicates a privately-received
	// share σ_{i→j}[b] does not match the polynomial evaluation
	// f_{i,b}(j) computed from the accused's Round-2 reveal.
	PVSSComplaintShareInconsistent PVSSComplaintReason = 2
)

// String returns the canonical reason name.
func (r PVSSComplaintReason) String() string {
	switch r {
	case PVSSComplaintCommitMismatch:
		return "commit-mismatch"
	case PVSSComplaintShareInconsistent:
		return "share-inconsistent"
	default:
		return "unknown"
	}
}

// PVSSTranscript is the public-form record of the full DKG run. It is
// the audit-trail input to VerifyDKGTranscript and the share-envelope
// input to NewThbsSeKeyFromDealerlessDKG. Every field is public.
//
// Wire shape (canonical):
//
//	committee[]      || n × NodeID (sorted ascending)
//	contributions[]  || n × Round-1 public contribution
//	reveals[]        || n × Round-2 reveal message
//	receivedShares[] || n × (n × seed_size) — the shares each party
//	                    received from every other party in Round 1
//
// The receivedShares matrix is published at Round 2; honest parties
// publish the shares they received (as part of their Round-2
// broadcast). The published shares cross-check against the polynomial
// reveals to detect malicious dealers.
type PVSSTranscript struct {
	Params    *Params
	Committee []NodeID
	Threshold int

	Contributions []PVSSPublicContribution
	Reveals       []PVSSRevealMsg

	// ReceivedShares[i][j][b] is the share party i+1 received from
	// party j+1 at byte b. After Round 2, each party publishes this
	// row (its own received shares); the transcript collates the rows.
	ReceivedShares [][][]uint16

	// SetupTr is the 32-byte transcript commit pinning (params, n, t,
	// committee). The same transcript binder used by the dealer path.
	SetupTr [32]byte
}

// pvssSetupTranscript binds the public-key-independent inputs of a
// DKG run into a single 32-byte digest. Used as the cSHAKE256
// customisation-bound prefix for every commitment in the run. By
// binding all parties to the same setup_tr, we prevent a malicious
// party from publishing a commitment that "matches" two different
// setup contexts.
func pvssSetupTranscript(params *Params, threshold int, committee []NodeID) [32]byte {
	buf := make([]byte, 0, 64+len(committee)*32)
	buf = binary.BigEndian.AppendUint32(buf, uint32(params.Mode))
	buf = binary.BigEndian.AppendUint32(buf, uint32(params.SeedSize))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(committee)))
	buf = binary.BigEndian.AppendUint32(buf, uint32(threshold))
	for _, id := range committee {
		buf = append(buf, id[:]...)
	}
	digest := cshake256(buf, 32, tagPVSSTranscript)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// pvssCommit computes the cSHAKE256 commitment for a single
// polynomial coefficient. Layout of the absorb buffer:
//
//	setup_tr (32) || node_id (32) || byte_index (4) || degree (4) ||
//	  blinding (16) || coeff (2)
//
// Total: 90 bytes per absorb. Customisation tag tagPVSSCommit binds
// the call to the PVSS-DKG primitive (not reusable across protocols).
func pvssCommit(setupTr [32]byte, node NodeID, byteIdx, degree uint32, blinding []byte, coeff uint16) []byte {
	if len(blinding) != pvssBlindingSize {
		// Static check; called only from internal paths that pin
		// blinding length.
		panic("magnetar/pvss-dkg: blinding length is fixed at pvssBlindingSize")
	}
	buf := make([]byte, 0, 32+32+4+4+pvssBlindingSize+2)
	buf = append(buf, setupTr[:]...)
	buf = append(buf, node[:]...)
	buf = binary.BigEndian.AppendUint32(buf, byteIdx)
	buf = binary.BigEndian.AppendUint32(buf, degree)
	buf = append(buf, blinding...)
	buf = binary.BigEndian.AppendUint16(buf, coeff)
	return cshake256(buf, 32, tagPVSSCommit)
}

// pvssEvalPoly evaluates f_b(j) = Σ_d coeffs[b][d] · j^d mod 257 via
// Horner's method. coeffs[b] has length t.
func pvssEvalPoly(coeffs []uint16, x uint32) uint16 {
	t := len(coeffs)
	if t == 0 {
		return 0
	}
	acc := uint32(coeffs[t-1])
	for d := t - 2; d >= 0; d-- {
		acc = (acc*x + uint32(coeffs[d])) % thbsseSharePrime
	}
	return uint16(acc)
}

// NewPVSSPartyState samples one party's complete Round-1 state. Each
// party invokes this independently with its own RNG. NO COORDINATION
// is needed across parties at Round 1 beyond agreement on (committee,
// threshold, params).
//
// The returned state contains the party's SECRET m_i contribution and
// the polynomial coefficients. The associated PUBLIC payload (the
// commits) is extracted via state.PublicContribution(). The private
// shares to send to recipients are extracted via state.ShareTo(j).
//
// Returns an error if rng is short of entropy or if params is invalid.
func NewPVSSPartyState(
	params *Params,
	threshold int,
	committee []NodeID,
	partyIndex uint32,
	rng io.Reader,
) (*PVSSPartyState, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}
	if partyIndex < 1 || partyIndex > uint32(n) {
		return nil, fmt.Errorf("magnetar/pvss-dkg: party index %d out of range [1, %d]", partyIndex, n)
	}
	if rng == nil {
		rng = rand.Reader
	}

	setupTr := pvssSetupTranscript(params, threshold, committee)
	nodeID := committee[partyIndex-1]
	L := params.SeedSize

	// Allocate.
	st := &PVSSPartyState{
		NodeID:            nodeID,
		PartyIndex:        partyIndex,
		SeedSize:          L,
		Threshold:         threshold,
		N:                 n,
		polyCoeffs:        make([][]uint16, L),
		blindings:         make([][]byte, L),
		commits:           make([][][]byte, L),
		distributedShares: make([][]uint16, n),
	}
	for b := 0; b < L; b++ {
		st.polyCoeffs[b] = make([]uint16, threshold)
		st.blindings[b] = make([]byte, threshold*pvssBlindingSize)
		st.commits[b] = make([][]byte, threshold)
	}
	for j := 0; j < n; j++ {
		st.distributedShares[j] = make([]uint16, L)
	}

	// Sample coefficients. We need L × t coefficients in [0, 257).
	// To do this constant-time over GF(257), we sample 2 bytes per
	// coefficient and reduce mod 257. The rejection probability per
	// 2-byte draw is (65536 mod 257) / 65536 ≈ 0.00076 < 2^-10, so a
	// single 2-byte draw per coefficient gives statistical bias <
	// 2^-10 per byte. For SLH-DSA category 3 / 5 this is acceptable
	// because the master byte vector has L = 96/128 bytes of entropy,
	// far exceeding the rejection-sample bias term. The same scheme
	// is used by thbsseDealRandomGF in the dealer path.
	coeffStream := make([]byte, L*threshold*2)
	if _, err := io.ReadFull(rng, coeffStream); err != nil {
		return nil, ErrShortRand
	}
	off := 0
	for b := 0; b < L; b++ {
		for d := 0; d < threshold; d++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			st.polyCoeffs[b][d] = uint16(r % thbsseSharePrime)
		}
	}

	// Sample blindings. L × t × 16 bytes.
	blindingStream := make([]byte, L*threshold*pvssBlindingSize)
	if _, err := io.ReadFull(rng, blindingStream); err != nil {
		zeroizeU16Slice2D(st.polyCoeffs)
		return nil, ErrShortRand
	}
	for b := 0; b < L; b++ {
		copy(st.blindings[b], blindingStream[b*threshold*pvssBlindingSize:(b+1)*threshold*pvssBlindingSize])
	}

	// Compute commits.
	for b := 0; b < L; b++ {
		for d := 0; d < threshold; d++ {
			st.commits[b][d] = pvssCommit(
				setupTr, nodeID,
				uint32(b), uint32(d),
				st.blindings[b][d*pvssBlindingSize:(d+1)*pvssBlindingSize],
				st.polyCoeffs[b][d],
			)
		}
	}

	// Compute distributed shares to each recipient j ∈ [1..n].
	for j := 1; j <= n; j++ {
		for b := 0; b < L; b++ {
			st.distributedShares[j-1][b] = pvssEvalPoly(st.polyCoeffs[b], uint32(j))
		}
	}

	// Zeroize the raw coeffStream and blindingStream; they are
	// captured by st.polyCoeffs / st.blindings.
	zeroizeBytes(coeffStream)
	zeroizeBytes(blindingStream)

	return st, nil
}

// PublicContribution extracts the party's PUBLIC Round-1 broadcast
// (commits only). Safe to publish to the entire committee.
func (st *PVSSPartyState) PublicContribution() PVSSPublicContribution {
	out := PVSSPublicContribution{
		NodeID:     st.NodeID,
		PartyIndex: st.PartyIndex,
		Commits:    make([][][]byte, st.SeedSize),
	}
	for b := 0; b < st.SeedSize; b++ {
		out.Commits[b] = make([][]byte, st.Threshold)
		for d := 0; d < st.Threshold; d++ {
			out.Commits[b][d] = append([]byte(nil), st.commits[b][d]...)
		}
	}
	return out
}

// ShareTo extracts the privately-distributed share row for recipient
// j ∈ [1..n]. The dealing party calls this n times — once per
// recipient — and sends each row over an authenticated point-to-point
// channel.
//
// The returned slice has length seed_size; ShareTo(j)[b] = f_{i,b}(j)
// mod 257.
func (st *PVSSPartyState) ShareTo(j uint32) ([]uint16, error) {
	if j < 1 || j > uint32(st.N) {
		return nil, fmt.Errorf("magnetar/pvss-dkg: recipient index %d out of range [1, %d]", j, st.N)
	}
	out := make([]uint16, st.SeedSize)
	copy(out, st.distributedShares[j-1])
	return out, nil
}

// RevealMsg extracts a party's FULL Round-2 reveal: every polynomial
// coefficient INCLUDING the constant term m_i[b], plus the blindings.
//
// !!! THIS LEAKS THE CONTRIBUTION. !!!
//
// PolyCoeffs[b][0] == m_i[b] is the party's contribution to the
// master M = sum_i m_i. If every party publishes its RevealMsg (the
// "open-reveal" mode), then M is reconstructible by ANY observer of
// the transcript, not merely by t-1 colluding insiders. A transcript
// that contains every party's RevealMsg has NO master secrecy.
//
// Therefore this method is for the TEST / KAT / complaint paths only:
//
//   - The open-reveal simulation `RunDKGSimulationOpenRevealTestOnly`
//     (test/KAT reproducibility; produces a master-revealing
//     transcript) calls it for every party.
//   - The complaint flow may call it for a SINGLE accused party whose
//     misbehavior has been recorded (`ComplaintReveal`). Even there,
//     publishing the constant term sacrifices that party's
//     contribution secrecy; a sound production complaint flow reveals
//     only the disputed recipient's share value, not the whole
//     polynomial (see the honest-limitations note on RunDKG).
//
// The PRODUCTION path (`RunDKG`) does NOT call this on the honest run:
// its transcript carries Reveals == nil so M is never reconstructible
// from it.
func (st *PVSSPartyState) RevealMsg() PVSSRevealMsg {
	out := PVSSRevealMsg{
		NodeID:     st.NodeID,
		PartyIndex: st.PartyIndex,
		PolyCoeffs: make([][]uint16, st.SeedSize),
		Blindings:  make([][][]byte, st.SeedSize),
	}
	for b := 0; b < st.SeedSize; b++ {
		out.PolyCoeffs[b] = append([]uint16(nil), st.polyCoeffs[b]...)
		out.Blindings[b] = make([][]byte, st.Threshold)
		for d := 0; d < st.Threshold; d++ {
			out.Blindings[b][d] = append([]byte(nil),
				st.blindings[b][d*pvssBlindingSize:(d+1)*pvssBlindingSize]...)
		}
	}
	return out
}

// VerifyContribution checks one party's Round-2 reveal against their
// Round-1 commits. Returns the list of (byteIndex, degree) tuples for
// which the commitment opening failed; an empty list means the party's
// reveal is well-formed.
//
// The check has cost O(L × t) hashes. For SHAKE-192s (L=96, t=4) that
// is 384 cSHAKE256 calls per party — trivially fast.
func VerifyContribution(
	params *Params,
	threshold int,
	committee []NodeID,
	contrib PVSSPublicContribution,
	reveal PVSSRevealMsg,
) ([][2]uint32, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if contrib.NodeID != reveal.NodeID {
		return nil, errors.New("magnetar/pvss-dkg: contribution and reveal node IDs differ")
	}
	if contrib.PartyIndex != reveal.PartyIndex {
		return nil, errors.New("magnetar/pvss-dkg: contribution and reveal party indices differ")
	}
	L := params.SeedSize
	if len(contrib.Commits) != L {
		return nil, ErrPVSSWrongShape
	}
	if len(reveal.PolyCoeffs) != L {
		return nil, ErrPVSSWrongShape
	}
	if len(reveal.Blindings) != L {
		return nil, ErrPVSSWrongShape
	}

	setupTr := pvssSetupTranscript(params, threshold, committee)
	var failed [][2]uint32
	for b := 0; b < L; b++ {
		if len(contrib.Commits[b]) != threshold {
			return nil, ErrPVSSWrongShape
		}
		if len(reveal.PolyCoeffs[b]) != threshold {
			return nil, ErrPVSSWrongShape
		}
		if len(reveal.Blindings[b]) != threshold {
			return nil, ErrPVSSWrongShape
		}
		for d := 0; d < threshold; d++ {
			if len(reveal.Blindings[b][d]) != pvssBlindingSize {
				return nil, ErrPVSSWrongShape
			}
			recomputed := pvssCommit(
				setupTr, contrib.NodeID,
				uint32(b), uint32(d),
				reveal.Blindings[b][d], reveal.PolyCoeffs[b][d],
			)
			if !bytes.Equal(recomputed, contrib.Commits[b][d]) {
				failed = append(failed, [2]uint32{uint32(b), uint32(d)})
			}
		}
	}
	return failed, nil
}

// VerifyShareConsistency checks that party j received share row
// σ_{i→j} from party i consistent with i's revealed polynomial
// coefficients. Returns a slice of byte indices where the share value
// does not match f_{i,b}(j) mod 257.
func VerifyShareConsistency(
	params *Params,
	dealerReveal PVSSRevealMsg,
	recipientIndex uint32,
	receivedShare []uint16,
) ([]uint32, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	L := params.SeedSize
	if len(receivedShare) != L {
		return nil, ErrPVSSWrongShape
	}
	if len(dealerReveal.PolyCoeffs) != L {
		return nil, ErrPVSSWrongShape
	}
	var failed []uint32
	for b := 0; b < L; b++ {
		expected := pvssEvalPoly(dealerReveal.PolyCoeffs[b], recipientIndex)
		if expected != receivedShare[b] {
			failed = append(failed, uint32(b))
		}
	}
	return failed, nil
}

// OpenRevealAck is a required, self-documenting barrier value that a
// caller must pass to RunDKGSimulationOpenRevealTestOnly to confirm
// it understands the resulting transcript REVEALS THE MASTER. There
// is exactly one acceptable value; passing anything else fails. This
// makes the leaking path impossible to call by accident and trivially
// greppable in a production build review
// (grep for IUnderstandThisRevealsTheMaster).
type OpenRevealAck struct{ ack string }

// AckOpenRevealRevealsMaster is the only value RunDKGSimulationOpenReveal
// TestOnly accepts. Its single field documents the hazard at the call
// site.
var AckOpenRevealRevealsMaster = OpenRevealAck{ack: "IUnderstandThisRevealsTheMaster"}

// ErrOpenRevealNotAcknowledged is returned when the open-reveal
// simulation is invoked without the explicit hazard acknowledgement.
var ErrOpenRevealNotAcknowledged = errors.New(
	"magnetar/pvss-dkg: open-reveal simulation reveals the master and is TEST-ONLY; " +
		"pass AckOpenRevealRevealsMaster to confirm, or use RunDKG for production")

// RunDKGSimulationOpenRevealTestOnly runs an n-party PVSS-DKG in a
// single process in OPEN-REVEAL mode.
//
// !!! TEST / KAT ONLY. THE OUTPUT TRANSCRIPT REVEALS THE MASTER. !!!
//
// Every party publishes its full RevealMsg (PolyCoeffs including the
// constant terms m_i). The resulting transcript therefore lets ANY
// observer reconstruct M = sum_i m_i. This is acceptable ONLY for
// deterministic KAT replay and for exercising the verification logic
// in tests. It MUST NOT run in a production deployment. The required
// `ack` barrier makes accidental production use impossible and makes
// the call site greppable.
//
// For production, use RunDKG (below): its transcript carries
// Reveals == nil and M is never reconstructible from it.
//
// rngs is a slice of n io.Readers, one per party. Pass nil to use
// crypto/rand.Reader for all parties. Tests use bytes.NewReader of a
// deterministic vector for KAT replay.
func RunDKGSimulationOpenRevealTestOnly(
	ack OpenRevealAck,
	params *Params,
	threshold int,
	committee []NodeID,
	rngs []io.Reader,
) (*PVSSTranscript, error) {
	if ack != AckOpenRevealRevealsMaster {
		return nil, ErrOpenRevealNotAcknowledged
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}
	if rngs != nil && len(rngs) != n {
		return nil, fmt.Errorf("magnetar/pvss-dkg: rngs length %d does not match committee size %d", len(rngs), n)
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(committee[i-1][:], committee[i][:]) >= 0 {
			return nil, errors.New("magnetar/pvss-dkg: committee not sorted ascending or contains duplicates")
		}
	}

	// Round 1: each party computes their own state.
	states := make([]*PVSSPartyState, n)
	contribs := make([]PVSSPublicContribution, n)
	for i := 0; i < n; i++ {
		var rng io.Reader
		if rngs != nil {
			rng = rngs[i]
		}
		st, err := NewPVSSPartyState(params, threshold, committee, uint32(i+1), rng)
		if err != nil {
			return nil, fmt.Errorf("magnetar/pvss-dkg: party %d Round-1 setup: %w", i+1, err)
		}
		states[i] = st
		contribs[i] = st.PublicContribution()
	}

	// Round 2 (private share distribution): for each (sender i,
	// recipient j) pair, sender i computes σ_{i→j} and recipient j
	// stores it in its own receivedShares row.
	receivedShares := make([][][]uint16, n) // receivedShares[j-1][i-1] = σ_{i→j}
	for j := 0; j < n; j++ {
		receivedShares[j] = make([][]uint16, n)
		for i := 0; i < n; i++ {
			row, err := states[i].ShareTo(uint32(j + 1))
			if err != nil {
				return nil, fmt.Errorf("magnetar/pvss-dkg: party %d ShareTo(%d): %w", i+1, j+1, err)
			}
			receivedShares[j][i] = row
		}
	}

	// Round 2 (public reveal): each party publishes their full reveal.
	// In production deployments this is conditional on a complaint;
	// in our reference open-reveal mode every party always publishes.
	reveals := make([]PVSSRevealMsg, n)
	for i := 0; i < n; i++ {
		reveals[i] = states[i].RevealMsg()
	}

	// Round 2 (verification): every party verifies every other
	// party's reveal against the published commit AND against their
	// own privately-received share row. Any failure marks the dealer
	// as malicious; they are excluded from the qualified set Q.
	qualified := make(map[uint32]struct{}, n)
	for i := 0; i < n; i++ {
		qualified[uint32(i+1)] = struct{}{}
	}
	for i := 0; i < n; i++ {
		failedCommits, err := VerifyContribution(params, threshold, committee, contribs[i], reveals[i])
		if err != nil {
			return nil, fmt.Errorf("magnetar/pvss-dkg: party %d VerifyContribution: %w", i+1, err)
		}
		if len(failedCommits) > 0 {
			delete(qualified, uint32(i+1))
			continue
		}
		// Verify every recipient's share is consistent with the
		// polynomial.
		for j := 0; j < n; j++ {
			failedBytes, err := VerifyShareConsistency(params, reveals[i], uint32(j+1), receivedShares[j][i])
			if err != nil {
				return nil, fmt.Errorf("magnetar/pvss-dkg: party %d VerifyShareConsistency: %w", i+1, err)
			}
			if len(failedBytes) > 0 {
				delete(qualified, uint32(i+1))
				break
			}
		}
	}

	if len(qualified) < threshold {
		return nil, ErrPVSSQuorumLost
	}

	setupTr := pvssSetupTranscript(params, threshold, committee)

	tr := &PVSSTranscript{
		Params:         params,
		Committee:      committee,
		Threshold:      threshold,
		Contributions:  contribs,
		Reveals:        reveals,
		ReceivedShares: receivedShares,
		SetupTr:        setupTr,
	}

	// Zeroize per-party secret state so the simulation itself does
	// not leave dealer-style material on the heap. We are in a
	// reference / test harness; production deployments where each
	// party runs in its own process should call zeroize on their own
	// state at protocol termination.
	for i := 0; i < n; i++ {
		zeroizePartyState(states[i])
	}

	return tr, nil
}

// RevealsMaster reports whether this transcript contains the full
// polynomial reveals (constant terms m_i) that make the master
// M = sum_i m_i reconstructible by any observer. A production
// transcript MUST return false. The open-reveal test transcript
// returns true.
//
// A transcript reveals the master iff ANY party's reveal carries a
// non-empty constant-term coefficient vector.
func (tr *PVSSTranscript) RevealsMaster() bool {
	for i := range tr.Reveals {
		for b := range tr.Reveals[i].PolyCoeffs {
			if len(tr.Reveals[i].PolyCoeffs[b]) > 0 {
				return true
			}
		}
	}
	return false
}

// RunDKG runs the PRODUCTION n-party PVSS-DKG. Unlike the open-reveal
// test simulation, the transcript it returns carries Reveals == nil:
// no party publishes its polynomial constant term, so the master
// M = sum_i m_i is NOT reconstructible from the transcript by any
// observer. `tr.RevealsMaster()` is false for this output.
//
// HONEST LIMITATIONS (read before deploying):
//
//  1. SLH-DSA group public-key derivation inherently needs the master.
//     pk = SLH-DSA.PK(M) is a hash tree over M; there is no way to
//     compute it from shares without either reconstructing M at some
//     party or running full MPC over the SHAKE hash tree (open
//     research). RunDKG reconstructs M transiently inside
//     deriveDKGPublicKey to compute pk and zeroizes it. That single
//     reconstruction is the inherent cost; it is NOT published. If you
//     need NO party to ever hold M (not even transiently for pk
//     derivation), you must run the TEE-attested path
//     (luxfi/threshold/protocols/slhdsa-tee) or the dealer path
//     (NewThbsSeKey) where the dealer is in the TCB for setup only.
//
//  2. With hash-based commitments (cSHAKE256 over coefficients), a
//     recipient CANNOT non-interactively verify a received share
//     against the public commitments without the dealer's opening,
//     and the opening includes the constant term. So RunDKG does NOT
//     exclude malicious dealers at DKG time (it cannot, soundly,
//     without revealing m_i or switching to group-homomorphic /
//     encrypted-share+NIZK commitments — a separate construction).
//     Malformed-share detection is DEFERRED to:
//     - THBS-SE Combine's per-party commit re-derivation at sign
//     time, which drops a tampered share and emits slashable
//     evidence (TestThbsSE_RejectOversizedShareWireSize /
//     TestThbsSE_RejectTamperedShareCommitMismatch);
//     - the complaint flow, where an accused party reveals ONLY the
//     disputed recipient's share value (never the constant term).
//     Because robust DKG-time dealer exclusion is NOT delivered here,
//     RunDKG is the no-leak setup path but NOT a robust-against-
//     malicious-dealers path. For adversarial committees, prefer the
//     dealer path or the TEE pool. This is labeled, not hidden.
//
// The production transcript is consumed by
// NewThbsSeKeyFromDealerlessDKG, which verifies commitment shape +
// setup binding (it cannot verify shares without reveals) and derives
// the share envelopes + group PK.
//
// rngs is a slice of n io.Readers, one per party. Pass nil for
// crypto/rand.
func RunDKG(
	params *Params,
	threshold int,
	committee []NodeID,
	rngs []io.Reader,
) (*PVSSTranscript, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, ErrInvalidThreshold
	}
	if n > MaxCommittee257 {
		return nil, ErrCommitteeTooLarge
	}
	if rngs != nil && len(rngs) != n {
		return nil, fmt.Errorf("magnetar/pvss-dkg: rngs length %d does not match committee size %d", len(rngs), n)
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(committee[i-1][:], committee[i][:]) >= 0 {
			return nil, errors.New("magnetar/pvss-dkg: committee not sorted ascending or contains duplicates")
		}
	}

	// Round 1: each party computes its own state; only the PUBLIC
	// commitments are collected for the transcript.
	states := make([]*PVSSPartyState, n)
	contribs := make([]PVSSPublicContribution, n)
	for i := 0; i < n; i++ {
		var rng io.Reader
		if rngs != nil {
			rng = rngs[i]
		}
		st, err := NewPVSSPartyState(params, threshold, committee, uint32(i+1), rng)
		if err != nil {
			return nil, fmt.Errorf("magnetar/pvss-dkg: party %d Round-1 setup: %w", i+1, err)
		}
		states[i] = st
		contribs[i] = st.PublicContribution()
	}

	// Round 2 (private share distribution): each recipient stores the
	// shares it received. These are published as part of the transcript
	// (they are Shamir leaves, which leak nothing about any individual
	// m_i below the threshold, and are needed to aggregate the final
	// shares). NOTE: a recipient publishing a share row reveals only
	// other parties' leaves AT THAT RECIPIENT'S point — not constant
	// terms.
	receivedShares := make([][][]uint16, n)
	for j := 0; j < n; j++ {
		receivedShares[j] = make([][]uint16, n)
		for i := 0; i < n; i++ {
			row, err := states[i].ShareTo(uint32(j + 1))
			if err != nil {
				return nil, fmt.Errorf("magnetar/pvss-dkg: party %d ShareTo(%d): %w", i+1, j+1, err)
			}
			receivedShares[j][i] = row
		}
	}

	setupTr := pvssSetupTranscript(params, threshold, committee)

	// Production transcript: Reveals is nil. The master is NOT
	// reconstructible from this transcript.
	tr := &PVSSTranscript{
		Params:         params,
		Committee:      committee,
		Threshold:      threshold,
		Contributions:  contribs,
		Reveals:        nil,
		ReceivedShares: receivedShares,
		SetupTr:        setupTr,
	}

	for i := 0; i < n; i++ {
		zeroizePartyState(states[i])
	}

	if tr.RevealsMaster() {
		// Defense in depth: a production transcript that somehow
		// carries constant-term reveals must never be returned.
		return nil, errors.New("magnetar/pvss-dkg: internal error: production transcript reveals master")
	}
	return tr, nil
}

// AggregateShareEnvelope aggregates the received shares for party j
// across the qualified set Q. Returns the GF(257) share vector
// σ_j[b] = Σ_{i ∈ Q} σ_{i→j}[b] mod 257. This is the input to the
// canonical wire-shape thbsseShareToBytes lift.
//
// Pure function of the transcript + the qualified set; any third
// party (or party j itself) computes it identically.
func AggregateShareEnvelope(tr *PVSSTranscript, qualified map[uint32]struct{}, partyIndex uint32) []uint16 {
	L := tr.Params.SeedSize
	out := make([]uint16, L)
	// partyIndex is 1-based (party p reads ReceivedShares[p-1]). A zero or
	// out-of-range index would wrap partyIndex-1 to a huge uint and panic; an
	// unknown party aggregates to the zero row, not a crash.
	if partyIndex < 1 || int(partyIndex) > len(tr.ReceivedShares) {
		return out
	}
	for i := 0; i < tr.Params.committeeSize(tr.Committee); i++ {
		if _, ok := qualified[uint32(i+1)]; !ok {
			continue
		}
		for b := 0; b < L; b++ {
			out[b] = uint16((uint32(out[b]) + uint32(tr.ReceivedShares[partyIndex-1][i][b])) % thbsseSharePrime)
		}
	}
	return out
}

// committeeSize is a helper to read len(committee) without forcing the
// caller to pass it. Not a method on Params (Params has no committee
// state); pinned here as a one-line internal helper to keep the
// AggregateShareEnvelope signature compact.
func (*Params) committeeSize(committee []NodeID) int {
	return len(committee)
}

// VerifyDKGTranscript is the public auditor's entry point. It returns
// the qualified set Q, the derived FIPS 205 group public key, and an
// error. It dispatches on the transcript type:
//
//   - PRODUCTION transcript (tr.Reveals == nil, tr.RevealsMaster() ==
//     false): verifies commitment shape + setup binding + received-
//     share shape. It CANNOT verify shares against commitments
//     (hash commitments are not openable without the constant-term
//     reveal), so it does NOT exclude malicious dealers at this stage:
//     every party with well-shaped commitments is qualified, and
//     malformed-share detection is deferred to THBS-SE Combine's
//     sign-time commit binding + the complaint flow. This is the
//     no-leak path; see RunDKG's HONEST LIMITATIONS.
//
//   - OPEN-REVEAL transcript (tr.Reveals populated, tr.RevealsMaster()
//     == true): the TEST/KAT path. It additionally re-derives every
//     commitment from the published reveals and checks every received
//     share against the revealed polynomial, excluding any party whose
//     reveal is inconsistent. This path REVEALS THE MASTER and is for
//     tests / KATs only.
//
// In both cases the group public key is derived in deriveDKGPublicKey,
// which transiently reconstructs the master to compute pk and zeroizes
// it (the inherent SLH-DSA cost; see RunDKG limitation 1). The
// reconstruction is internal to this function and is never published.
func VerifyDKGTranscript(tr *PVSSTranscript) (map[uint32]struct{}, *PublicKey, error) {
	if tr == nil {
		return nil, nil, errors.New("magnetar/pvss-dkg: nil transcript")
	}
	if err := tr.Params.Validate(); err != nil {
		return nil, nil, err
	}
	n := len(tr.Committee)
	if tr.Threshold < 1 || n < tr.Threshold {
		return nil, nil, ErrInvalidThreshold
	}
	if len(tr.Contributions) != n {
		return nil, nil, ErrPVSSWrongShape
	}
	if len(tr.ReceivedShares) != n {
		return nil, nil, ErrPVSSWrongShape
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(tr.Committee[i-1][:], tr.Committee[i][:]) >= 0 {
			return nil, nil, errors.New("magnetar/pvss-dkg: transcript committee not sorted ascending")
		}
	}

	// Re-derive setup transcript and verify it matches.
	setupTr := pvssSetupTranscript(tr.Params, tr.Threshold, tr.Committee)
	if setupTr != tr.SetupTr {
		return nil, nil, errors.New("magnetar/pvss-dkg: transcript setup_tr mismatch")
	}

	openReveal := tr.RevealsMaster()
	if openReveal && len(tr.Reveals) != n {
		return nil, nil, ErrPVSSWrongShape
	}

	qualified := make(map[uint32]struct{}, n)
	for i := 0; i < n; i++ {
		qualified[uint32(i+1)] = struct{}{}
	}
	for i := 0; i < n; i++ {
		if tr.Contributions[i].NodeID != tr.Committee[i] {
			delete(qualified, uint32(i+1))
			continue
		}
		// Commitment shape check applies to both paths: every party
		// must publish n_coeff = threshold commitments per byte.
		if !pvssCommitShapeOK(tr.Params, tr.Threshold, tr.Contributions[i]) {
			delete(qualified, uint32(i+1))
			continue
		}
		// Received-share shape check (both paths).
		for j := 0; j < n; j++ {
			if len(tr.ReceivedShares[j]) <= i || len(tr.ReceivedShares[j][i]) != tr.Params.SeedSize {
				delete(qualified, uint32(i+1))
				break
			}
		}
		if _, still := qualified[uint32(i+1)]; !still {
			continue
		}

		if !openReveal {
			// Production path: hash commitments cannot be opened without
			// the constant-term reveal, so no DKG-time share verification
			// is possible. A well-shaped party is qualified; malformed
			// shares are caught at sign time (THBS-SE commit binding) and
			// via the complaint flow. See RunDKG limitation 2.
			continue
		}

		// Open-reveal path (TEST/KAT): full verification against the
		// published reveals.
		if tr.Reveals[i].NodeID != tr.Committee[i] {
			delete(qualified, uint32(i+1))
			continue
		}
		failedCommits, err := VerifyContribution(tr.Params, tr.Threshold, tr.Committee, tr.Contributions[i], tr.Reveals[i])
		if err != nil {
			return nil, nil, err
		}
		if len(failedCommits) > 0 {
			delete(qualified, uint32(i+1))
			continue
		}
		for j := 0; j < n; j++ {
			failedBytes, err := VerifyShareConsistency(tr.Params, tr.Reveals[i], uint32(j+1), tr.ReceivedShares[j][i])
			if err != nil {
				return nil, nil, err
			}
			if len(failedBytes) > 0 {
				delete(qualified, uint32(i+1))
				break
			}
		}
	}

	if len(qualified) < tr.Threshold {
		return nil, nil, ErrPVSSQuorumLost
	}

	pk, err := deriveDKGPublicKey(tr, qualified)
	if err != nil {
		return nil, nil, err
	}
	return qualified, pk, nil
}

// pvssCommitShapeOK reports whether a public contribution has the
// canonical commitment shape: SeedSize byte-rows, each with exactly
// `threshold` 32-byte commitments. Pure shape check (no secret access).
func pvssCommitShapeOK(params *Params, threshold int, contrib PVSSPublicContribution) bool {
	if len(contrib.Commits) != params.SeedSize {
		return false
	}
	for b := 0; b < params.SeedSize; b++ {
		if len(contrib.Commits[b]) != threshold {
			return false
		}
		for d := 0; d < threshold; d++ {
			if len(contrib.Commits[b][d]) != 32 {
				return false
			}
		}
	}
	return true
}

// deriveDKGPublicKey computes the FIPS 205 group public key from the
// transcript. To do so it RECONSTRUCTS the master byte vector into
// `lagrangeScratch`, feeds it to KeyFromSeed, and zeroizes it.
//
// This reconstruction is PK-derivation-only and is INHERENT, not a
// shortcut: pk = SLH-DSA.PK(M) is a hash tree over M, so there is no
// way to derive pk from shares without reconstructing M somewhere (or
// running full MPC over the SHAKE hash tree — open research). The
// reconstruction is internal to this function and is NEVER published;
// only the public key bytes are returned. It runs at whoever calls
// VerifyDKGTranscript (an auditor or any party deriving the group pk).
//
// This is the same fundamental barrier as THBS-SE Combine: producing
// or deriving anything SLH-DSA-shaped from a shared seed touches the
// seed. Deployments that must guarantee NO party ever holds M (not
// even transiently for pk derivation) route this through the
// TEE-attested path (luxfi/threshold/protocols/slhdsa-tee) or use the
// dealer path. The buffer name `lagrangeScratch` is incidental; it is
// not a security property.
func deriveDKGPublicKey(tr *PVSSTranscript, qualified map[uint32]struct{}) (*PublicKey, error) {
	L := tr.Params.SeedSize
	n := len(tr.Committee)

	// Sort the qualified set ascending by party index so the
	// Lagrange basis is deterministic.
	q := make([]uint32, 0, len(qualified))
	for idx := range qualified {
		q = append(q, idx)
	}
	sort.Slice(q, func(i, j int) bool { return q[i] < q[j] })
	if len(q) < tr.Threshold {
		return nil, ErrPVSSQuorumLost
	}
	pick := q[:tr.Threshold]

	// Aggregate share envelopes for the picked parties.
	aggregated := make([]thbsseShare, tr.Threshold)
	for k, partyIdx := range pick {
		yvec := make([]uint16, L)
		for i := 0; i < n; i++ {
			if _, ok := qualified[uint32(i+1)]; !ok {
				continue
			}
			for b := 0; b < L; b++ {
				yvec[b] = uint16((uint32(yvec[b]) + uint32(tr.ReceivedShares[partyIdx-1][i][b])) % thbsseSharePrime)
			}
		}
		aggregated[k] = thbsseShare{X: partyIdx, Y: yvec}
	}

	// Lagrange-reconstruct the master into the lagrangeScratch buffer.
	masterU16, err := thbsseReconstructGF(aggregated, L)
	if err != nil {
		return nil, err
	}
	lagrangeScratch := make([]byte, L)
	for b := 0; b < L; b++ {
		lagrangeScratch[b] = byte(masterU16[b])
	}
	zeroizeU16Slice(masterU16)
	for k := range aggregated {
		zeroizeU16Slice(aggregated[k].Y)
	}

	// Derive PK and immediately zeroize the scratch buffer.
	sk, err := KeyFromSeed(tr.Params, lagrangeScratch)
	zeroizeBytes(lagrangeScratch)
	if err != nil {
		return nil, err
	}
	pk := &PublicKey{Mode: tr.Params.Mode, Bytes: append([]byte(nil), sk.Pub.Bytes...)}
	zeroizePrivateKey(sk)
	return pk, nil
}

// zeroizeU16Slice2D wipes every element of a 2-D uint16 slice.
func zeroizeU16Slice2D(s [][]uint16) {
	for _, row := range s {
		zeroizeU16Slice(row)
	}
}

// zeroizePartyState wipes the secret-bearing fields of a
// PVSSPartyState. Sets references to nil where possible.
func zeroizePartyState(st *PVSSPartyState) {
	if st == nil {
		return
	}
	zeroizeU16Slice2D(st.polyCoeffs)
	for b := range st.blindings {
		zeroizeBytes(st.blindings[b])
	}
	zeroizeU16Slice2D(st.distributedShares)
}

// VerifyPVSSComplaint is the third-party check that a complaint blob
// is genuine: the recomputed commit must differ from the published
// commit by at least one byte. Returns true if the complaint is well-
// formed and the accusation is supported by the evidence.
func VerifyPVSSComplaint(c PVSSComplaint) bool {
	if len(c.PublishedCommit) != 32 {
		return false
	}
	if len(c.RecomputedCommit) != 32 {
		return false
	}
	// The complaint is valid iff the two byte strings actually differ.
	return !bytes.Equal(c.PublishedCommit, c.RecomputedCommit)
}
