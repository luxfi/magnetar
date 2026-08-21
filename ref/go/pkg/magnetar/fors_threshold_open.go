// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// fors_threshold_open.go --- the ONE concretely-buildable, genuinely
// no-reconstruct, stock-FIPS-205-verifiable Track-B sub-protocol:
// DISTRIBUTED FORS-LEAF THRESHOLD OPENING.
//
// =====================================================================
//  WHAT THIS PROVES (and what it does NOT)
// =====================================================================
//
// This file builds the FORS bottom of an SLH-DSA signature from a
// t-of-n committee such that:
//
//   * NO global seed / full secret key is ever reconstructed. There is
//     no master seed in this construction at all: the FORS leaf secrets
//     are secret-shared DIRECTLY (jointly-random, byte-wise GF(257)
//     Shamir). At sign time the combiner interpolates ONLY the k
//     message-selected one-time leaf secrets --- each exactly n bytes
//     (one leaf), guarded by assertLeafWidth so the path is structurally
//     incapable of widening to the SeedSize-byte master. (Approach B of
//     the paper: "threshold leaf opening".)
//
//   * The assembled FORS signature is BYTE-IDENTICAL to the centralized
//     FIPS 205 forsSign output on the same leaf material, and its FORS
//     public key reconstructs via the UNMODIFIED FIPS 205 Algorithm 17
//     (forsPkFromSig) --- the verifier's own FORS step, proven
//     byte-equal to cloudflare/circl by TestSlhdsaInternal_ByteEqualToCirclSign.
//
//   * One-time material is BURNED: every opened leaf address is recorded
//     in the BurnLedger; a second open of the same FORS keypair under a
//     different message digest is refused as a slashable equivocation.
//
// What it does NOT do: it is NOT a full SLH-DSA signature. A full
// signature additionally needs the hypertree --- d WOTS+ signatures plus
// XMSS authentication paths whose sibling nodes are secret-derived WOTS+
// public keys over a 2^h-leaf tree. Those siblings cannot be opened at
// sign time (that would expose ~2^h' one-time WOTS+ keypairs and destroy
// one-time security) and cannot be precomputed without either a 2^h
// materialisation (infeasible for h = 63..68) or a keygen-time MPC over
// SHAKE (the Cozzo-Smart wall). Hence the FULL Track-B signer fails
// closed (threshold_noreconstruct.go); THIS file is a proven COMPONENT.
//
// =====================================================================
//  KEYGEN HONESTY
// =====================================================================
//
// The PUBLIC FORS material (auth paths + pkFORS) is a deterministic hash
// of the secret leaves; computing it from secret-shared leaves without
// exposing the unopened leaves requires either an MPC over F at keygen
// or a setup-TCB dealer. DistributedForsSetup below uses a setup-TCB
// dealer (it knows the genuine leaves for the keypair it is provisioning
// and shares them) --- this is the SAME "dealer-in-the-TCB-for-setup-only"
// pattern the production Magnetar v1.0 setup uses, and it is honestly the
// keygen obstruction, documented in the paper. The NOVELTY proven here
// is no-reconstruct SIGNING: once setup returns, no party holds the
// leaves; the combiner opens only the per-message selected one-time
// leaves and never the full FORS key.

import (
	"encoding/binary"
	"errors"
	"io"
)

// Customisation tag for the FORS-open commit. Distinct from every other
// Magnetar tag so a cross-protocol replay deterministically mismatches.
const tagForsOpenCommit = "MAGNETAR-FORS-THRESHOLD-OPEN-V1"

// Errors specific to the distributed FORS-leaf opening.
var (
	// ErrForsSetupParams is returned when the FORS open is invoked for a
	// parameter set the internal FIPS 205 engine does not implement.
	ErrForsSetupParams = errors.New("magnetar/fors-open: parameter set not implemented by the FIPS 205 engine")

	// ErrForsQuorum is returned when fewer than threshold partial opens
	// are presented for some selected leaf.
	ErrForsQuorum = errors.New("magnetar/fors-open: insufficient partial opens for a selected leaf")

	// ErrForsShape is returned when a partial-open payload has the wrong
	// dimensions.
	ErrForsShape = errors.New("magnetar/fors-open: partial-open payload has wrong shape")

	// ErrForsCommitMismatch is returned when a partial open does not
	// re-derive its commit against the published (addr, digest).
	ErrForsCommitMismatch = errors.New("magnetar/fors-open: partial-open commit does not re-derive")
)

// ForsKeypairAddr identifies one FORS keypair in the SLH-DSA hypertree:
// the XMSS tree address (3 words, FIPS 205 §4.2) and the keypair (XMSS
// leaf) index. In a full signature this is selected by R from the
// message; the component protocol takes it as an explicit input.
type ForsKeypairAddr struct {
	IdxTree [3]uint32
	IdxLeaf uint32
}

// forsAddrBuf builds the FIPS 205 address template forsSign / forsPkFromSig
// expect for this keypair (layer 0, type FORS-tree, keypair address set).
func (a ForsKeypairAddr) forsAddrBuf() adrsBuf {
	var adr adrsBuf
	adr.setLayerAddress(0)
	adr.setTreeAddress(a.IdxTree)
	adr.setTypeAndClear(adrsTypeForsTree)
	adr.setKeyPairAddress(a.IdxLeaf)
	return adr
}

// ForsPublicMaterial is everything the combiner and any third-party
// verifier need that carries NO secret: the keypair address, the message
// digest md (which selects the leaves), the k selected leaf indices, the
// k public authentication paths, and the published FORS public key.
//
// Published at setup. A verifier checks an assembled FORS signature by
// running stock FIPS 205 forsPkFromSig and comparing to PkFors.
type ForsPublicMaterial struct {
	Params    *Params
	Addr      ForsKeypairAddr
	Digest    []byte   // md (>= ceil(k*a/8) bytes); public
	Indices   []uint32 // k selected leaf indices, derived from md (public)
	AuthPaths [][]byte // k auth paths, each a*n bytes (public)
	PkFors    []byte   // n-byte FORS public key T_k(roots) (public)
	PkSeed    []byte   // n-byte FIPS 205 public seed (public)
	Threshold int      // t: leaves reconstruct from any t partial opens
}

// ForsLeafShareMatrix is the secret-shared FORS leaf material produced by
// DistributedForsSetup. Shares[partyIdx][forsTree] is party (partyIdx+1)'s
// byte-wise GF(257) Shamir share of the n-byte leaf secret selected in
// FORS sub-tree forsTree. NO party holds more than its own row; the
// genuine leaves exist only inside the setup-TCB dealer and are erased
// before this matrix is returned.
type ForsLeafShareMatrix struct {
	Params *Params
	Addr   ForsKeypairAddr
	N      int // committee size
	T      int // threshold
	// Shares[partyIdx][forsTree] is one party's share of one leaf secret.
	Shares [][]thbsseShare
}

// PartyRow returns party (partyIndex, 1-based) view: its column of leaf
// shares across the k FORS sub-trees. This is the ONLY share material a
// party holds; it never sees other parties' rows or the genuine leaves.
func (m *ForsLeafShareMatrix) PartyRow(partyIndex uint32) ([]thbsseShare, error) {
	if partyIndex < 1 || int(partyIndex) > m.N {
		return nil, ErrForsShape
	}
	return m.Shares[partyIndex-1], nil
}

// forsSelectedIndices replays FIPS 205 §8.3 Algorithm 16 index parsing:
// for digest md it returns the k leaf indices (one per FORS sub-tree)
// selected for signing. Public function of md only.
func forsSelectedIndices(p *internalParams, digest []byte) []uint32 {
	indices := make([]uint32, p.k)
	in, bits, total := 0, uint32(0), uint32(0)
	maskA := (uint32(1) << p.a) - 1
	for i := uint32(0); i < p.k; i++ {
		for bits < p.a {
			total = (total << 8) + uint32(digest[in])
			in++
			bits += 8
		}
		bits -= p.a
		indices[i] = (total >> bits) & maskA
	}
	return indices
}

// DistributedForsSetup is the setup-TCB dealer for one FORS keypair. It
// derives the genuine FORS leaf material from a setup seed (the dealer is
// in the TCB FOR SETUP ONLY), shares the k message-selected leaf secrets
// across the committee, publishes the auth paths + pkFORS, and erases the
// genuine leaves before returning.
//
// Production deployments replace this with a dealerless DKG + MPC-over-F
// keygen (the documented keygen obstruction); the SIGN-side wire shape
// (ForsLeafShareMatrix + ForsPublicMaterial) is unchanged.
//
// seed is a FIPS 205 SeedSize-byte scheme seed; addr is the FORS keypair
// to provision; digest is md (selects the leaves); (n, t) is the
// committee. coeffStream feeds the Shamir polynomials (stretched if short).
func DistributedForsSetup(
	params *Params,
	seed []byte,
	addr ForsKeypairAddr,
	digest []byte,
	n, t int,
	coeffStream []byte,
) (*ForsLeafShareMatrix, *ForsPublicMaterial, error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	internal, ok := internalParamsForMode(params.Mode)
	if !ok {
		return nil, nil, ErrForsSetupParams
	}
	if t < 1 || n < t || n > MaxCommittee257 {
		return nil, nil, ErrInvalidThreshold
	}
	if len(seed) != params.SeedSize {
		return nil, nil, ErrSeedSize
	}
	if len(digest) < int((internal.k*internal.a+7)/8) {
		return nil, nil, ErrForsShape
	}

	// --- SETUP TCB: derive the genuine FORS material from the seed. ---
	// Expand the seed to (skSeed || skPrf || pkSeed) exactly as FIPS 205
	// §10.1 DeriveKey does, then build the secret-side PRF closure. This
	// is the ONLY place the seed expansion exists; it lives inside this
	// dealer and is erased before return.
	derived := make([]byte, 3*internal.n)
	shakeIntoCat(derived, seed)
	skSeedSeg := derived[:internal.n]
	pkSeed := append([]byte(nil), derived[2*internal.n:3*internal.n]...)
	prfOut := makePRFClosure(internal, pkSeed, skSeedSeg)

	// Centralized reference FORS signature on md at addr: this gives both
	// the genuine leaf secrets (to share) and the public auth paths (to
	// publish), byte-for-byte as FIPS 205 forsSign emits them.
	adr := addr.forsAddrBuf()
	refSig := make([]byte, internal.forsSigSize())
	forsSign(internal, refSig, pkSeed, &adr, digest, prfOut)

	// Genuine pkFORS via the verifier's own Algorithm 17.
	pkFors := make([]byte, internal.n)
	forsPkFromSig(internal, pkFors, pkSeed, &adr, digest, refSig)

	indices := forsSelectedIndices(internal, digest)

	pairSize := int(internal.forsPairSize())
	leafN := int(internal.n)
	authLen := int(internal.forsAuthPathSize())

	// Extract genuine leaves + public auth paths from refSig.
	authPaths := make([][]byte, internal.k)
	shares := make([][]thbsseShare, n) // shares[party][forsTree]
	for p := 0; p < n; p++ {
		shares[p] = make([]thbsseShare, internal.k)
	}

	// Share each leaf secret independently (byte-wise GF(257) Shamir).
	// CRITICAL: each leaf gets an INDEPENDENT Shamir coefficient stream
	// (domain-separated by leaf index). Reusing coefficients across leaves
	// would let an adversary holding one share of two leaves learn their
	// GF(257) difference (the coefficient terms cancel) --- a real leak.
	needed := (t - 1) * leafN * 2
	if needed < 2 {
		needed = 2
	}
	for i := 0; i < int(internal.k); i++ {
		skOff := i * pairSize
		leaf := refSig[skOff : skOff+leafN] // genuine leaf secret (n bytes)
		authPaths[i] = append([]byte(nil), refSig[skOff+leafN:skOff+leafN+authLen]...)

		// Per-leaf independent coefficient stream: cSHAKE256(coeffStream ||
		// leaf_index). Distinct customisation-bound output per leaf.
		csSeed := make([]byte, 0, len(coeffStream)+4)
		csSeed = append(csSeed, coeffStream...)
		csSeed = binary.BigEndian.AppendUint32(csSeed, uint32(i))
		cs := cshake256(csSeed, needed, tagForsOpenCommit)

		gf := make([]uint16, leafN)
		for b := 0; b < leafN; b++ {
			gf[b] = uint16(leaf[b])
		}
		leafShares, err := thbsseDealRandomGF(gf, n, t, cs)
		if err != nil {
			zeroizeBytes(derived)
			zeroizeBytes(refSig)
			return nil, nil, err
		}
		for p := 0; p < n; p++ {
			shares[p][i] = leafShares[p]
		}
		zeroizeU16Slice(gf)
	}

	pub := &ForsPublicMaterial{
		Params:    params,
		Addr:      addr,
		Digest:    append([]byte(nil), digest...),
		Indices:   indices,
		AuthPaths: authPaths,
		PkFors:    pkFors,
		PkSeed:    pkSeed,
		Threshold: t,
	}
	mat := &ForsLeafShareMatrix{Params: params, Addr: addr, N: n, T: t, Shares: shares}

	// Erase the setup-TCB secret material. After this point no genuine
	// leaf, no skSeed, no seed expansion exists anywhere; only the shares
	// (held one-row-per-party) and the public material remain.
	zeroizeBytes(refSig)
	zeroizeBytes(derived)

	return mat, pub, nil
}

// ForsPartialOpen is one party's release of its shares of the k selected
// one-time leaf secrets, bound by a commit to (addr, digest, party) so a
// cross-context replay deterministically mismatches and so the burn
// ledger can attribute reuse. The LeafShares carry the party's GF(257)
// Shamir value for each selected leaf; the share at a single evaluation
// point is information-theoretically independent of the leaf for any
// party holding < t shares.
type ForsPartialOpen struct {
	PartyIndex uint32     // 1-based committee position == Shamir eval point
	Commit     [32]byte   // cSHAKE256(addr || digest || party || leaf-shares)
	LeafShares [][]uint16 // [forsTree][n] GF(257) share values at PartyIndex
}

// PartialOpen builds party (partyIndex)'s ForsPartialOpen from its row of
// the share matrix. The commit binds the release to the public (addr,
// digest) so the same shares cannot be replayed for a different keypair
// or message.
func (m *ForsLeafShareMatrix) PartialOpen(partyIndex uint32, digest []byte) (ForsPartialOpen, error) {
	row, err := m.PartyRow(partyIndex)
	if err != nil {
		return ForsPartialOpen{}, err
	}
	leafShares := make([][]uint16, len(row))
	for i := range row {
		leafShares[i] = append([]uint16(nil), row[i].Y...)
	}
	open := ForsPartialOpen{PartyIndex: partyIndex, LeafShares: leafShares}
	open.Commit = forsOpenCommit(m.Addr, digest, partyIndex, leafShares)
	return open, nil
}

// forsOpenCommit binds a partial open to (addr, digest, party, shares).
func forsOpenCommit(addr ForsKeypairAddr, digest []byte, party uint32, leafShares [][]uint16) [32]byte {
	buf := make([]byte, 0, 64+len(digest))
	for _, w := range addr.IdxTree {
		buf = binary.BigEndian.AppendUint32(buf, w)
	}
	buf = binary.BigEndian.AppendUint32(buf, addr.IdxLeaf)
	buf = append(buf, digest...)
	buf = binary.BigEndian.AppendUint32(buf, party)
	for _, ls := range leafShares {
		for _, v := range ls {
			buf = binary.BigEndian.AppendUint16(buf, v)
		}
	}
	var out [32]byte
	copy(out[:], cshake256(buf, 32, tagForsOpenCommit))
	return out
}

// digest32 hashes md into the 32-byte burn-ledger digest key.
func digest32(md []byte) [32]byte {
	var out [32]byte
	copy(out[:], cshake256(md, 32, tagForsOpenCommit))
	return out
}

// OpenForsThreshold is the PUBLIC combiner. From the public material and
// >= t partial opens, it interpolates ONLY the k message-selected one-time
// leaf secrets --- each exactly one leaf wide, guarded by assertLeafWidth
// so no global-seed reconstruction is possible --- assembles the FORS
// signature, burns the opened leaf addresses, and returns the FORS
// signature bytes.
//
// The returned bytes are byte-identical to the centralized FIPS 205
// forsSign output, and forsPkFromSig(returned) == pub.PkFors under the
// unmodified FIPS 205 Algorithm 17.
//
// ledger enforces one-time/few-time safety: each selected FORS leaf
// address is burned for the message digest; a second open of the same
// keypair under a different digest fails with *BurnConflict (constraint 3).
// Pass a fresh *BurnLedger for an isolated open; pass a persistent one to
// enforce no-reuse across messages.
func OpenForsThreshold(
	pub *ForsPublicMaterial,
	partials []ForsPartialOpen,
	ledger *BurnLedger,
) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("magnetar/fors-open: nil public material")
	}
	params := pub.Params
	if err := params.Validate(); err != nil {
		return nil, err
	}
	internal, ok := internalParamsForMode(params.Mode)
	if !ok {
		return nil, ErrForsSetupParams
	}
	if ledger == nil {
		return nil, errors.New("magnetar/fors-open: nil burn ledger (one-time safety requires a ledger)")
	}
	leafN := int(internal.n)
	authLen := int(internal.forsAuthPathSize())
	pairSize := int(internal.forsPairSize())
	k := int(internal.k)
	if len(pub.AuthPaths) != k {
		return nil, ErrForsShape
	}

	// Validate partial opens against their commits and collect, per FORS
	// sub-tree, the (eval-point, share-vector) pairs.
	type pt struct {
		x uint32
		y []uint16
	}
	collected := make([][]pt, k)
	for j := 0; j < k; j++ {
		collected[j] = make([]pt, 0, len(partials))
	}
	seenParty := make(map[uint32]struct{}, len(partials))
	for _, po := range partials {
		if po.PartyIndex == 0 {
			return nil, ErrForsShape
		}
		if _, dup := seenParty[po.PartyIndex]; dup {
			continue // ignore duplicate party submissions
		}
		if len(po.LeafShares) != k {
			return nil, ErrForsShape
		}
		for j := 0; j < k; j++ {
			if len(po.LeafShares[j]) != leafN {
				return nil, ErrForsShape
			}
		}
		want := forsOpenCommit(pub.Addr, pub.Digest, po.PartyIndex, po.LeafShares)
		if want != po.Commit {
			return nil, ErrForsCommitMismatch
		}
		seenParty[po.PartyIndex] = struct{}{}
		for j := 0; j < k; j++ {
			collected[j] = append(collected[j], pt{x: po.PartyIndex, y: po.LeafShares[j]})
		}
	}

	mdDigest := digest32(pub.Digest)
	forsSig := make([]byte, internal.forsSigSize())

	for j := 0; j < k; j++ {
		// CONSTRAINT 1 (fail-closed): we interpolate exactly one leaf
		// (leafN bytes), never the SeedSize master. assertLeafWidth makes
		// a widening refactor fault immediately.
		if err := assertLeafWidth(params, leafN); err != nil {
			return nil, err
		}
		if pub.Threshold < 1 || len(collected[j]) < pub.Threshold {
			return nil, ErrForsQuorum
		}

		// CONSTRAINT 3 (fail-closed): burn the one-time FORS leaf address
		// for this digest before releasing the opened secret. A second
		// open of the same keypair sub-tree under a different message
		// digest is a slashable equivocation.
		addr := OneTimeAddr{
			Kind:     KindForsFewTime,
			Layer:    0,
			Tree:     pub.Addr.IdxTree[0],
			Leaf:     pub.Addr.IdxLeaf,
			ForsTree: uint32(j),
		}
		if err := ledger.Burn(addr, mdDigest); err != nil {
			return nil, err
		}

		// Lagrange-interpolate this single leaf secret over GF(257) from
		// any t of the collected shares (deterministic public combiner).
		shares := make([]thbsseShare, pub.Threshold)
		for s := 0; s < pub.Threshold; s++ {
			shares[s] = thbsseShare{X: collected[j][s].x, Y: collected[j][s].y}
		}
		leaf, err := thbsseReconstructGF(shares, leafN)
		if err != nil {
			return nil, err
		}

		// Write leaf secret + public auth path into the FORS signature.
		skOff := j * pairSize
		for b := 0; b < leafN; b++ {
			forsSig[skOff+b] = byte(leaf[b])
		}
		copy(forsSig[skOff+leafN:skOff+leafN+authLen], pub.AuthPaths[j])
		zeroizeU16Slice(leaf)
	}

	return forsSig, nil
}

// VerifyForsThreshold checks an assembled FORS signature against the
// published FORS public key using the UNMODIFIED FIPS 205 Algorithm 17
// (forsPkFromSig). This is exactly the verifier-side FORS step; it is
// proven byte-equal to cloudflare/circl by TestSlhdsaInternal_ByteEqualToCirclSign.
//
// Returns true iff forsPkFromSig(forsSig) == pub.PkFors.
func VerifyForsThreshold(pub *ForsPublicMaterial, forsSig []byte) (bool, error) {
	if pub == nil {
		return false, errors.New("magnetar/fors-open: nil public material")
	}
	internal, ok := internalParamsForMode(pub.Params.Mode)
	if !ok {
		return false, ErrForsSetupParams
	}
	if len(forsSig) != int(internal.forsSigSize()) {
		return false, ErrForsShape
	}
	if len(pub.PkFors) != int(internal.n) {
		return false, ErrForsShape
	}
	if len(pub.PkSeed) != int(internal.n) {
		return false, ErrForsShape
	}
	// The digest is read by forsPkFromSig to index k message blocks; too few bytes
	// panics there. The producing door (DistributedForsSetup) refuses the same
	// short shape, so the verifying door must too — a malformed public input is a
	// refused verification, not a crash.
	if len(pub.Digest) < int((internal.k*internal.a+7)/8) {
		return false, ErrForsShape
	}
	adr := pub.Addr.forsAddrBuf()
	got := make([]byte, internal.n)
	forsPkFromSig(internal, got, pub.PkSeed, &adr, pub.Digest, forsSig)
	return ctEqualBytes(got, pub.PkFors), nil
}

// readFullOrErr is a tiny helper for setup callers that want to source
// the Shamir coefficient stream from an io.Reader. Returns ErrShortRand
// on a short read.
func readFullOrErr(rng io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rng, buf); err != nil {
		return nil, ErrShortRand
	}
	return buf, nil
}
