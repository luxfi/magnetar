// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// slhdsa_internal.go — Magnetar-internal FIPS 205 SLH-DSA reference
// implementation for the SHAKE-{192s, 192f, 256s} parameter sets.
//
// This file is the v1.1 substrate for the strict-atom-assembly Combine
// path (thbsse_assemble.go). It implements FIPS 205 §5 (WOTS+ chain),
// §6.2 (FORS sign), §7 (XMSS), and §8 (Hypertree) directly, exposing
// the FIPS 205 byte production as a sequence of WRITES into an
// already-allocated signature buffer driven by an opaque PRF-output
// CALLBACK. The callback (called prfOutFn) takes a fully-prepared
// address and returns the n-byte PRF output that FIPS 205 §11.2 specifies
// for SHAKE families:
//
//   PRF(PK.seed, ADRS, X) = SHAKE256(PK.seed || ADRS || X)[:n]
//
// The CALLBACK is the strict-atom path's seam: thbsse_assemble.go
// installs a callback that composes the X portion of the SHAKE input
// from per-party Shamir shares of the FIPS 205 derived material WITHOUT
// ever materialising the derived bytes as a free-standing variable.
//
// Every primitive in this file is fed BYTES — pkSeed, the address bytes,
// the FORS-leaf indices, the WOTS+ chain indices. None of them holds
// the underlying byte-shares of SK.seed / SK.prf; those live inside
// thbsse_assemble.go's atom bag and never escape its closures.
//
// This file is FIPS 205 byte-exact against cloudflare/circl 1.6.3:
// the byte-equality test in slhdsa_internal_test.go drives a circl-
// derived (skSeed, skPrf, pkSeed) tuple through the SAME PRF callback
// and asserts the output matches circl's SignDeterministic for the
// same inputs across all three SHAKE parameter sets.
//
// =====================================================================
//  Parameter sets supported
// =====================================================================
//
// Only the SHAKE family (SHAKE_192s, SHAKE_192f, SHAKE_256s) is
// implemented here. The Magnetar package as a whole supports only these
// three modes (params.go). The SHA-2 family would require a separate
// PRF/PRFMsg/HashMsg dispatch and is intentionally out of scope.
//
// =====================================================================
//  Address layout (FIPS 205 §4.2)
// =====================================================================
//
// SHAKE addresses are 32 bytes (non-compressed); SHA-2 addresses are
// 22 bytes (compressed). This file uses 32-byte addresses unconditionally
// for SHAKE modes:
//
//   bytes  0- 3 : layer address (uint32 BE)
//   bytes  4- 7 : tree address [2] (uint32 BE)
//   bytes  8-11 : tree address [1] (uint32 BE)
//   bytes 12-15 : tree address [0] (uint32 BE)
//   bytes 16-19 : type           (uint32 BE)
//   bytes 20-23 : key-pair address (uint32 BE)
//   bytes 24-27 : chain address / tree height (uint32 BE)
//   bytes 28-31 : hash address / tree index   (uint32 BE)
//
// The constants below name the type values.
//
// =====================================================================
//  Hash primitives (FIPS 205 §11.2 — SHAKE instantiation)
// =====================================================================
//
//   H_msg(R, PK.seed, PK.root, M) =
//       SHAKE256(R || PK.seed || PK.root || M)[:m]
//
//   PRF_msg(SK.prf, optRand, M) =
//       SHAKE256(SK.prf || optRand || M)[:n]
//
//   PRF(PK.seed, ADRS, SK.seed) =
//       SHAKE256(PK.seed || ADRS || SK.seed)[:n]
//
//   F(PK.seed, ADRS, M_1) =
//       SHAKE256(PK.seed || ADRS || M_1)[:n]
//
//   H(PK.seed, ADRS, M_1 || M_2) =
//       SHAKE256(PK.seed || ADRS || M_1 || M_2)[:n]
//
//   T_l(PK.seed, ADRS, M) =
//       SHAKE256(PK.seed || ADRS || M)[:n]
//
// The implementation routes ALL of {F, H, T_l, H_msg, PRF_msg} through
// the SAME absorbBuf helper. The PRF call alone is hosted by the
// strict-atom callback (prfOutFn) because it is the ONE site where
// secret material (SK.seed) enters the input. F/H/T_l/H_msg/PRF_msg
// operate on either public bytes (msg, R, pkSeed, addr) or on outputs
// of earlier PRF calls; their inputs do not contain seed bytes
// directly.

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Address types per FIPS 205 §4.2 Table 1.
const (
	adrsTypeWotsHash  uint32 = 0
	adrsTypeWotsPk    uint32 = 1
	adrsTypeTree      uint32 = 2
	adrsTypeForsTree  uint32 = 3
	adrsTypeForsRoots uint32 = 4
	adrsTypeWotsPrf   uint32 = 5
	adrsTypeForsPrf   uint32 = 6
)

// WOTS+ Winternitz parameter w = 16, lg(w) = 4.
const (
	wotsW    uint32 = 16
	wotsLen2 uint32 = 3
)

// internalParams is the FIPS 205 §10.1 parameter tuple this file
// dispatches on. Materialised from a public-facing Magnetar Mode via
// internalParamsForMode.
type internalParams struct {
	mode   Mode
	n      uint32 // WOTS+ message length in bytes
	hPrime uint32 // XMSS Merkle tree height
	h      uint32 // total hypertree height
	d      uint32 // hypertree layers
	a      uint32 // FORS bits per leaf
	k      uint32 // FORS trees
	m      uint32 // HashMsg digest length

	// addrSize is fixed at 32 for SHAKE; included as a parameter so
	// future SHA-2 dispatch lines up uniformly.
	addrSize uint32
}

// FIPS 205 §10.1 Table 2 — SHAKE family only.
var (
	internalParamsM192s = &internalParams{
		mode: ModeM192s, n: 24, hPrime: 9, h: 63, d: 7, a: 14, k: 17, m: 39, addrSize: 32,
	}
	internalParamsM192f = &internalParams{
		mode: ModeM192f, n: 24, hPrime: 3, h: 66, d: 22, a: 8, k: 33, m: 42, addrSize: 32,
	}
	internalParamsM256s = &internalParams{
		mode: ModeM256s, n: 32, hPrime: 8, h: 64, d: 8, a: 14, k: 22, m: 47, addrSize: 32,
	}
)

func internalParamsForMode(mode Mode) (*internalParams, bool) {
	switch mode {
	case ModeM192s:
		return internalParamsM192s, true
	case ModeM192f:
		return internalParamsM192f, true
	case ModeM256s:
		return internalParamsM256s, true
	default:
		return nil, false
	}
}

// wotsLen1 = 2n (per FIPS 205 §5).
func (p *internalParams) wotsLen1() uint32 { return 2 * p.n }

// wotsLen = wotsLen1 + wotsLen2.
func (p *internalParams) wotsLen() uint32 { return p.wotsLen1() + wotsLen2 }

// wotsSigSize = wotsLen * n.
func (p *internalParams) wotsSigSize() uint32 { return p.wotsLen() * p.n }

// xmssAuthPathSize = hPrime * n.
func (p *internalParams) xmssAuthPathSize() uint32 { return p.hPrime * p.n }

// xmssSigSize = wotsSigSize + xmssAuthPathSize.
func (p *internalParams) xmssSigSize() uint32 {
	return p.wotsSigSize() + p.xmssAuthPathSize()
}

// hyperTreeSigSize = d * xmssSigSize.
func (p *internalParams) hyperTreeSigSize() uint32 {
	return p.d * p.xmssSigSize()
}

// forsAuthPathSize = a * n per FORS tree.
func (p *internalParams) forsAuthPathSize() uint32 { return p.a * p.n }

// forsPairSize = n (sk) + a*n (auth) per FORS tree.
func (p *internalParams) forsPairSize() uint32 {
	return p.n + p.forsAuthPathSize()
}

// forsSigSize = k * (n + a*n).
func (p *internalParams) forsSigSize() uint32 {
	return p.k * p.forsPairSize()
}

// signatureSize = n (rnd) + forsSigSize + hyperTreeSigSize.
func (p *internalParams) signatureSize() uint32 {
	return p.n + p.forsSigSize() + p.hyperTreeSigSize()
}

// =====================================================================
//  Address manipulation
// =====================================================================
//
// Addresses for SHAKE modes are 32 bytes laid out per FIPS 205 §4.2.

// adrsBuf is a 32-byte address scratchpad. All field setters write at
// fixed offsets; the buffer is reused across PRF/F/H calls.
type adrsBuf [32]byte

// setLayerAddress writes the layer address (uint32 BE) at offset 0.
func (a *adrsBuf) setLayerAddress(l uint32) {
	binary.BigEndian.PutUint32(a[0:], l)
}

// setTreeAddress writes the 3-word tree address.
//   - t[2] → bytes [4:8]
//   - t[1] → bytes [8:12]
//   - t[0] → bytes [12:16]
func (a *adrsBuf) setTreeAddress(t [3]uint32) {
	binary.BigEndian.PutUint32(a[4:], t[2])
	binary.BigEndian.PutUint32(a[8:], t[1])
	binary.BigEndian.PutUint32(a[12:], t[0])
}

// setTypeAndClear writes the type word at offset 16 and zeros bytes
// 20..32 (key-pair address, chain/height address, hash/tree-index
// address).
func (a *adrsBuf) setTypeAndClear(t uint32) {
	binary.BigEndian.PutUint32(a[16:], t)
	for i := 20; i < 32; i++ {
		a[i] = 0
	}
}

// setKeyPairAddress writes the keypair address at offset 20.
func (a *adrsBuf) setKeyPairAddress(i uint32) {
	binary.BigEndian.PutUint32(a[20:], i)
}

// setChainAddress writes the chain-address word at offset 24.
func (a *adrsBuf) setChainAddress(i uint32) {
	binary.BigEndian.PutUint32(a[24:], i)
}

// setTreeHeight writes the tree-height word at offset 24 (overlaps
// chain address per FIPS 205 §4.2 — they are union fields per address
// type).
func (a *adrsBuf) setTreeHeight(i uint32) {
	binary.BigEndian.PutUint32(a[24:], i)
}

// setHashAddress writes the hash-address word at offset 28.
func (a *adrsBuf) setHashAddress(i uint32) {
	binary.BigEndian.PutUint32(a[28:], i)
}

// setTreeIndex writes the tree-index word at offset 28 (overlaps
// hash address by FIPS 205 §4.2 union).
func (a *adrsBuf) setTreeIndex(i uint32) {
	binary.BigEndian.PutUint32(a[28:], i)
}

// =====================================================================
//
//	PRF callback (the strict-atom seam)
//
// =====================================================================
//
// prfOutFn is the FIPS 205 §11.2 PRF for SHAKE:
//
//	PRF(PK.seed, ADRS, X) = SHAKE256(PK.seed || ADRS || X)[:n]
//
// where X is the n-byte secret seed material per FIPS 205 §6.2 and §5.
//
// The strict-atom Combine path (thbsse_assemble.go) installs a closure
// here that composes X from Lagrange-interpolated per-party shares
// WITHOUT ever holding X as a free-standing variable. The closure
// owns the only buffer that holds X bytes and zeroizes it before
// returning.
//
// The callee MUST write exactly n bytes to out. Callees that mutate the
// supplied addr argument are responsible for restoring it before
// return (the implementation here passes a fresh address per call so
// this is moot).
type prfOutFn func(out []byte, addr *adrsBuf)

// prfMsgFn is the FIPS 205 §11.2 PRF_msg for SHAKE:
//
//	PRF_msg(SK.prf, optRand, M) = SHAKE256(SK.prf || optRand || M)[:n]
//
// SK.prf is the message-randomizer key half of the FIPS 205 expanded
// material; it is hosted by the strict-atom atom bag for the same
// reason X is.
type prfMsgFn func(out, optRand, msgPrime []byte)

// =====================================================================
//  Hash primitives — public-byte hashes
// =====================================================================

// shakeIntoCat absorbs the concatenation of parts and writes outLen
// bytes to out. The standard SHAKE256 squeeze.
func shakeIntoCat(out []byte, parts ...[]byte) {
	h := sha3.NewShake256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	_, _ = h.Read(out)
}

// fPub computes F(PK.seed, ADRS, M_1) per FIPS 205 §11.2 for SHAKE.
// M_1 is n bytes. Used in WOTS+ chain step and FORS leaf hashing.
func fPub(out, pkSeed []byte, addr *adrsBuf, m1 []byte) {
	shakeIntoCat(out, pkSeed, addr[:], m1)
}

// hPub computes H(PK.seed, ADRS, M_1 || M_2) per FIPS 205 §11.2 for
// SHAKE. M_1 and M_2 are each n bytes. Used in XMSS / FORS tree
// concatenation steps.
func hPub(out, pkSeed []byte, addr *adrsBuf, m1, m2 []byte) {
	shakeIntoCat(out, pkSeed, addr[:], m1, m2)
}

// tlPub computes T_l(PK.seed, ADRS, M) per FIPS 205 §11.2 for SHAKE.
// M is the concatenation of the WOTS+ public key chains (T_len)
// or FORS root chains (T_k). Variadic to match FIPS 205's variable-
// length input.
func tlPub(out, pkSeed []byte, addr *adrsBuf, parts ...[]byte) {
	h := sha3.NewShake256()
	_, _ = h.Write(pkSeed)
	_, _ = h.Write(addr[:])
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	_, _ = h.Read(out)
}

// hMsgPub computes H_msg(R, PK.seed, PK.root, M) per FIPS 205 §11.2
// for SHAKE. R is n bytes, PK.seed is n, PK.root is n, M is the
// concatenation (b, |ctx|, ctx, msg) per FIPS 205 §10.2 Algorithm 22.
func hMsgPub(out, r, pkSeed, pkRoot, msgPrime []byte) {
	shakeIntoCat(out, r, pkSeed, pkRoot, msgPrime)
}

// =====================================================================
//  Index parsing (FIPS 205 §9.2 Algorithm 19 lines 4-13)
// =====================================================================

// parseDigest unpacks the FIPS 205 HashMsg output into the FORS index
// stream md and the hypertree leaf coordinates (idxTree, idxLeaf).
func parseDigest(p *internalParams, digest []byte) (md []byte, idxTree [3]uint32, idxLeaf uint32) {
	l1 := (p.k*p.a + 7) / 8
	l2 := (p.h - p.h/p.d + 7) / 8
	l3 := (p.h + 8*p.d - 1) / (8 * p.d)

	md = make([]byte, l1)
	copy(md, digest[:l1])

	s2 := digest[l1 : l1+l2]
	s3 := digest[l1+l2 : l1+l2+l3]

	var b2 [12]byte
	copy(b2[12-len(s2):], s2)
	n2 := p.h - p.h/p.d
	idxTree[0] = binary.BigEndian.Uint32(b2[8:]) & ((1 << n2) - 1)
	n2 -= 32
	idxTree[1] = binary.BigEndian.Uint32(b2[4:]) & ((1 << n2) - 1)
	idxTree[2] = binary.BigEndian.Uint32(b2[0:])

	var b3 [4]byte
	copy(b3[4-len(s3):], s3)
	mask32 := (uint32(1) << (p.h / p.d)) - 1
	idxLeaf = mask32 & binary.BigEndian.Uint32(b3[0:])
	return
}

// nextHTIndex shifts the hypertree tree-address one XMSS layer and
// returns the next idxLeaf. FIPS 205 §7.1 Algorithm 12 line 11.
func nextHTIndex(idxTree *[3]uint32, n uint32) (idxLeaf uint32) {
	idxLeaf = idxTree[0] & ((1 << n) - 1)
	idxTree[0] = (idxTree[0] >> n) | (idxTree[1] << (32 - n))
	idxTree[1] = (idxTree[1] >> n) | (idxTree[2] << (32 - n))
	idxTree[2] = (idxTree[2] >> n)
	return
}

// =====================================================================
//  FIPS 205 §5 — WOTS+ chain compute
// =====================================================================

// wotsChain implements the FIPS 205 §5 Algorithm 5 chain function:
//
//	chain(X, i, s, PK.seed, ADRS):
//	  tmp ← X
//	  for j ∈ [i, i+s):
//	    ADRS.SetHashAddress(j)
//	    tmp ← F(PK.seed, ADRS, tmp)
//	  return tmp
//
// X is the chain base (n bytes). The caller is responsible for the
// outer address state; this routine mutates only the hash-address word.
func wotsChain(out, pkSeed []byte, addr *adrsBuf, x []byte, i, s uint32) {
	scratch := make([]byte, len(x))
	copy(scratch, x)
	for j := i; j < i+s; j++ {
		addr.setHashAddress(j)
		fPub(scratch, pkSeed, addr, scratch)
	}
	copy(out, scratch)
}

// wotsBaseW partitions n bytes of message into 2n base-w (w=16) digits
// (big-endian nibble order). FIPS 205 §4.5 base_2b helper, b=4.
func wotsBaseW(out []uint32, msg []byte) {
	for i := range out {
		out[i] = uint32((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
	}
}

// wotsChecksum computes the WOTS+ checksum digits. FIPS 205 §5.2
// Algorithm 7 lines 7-9 + §4.5 base_2b unpack.
func wotsChecksum(p *internalParams, baseWMsg []uint32) [wotsLen2]uint32 {
	wotsLen1 := p.wotsLen1()
	csum := wotsLen1 * (wotsW - 1)
	for i := uint32(0); i < wotsLen1; i++ {
		csum -= baseWMsg[i]
	}
	var out [wotsLen2]uint32
	for i := uint32(0); i < wotsLen2; i++ {
		out[i] = (csum >> (8 - 4*i)) & 0xF
	}
	return out
}

// wotsSign produces a WOTS+ signature on msg under the seed material
// reachable via prfOut. The signature occupies wotsSigSize bytes of out.
//
// FIPS 205 §5.2 Algorithm 7 — but expressed with the secret-side PRF
// as an opaque callback. addr's keypair address must be pre-set; this
// routine sets the chain address, type, and hash address per chain
// step.
func wotsSign(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	msg []byte,
	prfOut prfOutFn,
) {
	wotsLen1 := p.wotsLen1()

	baseW := make([]uint32, wotsLen1)
	wotsBaseW(baseW, msg)
	csum := wotsChecksum(p, baseW)

	// Save outer address words so we can restore between PRF and F.
	keypair := binary.BigEndian.Uint32(addr[20:])

	// PRF (chain-base derivation) address template.
	prfAddr := *addr
	prfAddr.setTypeAndClear(adrsTypeWotsPrf)
	prfAddr.setKeyPairAddress(keypair)

	// F-chain (chain-step) address template.
	chainAddr := *addr
	chainAddr.setTypeAndClear(adrsTypeWotsHash)
	chainAddr.setKeyPairAddress(keypair)

	for i := uint32(0); i < wotsLen1; i++ {
		prfAddr.setChainAddress(i)
		sk := make([]byte, p.n)
		prfOut(sk, &prfAddr)

		chainAddr.setChainAddress(i)
		wotsChain(out[i*p.n:(i+1)*p.n], pkSeed, &chainAddr, sk, 0, baseW[i])
		// Best-effort wipe of the PRF-derived chain base; the chain-
		// step output is what enters the WOTS+ signature publicly.
		for j := range sk {
			sk[j] = 0
		}
	}
	for i := uint32(0); i < wotsLen2; i++ {
		prfAddr.setChainAddress(wotsLen1 + i)
		sk := make([]byte, p.n)
		prfOut(sk, &prfAddr)

		chainAddr.setChainAddress(wotsLen1 + i)
		offset := (wotsLen1 + i) * p.n
		wotsChain(out[offset:offset+p.n], pkSeed, &chainAddr, sk, 0, csum[i])
		for j := range sk {
			sk[j] = 0
		}
	}
}

// wotsPkGen derives the WOTS+ public key (one n-byte node) under the
// supplied addr template. FIPS 205 §5.1 Algorithm 6. Used by XMSS leaf
// computation.
func wotsPkGen(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	prfOut prfOutFn,
) {
	wotsLen := p.wotsLen()
	keypair := binary.BigEndian.Uint32(addr[20:])

	prfAddr := *addr
	prfAddr.setTypeAndClear(adrsTypeWotsPrf)
	prfAddr.setKeyPairAddress(keypair)

	chainAddr := *addr
	chainAddr.setTypeAndClear(adrsTypeWotsHash)
	chainAddr.setKeyPairAddress(keypair)

	concat := make([]byte, wotsLen*p.n)
	for i := uint32(0); i < wotsLen; i++ {
		prfAddr.setChainAddress(i)
		sk := make([]byte, p.n)
		prfOut(sk, &prfAddr)

		chainAddr.setChainAddress(i)
		wotsChain(concat[i*p.n:(i+1)*p.n], pkSeed, &chainAddr, sk, 0, wotsW-1)
		for j := range sk {
			sk[j] = 0
		}
	}

	tAddr := *addr
	tAddr.setTypeAndClear(adrsTypeWotsPk)
	tAddr.setKeyPairAddress(keypair)
	tlPub(out, pkSeed, &tAddr, concat)
	for j := range concat {
		concat[j] = 0
	}
}

// =====================================================================
//  FIPS 205 §6 — XMSS tree (sign + node compute)
// =====================================================================

// xmssNodeCompute returns the node at (i, z) of the XMSS Merkle tree
// for the supplied addr template. FIPS 205 §6.1 Algorithm 9 — iterative
// stack-based reduction.
func xmssNodeCompute(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	i, z uint32,
	prfOut prfOutFn,
) {
	if z == 0 {
		// Leaf: WOTS+ public key.
		a := *addr
		a.setTypeAndClear(adrsTypeWotsHash)
		a.setKeyPairAddress(i)
		wotsPkGen(p, out, pkSeed, &a, prfOut)
		return
	}
	// Internal node: hash left || right children.
	left := make([]byte, p.n)
	right := make([]byte, p.n)
	xmssNodeCompute(p, left, pkSeed, addr, 2*i, z-1, prfOut)
	xmssNodeCompute(p, right, pkSeed, addr, 2*i+1, z-1, prfOut)
	a := *addr
	a.setTypeAndClear(adrsTypeTree)
	a.setTreeHeight(z)
	a.setTreeIndex(i)
	hPub(out, pkSeed, &a, left, right)
	for j := range left {
		left[j] = 0
	}
	for j := range right {
		right[j] = 0
	}
}

// xmssSign produces an XMSS signature (WOTS+ sig + auth path) on msg
// under the addr template at leaf idx. FIPS 205 §6.2 Algorithm 10.
func xmssSign(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	msg []byte,
	idx uint32,
	prfOut prfOutFn,
) {
	// Auth path (hPrime sibling nodes).
	authOffset := p.wotsSigSize()
	for j := uint32(0); j < p.hPrime; j++ {
		k := (idx >> j) ^ 1
		xmssNodeCompute(p, out[authOffset+j*p.n:authOffset+(j+1)*p.n], pkSeed, addr, k, j, prfOut)
	}
	// WOTS+ signature on msg at leaf idx.
	a := *addr
	a.setTypeAndClear(adrsTypeWotsHash)
	a.setKeyPairAddress(idx)
	wotsSign(p, out[:p.wotsSigSize()], pkSeed, &a, msg, prfOut)
}

// xmssPkFromSig reconstructs the XMSS public key (one n-byte node) from
// an XMSS signature on msg at leaf idx. FIPS 205 §6.3 Algorithm 11.
// Public — only operates on (pkSeed, sig bytes, msg, idx).
func xmssPkFromSig(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	sig []byte,
	msg []byte,
	idx uint32,
) {
	wotsSig := sig[:p.wotsSigSize()]
	authPath := sig[p.wotsSigSize():]

	a := *addr
	a.setTypeAndClear(adrsTypeWotsHash)
	a.setKeyPairAddress(idx)
	node := make([]byte, p.n)
	wotsPkFromSig(p, node, pkSeed, &a, wotsSig, msg)

	treeIdx := idx
	tAddr := *addr
	tAddr.setTypeAndClear(adrsTypeTree)
	for k := uint32(0); k < p.hPrime; k++ {
		tAddr.setTreeHeight(k + 1)
		if (idx>>k)&1 == 0 {
			treeIdx >>= 1
			tAddr.setTreeIndex(treeIdx)
			hPub(node, pkSeed, &tAddr, node, authPath[k*p.n:(k+1)*p.n])
		} else {
			treeIdx = (treeIdx - 1) >> 1
			tAddr.setTreeIndex(treeIdx)
			hPub(node, pkSeed, &tAddr, authPath[k*p.n:(k+1)*p.n], node)
		}
	}
	copy(out, node)
}

// wotsPkFromSig reconstructs the WOTS+ public key (one n-byte node)
// from a WOTS+ signature on msg. FIPS 205 §5.3 Algorithm 8. Public.
func wotsPkFromSig(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	sig []byte,
	msg []byte,
) {
	wotsLen1 := p.wotsLen1()
	baseW := make([]uint32, wotsLen1)
	wotsBaseW(baseW, msg)
	csum := wotsChecksum(p, baseW)

	keypair := binary.BigEndian.Uint32(addr[20:])
	chainAddr := *addr
	chainAddr.setTypeAndClear(adrsTypeWotsHash)
	chainAddr.setKeyPairAddress(keypair)

	concat := make([]byte, p.wotsLen()*p.n)
	for i := uint32(0); i < wotsLen1; i++ {
		chainAddr.setChainAddress(i)
		wotsChain(concat[i*p.n:(i+1)*p.n], pkSeed, &chainAddr, sig[i*p.n:(i+1)*p.n], baseW[i], wotsW-1-baseW[i])
	}
	for i := uint32(0); i < wotsLen2; i++ {
		chainAddr.setChainAddress(wotsLen1 + i)
		offset := (wotsLen1 + i) * p.n
		wotsChain(concat[offset:offset+p.n], pkSeed, &chainAddr, sig[offset:offset+p.n], csum[i], wotsW-1-csum[i])
	}
	tAddr := *addr
	tAddr.setTypeAndClear(adrsTypeWotsPk)
	tAddr.setKeyPairAddress(keypair)
	tlPub(out, pkSeed, &tAddr, concat)
}

// =====================================================================
//  FIPS 205 §7 — Hypertree (sign + verify)
// =====================================================================

// htSign produces a hypertree signature: d XMSS layers each signing
// the previous root (or pkFors at layer 0). FIPS 205 §7.1 Algorithm 12.
func htSign(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	pkFors []byte,
	idxTree [3]uint32,
	idxLeaf uint32,
	prfOut prfOutFn,
) {
	addr := adrsBuf{}
	addr.setLayerAddress(0)
	addr.setTreeAddress(idxTree)

	msg := make([]byte, p.n)
	copy(msg, pkFors)

	for j := uint32(0); j < p.d; j++ {
		xmssSig := out[j*p.xmssSigSize() : (j+1)*p.xmssSigSize()]
		xmssSign(p, xmssSig, pkSeed, &addr, msg, idxLeaf, prfOut)
		if j < p.d-1 {
			xmssPkFromSig(p, msg, pkSeed, &addr, xmssSig, msg, idxLeaf)
			idxLeaf = nextHTIndex(&idxTree, p.hPrime)
			addr.setLayerAddress(j + 1)
			addr.setTreeAddress(idxTree)
		}
	}
}

// =====================================================================
//  FIPS 205 §8 — FORS sign + public-key reconstruction
// =====================================================================

// forsNodeCompute returns the node at (i, z) of the i-th FORS subtree
// rooted in addr.keyPairAddress. FIPS 205 §8.2 Algorithm 15.
func forsNodeCompute(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	i, z uint32,
	prfOut prfOutFn,
) {
	if z == 0 {
		// Leaf: F(PK.seed, ADRS, PRF(PK.seed, ADRS_prf, SK.seed))
		prfAddr := *addr
		prfAddr.setTypeAndClear(adrsTypeForsPrf)
		prfAddr.setKeyPairAddress(binary.BigEndian.Uint32(addr[20:]))
		prfAddr.setTreeIndex(i)
		sk := make([]byte, p.n)
		prfOut(sk, &prfAddr)

		fAddr := *addr
		fAddr.setTreeHeight(0)
		fAddr.setTreeIndex(i)
		fPub(out, pkSeed, &fAddr, sk)
		for j := range sk {
			sk[j] = 0
		}
		return
	}
	left := make([]byte, p.n)
	right := make([]byte, p.n)
	forsNodeCompute(p, left, pkSeed, addr, 2*i, z-1, prfOut)
	forsNodeCompute(p, right, pkSeed, addr, 2*i+1, z-1, prfOut)
	a := *addr
	a.setTreeHeight(z)
	a.setTreeIndex(i)
	hPub(out, pkSeed, &a, left, right)
	for j := range left {
		left[j] = 0
	}
	for j := range right {
		right[j] = 0
	}
}

// forsSign produces a FORS signature (k pairs of (sk, auth path))
// over the digest md under the supplied addr template. FIPS 205 §8.3
// Algorithm 16.
func forsSign(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	digest []byte,
	prfOut prfOutFn,
) {
	pairSize := p.forsPairSize()
	in, bits, total := 0, uint32(0), uint32(0)
	maskA := (uint32(1) << p.a) - 1

	for i := uint32(0); i < p.k; i++ {
		for bits < p.a {
			total = (total << 8) + uint32(digest[in])
			in++
			bits += 8
		}
		bits -= p.a
		indicesI := (total >> bits) & maskA

		// sk = PRF(PK.seed, ADRS_forsPrf, SK.seed) at tree index (i << a) + indicesI
		treeIdx := (i << p.a) + indicesI
		prfAddr := *addr
		prfAddr.setTypeAndClear(adrsTypeForsPrf)
		prfAddr.setKeyPairAddress(binary.BigEndian.Uint32(addr[20:]))
		prfAddr.setTreeIndex(treeIdx)

		skOffset := i * pairSize
		prfOut(out[skOffset:skOffset+p.n], &prfAddr)

		// Auth path: a sibling nodes at heights 0..a-1.
		authOffset := skOffset + p.n
		for j := uint32(0); j < p.a; j++ {
			s := (indicesI >> j) ^ 1
			nodeIdx := (i << (p.a - j)) + s
			forsNodeCompute(p, out[authOffset+j*p.n:authOffset+(j+1)*p.n], pkSeed, addr, nodeIdx, j, prfOut)
		}
	}
}

// forsPkFromSig reconstructs the FORS public key (one n-byte T_k root)
// from the FORS signature + message digest md. FIPS 205 §8.4 Algorithm
// 17. Public.
func forsPkFromSig(
	p *internalParams,
	out []byte,
	pkSeed []byte,
	addr *adrsBuf,
	digest []byte,
	sig []byte,
) {
	pairSize := p.forsPairSize()
	in, bits, total := 0, uint32(0), uint32(0)
	maskA := (uint32(1) << p.a) - 1

	rootsConcat := make([]byte, p.k*p.n)

	for i := uint32(0); i < p.k; i++ {
		for bits < p.a {
			total = (total << 8) + uint32(digest[in])
			in++
			bits += 8
		}
		bits -= p.a
		indicesI := (total >> bits) & maskA

		treeIdx := (i << p.a) + indicesI
		skOffset := i * pairSize
		authOffset := skOffset + p.n

		fAddr := *addr
		fAddr.setTreeHeight(0)
		fAddr.setTreeIndex(treeIdx)
		node := make([]byte, p.n)
		fPub(node, pkSeed, &fAddr, sig[skOffset:skOffset+p.n])

		for j := uint32(0); j < p.a; j++ {
			hAddr := *addr
			hAddr.setTreeHeight(j + 1)
			if (indicesI>>j)&1 == 0 {
				treeIdx >>= 1
				hAddr.setTreeIndex(treeIdx)
				hPub(node, pkSeed, &hAddr, node, sig[authOffset+j*p.n:authOffset+(j+1)*p.n])
			} else {
				treeIdx = (treeIdx - 1) >> 1
				hAddr.setTreeIndex(treeIdx)
				hPub(node, pkSeed, &hAddr, sig[authOffset+j*p.n:authOffset+(j+1)*p.n], node)
			}
		}
		copy(rootsConcat[i*p.n:(i+1)*p.n], node)
	}

	tAddr := *addr
	tAddr.setTypeAndClear(adrsTypeForsRoots)
	tAddr.setKeyPairAddress(binary.BigEndian.Uint32(addr[20:]))
	tlPub(out, pkSeed, &tAddr, rootsConcat)
}

// =====================================================================
//  FIPS 205 §9 / §10 — top-level Sign (deterministic, ctx-binding)
// =====================================================================

// slhSignAtom is the top-level Magnetar-internal SLH-DSA Sign. It
// implements FIPS 205 §10.2 Algorithm 23 (Sign) ∘ §9.2 Algorithm 19
// (slh_sign_internal) for SHAKE deterministic signing.
//
// Inputs:
//   - p:        the parameter set
//   - pkSeed:   the public seed (n bytes)
//   - pkRoot:   the public root (n bytes)
//   - message:  the user message bytes
//   - ctx:      the FIPS 205 §10.2 context string (<= 255 bytes)
//   - prfOut:   the secret-side PRF (FIPS 205 §11.2) — the only seam
//     for SK.seed access
//   - prfMsg:   the message-randomizer PRF — the only seam for SK.prf
//     access
//
// Output: the signatureSize-byte FIPS 205 wire signature.
func slhSignAtom(
	p *internalParams,
	pkSeed, pkRoot []byte,
	message, ctx []byte,
	prfOut prfOutFn,
	prfMsg prfMsgFn,
) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, ErrCtxTooLong
	}

	// FIPS 205 §10.2 Algorithm 23 — bind ctx to msgPrime.
	msgPrime := make([]byte, 0, 2+len(ctx)+len(message))
	msgPrime = append(msgPrime, 0)              // domain separator: pure
	msgPrime = append(msgPrime, byte(len(ctx))) // ctx length
	msgPrime = append(msgPrime, ctx...)
	msgPrime = append(msgPrime, message...)

	sigBytes := make([]byte, p.signatureSize())

	// Step 1: randomizer R = PRF_msg(SK.prf, addRand=pkSeed, msgPrime).
	// SignDeterministic uses addRand = pkSeed per FIPS 205 §10.2 line 5.
	rBuf := sigBytes[:p.n]
	prfMsg(rBuf, pkSeed, msgPrime)

	// Step 2: digest = H_msg(R, PK.seed, PK.root, M').
	digest := make([]byte, p.m)
	hMsgPub(digest, rBuf, pkSeed, pkRoot, msgPrime)

	md, idxTree, idxLeaf := parseDigest(p, digest)

	// Step 3: FORS sign on md at (idxTree, idxLeaf).
	addr := adrsBuf{}
	addr.setLayerAddress(0)
	addr.setTreeAddress(idxTree)
	addr.setTypeAndClear(adrsTypeForsTree)
	addr.setKeyPairAddress(idxLeaf)

	forsOffset := p.n
	forsEnd := forsOffset + p.forsSigSize()
	forsSign(p, sigBytes[forsOffset:forsEnd], pkSeed, &addr, md, prfOut)

	// Step 4: pkFors = forsPkFromSig (deterministic from FORS sig + md).
	pkFors := make([]byte, p.n)
	forsPkFromSig(p, pkFors, pkSeed, &addr, md, sigBytes[forsOffset:forsEnd])

	// Step 5: htSign on pkFors at (idxTree, idxLeaf).
	htSign(p, sigBytes[forsEnd:], pkSeed, pkFors, idxTree, idxLeaf, prfOut)

	return sigBytes, nil
}
