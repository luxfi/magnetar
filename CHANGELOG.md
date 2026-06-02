# Changelog --- Magnetar

All notable changes to the Magnetar SLH-DSA library and NIST MPTC
submission package are tracked in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Magnetar adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] --- 2026-05-31 --- Strict-atom Combine: no named transient seed binder

### Headline

v1.1 closes `MAGNETAR-STRICT-ATOM-V11`. The THBS-SE permissionless
threshold Combine path no longer materialises the FIPS 205 master
under a named `seed` / `skSeed` / `skPrf` variable in the public
combiner's scope. The path is implemented at
`ref/go/pkg/magnetar/thbsse_assemble.go::assembleSignatureBytes`
backed by `ref/go/pkg/magnetar/slhdsa_internal.go::slhSignAtom`
(Magnetar-internal FIPS 205 sec 5--sec 8 walk for the SHAKE family).

### Wire-format-stable refactor

- Wire format (MAGS / MAGG envelopes) is UNCHANGED at v1.1. KAT
  vectors regenerate to the same bytes.
- THBS-SE share format, slot-guard state, equivocation evidence
  shape, and protocol round structure are UNCHANGED.
- API: `Combine`, `NewThbsSeKey`, `ThbsSeRound1`, etc. have the
  SAME signatures. The strict-atom path is an internal refactor of
  Combine's tail.
- v1.0.0 consumers bump to v1.1.0 transparently.

### Strict-atom discipline (load-bearing v1.1 invariant)

The v1.1 audit grep that defines compliance:

```
grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" ref/go/pkg/magnetar/thbsse_assemble.go
```

MUST return zero matches. Enforced by:

- `TestThbsSE_StrictAtom_NoTransientSeed` (AST walk + raw-byte grep).
- `scripts/checks/strict-atom-ast.sh` (shell gate replicating the
  audit grep verbatim).
- `ct/dudect/strict_atom_combine_ct_test.go::
  TestStrictAtom_CT_NoSecretDependentBranch` (AST walk asserting no
  secret-tagged identifier feeds an if/switch condition or an index
  expression).

See `ASSEMBLE-INVARIANT.md` for the load-bearing prose statement.

### Byte-identity to circl FIPS 205

The Magnetar-internal FIPS 205 sec 5--sec 8 walk is byte-equal to
`cloudflare/circl/sign/slhdsa.SignDeterministic` for the SHAKE
families. Pinned by `TestSlhdsaInternal_ByteEqualToCirclSign` per
mode (SHAKE-192s, SHAKE-192f, SHAKE-256s).

### Proof track restoration

The v0.x EasyCrypt scaffolding (modelled the abandoned v0.x
reveal-and-aggregate path; removed at v1.0) is replaced with v1.1
strict-atom theories:

- `proofs/easycrypt/Magnetar_N1_StrictAtom.ec` --- Class N1-analog
  strict-atom byte-equality theorem.
- `proofs/easycrypt/Magnetar_N1_SHAKE_Expand.ec` --- FIPS 205 SHAKE
  expansion lemmas.
- `proofs/easycrypt/Magnetar_N1_Atom_Refinement.ec` --- internal
  refinement to circl.
- `proofs/easycrypt/Magnetar_N4_KeyDeriveStable.ec` --- pk stability
  under Lagrange reconstruction.
- `proofs/easycrypt/lemmas/SLHDSA_Functional.ec` --- FIPS 205 SHAKE
  primitive black-box specs.
- `proofs/easycrypt/lemmas/Magnetar_CT.ec` --- abstract-level CT
  lemma.
- `proofs/lean/Crypto/Magnetar/StrictAtom.lean` --- Lean bridge
  carrying the algebraic identities.

Axiom budget: 5 substantive + 1 abstract-vacuous CT admit. Per
`proofs/README.md`.

### dudect harness restoration

The v0.x dudect harness (modelled deleted seed-recombine surfaces;
removed at v1.0) is replaced with a v1.1 Go-side CT static check at
`ct/dudect/strict_atom_combine_ct_test.go`. Per-push smoke gate at
`scripts/checks/dudect-smoke.sh`.

### Benchmark (Apple M1 Max, single-goroutine, 5-of-7)

Strict-atom v1.1 ns/op vs v1.0-equivalent baseline (circl-dispatched
SignDeterministic on the Shamir-reconstructed seed):

| Mode | v1.0-equivalent | v1.1 strict-atom | Delta |
|---|---|---|---|
| Magnetar-SHAKE-192s | 2.93 s/op | 1.43 s/op | -51% |
| Magnetar-SHAKE-192f | 113 ms/op | 63 ms/op | -44% |
| Magnetar-SHAKE-256s | 2.22 s/op | 2.04 s/op | -8% |

The strict-atom path is FASTER because the Magnetar-internal SHAKE
walk avoids circl's per-call PrivateKey unmarshal + state struct
initialisation overhead.

### Honest residual gap

The bytes of the FIPS 205 master DO exist transiently inside the
SHAKE-expansion output buffer (`derivedMaterial`) and the
Lagrange-reconstruction input (`derivedExpandInput`) for the
duration of the SHAKE absorb. A coredump or /proc/self/mem dump at
exactly the right wall-clock instant would observe them. Closing
this gap requires either full MPC over the SHAKE-256 hash tree
(open research) or a TEE-attested host in the TCB
(`luxfi/threshold/protocols/slhdsa-tee`). The strict-atom discipline
is the strictest available without crossing into either regime;
see `ASSEMBLE-INVARIANT.md`.

## [1.0.0] --- 2026-05-31 --- ONE construction per regime; legacy seed-recombine paths killed

### Architectural decomplecting (HONEST framing)

This release closes Magnetar's permissionless-threshold story at
**ONE** construction --- **THBS-SE** (Threshold Hash-Based Signatures
with Selected-Element Reconstruction) --- and removes every legacy
seed-recombine path from the codebase. Magnetar v1.0 ships exactly
two primitives:

- **Per-validator standalone** (`ref/go/pkg/magnetar/standalone.go`,
  unchanged from v0.5.x) --- the public-BFT primary primitive. Each
  validator holds its own FIPS 205 keypair, signs independently,
  consensus collects N signatures into a `ValidatorAggregateCert`.
- **THBS-SE** (`ref/go/pkg/magnetar/thbsse.go` +
  `thbsse_field.go`) --- the permissionless threshold companion.
  t-of-n committee, slot-bound commit-and-reveal, **public combiner
  role** (anyone can run Combine), slashable equivocation +
  malformed-share evidence.

Both emit byte-identical FIPS 205 signatures that unmodified
verifiers accept.

### Hard invariant (THBS-SE)

A revealed value is allowed ONLY if it is also present in the final
SLH-DSA signature.

- ALLOWED reveals: the per-round mask `r_i`, the masked share
  `s'_i = share_i XOR r_i`, the public commit hash, the final FIPS
  205 signature bytes.
- FORBIDDEN reveals: `SK.seed`, `SK.prf`, future-slot share
  material. The slot guard refuses any same-slot re-emission and the
  share envelope is per-slot.

### v1.0 honest open item

The strict invariant ("no party or combiner EVER reconstructs
SK.seed, even transiently in memory") requires the v1.1
strict-atom-assembly path tracked at
`BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11`. v1.0 ships a PUBLIC
COMBINER (anyone-can-combine) that holds the seed for the duration
of one `slhdsa.SignDeterministic` call and then zeroizes. This is
materially stronger than a TEE-attested privileged-aggregator model
(no host in TCB; the combiner is a pure function any peer can run)
and materially weaker than the strict invariant (a peer-local
memory-disclosure adversary at exactly the combine moment could
observe the seed). The strict-atom path requires a Magnetar-internal
re-implementation of FIPS 205 sec 5/6/7/8 that bypasses
slh_sign_internal; cloudflare/circl's slhdsa does not expose those
internals.

### Added

- **`ref/go/pkg/magnetar/thbsse.go`** --- the THBS-SE construction:
  - `NewThbsSeKey(params, threshold, committee, rng) -> (*ThbsSeKey, error)`
    --- deterministic-dealer setup that produces (PK, [share_i],
    setup_transcript). The dealer is in the TCB FOR SETUP ONLY;
    once NewThbsSeKey returns no party including the dealer holds
    the master seed. Production deployments run the leaderless
    PVSS-DKG path via the sibling `luxfi/threshold` DKG package
    and feed the result into the wire-equivalent share envelope.
  - `ThbsSeRound1(params, share, binding, msg, guard, rng) -> (r1, r2, error)`
    --- per-party Round-1 commit + Round-2 reveal pair. Idempotent
    replay on the same `(slot, msg)`; emits
    `*ThbsSeEquivocationError` with a wire-shaped `ThbsSeEvidence`
    blob on a same-slot, distinct-message second attempt.
  - `Combine(input ThbsSeCombineInput) -> (*Signature, []ThbsSeShareEvidence, error)`
    --- the PUBLIC combiner. Pure function of its inputs. Any peer
    with the public ThbsSeKey, the slot binding, the message, and
    >= t valid Round-1/Round-2 pairs can produce the FIPS 205
    signature. Emits typed `ThbsSeShareEvidence` for malformed
    shares (slot-mismatch, wire-size, commit-mismatch).
  - `ThbsSeSlotGuard` + `Record` / `Has` --- per-party persistent
    slot-use guard. Local-state defense against equivocation.
  - `VerifyThbsSeEvidence` / `VerifyThbsSeShareEvidence` --- pure
    third-party evidence verifiers. No committee state required.
  - Slot binding: every signature is bound to
    `(chain_id, epoch, slot, height, committee_id, message_domain)`
    via cSHAKE256 transcript + FIPS 205 ctx string.
- **`ref/go/pkg/magnetar/thbsse_field.go`** --- the GF(257)
  byte-wise share arithmetic the THBS-SE construction consumes
  internally. Unexported helpers: `thbsseDealRandom`,
  `thbsseDealRandomGF`, `thbsseReconstructGF`, `thbsseShareToBytes`,
  `thbsseShareFromBytes`. The only exported names are
  `MaxCommittee257`, `EvalPointFromID`, and the THBS-SE error
  values.
- **`ref/go/pkg/magnetar/thbsse_test.go`** --- the 8 mandated test
  gates plus a determinism check and a binding-distinct-signature
  check:
  - `TestThbsSE_Wire_FIPS205Verifiable` (3 SHAKE modes)
  - `TestThbsSE_RejectSeedReveal`
  - `TestThbsSE_RejectUnselectedFORS`
  - `TestThbsSE_RejectUnselectedWOTS`
  - `TestThbsSE_SlotReuseRejected`
  - `TestThbsSE_OverselectedCommittee` (n=7, t=3, 4 honest + 3
    withholders)
  - `TestThbsSE_SlotBindingDomainSeparation`
  - `BenchmarkThbsSE_Sign_5of7` (3 SHAKE modes)
  - bonus: `TestThbsSE_PublicCombiner_Determinism` (disjoint
    t-subsets produce byte-equal signatures)
- **`vectors/thbsse-sign.json`** --- deterministic KAT vectors at
  (n=7, t=4) x 3 SHAKE modes x 3 messages. Replayed by
  `TestKAT_ThbsSe`.

### Removed

- `ref/go/pkg/magnetar/threshold.go` + `threshold_test.go` ---
  legacy reveal-and-aggregate threshold sign path.
- `ref/go/pkg/magnetar/aggregate.go` + `aggregate_test.go` ---
  legacy aggregate-sign (subsumed by `standalone.go`'s
  `ValidatorAggregateCert`).
- `ref/go/pkg/magnetar/combine.go` --- legacy
  `CombineWithSeedReconstruction` entry point.
- `ref/go/pkg/magnetar/shamir.go` + `shamir_test.go` --- legacy
  byte-wise Shamir helpers; the THBS-SE-internal subset lives in
  `thbsse_field.go`.
- `ref/go/pkg/magnetar/dkg.go` + `dkg_test.go` --- legacy DKG
  primitives; the leaderless PVSS-DKG path now lives in the sibling
  `luxfi/threshold` DKG package.
- `ref/go/pkg/magnetar/e2e_test.go`, `fuzz_test.go`,
  `n1_byte_equality_test.go` --- legacy tests tied to the
  deleted threshold path. Equivalent coverage lives in
  `thbsse_test.go` + `kat_test.go::TestKAT_ThbsSe`.
- `ref/go/pkg/thbs/` (entire subtree) --- the legacy true-HBS
  threshold path including the `dkg2/` PVSS skeleton.
- `vectors/threshold-sign.json` + `vectors/dkg.json` --- legacy
  KATs.
- `jasmin/threshold/` + `jasmin/lib/` --- legacy Jasmin model of
  the seed-recombine path. The v1.0 Jasmin scope (single-party
  SLH-DSA via formosa-crypto libjade upstream when it lands) is
  documented in `jasmin/README.md`.
- `proofs/easycrypt/` (entire tree) --- legacy EasyCrypt theories
  modeling the deleted `combine.go` / `threshold.go`. The v1.0
  proof track (`proofs/README.md`) ports to the THBS-SE
  construction shape in v1.1.
- `ct/dudect/` (entire tree) --- legacy dudect harness over the
  deleted `Combine` / `Verify` API surfaces. The v1.0 CT story is
  "inherit CIRCL"; the v1.1 harness lands alongside the
  strict-atom-assembly path.

### Verification

```bash
cd ref/go && GOWORK=off go build ./... && GOWORK=off go test -count=1 -short -timeout 600s ./pkg/magnetar/...
```

The 8 test gates pass at `-count=1 -short -race`. The
`BenchmarkThbsSE_Sign_5of7/Magnetar-SHAKE-192f` benchmark clocks at
< 100 ms/op on Apple M1 Max.

## [Unreleased]

(Nothing pending at this writing.)

## [0.5.0] — 2026-05-21 — Per-validator standalone is the primary public-BFT primitive; THBS demoted to TEE-only

### Architectural decomplecting (HONEST framing)

This release re-architects Magnetar for **public-BFT-safety**. The
previous v0.4.x messaging conflated two distinct trust models:
threshold-HBS (custody, requires dealer/aggregator-in-TCB) and
N-of-N collected signatures (public-BFT, no TCB). v0.5.0 ships the
canonical separation:

- **PRIMARY public-BFT primitive**: per-validator standalone
  SLH-DSA via `magnetar.PerValidatorKeypair` +
  `magnetar.ValidatorSign` + `magnetar.VerifyAggregateCert`
  (`ref/go/pkg/magnetar/standalone.go`). Per-validator keypair, no
  DKG, no dealer, no aggregator-in-TCB. The consensus layer
  collects N validator signatures and counts valid signers; the
  quorum policy decision lives at the consumer. Z-Chain Groth16
  rollup compresses N × |σ| to ~192 bytes.
- **CUSTODY (TEE required)**: `magnetar.CombineWithSeedReconstruction`
  (reveal-and-aggregate) OR `thbs.DealerDKG` + `thbs.SignShare` +
  `thbs.Aggregate` (true threshold HBS). The dealer / aggregator
  is in the TCB by policy — both REQUIRE TEE attestation.
- **RESEARCH (v0.6+)**: `thbs/dkg2/` skeleton ships the PVSS
  layer; MPC-root layer is OPEN RESEARCH tracked at
  `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1`.

The honest architectural truth: SLH-DSA is hash-based and has no
algebraic structure that admits FROST-style threshold aggregation
(Cozzo-Smart EUROCRYPT 2019; Bonte-Smart-Tan 2023; NIST IR 8214).
True-threshold SLH-DSA without TEE/dealer requires full MPC over
the SHA-256/SHAKE hash tree — research-grade. For Lux's PUBLIC-BFT
consensus, per-validator standalone is the right primitive; for
M-Chain custody (where a TEE-attested host can be in the TCB by
policy), the threshold form is correct.

### Added

- **`ref/go/pkg/magnetar/standalone.go`** — the public-BFT-safe
  PRIMARY primitive surface:
  - `PerValidatorKeypair(params, rng) → (sk, pk, error)` — standalone
    FIPS 205 keypair generator. Semantic alias for
    `GenerateValidatorKey`; explicit name for the public-BFT path.
  - `ValidatorSign(sk, rng, message) → ([]byte, error)` — canonical
    public-BFT signing primitive. Returns raw FIPS 205 signature
    bytes. Deterministic when rng is nil (FIPS 205
    SignDeterministic).
  - `ValidatorBatchVerify(params, pubs, msgs, sigs) → ([]bool, error)`
    — parallel-CPU batch verify returning per-signer bitmap.
    Routes through the same goroutine fork-join pattern as
    `luxfi/crypto/slhdsa.VerifyBatch`.
  - `ValidatorAggregateCert{Mode, Signers, PubKeys, Sigs}` —
    parallel-slices wire envelope for N per-validator signatures
    over a single message. Sibling shape to `AggregatedSignature`
    (aggregate.go) but maps directly to Z-Chain Groth16 rollup
    witness layout.
  - `BuildAggregateCert(params, signers, pubKeys, sigs)` —
    constructor with shape + mode validation and defensive copies.
  - `VerifyAggregateCert(cert, message, knownValidators) → (count, err)`
    — verifies every signature against the registered public key
    and returns the count of valid signers. Unknown / pubkey-
    mismatched signers are counted as INVALID (not fatal — defense
    against impersonation that does not abort the entire batch).
- **`ref/go/pkg/magnetar/standalone_test.go`** — 7 tests covering
  round-trip + determinism + independence, parallel batch verify,
  bad-sig-counted-out, unknown-validator rejection,
  duplicate-validator dedupe-and-count-once, GPU/parallel
  provenance assertion, all-invalid returns-zero, and shape checks.
- **`ref/go/pkg/thbs/dkg2/`** — research-grade SKELETON of a
  public DKG for threshold HBS. v1 ships the PVSS layer; the
  MPC-root layer is OPEN RESEARCH tracked at
  `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1`. Files:
  - `doc.go` — package doc, scope, literature (Schoenmakers PVSS,
    Damgård-Pastro-Smart-Zakarias SPDZ, Boyle-Gilboa-Ishai FSS,
    Wang-Ranellucci-Katz MPC).
  - `pvss.go` — Deal / Verify wire shape with `ErrSkeletonOnly` /
    `ErrMPCRootNotImpl` sentinels preventing production
    consumption.
  - `complaint.go` — Complaint round wire shape (BadShare,
    MissingDelivery, CommitmentMalformed) + dealer Defense.
  - `consensus.go` — qualified-set agreement + `Run` orchestrator +
    `RootMPC` stub. Every public function returns
    `ErrSkeletonOnly` or `ErrMPCRootNotImpl`.
  - `README.md` — public-facing scope, literature, v0.6+ checklist.
  - `dkg2_test.go` — sentinel-pinning tests.
- **`BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1`** — open-research entry
  for public DKG over HBS. PVSS skeleton shipped; MPC-root layer
  open. 9-step v0.6+ checklist.

### Changed

- **`ref/go/pkg/thbs/thbs.go`** — package doc rewritten to honestly
  demote the threshold form to "DEALER-BACKED v1 — NOT public-BFT-
  safe". Directs callers to `magnetar.ValidatorSign` for public BFT
  and to `thbs.DealerDKG` only for M-Chain custody where the
  dealer is in the TCB by TEE attestation. Cites the
  `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1` research path.
- **`ref/go/pkg/thbs/dealer.go`** — renamed `DKG` → `DealerDKG` and
  `DKGAll` → `DealerDKGAll`. The function bodies are unchanged;
  the rename honestly reflects that v1 has a dealer. Callers in
  `thbs_test.go` updated. `DKGConfig` / `DKGOptions` retained
  (config struct shape applies to both v1 dealer and a future v2
  public DKG).
- **`DEPLOYMENT-RUNBOOK.md` §0** — rewritten to direct PUBLIC BFT
  CONSENSUS users to `magnetar.ValidatorSign` +
  `magnetar.VerifyAggregateCert` as the primary primitive; demotes
  `CombineWithSeedReconstruction` and `thbs.DealerDKG` to the
  M-Chain custody / TEE-attested path; cites `thbs/dkg2/` as the
  v0.6+ research path. New §9 documents the
  `ValidatorSign`/`VerifyAggregateCert` primary primitive in detail.
- **`BLOCKERS.md`** — header updated to v0.5.0 framing; new
  `MAGNETAR-PUBLIC-DKG-1` research entry.

### Honest framing

- The threshold form of Magnetar (both `CombineWithSeedReconstruction`
  and `thbs.DealerDKG`) is FUNDAMENTALLY not public-BFT-safe. This
  is not a Magnetar choice; it is a property of hash-based
  signatures. The literature is clear (Cozzo-Smart, Bonte-Smart-Tan,
  NIST IR 8214). The honest fix is the architectural pivot in
  v0.5.0: use the threshold form for custody (where TEE
  attestation puts the dealer/aggregator in the TCB by policy) and
  use per-validator standalone for public consensus.
- The Lux consensus stack ALREADY does the right thing for ML-DSA
  via `QuasarCert.MLDSAProof` (per-validator standalone ML-DSA
  signatures collected into a multi-signer cert). The
  `ValidatorSign` + `VerifyAggregateCert` API makes the same
  pattern explicit and canonical for SLH-DSA.
- The `thbs/dkg2/` skeleton is honestly research-grade. It exists
  to make the v0.6+ research direction concrete without pretending
  to ship a working public DKG. Every function returns a sentinel
  error pointing at the BLOCKERS entry. A production caller
  CANNOT accidentally consume the unfinished pipeline.

## [0.4.2] — 2026-05-21 — THBS v1 + Public-BFT-safe aggregate-signatures API

This release introduces TWO new signing modes:
1. **THBS v1** — true threshold hash-based signatures (McGrew et al.):
   parties hold secret-shared FORS/WOTS+ elements; for each message they
   release shares ONLY for the SELECTED elements; combiner reconstructs
   the final signature; verifier sees an ordinary HBS-style signature.
   No aggregator-as-TCB. Dealer-backed v1; public DKG = v2; FIPS 205
   wire-compatibility = v3.
2. **Aggregate-signatures mode** — public-BFT-safe N-of-N collected
   signatures (each validator holds its own keypair). This was the
   originally-planned content of v0.4.2.

### Added

- **`pkg/thbs/`** — TRUE threshold hash-based signatures (McGrew,
  Fluhrer, Gazdag, Kampanakis, Morton, Westerbaan, IACR ePrint
  2019/793 / IRTF draft-mcgrew-hash-sigs). Subpackage layout:
  - `thbs.go` — types per the user-spec API shape (`DKGConfig`,
    `PublicKey`, `PrivateShare`, `PartialSignature`, `FinalSignature`,
    `Evidence`, `EquivocationError`).
  - `dealer.go` — v1 dealer-backed DKG. The dealer Shamir-shares each
    secret WOTS+ chain head and each FORS secret leaf across the
    committee via per-byte GF(257). Dealer seed is zeroised before
    return. v2 will replace with public DKG.
  - `wots.go` — WOTS+ primitive (Winternitz w=16, FIPS 205-style
    base-w digit + checksum decomposition; hash chains under
    cSHAKE-256 with domain-separated slot/chain/position binding).
  - `fors.go` — FORS primitive (k subtrees, height a, per-leaf
    binary Merkle paths).
  - `tree.go` — top-level public Merkle tree over WOTS+ leaf-roots
    (XMSS-style; v1 single tree, v3 will hypertree).
  - `slot.go` — anti-equivocation slot guard. Each (party, slot)
    used at most once; same-slot-different-digest emits Evidence.
  - `sign.go` — `SignShare` + `Aggregate` + `Verify`. SignShare
    releases shares for ONLY the selected elements (WOTSChains chain
    heads + FORSK FORS leaves). Aggregate Lagrange-reconstructs the
    selected elements (per-element, never a seed). Verify reproduces
    the public Merkle root from the assembled HBS-style signature.
  - `shamir.go` — per-byte Shamir over GF(257) tuned for THBS:
    elements (not seeds) are shared, byte-equal reconstruction is
    guaranteed because each byte is in [0, 256).
  - `hash.go` — cSHAKE-256 with the "Magnetar-THBS" function name
    and per-tag domain separation (chain, leaf, fors-node, share-MAC,
    dealer-PRF, etc.).
  - `thbs_test.go` — 24 unit tests pinning every invariant the spec
    requires: TestTHBS_DKG_NoSeedExposure,
    TestTHBS_WOTS_ReconstructsOnlySelectedChainValues,
    TestTHBS_FORS_ReconstructsOnlySelectedLeaves,
    TestTHBS_Aggregate_FinalSignatureVerifies,
    TestTHBS_Aggregate_NoFutureSigningMaterial,
    TestTHBS_AntiEquivocation_DetectsDoubleSign,
    TestTHBS_Threshold_TminusOne_Fails,
    TestTHBS_Threshold_T_Succeeds,
    TestTHBS_DifferentQuorumsSameSignature,
    TestTHBS_RejectsTamperedShare,
    TestTHBS_RejectsCrossSlotShare,
    TestTHBS_RejectsInconsistentDigest,
    TestTHBS_RejectsWrongMessageVerify, plus 11 supporting tests.
- **`THBS-SPEC.md`** — honest v1 scope (dealer-backed, helper data,
  custom HBS verifier), the v2 (public DKG) and v3 (FIPS 205
  byte-compatibility) roadmaps, and the McGrew et al. citation.
- **`pkg/magnetar/aggregate.go`** — public-BFT-safe N-of-N
  collected-signatures API. Each validator holds its OWN
  SLH-DSA keypair (no DKG, no shared seed). Construction
  primitives:
  - `GenerateValidatorKey(params, rng) → (sk, pk)` — per-validator
    standalone keypair.
  - `SignBundle(params, sk, validatorID, msg) → *SignedBundle` —
    single-validator sign producing a wire envelope.
  - `VerifyBundle(params, bundle, msg) → bool` — single-validator
    verify against the embedded public key.
  - `AggregateSignatures(params, bundles, msg) → *AggregatedSignature` —
    collects N bundles, dedupes by ValidatorID, shape-checks.
  - `VerifyAggregated(params, agg, knownValidators) → (count, err)` —
    per-bundle verify with parallel-CPU dispatch; returns the count
    of valid signers (policy decision lives at the consumer).
  - Parallel-CPU dispatch mirrors `luxfi/crypto/slhdsa.VerifyBatch`
    goroutine fork-join pattern. `LastVerifyAggregatedTier()`
    exposes the dispatch provenance for the BatchVerify test.
- **`pkg/magnetar/aggregate_test.go`** — 10 tests covering single-
  validator round-trip, 5-of-5 aggregation, bad-signature-counted-
  out (not fatal), unknown-validator rejection, duplicate-validator
  dedupe, pubkey-mismatch rejection, BatchVerify provenance (asserts
  parallel-CPU dispatch on a 5-bundle batch), empty-bundle / shape-
  check fail-fast cases, and per-validator key independence.

### Changed

- **`pkg/magnetar/combine.go`** — `Combine` renamed to
  `CombineWithSeedReconstruction` to make the TEE requirement
  explicit in the API. Docstring updated to scream "REQUIRES TEE
  for public deployment. NOT public-BFT-safe. For public BFT, use
  AggregateSignatures." The function's existing implementation is
  preserved byte-for-byte (used by M-Chain custody where TEE is in
  the TCB; KAT byte-equality is preserved). File header cites
  Cozzo-Smart 2019 / Bonte-Smart-Tan 2023 / FIPS 205 §6 as the
  impossibility argument that motivates the rename.
- **All in-package call sites** — `e2e_test.go`, `threshold_test.go`,
  `n1_byte_equality_test.go`, `fuzz_test.go`,
  `ref/go/cmd/genkat/main.go`, `ct/dudect/combine_ct.go` — updated to
  the new name. KAT vectors are byte-identical (the function body
  did not change).
- **`pkg/magnetar/doc.go`** — package docstring rewritten to lead
  with the two-mode chooser and explain the impossibility argument
  for why `CombineWithSeedReconstruction` requires TEE.
- **`DEPLOYMENT-RUNBOOK.md`** — added §0 "Choose your mode"
  decision tree and §10 "Public-BFT aggregate mode" documenting the
  new API. §1 retitled to scope the v0.1 reveal-and-aggregate
  caveat explicitly to `CombineWithSeedReconstruction`.

### Why this matters

SLH-DSA (FIPS 205) is hash-based — WOTS+, FORS, and Merkle
hypertrees over a secret seed. The literature (Cozzo-Smart 2019,
Bonte-Smart-Tan 2023, NIST IR 8214) establishes that there is no
efficient threshold MPC that produces a single FIPS 205-shaped
signature without reconstructing the master seed. The Magnetar v0.1
`CombineWithSeedReconstruction` path embraces this: byte-equality
with single-party FIPS 205 is the headline N1 claim, but the cost
is that the aggregator host is in the TCB for the brief
seed-reconstruction window.

For Lux's public-BFT validator quorum, that TCB requirement is too
strong — no individual validator host should be trusted with the
group seed. The `AggregateSignatures` path is the honest SOTA
answer: each validator signs independently, the consensus layer
collects N signatures, verification iterates per-signer. Wire size
grows linearly with N (compressible via a Z-Chain Groth16 rollup to
~192 bytes, a separate primitive). This release does not change the
custody story — M-Chain thresholdvm in TEE-attested mode continues
to use `CombineWithSeedReconstruction`. It adds the public-BFT path
that was previously missing.

## [0.3.0] — 2026-05-18 — Tier A documentation shape complete

The full 12-document Tier A submission package shape now ships,
mirroring Pulsar's structure. Internal cryptographer sign-off
landed (APPROVED WITH GATES). Submission orchestration scripts
landed.

### Added

- **`SUBMISSION.md`** — NIST MPTC cover sheet. Headline N1 claim:
  Magnetar threshold signatures are byte-identical to single-party
  FIPS 205 `slhdsa.SignDeterministic` on the reconstructed master
  seed. Honest delta vs Pulsar (no EC/Lean/Jasmin yet for the
  threshold overlay).
- **`NIST-SUBMISSION.md`** — one-page executive summary mapped to
  NIST IR 8214C requirements.
- **`PATENTS.md`** — royalty-free patent grant + defensive
  termination. Defensive scope extends to FIPS 205, FIPS 204,
  FIPS 203, successors. Claims limited to Magnetar-novel lifecycle
  additions.
- **`PROOF-CLAIMS.md`** — narrow Class-N1 byte-equality claim;
  §3 enumerates 7 explicit non-claims (mechanized refinement of
  threshold overlay, post-quantum hardness beyond FIPS 205,
  byte-equality with FIPS 204/R-LWE, dudect statistical CT,
  covert channels, protocol-level adversarial robustness beyond
  reveal-and-aggregate, external Lean theorems).
- **`AXIOM-INVENTORY.md`** — construction-level + implementation-level
  axioms with closure plans for the proof-tier roadmap.
- **`FIPS-TRACEABILITY.md`** — FIPS 205 §10.1/10.2/10.3 → code map.
  FIPS 202 + SP 800-185 cSHAKE256/KMAC256 customisation tags pinned
  in `transcript.go`. Threshold overlay traces to `SPEC.md`
  §3/§4/§6.
- **`TRUSTED-COMPUTING-BASE.md`** — implementation TCB inventory.
  `cloudflare/circl/sign/slhdsa` at the single-party FIPS 205 layer.
  Aggregator process in TCB for the brief seed-reconstruction
  window (v0.1 reveal-and-aggregate caveat). Comparison vs Pulsar
  and Corona.
- **`CRYPTOGRAPHER-SIGN-OFF.md`** — internal cryptographer agent
  review. Conducted by direct reading of all 12 production Go
  source files + test surface; verified build + vet + tests +
  coverage (76.8%). Verdict: **APPROVED WITH GATES**. Five open
  gates: GATE-1 (EC theory shells, v0.5.0), GATE-2 (Lean ↔ EC
  bridge, v0.5.0), GATE-3 (dudect 10⁹ samples, v0.6.0), GATE-4
  (external audit, v0.6.0), GATE-5 (v0.4 lifecycle additions).
- **`scripts/cut-submission.sh`** — 8-step tarball cut.
  Verifies clean tree + branch=main, runs high-assurance gate,
  regenerates KATs via `ref/go/cmd/genkat` and verifies
  byte-identical with committed `vectors/*.json`, runs core tests,
  tars (excluding `.git` / `.claude` / `bench/results`), SHA-256s,
  tags. Idempotent (refuses tag/tarball re-cut unless `--force`).
  Dry-run mode for review.
- **`scripts/check-high-assurance.sh`** — per-push gate. Runs `go
  build` + `go vet` + secret-log grep + short test suite. HONEST
  about absent gates (no EC/Lean/Jasmin theories for threshold
  overlay; libjade covers FIPS 205 single-party but is not
  redistributed). Honest scope documented in the script header.

### Changed

- **`README.md`** — flipped status to "Tier A documentation shape
  complete". Updated "What v0.3.0 ships" / "does NOT yet ship"
  to reflect the closed BLK-5/BLK-8 + the open gates per
  `CRYPTOGRAPHER-SIGN-OFF.md`.
- **`SUBMISSION-STATUS.md`** — promoted to Tier A documentation
  shape; Phase 4 (submission package) marked CLOSED for doc shape;
  Phase 5 (cryptographer review) marked PARTIAL (internal v0.3.0,
  external roadmap v0.6.0).
- **`BLOCKERS.md`** — closed BLK-8 (submission package documentation
  shape) at v0.3.0; partially closed BLK-9 (internal review
  landed; external roadmap v0.6.0). BLK-4 / BLK-6 / BLK-7 remain
  open.

### Honesty notes

- The five open gates in `CRYPTOGRAPHER-SIGN-OFF.md` are
  documentation + formal-methods + measurement + lifecycle
  gates; none requires an algorithm or code change at v0.3.0.
- `PROOF-CLAIMS.md` §3 enumerates 7 explicit non-claims; this
  is the honest disclosure that the submission package surfaces
  to NIST reviewers.
- EC theory shells, Lean ↔ EC bridges, and Jasmin sources for
  the threshold overlay are NOT in this submission. Pulsar at
  v1.0.7 has 13/13 EC files compiling with admit 0/0; Magnetar's
  comparable closure is roadmap v0.5.0 with cross-citation to
  Pulsar's GF(257) Shamir / Lagrange bridges as the closure plan.

## [0.2.0] — 2026-05-18 — Tier B: production library + submission scaffold

First production-library release. Implements v0.1 reveal-and-aggregate
threshold SLH-DSA over FIPS 205 with KAT-deterministic vectors and
the honest trust-model disclosure.

### Added

- **`ref/go/pkg/magnetar/`** — production Go reference implementation
  (~2186 LOC). Single-party + DKG + threshold-sign + Combine over
  the SLH-DSA scheme seed. Three FIPS 205 parameter sets:
  SHAKE-192s (recommended, NIST PQ Cat 3), SHAKE-192f (Cat 3 fast),
  SHAKE-256s (Cat 5).
- **`ref/go/cmd/genkat`** — deterministic KAT generator. Produces
  byte-stable JSON output at five profiles (keygen, sign, verify,
  threshold-sign, dkg). Re-running on a clean checkout produces
  byte-identical vectors.
- **`vectors/{keygen,sign,verify,threshold-sign,dkg}.json`** —
  committed KAT vectors. KAT replay tests (`kat_test.go`) validate
  the package implementation reproduces every entry verbatim.
- **`n1_byte_equality_test.go`** — empirical N1 byte-equality
  harness. Threshold-Combine output byte-identical to centralized
  FIPS 205 `slhdsa.SignDeterministic` on the reconstructed master
  seed. Tested at (3,2), (5,3), (7,4) committee/threshold
  configurations.
- **`SPEC.md`** — construction specification: notation, hash domain
  separation, DKG protocol, threshold signing, Class-N1-analog
  byte-equality claim, trust model, identifiable abort, parameter
  sets.
- **`DEPLOYMENT-RUNBOOK.md`** — operator-facing trust-model
  disclosure. v0.1 reveal-and-aggregate aggregator-as-TCB caveat
  documented with TEE / mlock / ptrace-off hardening matrix.
- **`BLOCKERS.md`** — Tier B → A path enumeration (9 blockers,
  3 closed at v0.2.0).
- **`SUBMISSION-STATUS.md`** — NIST MPTC submission status; phased
  plan to submission-readiness.
- **`README.md`** — repo purpose + status (v0.2.0 = Tier B).

### Closed (Tier C → Tier B)

- **BLK-1**: construction selected (v0.1 reveal-and-aggregate over
  the SLH-DSA scheme seed; mirrors Pulsar's v0.1 pattern).
- **BLK-2**: academic basis (Shamir 1979 + reveal-and-aggregate
  industry pattern; open citation gap noted).
- **BLK-3**: spec defined (`SPEC.md`).
- **BLK-5**: KAT vectors shipped + deterministic regeneration.

### Honesty notes

- The v0.1 reveal-and-aggregate trust caveat: the aggregator
  process holds the reconstructed master SLH-DSA scheme seed in
  memory for the duration of one `Combine` call. Same trust model
  as Pulsar v0.1; documented honestly in `DEPLOYMENT-RUNBOOK.md`
  with the TEE / mlock / ptrace-off hardening matrix.
- v0.1 DKG envelopes are plaintext (KAT-deterministic). A passive
  network observer can collect shares. v0.4 closes this channel
  with ML-KEM-768 envelope wrapping (matching Pulsar CR-8).

## [0.1.0] — 2026-05-18 — Tier C: research-stage

Initial Magnetar research-stage commit.

### Added

- **`DESIGN.md`** — initial design notes for threshold SLH-DSA.
- **`README.md`** — research-stage status.
- **`LICENSE`** — BSD-3-Clause.

---

**Footer**

This CHANGELOG covers the Magnetar library + NIST MPTC submission
package. Sibling submissions:

- `luxfi/pulsar` — M-LWE threshold ML-DSA-65 (FIPS 204 byte-equal),
  Tier A reference at v1.0.7.
- `luxfi/corona` — R-LWE threshold signature (Boschini ePrint
  2024/1113), Tier A documentation shape at v0.6.0.
