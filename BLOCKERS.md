# Magnetar --- Blockers

Honest enumeration of what remains open at each release.

## v1.2 ship state (current)

v1.2 closes `MAGNETAR-PVSS-DKG-V11` --- the leaderless PVSS-DKG that
removes the trusted dealer from the THBS-SE setup. The v1.2 ship
state is the first Magnetar release with a fully dealerless setup
path; the dealer-path `NewThbsSeKey` is retained for KAT
reproducibility but is no longer recommended for production.

The two paths emit byte-shape-identical share envelopes (pinned by
`TestPVSS_DKG_ByteCompatWithDealerPath`), so already-deployed share
material is forward-compatible with the dealerless setup.

## v1.1 ship state (historical)

v1.1 closed the v1.0 strict-atom + proof-track + dudect open items.
See `CHANGELOG.md` v1.1.0 for the closure summary.

## v1.0 ship state

The two primitives shipped at v1.0 are:

- **Per-validator standalone**
  (`ref/go/pkg/magnetar/standalone.go`) --- the public-BFT primary
  primitive. Each validator runs `PerValidatorKeypair` and
  `ValidatorSign`; the consensus layer collects N signatures into
  `ValidatorAggregateCert` and verifies via `VerifyAggregateCert`.
  This is the production-ready surface.

- **THBS-SE** (Threshold Hash-Based Signatures with Selected-Element
  Reconstruction;
  `ref/go/pkg/magnetar/thbsse.go` + `thbsse_field.go`) --- the
  permissionless threshold companion. t-of-n committee, slot-bound
  commit-and-reveal, anyone-can-combine public combiner, slashable
  evidence for equivocation and malformed shares.

Both emit byte-identical FIPS 205 signatures any unmodified verifier
accepts.

## Open items at v1.0

### MAGNETAR-STRICT-ATOM-V11 --- Strict per-atom THBS-SE Combine

**Status:** CLOSED at v1.1.0. See `ASSEMBLE-INVARIANT.md` for the
load-bearing prose statement and `CHANGELOG.md` v1.1.0 for the
release summary.

**Closure shape.** The v1.1 Combine path is implemented at
`ref/go/pkg/magnetar/thbsse_assemble.go::assembleSignatureBytes`
backed by `ref/go/pkg/magnetar/slhdsa_internal.go::slhSignAtom`
(Magnetar-internal FIPS 205 sec 5--sec 8 walk for the SHAKE family).
The strict-atom discipline is the four-pattern audit grep:

```
grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" thbsse_assemble.go
```

returns ZERO, enforced by `TestThbsSE_StrictAtom_NoTransientSeed`
(AST walk + raw-byte grep) and `scripts/checks/strict-atom-ast.sh`
(shell gate). Byte-identity to `cloudflare/circl/sign/slhdsa.
SignDeterministic` is pinned by `TestSlhdsaInternal_ByteEqualToCirclSign`
across all three SHAKE modes.

**Residual gap.** The bytes of the FIPS 205 master DO exist
transiently inside `derivedMaterial` (the SHAKE-expansion output
buffer) and `derivedExpandInput` (the Lagrange-reconstructed input
to SHAKE) for the duration of the SHAKE absorb. A coredump or
/proc/self/mem dump at exactly the right wall-clock instant would
observe them. Closing this gap requires either full MPC over the
SHAKE-256 hash tree (open research; multi-second per signature) or
a TEE-attested host in the TCB (sibling primitive at
`luxfi/threshold/protocols/slhdsa-tee`). The strict-atom discipline
is the strictest discipline available without crossing into either
regime; see `ASSEMBLE-INVARIANT.md` for the honest statement.

**Residual closed for `strict-PQ` chain profile at 2026-06-01** via
`luxfi/threshold/pkg/thresholdd/magnetar.go` profile gate +
`luxfi/threshold/protocols/slhdsa-tee/pool.go` t-of-n attested-
combiner pool. Strict-PQ chains route every Combine through a
TEE-attested combiner whose binary + firmware chain-validate to the
vendor root (AMD KDS / Intel PCS / NVIDIA NRAS JWKS) --- the bytes
only ever exist inside a measured enclave. The single profile gate
`magnetarRefuseUnderStrictPQ` mirrors the precompile-side
`contract.RefuseUnderStrictPQ` discipline: ONE function, ONE place,
ONE canonical refusal sentinel
(`slhdsatee.ErrMagnetarNoTEEAttestation`, wire identifier
`ERR_MAGNETAR_NO_TEE_ATTESTATION`). The legacy-compat profile
retains the strict-atom commodity-host path verbatim; no caveat
under strict-PQ. See `SECURITY.md` for the full threat-model
statement.

**Production attestation kinds.** Strict-PQ deployments today MUST
use SEV-SNP --- the only `cc/attest` verifier currently production-
implemented. TDX and NRAS verifiers are stubs returning
`ErrNotImplemented` (tracked at #222 stages 2--3); they wire through
the same pool contract once shipped --- no magnetar-side code change
required, only an addition to `CombinerPoolConfig.KnownIssuers`.

**Pool policy defaults:** `Threshold = 2` (2-of-3 attested combiners,
no single-host quorum), `RotationWindow = 60s` (per-member
attestation freshness), `KnownIssuers = {"amd.sev.snp"}` (strict
vendor pin). Operators rotating attestations re-attest each pool
member on a per-block tick (~1s); the 60s rotation window absorbs
~60 blocks of control-plane latency before any sign would refuse.

**Verification gates** (all green under `-race`):

- `TestMagnetarCombine_StrictPQProfile_RequiresTEE` --- strict-PQ
  refuses `Sign` and `Sign_Ctx`; permits `Combine_TEE` only when pool
  is wired; profile flip is reversible + idempotent.
- `TestMagnetarCombine_AttestationVerified_AllowsSign` --- end-to-end
  pool drive against committed AMD Milan SEV-SNP fixture; output
  verifies under `magnetar.VerifyBytes` (no caller awareness of the
  pool's existence).
- `TestMagnetarCombine_StaleAttestation_RejectsSign` --- members
  outside rotation window refused; partial re-attestation recovers.
- `TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig` ---
  2-of-3 attested-fresh quorum surfaces signature; 1-of-3 stops.
- `TestMagnetarCombine_SignatureDivergence_HardRefusal` --- pool
  refuses byte-divergent quorum output (no silent winner-picking).

**v1.0 ship state (archival).** Magnetar v1.0 routed the final FIPS
205 byte production via `circl/slhdsa.SignDeterministic` on a seed
reconstructed by the PUBLIC COMBINER (NOT a privileged aggregator).
The seed was briefly present in the public combiner's memory for one
Sign call and zeroized before return. The combiner role was PUBLIC.

This was materially stronger than a TEE-attested
privileged-aggregator model (no host in the TCB; the combiner was
a pure function any peer could run on its own substrate). v1.1
materially tightens the discipline by replacing the seed binder
with positional slices of a SHAKE-expansion buffer.

### MAGNETAR-PVSS-DKG-V11 --- Leaderless PVSS-DKG for THBS-SE setup

**Status:** CLOSED at v1.2.0. See `ref/go/pkg/magnetar/pvss_dkg.go`
for the construction, `ref/go/pkg/magnetar/key.go` for the
`NewThbsSeKeyFromDealerlessDKG` constructor,
`proofs/easycrypt/Magnetar_N5_PVSS_DKG.ec` for the EasyCrypt theory,
and `CHANGELOG.md` v1.2.0 for the release summary.

**Closure shape.** A Schoenmakers-style PVSS-DKG over GF(257). Each
party i samples its own contribution m_i and a degree-(t-1)
polynomial per byte; publishes hash-based commitments to every
polynomial coefficient at Round 1; distributes shares to each
recipient via authenticated point-to-point channels; reveals the
polynomial at Round 2 alongside blinding randomness so any third
party can verify; aggregates received shares to produce its final
Shamir share. The implicit master M = sum_{i in Q} m_i mod 257
byte-wise is NEVER assembled in any party's memory at any time
during setup. The only point at which M is transiently materialised
is inside the `deriveDKGPublicKey` closure (named `lagrangeScratch`,
zeroized at closure exit) when an external auditor invokes
`VerifyDKGTranscript` to derive the public key.

**Hard invariants enforced (regression-tested):**

- `TestPVSS_DKG_NoSinglePartyHoldsMaster` --- exercises the full DKG
  and asserts no party's in-memory state contains the master, with an
  AST-walk guard on `pvss_dkg.go` against master-naming.
- `TestPVSS_DKG_ByteCompatWithDealerPath` --- the dealerless share
  envelopes byte-equal what the dealer path would emit for the same
  implicit master.
- `TestPVSS_DKG_AdversarialReveals` --- t-1 corrupted parties cannot
  recover the master from their partial-sum view.
- `TestPVSS_DKG_RobustnessAgainstMaliciousCommitments` --- malicious
  parties are detected at Round 2 and excluded from Q; the protocol
  terminates with valid output when |Q| >= t and fails cleanly with
  `ErrPVSSQuorumLost` otherwise.
- `TestPVSS_DKG_EndToEnd_SignAndVerify` --- the closing loop: a
  dealerless-DKG-produced `ThbsSeKey` flows into `ThbsSeRound1` /
  `Combine` unchanged and emits a signature that verifies under
  unmodified `cloudflare/circl/sign/slhdsa.Verify`.

**Production deployment.** Each party runs its own
`NewPVSSPartyState`, broadcasts its `PublicContribution`,
distributes its `ShareTo(j)` rows over authenticated channels, and
publishes its `RevealMsg` at Round 2. An external auditor (or any
party) collates the public-form payloads into a `PVSSTranscript` and
invokes `NewThbsSeKeyFromDealerlessDKG` to assemble the final
`ThbsSeKey`. The dealer-path `NewThbsSeKey` is retained for KAT
reproducibility and foundation-HSM bootstrap; the wire shapes match.

### MAGNETAR-PROOF-TRACK-V11 --- THBS-SE EasyCrypt + Lean track

**Status:** CLOSED at v1.1.0. See `proofs/easycrypt/README.md` for
the v1.1 theory inventory and `proofs/lean-easycrypt-bridge.md` for
the cross-reference table.

**Theory files.** `Magnetar_N1_StrictAtom.ec` carries the headline
byte-equality theorem for the strict-atom Combine path;
`Magnetar_N1_SHAKE_Expand.ec` and `Magnetar_N1_Atom_Refinement.ec`
discharge the supporting refinements; `lemmas/SLHDSA_Functional.ec`
and `lemmas/Magnetar_CT.ec` provide the FIPS 205 SHAKE primitive
definitions + CT lemma. Lean side at
`proofs/lean/Crypto/Magnetar/StrictAtom.lean`.

**Axiom budget.** 5 substantive admits + 1 abstract-vacuous CT
admit. Cross-cites Pulsar Shamir (Lean) and Lux SHA3 (Lean) for the
algebraic content.

### MAGNETAR-DUDECT-V11 --- v1.1 dudect harness

**Status:** CLOSED at v1.1.0. See `ct/dudect/README.md` for the
methodology + Go-side gate.

**Per-push gate.** `ct/dudect/strict_atom_combine_ct_test.go::
TestStrictAtom_CT_NoSecretDependentBranch` (build tag `ct`) walks
the strict-atom emit path's AST and asserts no secret-tagged
identifier feeds an `if` / `switch` condition or an index
expression. Run via `scripts/checks/dudect-smoke.sh`.

**Release-time gate.** The full dudect statistical test on a
compiled harness is documented in `ct/dudect/README.md` and is
release-time only.

### MAGNETAR-EXTERNAL-AUDIT-V11 --- External cryptographer review

**Status:** OPEN. Scope: v1.1 / post-v1.1.

The v0.x internal cryptographer sign-off applies to the v0.x
construction surface, much of which has been removed. The v1.1
external audit should target the THBS-SE construction shape, the
strict-atom-assembly path, and the leaderless PVSS-DKG setup, all
of which land at v1.1.

## v1.3 / v1.4 work items (proposed 2026-06-03 audit)

### MAGNETAR-GPU-PORT-V13 --- Batched FIPS 205 hash-tree GPU kernels

**Status:** PROPOSED. Scope: v1.3.

Land four batched SHAKE256-based kernels at
`lux-private/gpu-kernels/ops/crypto/slhdsa/` and wire through
`luxcpp/gpu` to the magnetar `slhSignAtom` substrate. Kernels:

- `magnetar_wotsplus_chain_batch` --- FIPS 205 §5 chain
  (CPU `wotsChain`).
- `magnetar_fors_subtree_batch` --- FIPS 205 §8.2 FORS subtree
  (CPU `forsNodeCompute`).
- `magnetar_xmss_subtree_batch` --- FIPS 205 §6.1 XMSS subtree
  (CPU `xmssNodeCompute`).
- `magnetar_hmsg_prfmsg_batch` --- FIPS 205 §11.2 SHAKE H_msg /
  PRF_msg (CPU `hMsgPub` and `prfMsg` callback).

Full design + throughput estimates + 5-backend file layout
in `GPU-PORT-PLAN.md`.

Consumers: high-throughput bridge custody signing, N=100+
aggregate-cert verification, slashing-evidence sweep across
historical blocks. NOT required for consensus-rate signing
(~1 sig/block CPU-bound on commodity hardware is sufficient).

### MAGNETAR-PROACTIVE-RESHARE-V13 --- Zero-secret refresh

**Status:** PROPOSED. Scope: v1.3.

Augment the PVSS-DKG with proactive resharing against the same
group public key. Lifts the static-corruption bound to a
refresh-window-bounded adaptive-corruption bound. Share envelope
shape is forward-compatible; no wire break.

### MAGNETAR-APPLE-SE-HSM-V14 --- Apple Keychain SE-only hsm.Provider

**Status:** PROPOSED. Scope: v1.4.

`hsm.Provider` implementation backed by Apple Keychain with
`kSecAttrAccessControl = kSecAccessControlSecureEnclaveOnly`.
Tests can mock; production Apple Silicon hosts get a first-class
HSM substrate that layers BELOW the attestation chain (the
Apple SE is NOT a substitute for SEV-SNP / TDX / NRAS
attestation, it is the at-rest seed wrap).

## Cross-references

- v1.0 construction spec: `THBS-SPEC.md`
- v1.0 normative spec: `SPEC.md`
- v1.0 proof track: `proofs/README.md`
- v1.0 CT track: `ct/README.md`
- v1.0 release notes: `CHANGELOG.md` v1.0.0 entry
- v1.2 audit: `AUDIT-2026-06.md`
- v1.3 TEE integration spec: `TEE-INTEGRATION.md`
- v1.3 GPU port plan: `GPU-PORT-PLAN.md`
