# Magnetar --- Blockers

Honest enumeration of what remains open at each release.

## v1.1 ship state (current)

v1.1 closes the v1.0 strict-atom + proof-track + dudect open items.
See `CHANGELOG.md` v1.1.0 for the closure summary. The v1.1
remaining open item is the leaderless PVSS-DKG; see below.

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

**Status:** OPEN. Scope: v1.1.

**Problem.** Magnetar v1.0's `NewThbsSeKey` is a deterministic-dealer
setup. The dealer is in the TCB FOR SETUP ONLY --- once
NewThbsSeKey returns, no party (including the dealer) holds the
seed. But the v1.0 reference does NOT ship the leaderless PVSS-DKG
that the user's construction spec calls for ("Committee runs
leaderless PVSS/DKG for slot-local key --- no dealer, no TEE, no
aggregator secret").

**v1.0 ship state.** The deterministic-dealer setup is documented
honestly and KAT-reproducible. Production deployments that need the
leaderless-DKG variant route through the sibling `luxfi/threshold`
DKG package and feed the result into the same wire-shape share
envelope that `NewThbsSeKey` produces; the share envelope is
forward-compatible.

**v1.1 work.** Land a `NewThbsSeKeyFromDealerlessDKG` constructor in
magnetar that accepts the leaderless DKG output and assembles it
into the same `ThbsSeKey` shape, with the PVSS scheme choice
(Schoenmakers 1999 over a curve subgroup, with cSHAKE256
hash-to-byte to lift the group output into the GF(257) share field)
documented in the spec.

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

## Cross-references

- v1.0 construction spec: `THBS-SPEC.md`
- v1.0 normative spec: `SPEC.md`
- v1.0 proof track: `proofs/README.md`
- v1.0 CT track: `ct/README.md`
- v1.0 release notes: `CHANGELOG.md` v1.0.0 entry
