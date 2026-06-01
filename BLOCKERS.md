# Magnetar --- Blockers

Honest enumeration of what remains open at v1.0 and what is scoped at
v1.1.

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

**Status:** OPEN. Scope: v1.1.

**Problem.** The user's strictest formulation of the THBS-SE
invariant --- "no party or combiner EVER reconstructs SK.seed, even
transiently in memory" --- requires assembling the FIPS 205 signature
directly from per-atom share reconstructions of the message-selected
FORS leaves and WOTS+ chain bases, bypassing the canonical
`slh_sign_internal` procedure entirely.

That requires a Magnetar-internal re-implementation of FIPS 205
sec 5 (WOTS+ chain), sec 6.2 (FORS sign), sec 7 (XMSS), and sec 8
(hypertree) operations from per-atom share reconstructions;
`cloudflare/circl/sign/slhdsa`'s implementation does not expose these
as public APIs.

**v1.0 ship state.** Magnetar v1.0 routes the final FIPS 205 byte
production via `circl/slhdsa.SignDeterministic` on a seed
reconstructed by the PUBLIC COMBINER (NOT a privileged aggregator).
The seed is briefly present in the public combiner's memory for one
Sign call and is zeroized before return. The combiner role is PUBLIC
--- anyone can be the combiner --- and there is no long-lived secret
material outside party-local Shamir leaves.

This is materially stronger than a TEE-attested
privileged-aggregator model (no host is in the TCB; the combiner is
a pure function any peer can run on its own substrate). It is
materially weaker than the strict invariant (a peer-local
memory-disclosure adversary at exactly the combine moment could
observe the seed).

**v1.1 work.** Reimplement the WOTS+ chain compute, FORS sign, XMSS
node hash, and hypertree address derivation as Magnetar-internal
primitives. The public combiner then reconstructs ONLY the
message-selected FORS leaves and the WOTS+ chain bases sufficient
for the specific signature, never reconstructing the full seed. The
wire format, share format, slot-guard state, and protocol round
structure are all forward-compatible with that lift --- only the
Combine internals change.

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

**Status:** OPEN. Scope: v1.1.

The legacy EasyCrypt scaffolding that modeled the abandoned v0.x
seed-recombine path has been removed. The v1.0 proof track
(`proofs/README.md`) ports to the THBS-SE construction shape:
commit-bind ladder, byte-wise Shamir over GF(257), Lagrange
reconstruct, FIPS 205 dispatch. The Lean bridge for the algebraic
content (Shamir reconstruction identity, Lagrange basis uniqueness)
mirrors Pulsar's `~/work/lux/proofs/lean/Crypto/` setup.

### MAGNETAR-DUDECT-V11 --- v1.1 dudect harness

**Status:** OPEN. Scope: v1.1.

The v0.x dudect harness has been removed; it modeled deleted API
surfaces. v1.0's CT story is "inherit CIRCL"
(`ct/README.md`). The v1.1 harness re-lands alongside the
strict-atom-assembly construction --- at that point the per-atom
WOTS+ chain compute and FORS sign step become the new CT-critical
surfaces, and dudect is the right tool.

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
