# PROOF-CLAIMS — Magnetar (HONEST framing)

> **What this submission proves, and — critically — what it does NOT.**
> Companion to `TRUSTED-COMPUTING-BASE.md` (TCB) and `SUBMISSION.md`
> (cover sheet).
>
> Read this before reading the Magnetar code. The framing matters as
> much as the implementation.

## §1 The narrow claim Magnetar makes at this submission

The strongest precise statement supported by Magnetar v0.3.0:

> **Byte-equal threshold to single-party FIPS 205 SLH-DSA
> (Class N1).** For any honest threshold-sign session over committee
> `[n]` with reconstruction threshold `t`, any signing quorum `Q ⊆ [n]`
> of size `t`, message `m`, context `ctx`, session-id `sid`, attempt
> `kappa`, where each party holds a `KeyShare` from a successful
> Magnetar DKG ceremony, the signature byte string `sigma` emitted by
> Magnetar `Combine(...)` satisfies:
>
> `sigma = slhdsa.SignDeterministic(slhdsa.Scheme(ID).DeriveKey(S), NewMessage(m), ctx)`
>
> where `S` is the master SLH-DSA scheme seed computed at DKG Round 3
> (which equals the Lagrange-reconstructed seed at Combine time).
> Therefore `sigma` verifies under unmodified FIPS 205
> `slhdsa.Verify(pk, NewMessage(m), sigma, ctx)` with `pk` = the
> DKG-output group public key.

**Formal-statement status**: this is stated in prose and code,
validated by test (`TestN1_ByteEquality_*` across (3,2), (5,3), (7,4)
configurations), validated by KAT determinism, and inherited from
FIPS 205 SLH-DSA's NIST security analysis for the single-party
layer. It is **NOT mechanized** in EasyCrypt, Lean, Jasmin, or any
other proof assistant at this submission **for the threshold
overlay layer**. See §3 below for the explicit non-claims list.

## §2 What IS provided

| Aspect | Status | Source |
|---|---|---|
| Implementation of the FIPS 205 single-party layer | ✓ by dispatch to `cloudflare/circl/sign/slhdsa` (community-audited mainstream Go FIPS 205 implementation) | `keygen.go`, `sign.go`, `verify.go` |
| Class N1 (threshold output byte-identical to centralized FIPS 205 SignDeterministic on reconstructed seed) | ✓ by test (no mechanized refinement) | `n1_byte_equality_test.go` — `TestN1_ByteEquality_ThresholdMatchesCentralized`, `TestN1_ByteEquality_DifferentQuorumsSameSignature` |
| KAT determinism | ✓ by deterministic regeneration | `vectors/{keygen,sign,verify,threshold-sign,dkg}.json`; `ref/go/cmd/genkat` consumes fixed seeds + committed config |
| Constant-time discipline on commit verification and pubkey equality | ✓ by code (local `ctEqualSlice` / `ctEqual32` helpers) | `transcript.go` (helpers), `combine.go` (Round-2 commit gate), `keygen.go` (PublicKey.Equal) |
| Identifiable-abort evidence (DKG equivocation) | ✓ by test | `dkg.go` Round-3 emits `AbortEvidence{Kind: ComplaintEquivocation, Evidence: my_digest || accused_digest}` on digest mismatch |
| Domain separation across protocol round transcripts | ✓ by code (single source of truth: `transcript.go`) | `tagDKGCommit`, `tagDKGTranscript`, `tagSignR1`, `tagSignMask`, `tagSeedShare` — all centralised constants |
| Secret-buffer zeroization on every Combine return path | ✓ by code review | `combine.go` — explicit `zeroizeBytes`/`zeroizePrivateKey` at every error and success exit, no `defer` (locally-legible secret lifetime) |

## §3 What is NOT proved (HONEST)

This section is the load-bearing honesty disclosure. Read it.

### §3.1 NOT proved: mechanized refinement of the threshold overlay

Magnetar ships **no EasyCrypt theories, no Lean theorems, no Jasmin
sources** specific to the threshold overlay layer. Pulsar (the M-LWE
sibling at `~/work/lux/pulsar/`) ships 13/13 EasyCrypt files
compiling clean with 0/0 admits, 5/5 Lean ↔ EC bridges, and 3/3
jasmin-ct blocking gates on the threshold layer. **Magnetar does
NOT** ship this for the threshold overlay.

**What IS available upstream (but NOT redistributed in this
submission)**: libjade has SLH-DSA formal CT artifacts for the
**single-party FIPS 205 layer**. Magnetar's `Verify` and the
Combine-internal `SignDeterministic` call route through
`cloudflare/circl/sign/slhdsa`, not libjade's extracted code, so
Magnetar does not redistribute or re-verify libjade's artifacts.
A future Tier A++ delivery could either (a) integrate libjade's
verified single-party SLH-DSA, or (b) cross-cite libjade's CT
analysis as supporting evidence for the single-party half of the
trust chain. Neither is in scope for v0.3.0.

**Why no mechanized refinement of the overlay**: writing EC theories
for the threshold overlay (byte-wise Shamir VSS over GF(257),
three-round DKG transcript binding, two-round commit-bind sign,
cSHAKE256 mix to reconstructed seed) is a multi-month research
project. Pulsar took ~13 EC iterations (v4-v13) to drive admit
budget to 0/0 with extensive Lean-bridged algebraic identities.
Magnetar's algebraic identities are essentially identical to
Pulsar's (same byte-wise Shamir over GF(257), same Lagrange
reconstruction). The closure path is cross-citation: many Magnetar
EC theory shells can re-use Pulsar's Lean ↔ EC bridges for the
Shamir / Lagrange identities, with Magnetar-specific theory shells
covering only the SLH-DSA-specific mix and key derivation. See
`AXIOM-INVENTORY.md` §2 for the closure plan.

**What this means in practice**: a NIST reviewer should NOT expect
to find a `Magnetar_N1.ec` file with a `magnetar_n1_byte_equality_extracted`
lemma analogous to Pulsar's. The trust base for Magnetar's
byte-equality correctness reduces to:

- The FIPS 205 SLH-DSA standard (NIST 2024).
- The `cloudflare/circl/sign/slhdsa` Go reference implementation.
- The Go reference implementation review of the threshold overlay.
- The KAT determinism check (`ref/go/cmd/genkat`).
- The `TestN1_ByteEquality_*` empirical byte-equality harness.
- The constant-time review documented in this file's §3.4.

### §3.2 NOT proved: post-quantum hardness of SLH-DSA

This submission says nothing about the post-quantum hardness of
SLH-DSA itself. SLH-DSA's security rests on the collision and
preimage resistance of the underlying hash (SHAKE for the Magnetar
parameter sets), under the FIPS 205 (NIST 2024) analysis.

**The defensible PQ-safety claim**:
> Magnetar implements FIPS 205 SLH-DSA (NIST 2024 stateless
> hash-based signature standard) on three parameter sets:
> SHAKE-192s (NIST PQ Cat 3, recommended), SHAKE-192f (Cat 3 fast),
> SHAKE-256s (Cat 5). The single-party security analysis is NIST's
> per FIPS 205; the post-quantum hardness assumption is collision
> and preimage resistance of SHAKE, with no lattice dependence.

**NOT defensible**:
> Magnetar is proved post-quantum secure beyond the FIPS 205
> analysis.

### §3.3 NOT proved: byte-equality with FIPS 204 ML-DSA or any R-LWE construction

Magnetar signatures are NOT byte-equal to FIPS 204 ML-DSA
signatures (that is Pulsar's claim) or to any R-LWE construction
(Corona's domain). The three constructions use different hardness
families:

- Magnetar: hash-based (FIPS 205 SLH-DSA, SHAKE).
- Pulsar: M-LWE (FIPS 204 ML-DSA).
- Corona: R-LWE (Boschini et al. ePrint 2024/1113).

Any reviewer expecting cross-construction byte-equality should look
at the dedicated sibling for the desired hardness family.

### §3.4 NOT proved: statistical constant-time validation (dudect)

Magnetar's threshold-overlay code paths use constant-time helpers
(`ctEqualSlice`, `ctEqual32`) for every commit verification and
public-key equality check; secret-dependent branches are absent
from `verify.go`, `sign.go`, and the Combine commit-verify gate.
**However, no dudect-style statistical timing harness ships at
v0.3.0.** A dudect harness is roadmap item v0.4+; at submission
scaffolding time the constant-time evidence is:

- Code review: secret-dependent branches identified and replaced
  with constant-time helpers in `transcript.go`.
- `cloudflare/circl`'s upstream constant-time claims for the
  FIPS 205 single-party layer.
- The single-party layer's eventual libjade CT formal artifacts
  (available upstream, not redistributed here).

Pulsar's dudect harness is wired but not yet at submission-grade
sample count (10⁹). Magnetar's equivalent harness is roadmap.

### §3.5 NOT proved: implementation-side covert-channel safety

The constant-time review does NOT address:
- Memory-access leakage (cache-timing side channels)
- Power side-channels
- EM side-channels
- Fault attacks
- Microarchitectural leakage (Spectre / Meltdown class)
- Statistical timing under realistic deployment conditions

Production deployments MUST follow the hardening checklist in
`DEPLOYMENT-RUNBOOK.md` (mlock pinning, core-dump disable, ptrace
disable, TEE attestation, dedicated host, etc.).

### §3.6 NOT proved: protocol-level adversarial robustness beyond reveal-and-aggregate

The byte-equality claim in §1 is **honest-quorum correctness +
aggregator-trusted-during-Combine**. It says: "when all parties
follow the protocol AND the aggregator process is trusted for the
brief seed-reconstruction window, the output verifies under
single-party FIPS 205." It does NOT prove:

- **Unforgeability** under adaptive corruption of the threshold
  protocol — inherited (with caveats) from the reveal-and-aggregate
  trust model where the aggregator is TCB; no Magnetar-specific
  mechanization.
- **Identifiable abort** under network partition — synchronous
  network assumptions hold; async abort is out of scope.
- **Robust completion** under `f < t/2` Byzantine parties — the
  honest-quorum claim does not address robust signing under
  partial dishonesty.
- **Network-observer envelope confidentiality in v0.1** — v0.1
  envelopes are plaintext (KAT-deterministic). A passive observer
  can collect shares; v0.4 closes this with ML-KEM-768 envelope
  wrapping (matching Pulsar CR-8). See `BLOCKERS.md` BLK-4.
- **Threshold secrecy without aggregator trust** — v0.1 is
  reveal-and-aggregate. A v0.2 full-MPC construction (aggregator
  never sees the seed) is on the research path, no committed target.

### §3.7 NOT proved: external Lean theorems or EC bridges specific to Magnetar

Magnetar has NO Lean-bridged algebraic axioms specific to its
implementation. Pulsar has 5: `lagrange_inverse_eval`,
`threshold_partial_response_identity`, `add_share_zeroR`,
`reconstruct_linear`, `shamir_correct`. The Lagrange-aggregation
identity over GF(257) that Magnetar uses in Combine is
**algebraically identical** to Pulsar's GF(257) variant (same
field, same Shamir secret-sharing scheme, same Lagrange basis
evaluation at `x=0`). Closure plan: cross-citation to Pulsar's
`proofs/lean-easycrypt-bridge.md` once Magnetar's EC theory shells
land at v0.5.0; Magnetar-specific bridge entries needed only for
the SLH-DSA-specific mix (cSHAKE256 with `MAGNETAR-SEED-SHARE-V1`
tag) and the KeyFromSeed → SignDeterministic dispatch.

## §4 Refinement chain (what's connected to what)

```
Go implementation (ref/go/pkg/magnetar/*.go)
       implements (by code review + KAT + TestN1_ByteEquality_*)
FIPS 205 SLH-DSA standard (single-party layer)
  + Magnetar threshold overlay (SPEC.md §3 DKG, §4 threshold sign, §6 byte-equality)
       conforms to (by inspection)
SPEC.md §6 byte-equality claim (Class-N1-analog)
  ← validated empirically by n1_byte_equality_test.go
  ← validated empirically against cloudflare/circl FIPS 205 Verify
```

Each "implements" / "conforms" relation is by **inspection and
test**, NOT machine-checked for the threshold overlay. Compare to
Pulsar's refinement chain (machine-checked at every step via
EasyCrypt 13/13 + Lean bridges 5/5 + Jasmin-CT 3/3 against
FIPS 204).

The single-party FIPS 205 layer IS NIST-anchored (FIPS 205 2024),
which is the standard's analysis; Magnetar inherits it via the
`cloudflare/circl/sign/slhdsa` dispatch in `keygen.go`, `sign.go`,
`verify.go`, and the Combine-internal `slhSign` call.

## §5 What an auditor verifying this submission should do

1. **Read** the `SUBMISSION.md` cover sheet for context.
2. **Read** this document (`PROOF-CLAIMS.md`) for what's proved vs not.
3. **Read** `TRUSTED-COMPUTING-BASE.md` for the implementation TCB.
4. **Read** `FIPS-TRACEABILITY.md` for the FIPS 205 § → code map.
5. **Read** FIPS 205 (NIST 2024) §10 for the underlying single-party
   construction analysis (NIST standard).
6. **Read** `SPEC.md` §3 (DKG), §4 (threshold sign), §6 (byte-equality
   claim), §7 (trust model).
7. **Run** `GOWORK=off go test -count=1 -short -timeout 240s
   ./ref/go/pkg/magnetar/` — expect all tests green, including
   `TestN1_ByteEquality_ThresholdMatchesCentralized` and
   `TestN1_ByteEquality_DifferentQuorumsSameSignature`.
8. **Run** the KAT regeneration determinism check: backup `vectors/`,
   run `GOWORK=off go run ./ref/go/cmd/genkat -out=vectors/`, then
   `diff -qr vectors_backup/ vectors/` — expect zero differences.
9. **Read** the Go reference implementation: `keygen.go`, `sign.go`,
   `verify.go`, `shamir.go`, `transcript.go`, `dkg.go`,
   `threshold.go`, `combine.go`, `zeroize.go`.

## §6 The honest one-paragraph version

> Magnetar's submission package establishes that the Go reference
> implementation faithfully implements the FIPS 205 SLH-DSA
> single-party standard via the `cloudflare/circl/sign/slhdsa` Go
> reference, and adds a novel threshold lifecycle (byte-wise Shamir
> VSS over GF(257) of the SLH-DSA scheme seed, three-round DKG with
> transcript-digest equivocation detection, two-round commit-bind
> threshold sign with masked-share reveal, identifiable-abort
> evidence pipeline, KAT-deterministic Magnetar-SHA3 hash suite via
> cSHAKE256 / KMAC256 per FIPS 202 + SP 800-185). Magnetar's headline
> claim is byte-identity to single-party FIPS 205 SLH-DSA
> `slhdsa.SignDeterministic` on the reconstructed master seed —
> empirically validated by `TestN1_ByteEquality_*` across three
> committee/threshold configurations. Unlike the Pulsar sibling
> submission (which ships a mechanized EasyCrypt + Lean + Jasmin
> refinement chain against FIPS 204), Magnetar ships NO machine-checked
> refinement at this submission **for the threshold overlay layer** —
> the SLH-DSA single-party layer is FIPS-anchored (NIST 2024) but
> mechanizing the threshold overlay itself is a multi-month research
> roadmap item. Magnetar's correctness evidence reduces to: code
> review of the Go reference against the FIPS 205 standard + the
> Magnetar SPEC.md, the KAT determinism check, the
> `TestN1_ByteEquality_*` empirical byte-equality harness against
> single-party FIPS 205, and the constant-time review documented in
> §3.4. The proof tier is intentionally less mature than Pulsar's
> for the threshold overlay; the roadmap items in `NIST-SUBMISSION.md`
> §"Roadmap" lay out the multi-version path to mechanized refinement.

## §7 Roadmap (multi-version closure path)

| Milestone | Target version |
|---|---|
| ML-KEM-768 envelope wrapping of DKG Round-1 envelopes (closes passive-network-observer channel) | v0.4.0 |
| Reshare protocol (Refresh + ReshareToNewSet) — Class N4-analog evidence | v0.4.0 |
| EasyCrypt theory shells for the threshold overlay (refinement to FIPS 205) | v0.5.0 (research; multi-month) |
| Lean ↔ EC bridge (cross-citation to Pulsar's Shamir / Lagrange bridges; or Magnetar-specific entries if needed) | v0.5.0 |
| dudect-style statistical CT validation harness for the threshold overlay | v0.6.0 |
| External cryptographic audit (engaged lab) | v0.6.0 |
| Cross-implementation FIPS 205 verifier harness (BoringSSL / pq-crystals when SLH-DSA matures) | when third-party FIPS 205 implementations ship |
| v0.2 full-MPC construction (aggregator never sees the master seed) | research, no committed target |

The closure path is real but long. The honest framing at this
submission: production-hardened implementation of a FIPS-anchored
single-party primitive with a novel reveal-and-aggregate threshold
overlay, NOT machine-checked refinement of the threshold overlay
against FIPS 205.

---

**Document metadata**

- Name: `PROOF-CLAIMS.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
