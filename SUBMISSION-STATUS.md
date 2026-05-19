# NIST MPTC Submission Status — Magnetar

> Honest status of Magnetar's path to NIST Multi-Party Threshold
> Cryptography submission. Magnetar is **research-stage**; this
> document scopes the work required to reach NIST MPTC v0.3 readiness
> and commits to it as the target window.

## Today

**NOT submission-ready.** Magnetar is a research direction, not a
fixed protocol. Specifically:

- **No fixed construction.** Multiple candidate constructions exist
  in the literature (Komlo/Goldberg style FROST-of-SLH-DSA, full-MPC
  hash-computation, threshold seed-DKG with batched per-signature
  ceremony). Lux has not selected one.
- **No reference implementation.** `magnetar/` repo contains
  `DESIGN.md` + `README.md` only.
- **No KAT vectors.** Cannot exist without a fixed construction.
- **No proof artifacts.** No EC theories, no Lean bridges, no Jasmin
  sources.
- **No constant-time analysis.** Threshold SLH-DSA's per-signature
  MPC ceremony is hash-dominated; CT story is non-trivial.

## Why this is not Pulsar

Pulsar's NIST MPTC v0.1 readiness rests on three structural
advantages that Magnetar does not share:

1. **Linear-aggregation identity.** ML-DSA's Lagrange-reconstruction
   identity at accept time lets Pulsar produce a byte-equal FIPS 204
   signature from threshold inputs. SLH-DSA's hash-tree traversal
   has no such identity.
2. **Fixed FIPS standard to anchor against.** Pulsar's Class N1
   claim is "byte-equal to single-party FIPS 204 ML-DSA." Magnetar
   would have to define a NEW threshold construction (with its own
   security analysis), not anchor to FIPS 205 byte-equally.
3. **Mature academic basis.** Pulsar's protocol shape is FROST-like
   threshold-Schnorr-style, well-studied. Threshold SLH-DSA work in
   the literature is sparser and not yet converged.

## Path to NIST MPTC v0.3

Estimated 2-3 months of focused research + 1-2 months of
implementation + 2-3 months of submission-package authoring.

### Phase 1 — Construction selection (research)

- Survey published threshold SLH-DSA constructions
- Compare on: per-signature MPC complexity, distributed seed
  generation, identifiable abort, public-key preservation across
  resharing
- Select ONE construction; freeze its protocol shape
- Output: `SPEC.md` (initial draft) + reference paper citation

### Phase 2 — Reference implementation (engineering)

- Implement the selected construction in Go
- Targets: `magnetar/ref/go/pkg/magnetar/` mirroring Pulsar's layout
- Use existing SLH-DSA single-party implementations (cloudflare/circl,
  pq-crystals reference) as the underlying primitive
- Output: `ref/go/`, `vectors/`, `test/`

### Phase 3 — Proof artifacts (formal methods)

- EasyCrypt theories for correctness + Class N1-equivalent claim
  (whatever the analog is for Magnetar — likely "verifies under
  unmodified FIPS 205 verification given seed-DKG soundness")
- Lean bridges for the algebraic identities
- Jasmin constant-time analysis of the threshold layer
- Output: `proofs/`, `jasmin/`

### Phase 4 — Submission package (documentation)

Mirror Pulsar's 16-doc structure adapted to Magnetar's specifics:

- `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md`
- `PATENTS.md`, `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`,
  `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md`
- `CHANGELOG.md`, `DEPLOYMENT-RUNBOOK.md`
- `docs/{evaluation,nist-mptc-category,design-decisions,
  patent-claims,family-architecture,threat-model,
  ietf-draft-skeleton}.md`
- `scripts/cut-submission.sh` + supporting build/test/bench/vector
  generation scripts

### Phase 5 — Independent cryptographer review

- Same model as Pulsar's `CRYPTOGRAPHER-SIGN-OFF.md`
- Independent reviewer attests construction + impl + proofs + tests
- Output: `CRYPTOGRAPHER-SIGN-OFF.md`

## Target

**NIST MPTC v0.3** — first submission window after Pulsar v0.1
(2026-11-16). Exact NIST date TBA by NIST; Lux internal target is
**2027 Q3**.

## Cross-references

- `DESIGN.md` — research-direction notes
- `README.md` — repo purpose + status
- [`luxfi/quasar`](https://github.com/luxfi/quasar) — Polaris cert
  profile depends on Magnetar maturing
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — template
  submission package to mirror at Phase 4
- [`luxfi/lps/ROADMAP-CRYPTO-STACK.md`](https://github.com/luxfi/LPs/blob/main/ROADMAP-CRYPTO-STACK.md) — multi-year crypto stack plan

## Honest non-claims

Magnetar today is NOT:

- A NIST MPTC submission (won't be until v0.3)
- A production cryptographic primitive (no impl)
- A specification (construction not selected)
- A security claim (no analysis)
- A drop-in for the Polaris cert profile (the profile is reserved;
  not deployable until Magnetar matures)

This repo exists so the Polaris cert profile in `luxfi/quasar` has
a real repo to reference, and so the NIST MPTC v0.3 work has a home
to land in. It is a placeholder with intent, not a delivery.
