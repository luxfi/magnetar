# Changelog — Magnetar

All notable changes to the Magnetar threshold SLH-DSA library and
NIST MPTC submission package are tracked in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
Magnetar adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(Nothing pending at this writing.)

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
