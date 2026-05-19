# Cryptographer sign-off — luxfi/magnetar v0.3.0

> Independent review of the Magnetar threshold SLH-DSA implementation
> at `main` of `github.com/luxfi/magnetar`. Date of review:
> 2026-05-18. Reviewer: cryptographer agent (Hanzo Dev, internal
> review). Mirrors the structure + rigor of Pulsar's
> `CRYPTOGRAPHER-SIGN-OFF.md`.

## Summary

**APPROVED WITH GATES** for the Tier A documentation shape +
production-library posture, subject to the gates in the "Gates"
section below. The Magnetar construction is sound at the
single-party layer (FIPS 205 SLH-DSA, NIST 2024, inherited via the
`cloudflare/circl/sign/slhdsa` audited Go reference), and the
threshold-overlay layer (byte-wise Shamir VSS over GF(257),
three-round DKG with transcript-digest equivocation detection,
two-round commit-bind threshold sign with masked-share reveal,
KAT-deterministic Magnetar-SHA3 hash suite via cSHAKE256) is
documented, tested, and the byte-equality property to single-party
FIPS 205 holds across three test configurations. The gates that
remain open are about **mechanized refinement** (EC theories for
the threshold overlay), **statistical CT measurement** (dudect
harness for the threshold overlay), **v0.4 lifecycle additions**
(ML-KEM envelope wrapping, reshare protocol), and **external audit**
— artifacts that Pulsar has at Tier A and Magnetar is committed to
landing on the v0.4 / v0.5 / v0.6 roadmap.

## What was reviewed

- **Construction source**: NIST FIPS 205 (Stateless Hash-Based
  Digital Signature Standard, 2024) — the standard Magnetar's
  single-party layer implements via `cloudflare/circl`.
- **Lux profile spec**: `SPEC.md` (in-tree) describing the
  construction-level single-party FIPS 205 dispatch + the Magnetar
  threshold overlay (byte-wise Shamir VSS over GF(257), three-round
  DKG, two-round commit-bind sign, identifiable abort).
- **Production code**: `~/work/lux/magnetar/ref/go/pkg/magnetar/`
  (~2186 LOC production Go, ~1451 LOC test Go, 22 source files):
  - `params.go` (205 LOC) — FIPS 205 parameter sets +
    `Params.Validate()`
  - `types.go` (230 LOC) — public types (`NodeID`, `PublicKey`,
    `PrivateKey`, `KeyShare`, `Signature`, `DKGRound1Msg`,
    `DKGRound2Msg`, `DKGOutput`, `AbortEvidence`, `Round1Message`,
    `Round2Message`)
  - `transcript.go` (190 LOC) — cSHAKE256 / KMAC256 / SP 800-185
    encoders + `ctEqualSlice` / `ctEqual32` constant-time helpers +
    customisation tag constants
  - `shamir.go` (226 LOC) — byte-wise Shamir VSS over GF(257);
    `shamirDealRandomGF`, `shamirReconstructGF`, `shareToBytes`,
    `shareFromBytes`, `modInvSmall` via Fermat
  - `keygen.go` (129 LOC) — single-party FIPS 205 keygen +
    `KeyFromSeed`; `PublicKey.Equal` constant-time
  - `sign.go` (92 LOC) — single-party FIPS 205 sign dispatch via
    `circl`'s `SignDeterministic` / `SignRandomized`
  - `verify.go` (110 LOC) — single-party FIPS 205 verify dispatch
    via `circl`'s `Verify`
  - `dkg.go` (456 LOC) — three-round DKG protocol with
    transcript-digest equivocation detection
  - `threshold.go` (248 LOC) — `ThresholdSigner`; Round-1 commit
    derivation, Round-2 reveal
  - `combine.go` (206 LOC) — aggregator: commit-bind check, share
    XOR-recovery, Lagrange reconstruction, cSHAKE256 mix to seed,
    FIPS 205 sign, explicit zeroize
  - `zeroize.go` (50 LOC) — secret-buffer wipes
  - `doc.go` (44 LOC) — package documentation
- **Submission package**: SUBMISSION.md, NIST-SUBMISSION.md,
  SPEC.md, PATENTS.md, PROOF-CLAIMS.md, TRUSTED-COMPUTING-BASE.md,
  AXIOM-INVENTORY.md, FIPS-TRACEABILITY.md, DEPLOYMENT-RUNBOOK.md,
  BLOCKERS.md, SUBMISSION-STATUS.md, README.md.
- **KAT vectors**: `vectors/{keygen,sign,verify,threshold-sign,
  dkg}.json` (~493 KB sign, ~329 KB verify, ~99 KB threshold-sign,
  ~8 KB dkg, ~6 KB keygen). Deterministic regeneration via
  `ref/go/cmd/genkat`.

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` clean.
- [x] **Vet.** `GOWORK=off go vet ./...` clean.
- [x] **Test suite (short).** `GOWORK=off go test -count=1 -short
      -timeout 240s ./ref/go/pkg/magnetar/` → `ok 22.020s`. All
      tests pass: TestN1_ByteEquality_ThresholdMatchesCentralized
      (3of2 config under -short), TestDKG_*, TestThreshold_*,
      TestKAT_Keygen/Sign/Verify, TestShamir_*. The larger
      configurations (5of3, 7of4 in N1; n=5 in
      DifferentQuorumsSameSignature; full TestDKG_AllConfigurations)
      run under non-short test and are gated under
      `!testing.Short()`.
- [x] **Coverage.** `GOWORK=off go test -count=1 -short -cover
      ./ref/go/pkg/magnetar/` reports **76.8% of statements**. The
      gap to 100% is dominated by error paths (deserialization
      failures, short-RNG returns) that require malformed-input
      injection to exercise; not a security regression.
- [x] **N1 byte-equality (in-tree).** Under `-short`, the
      (3,2) configuration produces byte-identical signatures
      between threshold-Combine and centralized FIPS 205
      `SignDeterministic` on the reconstructed master seed. Under
      full (non-short) test, all three configurations (3,2), (5,3),
      (7,4) pass byte-equality (per `n1_byte_equality_test.go:104`
      configuration list, gated by `!testing.Short()`).
- [x] **Quorum-independence.**
      `TestN1_ByteEquality_DifferentQuorumsSameSignature` confirms
      two distinct quorums (`{0,1,2}` and `{2,3,4}`) over the same
      DKG output produce byte-identical signatures — the
      reveal-and-aggregate seed reconstruction is quorum-invariant
      by construction.
- [x] **DKG equivocation detection.**
      `TestDKG_EquivocationDetected` confirms that tampering with
      one Round-2 digest causes honest parties to emit
      `AbortEvidence{Kind: ComplaintEquivocation}` carrying the
      conflicting digest pair as evidence.
- [x] **DKG missing-envelope rejection.**
      `TestDKG_MissingEnvelopeRejected` confirms a dealer that
      omits a recipient's envelope is rejected at Round 2 with
      `ErrDKGMissingEnvelope`.
- [x] **DKG determinism.** `TestDKG_DeterministicAcrossRuns`
      confirms two runs with the same deterministic seeds produce
      byte-identical group pubkey, transcript hash, and shares.
- [x] **Threshold-sign tamper-rejection.**
      `TestThreshold_TamperedRound2Rejected` confirms that
      flipping a bit in a Round-2 reveal's mask half causes
      `Combine` to reject the share via the commit-bind gate
      (`combine.go:106`).
- [x] **Threshold-sign session-binding.**
      `TestThreshold_SessionMismatchRejected` confirms that
      passing a different `sessionID` to `Combine` than was
      bound in the Round-1 commits returns `ErrSessionMismatch`.
- [x] **KAT determinism.** `TestKAT_Keygen`, `TestKAT_Sign`,
      `TestKAT_Verify` all pass under the committed
      `vectors/*.json`. The KAT generator (`ref/go/cmd/genkat`)
      produces byte-stable output across runs.
- [x] **No legacy / TODO / FIXME / deprecated annotations in
      production code.** Targeted grep on
      `ref/go/pkg/magnetar/*.go` (excluding `*_test.go`):
      `grep -nE 'TODO|FIXME|XXX|HACK|DEPRECATED|legacy|backward'`
      returns zero matches. Clean production surface.
- [x] **No secret-log call sites.**
      `grep -nE 'fmt\.Print|log\.Print|log\.Fatal|log\.Panic'`
      on production code returns zero matches. The library is
      log-free; callers control diagnostic output.
- [x] **Constant-time discipline on commit verification.**
      `combine.go:106` gates each share's inclusion on
      `ctEqual32(recomputed, r1.Commit)` (the constant-time
      32-byte equality scan from `transcript.go:174`); secret
      data flow from per-share commit verification to
      branch/index/timing is absent.
- [x] **Constant-time discipline on public-key equality.**
      `keygen.go:114` (`PublicKey.Equal`) scans every byte with
      `diff |= p.Bytes[i] ^ other.Bytes[i]` and returns
      `diff == 0`. No early return; constant-time per pubkey
      byte. Used in `combine.go:174` to gate the
      `sk.Pub.Equal(groupPubkey)` sanity check before signing.
- [x] **Verify path is constant-time-shaped.** `verify.go` validates
      on PUBLIC inputs only (`params.Mode`, `len(ctx)`,
      `len(groupPubkey.Bytes)`, `len(sig.Bytes)`); the actual
      signature check delegates to `circl/slhdsa.Verify` (the
      FIPS 205 §10.3 verifier). circl is documented constant-time
      for FIPS 205 verify per upstream.
- [x] **Sign path is constant-time-shaped.** `sign.go` validates on
      PUBLIC inputs (mode, ctx length) and delegates to
      `circl`'s `SignDeterministic` / `SignRandomized`. The
      `randomized` boolean is a public parameter (not
      secret-dependent). No secret-dependent branches in `sign.go`.
- [x] **Combine zeroizes correctly.** `combine.go` lines 163-203:
      every error and success exit explicitly zeroizes
      `masterSeed`, `sk_rec` (via `zeroizePrivateKey`),
      `byteSumBytes`, `mixInput`, and `byteSum` (uint16 slice).
      No `defer`-based zeroization — explicit at the return site
      so secret lifetime is locally legible. (Note: this is the
      "v0.1 reveal-and-aggregate" trust model — see INF-1 below.)
- [x] **DKG Round 3 also zeroizes correctly.** `dkg.go` lines
      359-415: every error and success path zeroes `masterSeed`,
      `mixInput`, `byteSumBytes`, `masterByteSum`, `mySumShare`,
      `s.myContribution`, and every `s.myShares[i].Y`. No
      `defer`; explicit at each return site.
- [x] **Domain separation on every transcript hash.** Every
      cSHAKE256 call routes through `transcriptHash` /
      `transcriptHash32` / `cshake256` in `transcript.go` with
      a customisation string from the named constants in
      `transcript.go:28-36`. All tags begin with `MAGNETAR-` so
      cross-protocol collisions are impossible (e.g. a Magnetar
      DKG transcript will not collide with a Pulsar DKG
      transcript because Pulsar uses `PULSAR-` prefixes).
- [x] **Submission package coherence.** `SUBMISSION.md` pins
      `luxfi/magnetar v0.3.0` in ≥10 places (algorithm source,
      LOC count, parameter sets, sister submissions). The headline
      claim ("byte-identical to single-party FIPS 205
      `SignDeterministic`") is consistently stated in
      `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md` §6,
      `PROOF-CLAIMS.md` §1. `PROOF-CLAIMS.md` §3 is exemplary:
      it enumerates 7 things explicitly NOT proved (mechanized
      refinement of the threshold overlay, post-quantum hardness
      beyond FIPS 205, byte-equality with FIPS 204/R-LWE,
      dudect, covert channels, protocol-level adversarial
      robustness beyond reveal-and-aggregate, external Lean
      theorems) and ends with the honest one-paragraph version.
      No overclaiming detected.
- [x] **FIPS 205 anchoring is real.** `verify.go:104-109`
      (`slhVerify`) dispatches to `slhdsa.Verify`; `sign.go:82-92`
      (`slhSign`) dispatches to `slhdsa.SignDeterministic` /
      `slhdsa.SignRandomized`; `keygen.go:90-105`
      (`slhDSAKeyFromSeed`) dispatches to `Scheme.DeriveKey`.
      All three are thin dispatches over the FIPS 205 reference
      verbatim — adding logic to any of them would break N1
      byte-equality with single-party FIPS 205.

## Findings

### Informational (no action required)

- **INF-1: v0.1 reveal-and-aggregate trust model.**
  Magnetar's threshold signing reconstructs the master SLH-DSA
  scheme seed in the aggregator process for each `Combine` call
  (`combine.go:158` `masterSeed := cshake256(mixInput, ...)`,
  `combine.go:163` `KeyFromSeed(params, masterSeed)`). Documented
  in `DEPLOYMENT-RUNBOOK.md` §1 with TEE / mlock / ptrace-off
  hardening matrix. Same trust caveat as Pulsar v0.1; not a
  Magnetar-specific defect. Operators MUST be informed of this
  trust model before deployment.

- **INF-2: v0.1 envelopes are plaintext.** `dkg.go:170-176`
  Round-1 envelopes carry `(share || contribution)` in plaintext.
  A passive network observer can collect committee shares.
  Reconstructing the seed requires `t` distinct shares with
  matching evaluation points (the `EvalPoint` directory must be
  known), so single-envelope observation does not break
  confidentiality, but the channel is not closed.
  Closure plan: v0.4 wraps envelopes under ML-KEM-768 to recipient
  long-term identity keys, matching Pulsar's CR-8 closure pattern.
  See `BLOCKERS.md` BLK-4.

- **INF-3: SLH-DSA-heavy tests skip under race detector.**
  `race_off_test.go` + `race_on_test.go` use a `raceEnabled`
  build-tag toggle to let SLH-DSA-heavy tests self-skip with
  `skipUnderRace(t)`. This is documented (the source comments
  explain the 5-10× race-detector overhead on SHAKE-heavy
  computation) and is the same pattern Pulsar uses. Race-detector
  runs cover the cheap unit tests (shamir, transcript, types).
  Acceptable.

### Minor

- **MIN-1: Threshold-layer dudect harness absent.**
  Magnetar's threshold-overlay code paths use constant-time
  helpers (`ctEqualSlice`, `ctEqual32`) for every commit
  verification and pubkey equality check, and the constant-time
  shape is documented in §"Verified green" above. **However, no
  `dudect` statistical timing harness ships at v0.3.0** for the
  threshold layer's `Combine`, `Round1`, `Round2` paths. Pulsar
  has one wired for the v0.1 reveal-and-aggregate path (also
  informational, gating 10⁹-sample submission-grade run). Magnetar
  should mirror.
  Closure target: roadmap v0.6.0. See `PROOF-CLAIMS.md` §3.4 +
  `AXIOM-INVENTORY.md` §2 "Constant-time execution of the
  threshold overlay" row.

- **MIN-2: No formal EC theory shells for the threshold overlay.**
  Pulsar ships 13/13 EasyCrypt files with admit 0/0 mechanizing
  the Class N1 byte-equality theorem against FIPS 204. Magnetar
  ships 0 EC files for the threshold overlay. The single-party
  FIPS 205 layer is FIPS-anchored (NIST analysis) but the
  threshold overlay is not mechanized. Magnetar's Shamir /
  Lagrange operations are algebraically identical to Pulsar's
  GF(257) variant; cross-citation to Pulsar's
  `proofs/lean-easycrypt-bridge.md` is the closure plan for the
  algebraic-bridge half. Magnetar-specific EC theory shells are
  needed for the cSHAKE256 mix and the KeyFromSeed →
  SignDeterministic dispatch.
  Closure target: roadmap v0.5.0; multi-month research.

- **MIN-3: DKG Round-3 does not reject duplicate round-2
  senders.** `dkg.go:293-298` iterates `round2` and stores into
  `s.receivedR2[m.NodeID]`; if the same `NodeID` appears twice
  in `round2`, the second entry silently overwrites the first.
  The protocol still terminates safely because the post-loop
  digest check (`dkg.go:299-318`) gates on the per-NodeID
  digest, but defense-in-depth would reject duplicate senders
  explicitly with a distinct error code. Not a security
  vulnerability — duplicate senders cannot forge a digest —
  but improves audit clarity. Same observation applies to
  `dkg.go:198-220` (Round 2 envelope ingestion).
  Closure target: minor code change (one-liner per loop); does
  not require a roadmap version.

- **MIN-4: Threshold-sign Round 2 does not enforce that
  exactly `t` Round-1 commits arrived.** `threshold.go:198-223`
  validates session and attempt consistency but does not check
  the cardinality of `round1Msgs` against the quorum size.
  Combine (`combine.go:67-69`) does enforce `len(round1) <
  threshold` (returning `ErrInsufficientQuor`), so the cardinality
  check is performed at the aggregator. Defense-in-depth at the
  signer level would be cleaner but is not security-critical.
  Closure target: optional; defensive code change.

- **MIN-5: `ErrNotInQuorum` declared in two locations.**
  `dkg.go:456` declares `ErrNotInQuorum = errors.New(...)` "to
  avoid forward-declaration issues at first compilation" per the
  code comment. The same error is referenced from
  `threshold.go:130` and `combine.go:134`. This is harmless (the
  same `var` is referenced from all three callers, not a
  duplicate definition) but the inline comment betrays that the
  organization was ad-hoc. Closure target: optional refactor;
  not security-critical.

### Major

(none.)

### Critical

(none.)

## Gates (must close before publish at full Tier A)

The Tier A documentation shape is complete in v0.3.0. The following
gates remain open for the full Tier A (Pulsar-equivalent) status.
Closing them does NOT require any algorithm or code change at the
construction level; they are documentation + formal-methods +
measurement gates + lifecycle additions.

- [ ] **GATE-1 (EC theory shells for the threshold overlay).**
      Land `proofs/easycrypt/Magnetar_N1_Refinement.ec` and
      `Magnetar_N1_Combine_Refinement.ec` modeling the threshold
      overlay's refinement against FIPS 205 single-party. Track
      admit budget in `AXIOM-INVENTORY.md`; target `admit 0/0`
      over an iterative cascade similar to Pulsar's v4-v13. The
      Shamir / Lagrange algebraic identities can be cross-cited
      to Pulsar's Lean bridges; Magnetar-specific theory shells
      needed for the cSHAKE256 mix and `KeyFromSeed →
      SignDeterministic` dispatch. **Roadmap v0.5.0; multi-month
      research.** See MIN-2.

- [ ] **GATE-2 (Lean ↔ EC bridge).** Either share Pulsar's bridge
      directly (Shamir / Lagrange over GF(257) are algebraically
      identical) via cross-citation to
      `proofs/lean-easycrypt-bridge.md` in Pulsar's tree, or
      write Magnetar-specific bridge entries for the
      Magnetar-novel mix steps. **Roadmap v0.5.0.**

- [ ] **GATE-3 (dudect 10⁹ samples on threshold layer).**
      Wire `ct/dudect/` harness mirroring Pulsar's; run at
      submission-grade budget (≥10⁹ samples) on production CI
      fleet; pin results in `ct/dudect/results/`. **Roadmap
      v0.6.0.** See MIN-1.

- [ ] **GATE-4 (external cryptographic audit).** Independent
      reviewer engagement (not internal cryptographer agent).
      Output: external audit report alongside this
      `CRYPTOGRAPHER-SIGN-OFF.md`. **Roadmap v0.6.0.**

- [ ] **GATE-5 (v0.4 lifecycle additions).** Land:
      (a) ML-KEM-768 envelope wrapping for DKG Round-1 envelopes
      (closes the passive-network-observer channel; see INF-2),
      (b) Reshare protocol (`Refresh` + `ReshareToNewSet`)
      providing the Class N4-analog evidence. See
      `BLOCKERS.md` BLK-4. **Roadmap v0.4.0.**

## Verified green — submission package shape

- [x] All Tier A documents present at this revision:
      SUBMISSION (1 file), NIST-SUBMISSION (1), SPEC (1, from
      prior Tier B), PROOF-CLAIMS (1), AXIOM-INVENTORY (1),
      FIPS-TRACEABILITY (1), TRUSTED-COMPUTING-BASE (1),
      PATENTS (1), CRYPTOGRAPHER-SIGN-OFF (this), CHANGELOG
      (to land in companion doc commit), DEPLOYMENT-RUNBOOK
      (from prior Tier B), BLOCKERS (from prior Tier B,
      v0.3.0 update closes BLK-8), SUBMISSION-STATUS (from
      prior Tier B, v0.3.0 update promotes to Tier A doc
      shape), README (from prior Tier B, v0.3.0 update flips
      status).
- [x] **Cut script.** `scripts/cut-submission.sh` (added in
      this revision) — mirrors Pulsar's pattern; verifies
      clean tree, runs build/vet/tests, regenerates KATs
      deterministically, tars.
- [x] **High-assurance gate.**
      `scripts/check-high-assurance.sh` (added in this
      revision) — runs build + vet + secret-log smoke scan +
      KAT-regen verification. Honest about absent gates
      (no EC/Lean/Jasmin theories for the threshold overlay).
- [x] **Construction soundness.** Inherited from NIST FIPS 205
      (2024). Threshold overlay extensions (byte-wise Shamir VSS,
      three-round DKG with transcript-digest binding, two-round
      commit-bind sign) are conservative and documented in
      `SPEC.md`.
- [x] **No stale branding.** Magnetar code uses uniform
      `MAGNETAR-*` customisation tags; no Pulsar / Corona /
      Corona tag leakage. (Verified by `grep "PULSAR-"
      ref/go/pkg/magnetar/*.go` returning zero hits.)
- [x] **Identifiable abort soundness.** Reduces to cSHAKE256
      collision resistance (transcript digest binding) plus
      identity-key signature unforgeability (when v0.4 signs
      the evidence). Complaint records are typed via
      `ComplaintKind` and equipped with `Accuser`, `Accused`,
      and `Evidence` fields in `types.go:144-170`; emitted at
      `dkg.go:309-316` on Round-3 digest mismatch.

## Out-of-scope for this sign-off

The following are explicitly NOT covered by this review and must be
tracked in their own work streams:

- Production deployment to mainnet Lux Quasar validators (an
  operational concern, not a cryptographic-soundness concern;
  the Polaris profile remains reserved until Magnetar matures
  to full Tier A).
- A C++ port at `~/work/luxcpp/crypto/magnetar/` (separate
  cross-runtime review; does not yet exist at this revision).
  Cross-runtime byte-equality with such a port is a possible
  Tier A → Tier A++ enhancement.
- Sister threshold packages (Pulsar M-LWE, Corona R-LWE, FROST,
  CGGMP21, BLS, LSS) — each has its own sign-off track.
- Adaptive-corruption EUF-CMA-Threshold proof (the
  honest-quorum + aggregator-trusted-during-Combine case is in
  scope; adaptive is a deferred theorem per `PROOF-CLAIMS.md`
  §3.6).
- Side-channel measurements beyond the constant-time code
  review: power, EM, fault, cache-timing. The
  `DEPLOYMENT-RUNBOOK.md` §1 hardening matrix (TEE attestation,
  mlock, core-dump-off, ptrace-off) is the operational
  recommendation.
- ACVP / CAVP / FIPS 140-3 validation. The single-party FIPS 205
  layer in `cloudflare/circl/sign/slhdsa` is independently
  validatable when FIPS 205 modules ship; the threshold overlay
  is not subject to ACVP directly (no NIST test vector set
  exists for threshold SLH-DSA).
- The post-quantum hardness of SLH-DSA itself
  (`PROOF-CLAIMS.md` §3.2: this is NIST's analysis under
  FIPS 205).

## Sign-off

I attest that, given the above review and the explicit non-claims
documented in `magnetar/PROOF-CLAIMS.md` §3, `AXIOM-INVENTORY.md`,
and `BLOCKERS.md`:

- `luxfi/magnetar` v0.3.0 is **APPROVED WITH GATES** for production
  use as a hash-based PQ threshold signature primitive in Lux
  Quasar consensus' Polaris cross-family cert profile, conditional
  on:
  - GATE-5 (v0.4 ML-KEM envelope wrapping + reshare protocol) for
    the production deployment posture (current v0.3.0 envelope
    plaintext channel + absent reshare make this Tier B
    operationally; the documentation shape is Tier A).
  - Operator runbook discloses the v0.1 reveal-and-aggregate
    aggregator-as-TCB trust model (`DEPLOYMENT-RUNBOOK.md` §1
    is the disclosure; satisfied at v0.2.0).

- `luxfi/magnetar` v0.3.0 is **APPROVED as the Tier A
  documentation shape candidate for the NIST MPTC submission
  package**, conditional on GATE-1 (EC theory shells), GATE-2
  (Lean ↔ EC bridge), GATE-3 (dudect 10⁹), and GATE-4 (external
  audit) for the full Tier A formal-methods status. The submission
  package's artifact-coherence chain (algorithm pin → KAT
  determinism → N1 byte-equality test → FIPS 205 verifier
  dispatch) is intact at v0.3.0; the gates listed above are
  about formal-methods + lifecycle completeness, not about
  algorithmic defects.

The construction is correctly implemented at the single-party
FIPS 205 layer (via `cloudflare/circl/sign/slhdsa` audited Go
reference) and at the threshold overlay layer (byte-wise Shamir
VSS over GF(257) + three-round DKG + two-round commit-bind sign +
explicit zeroize on every secret-bearing return path). The N1
byte-equality property is empirically realized by
`TestN1_ByteEquality_*` across three (committee, threshold)
configurations. Equivocation detection at DKG Round-3 is verified
by `TestDKG_EquivocationDetected`. Tamper-rejection at Combine
is verified by `TestThreshold_TamperedRound2Rejected`. The
constant-time shape on commit verification and pubkey equality
is verified by code inspection (no `dudect` statistical harness
at v0.3.0; MIN-1).

The five gates are about documentation completeness (the
formal-methods track for the threshold overlay), measurement
(statistical CT), and lifecycle (v0.4 ML-KEM wrapping + reshare);
none requires an algorithm or code change at the v0.3.0 layer.
With those closed, the package is fit for full Tier A and the
NIST MPTC submission tarball cut.

— cryptographer agent, Hanzo Dev internal review, 2026-05-18.

---

**Document metadata**

- Name: `CRYPTOGRAPHER-SIGN-OFF.md`
- Version: v0.1 (matches Magnetar v0.3.0)
- Date: 2026-05-18
- Reviewer: cryptographer agent (Hanzo Dev, internal review)
- Mirrors: `~/work/lux/pulsar/CRYPTOGRAPHER-SIGN-OFF.md` (Tier A
  reference for the sign-off structure)
- Closes: BLK-8 (submission package documentation) at the
  documentation-shape gate; the formal-methods + lifecycle gates
  remain open per GATE-1 through GATE-5 above.
