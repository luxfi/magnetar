# Magnetar v0.1 — Deployment runbook

> Operator-facing trust-model disclosure and hardening guidance for
> Magnetar v0.1. **READ THIS BEFORE DEPLOYING.**

## 1. v0.1 reveal-and-aggregate trust caveat — single biggest disclosure

**The Magnetar v0.1 aggregator process holds the reconstructed master SLH-DSA seed in memory for the duration of one `Combine` call.**

This is the v0.1 reveal-and-aggregate trust model. It is identical to Pulsar's v0.1 reveal-and-aggregate trust model. The construction is **honest** about this: the security properties below are precisely what v0.1 delivers, and the path to v0.2 (true MPC, aggregator never sees the seed) is in `BLOCKERS.md`.

### What this means operationally

During a `Combine` call (typically ≤100 ms for SHAKE-192s on commodity hardware), the following secret material is live in the aggregator process's address space:

| Buffer | Lifetime | Wiped by |
|---|---|---|
| `master_seed` (96 / 128 bytes) | ~ duration of one `slhdsa.SignDeterministic` call | `zeroizeBytes` at every return path in `combine.go` |
| `sk_rec` (96 / 128 bytes) | ~ duration of one `slhdsa.SignDeterministic` call | `zeroizePrivateKey` |
| `byteSum_bytes` (2×seed_size bytes) | from share Lagrange reconstruction to mix completion | `zeroizeBytes` |
| `mixInput` (2×seed_size + 32 bytes) | from mix construction to cSHAKE output | `zeroizeBytes` |

During this window, an adversary with one of the capabilities below can extract `master_seed` (and therefore forge arbitrary future signatures under the group key):

- arbitrary-code-execution on the aggregator host
- `/proc/<pid>/mem` read of the aggregator process
- a coredump triggered during a Sign call
- a swap-file or hibernation image written to disk
- `ptrace` attached to the aggregator process
- a malicious kernel or hypervisor

### Hardening matrix

| Mitigation | What it protects against | How to enable |
|---|---|---|
| **TEE (SGX / SEV-SNP / TDX)** | malicious kernel/hypervisor, /proc/<pid>/mem from outside the enclave | run aggregator inside a confidential VM or enclave |
| `mlock` the secret buffers | swap / hibernation | the Go runtime does not expose `mlock`; deploy with `vm.swappiness=0` + `swapoff` |
| `prctl(PR_SET_DUMPABLE, 0)` | coredumps | set ulimit core 0 (`ulimit -c 0`), set `/proc/sys/kernel/core_pattern` to disable cores, or run inside a container with `--security-opt no-new-privileges` |
| ptrace-off (Yama LSM `kernel.yama.ptrace_scope=3`) | local ptrace attach | sysctl on the aggregator host |
| Aggregator is a **short-lived process** (one Sign per process invocation, then exit) | post-mortem analysis of the long-lived process | wrap aggregator behind a per-Sign exec spawn |
| Hardware HSM-backed aggregator | host compromise | offload `slhdsa.SignDeterministic` to an HSM — note: most commodity HSMs do not yet ship SLH-DSA |

The Pulsar v0.1 deployment runbook mandates **TEE + mlock + ptrace-off** as the baseline; Magnetar v0.1 inherits the same requirement.

### What this caveat does NOT cover (safe by construction)

- A **single Byzantine committee member** cannot forge a signature. Forging requires `t` valid Round-2 reveals, which requires `t` honest signers to participate.
- A **single Byzantine aggregator** cannot forge a signature for a message that did not receive `t` Round-2 reveals. `Combine`'s commit-bind check (re-derives each `D'_i` from the reveal and compares to the Round-1 broadcast `D_i`) rejects tampered reveals at constant-time check.
- A **passive network observer** does NOT see the reconstructed seed. v0.1 envelopes are plaintext, so a passive observer can collect Shamir shares (one per committee member, but at most one share value per dealer-recipient pair); reconstructing the seed requires the EvalPoint directory + at least `t` distinct envelopes from a single dealer. v0.2 closes this with ML-KEM-768 envelope wrapping.
- The **wire signature** is byte-equal to single-party FIPS 205. Any unmodified FIPS 205 verifier (including stock SLH-DSA validators in standard libraries) accepts Magnetar signatures with no code change.

## 2. Aggregator role assignment

Any party in the quorum (or an external third-party aggregator) can call `Combine`. The protocol does not assume a specific aggregator; the aggregator's identity is not bound into the signature.

**Recommendation:** rotate aggregator role across signing requests to minimise the seed-exposure window on any single host. A leader-rotation pattern over committee members (round-robin keyed by `session_id`) is a reasonable v0.1 default.

## 3. DKG ceremony procedure

1. **Committee membership freeze.** All `n` committee members must agree on the committee NodeID set BEFORE Round 1. Committee membership is bound into the transcript digest at DKG Round 2; mid-ceremony additions are rejected.
2. **Per-party entropy.** Each party MUST use a cryptographically secure RNG for `NewDKGSession.rng`. Reusing entropy across DKG ceremonies leaks contributions.
3. **Round-1 envelope authenticity.** v0.1 envelopes are NOT KEM-wrapped — the network layer MUST authenticate dealers (TLS, sigs, gossip auth) to prevent forged envelopes. v0.2 adds ML-KEM-768 wrapping.
4. **Round-2 digest agreement.** Honest parties detect dealer equivocation when their Round-3 local digest disagrees with any received Round-2 digest. The `ComplaintEquivocation` AbortEvidence is produced; protocol-layer drivers MUST broadcast this for slashing.

## 4. Threshold-sign ceremony procedure

1. **Quorum freeze.** All `t` quorum members must agree on the quorum NodeID set BEFORE Round 1. Quorum is bound into the `τ_1` transcript; mid-ceremony quorum changes are rejected.
2. **Per-attempt RNG.** Each `ThresholdSigner` MUST use a fresh RNG state per (session_id, attempt) pair. Reusing RNG across attempts gives the same mask, which leaks the share to anyone observing the Round-2 reveal.
3. **Round-2 timing.** Round-2 messages SHOULD be released only after every quorum member's Round-1 commit is in hand. This is a protocol invariant; if Round-2 is released early, an attacker can fork the session at Round 1 and extract two distinct shares from the same party (a forgery vector).
4. **Aggregator hardening.** The aggregator host MUST follow §1 hardening (TEE + mlock + ptrace-off baseline).

## 5. Key-share storage

`KeyShare` is a long-lived secret. Storage requirements:

- Encrypt-at-rest with a host-bound key (TPM-sealed, or KMS-wrapped under the host's identity attestation).
- NEVER write `KeyShare.Share` to disk in plaintext.
- Recommended: hold `KeyShare` in a TEE that performs the Round-1/Round-2 computation; the host process never touches the share bytes.

## 6. Quorum rotation / resharing

Magnetar v0.1 does NOT ship resharing. Once a committee is bootstrapped via DKG, the only way to rotate is to run a fresh DKG (producing a new group public key).

v0.2 will ship zero-secret-refresh resharing matching Pulsar's resharing pattern.

## 7. Honest non-warranties

Magnetar v0.1 is shipped under the BSD-3-Clause license with NO WARRANTY. In particular:

- **No independent cryptographic review** of the v0.1 protocol has occurred. See `BLOCKERS.md` BLK-9.
- **No EasyCrypt / Lean / Jasmin proofs** ship in v0.1. See `BLOCKERS.md` BLK-7.
- **No constant-time analysis** of the threshold layer has been conducted under `dudect` or formal tooling.
- **No NIST MPTC submission** has been made.
- **No production Lux deployment** uses Magnetar v0.1. The Polaris profile in `luxfi/quasar` references Magnetar at Tier A; v0.1 reaches Tier B only.

Operators deploying Magnetar v0.1 do so at their own risk and SHOULD layer it with Pulsar (Tier A production primitive) under a cross-family cert profile rather than as the sole signing scheme.

## 8. Cross-references

- `SPEC.md` — full protocol specification
- `BLOCKERS.md` — Tier B → A path
- `SUBMISSION-STATUS.md` — NIST MPTC submission status
- [`luxfi/pulsar/DEPLOYMENT-RUNBOOK.md`](https://github.com/luxfi/pulsar/blob/main/DEPLOYMENT-RUNBOOK.md) — sibling runbook for the threshold M-LWE primitive

---

**Document metadata**

- File: `DEPLOYMENT-RUNBOOK.md`
- Version: v0.1
- Date: 2026-05-18
- Status: operator-facing trust-model disclosure
