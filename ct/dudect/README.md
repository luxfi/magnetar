# Magnetar constant-time analysis — dudect harness

This directory holds the **dudect** harness (https://github.com/oreparaz/dudect)
that drives empirical constant-time testing on Magnetar's
Verify and Combine paths.

## Targets

| Target | What it tests | Operationally-meaningful CT? |
|---|---|---|
| `dudect_verify` | `magnetar.Verify(pk, msg, ctx, sig)` over a pool of VALID signatures | Yes — `Verify` is the consensus-consumer hot path; CT means an attacker can't extract sig content from timing |
| `dudect_combine` | `magnetar.Combine(...)` over a pool of VALID Round-1+Round-2 tapes (independent ceremonies over the SAME shares; all produce the SAME final signature) | Yes — Combine reconstructs the master seed in memory; CT means the seed value can't influence the leakage trace |

The valid-pool design is the same operationally-meaningful CT
framing Pulsar uses (`~/work/lux/pulsar/ct/dudect/`). Earlier
versions of the harness used class A = zero bytes and class B =
random bytes — both INVALID — which produced rejection-path timing
artifacts rather than data-dependent secret leaks.

## Build

```bash
./fetch.sh        # pulls dudect at the pinned commit
make              # builds both dudect_verify + dudect_combine
make verify       # just verify
make combine      # just combine
```

## Run

Smoke test (laptop, ~minute per target):

```bash
./dudect_verify
./dudect_combine
```

Full submission-grade run (10^9 samples on a pinned CPU, quiet host):

```bash
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
DUDECT_SAMPLES=500000  DUDECT_MAX_BATCHES=1000 ./dudect_combine
```

Or use the orchestrator: `./run-submission.sh`.

## Host support

- x86_64 Linux/macOS: builds cleanly against upstream dudect.h.
- aarch64 Linux/macOS: `dudect_compat.h` is force-included on AArch64
  hosts to supply ARM equivalents of `_mm_mfence()` and `__rdtsc()`.

## What this is NOT

- dudect is an EMPIRICAL CT validator; a negative result (no leakage
  detected) is evidence but not proof. The corresponding FORMAL CT
  artifacts live in `../../jasmin/` (when libjade-SLH-DSA lands; see
  `../../jasmin/slh-dsa/README.md`).
- The smoke-test budget (10,000 samples) is INSUFFICIENT for a CT
  certification claim. The full NIST submission requires ~10^9
  samples per target. See `run-submission.sh`.
- Constant-time analysis at this level does NOT address:
  - cache-timing side channels
  - power side channels
  - EM side channels
  - fault attacks
  - Spectre / Meltdown microarchitectural leakage
