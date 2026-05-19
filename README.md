# Magnetar — Threshold SLH-DSA (FIPS 205)

> **Research-stage construction.** Threshold hash-based PQ signature
> primitive over FIPS 205 SLH-DSA. Not production-ready. Not part of
> any current NIST submission. See `DESIGN.md` for the research
> direction and `BLOCKERS.md` for the path to production.

## Status

| Field | Value |
|---|---|
| Standard | FIPS 205 SLH-DSA (single-party) |
| Threshold construction | Open research — no fixed protocol |
| Implementation | None |
| Submission package | Roadmap: NIST MPTC v0.3 target |
| Cert-profile role | Polaris profile in `luxfi/quasar` (cross-family PQ diversity) |

## Where this is used

The `Magnetar` leg of the **Polaris** cert profile in
[`luxfi/quasar`](https://github.com/luxfi/quasar) — the
maximum-assurance cross-family profile that pairs lattice PQ
(Pulsar M-LWE + Corona R-LWE) with hash-based PQ (Magnetar
SLH-DSA). Polaris is the production migration target for when
Magnetar matures.

Until Magnetar exists in production form, the Polaris profile is
reserved but not deployable; production chains run the **Pulsar**
or **Aurora** profile.

## Why hash-based threshold matters

SLH-DSA's security rests on collision/preimage resistance of the
underlying hash (SHA-2 or SHAKE), with no lattice assumption.
A threshold profile of SLH-DSA gives cross-family defense in depth:
even if a future cryptanalytic break hits the entire lattice family
(both M-LWE and R-LWE), Magnetar's hash-based threshold leg keeps
the cert sound.

## Why it's hard

See `DESIGN.md` for the construction-level challenges. Summary:
SLH-DSA does not decompose into a linear-aggregation identity the
way ML-DSA does, so the FROST-style aggregation pattern that powers
Pulsar/Corona doesn't transfer. Threshold SLH-DSA in the literature
requires MPC over hash computations + per-signature MPC ceremony,
which dominates deployment economics.

## Cross-references

- [`luxfi/quasar`](https://github.com/luxfi/quasar) — umbrella spec; Magnetar is `PRIMITIVES.md` row
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — sibling threshold M-LWE primitive (production)
- [`luxfi/corona`](https://github.com/luxfi/corona) — sibling threshold R-LWE primitive (production)

## License

BSD-3-Clause. See `LICENSE`.

## Maintainer

`magnetar@lux.network` — Lux Industries, Inc.
