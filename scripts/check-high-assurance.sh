#!/usr/bin/env bash
# Magnetar high-assurance gate --- orchestrator (per-push).
#
# At v1.1.0 Magnetar's high-assurance scope is:
#
#   - Single-party SLH-DSA via cloudflare/circl/sign/slhdsa v1.6.3.
#     CT posture inherits CIRCL for the per-validator standalone path.
#     See ct/README.md.
#   - THBS-SE share arithmetic over GF(257). Straight-line modular
#     arithmetic with constant-time intent (no secret-dependent
#     branches). See thbsse_field.go.
#   - THBS-SE strict-atom Combine path: Magnetar-internal FIPS 205
#     sec 5/6/7/8 walk over a positional SHAKE-expansion buffer with
#     no named transient seed binder. See thbsse_assemble.go +
#     slhdsa_internal.go.
#   - dudect harness on the strict-atom path (ct/dudect/).
#   - EasyCrypt theory shells covering the strict-atom byte-equality
#     theorem (proofs/easycrypt/Magnetar_N1_StrictAtom.ec) + the FIPS
#     205 SHAKE expansion + the Magnetar-internal refinement to circl.
#
# Any per-check failure (exit 2) fails the orchestrator with the
# same code. Per-check skips (exit 0 with a [skip] message) do not
# fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/go-tests.sh"
    "scripts/checks/strict-atom-ast.sh"
    "scripts/checks/easycrypt-smoke.sh"
    "scripts/checks/dudect-smoke.sh"
)

echo "==> Magnetar high-assurance track (v1.1.0 scope)"
echo "    construction: per-validator standalone + THBS-SE strict-atom"
echo "    proof track : EasyCrypt + Lean bridge (strict-atom byte-equality)"
echo "    CT track    : dudect on strict-atom Combine path"
echo

OVERALL=0
for check in "${CHECKS[@]}"; do
    rc=0
    bash "$REPO_ROOT/$check" || rc=$?
    if [[ $rc -ne 0 ]]; then
        OVERALL=$rc
        echo
        echo "==> $check exited rc=$rc --- aborting gate"
        break
    fi
    echo
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done --- high-assurance gate green"
fi
exit $OVERALL
