#!/usr/bin/env bash
# Magnetar high-assurance gate --- orchestrator (per-push).
#
# At v1.0.0 Magnetar's high-assurance scope is:
#
#   - Single-party SLH-DSA via cloudflare/circl/sign/slhdsa v1.6.3.
#     CT posture inherits CIRCL. See ct/README.md.
#   - THBS-SE share arithmetic over GF(257). Straight-line modular
#     arithmetic with constant-time intent (no secret-dependent
#     branches). See thbsse_field.go.
#
# The v0.x EC + Jasmin + dudect harnesses that modeled the
# abandoned reveal-and-aggregate path have been removed. The v1.1
# proof + dudect track lands alongside the strict-atom-assembly
# construction.
#
# v1.0 per-push gate: go-tests.sh. The rest of the proof track
# lands at v1.1 (see BLOCKERS.md::MAGNETAR-PROOF-TRACK-V11 and
# MAGNETAR-DUDECT-V11).
#
# Any per-check failure (exit 2) fails the orchestrator with the
# same code. Per-check skips (exit 0 with a [skip] message) do not
# fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/go-tests.sh"
)

echo "==> Magnetar high-assurance track (v1.0.0 scope)"
echo "    construction: per-validator standalone + THBS-SE"
echo "    proof track : ports to THBS-SE at v1.1 (see BLOCKERS.md)"
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
