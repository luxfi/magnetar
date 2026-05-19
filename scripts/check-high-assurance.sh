#!/usr/bin/env bash
# Magnetar high-assurance gate — orchestrator (per-push, REAL checks).
#
# HONESTY NOTE: Magnetar's high-assurance surface is structurally
# lighter than Pulsar's. Pulsar runs 7 per-push checks (jasminc +
# jasmin-ct + ec-admits + ec-regressions + ec-refinement-scaffold +
# lean-bridge + ec-extraction + ec-compile). Magnetar has NO
# EasyCrypt theories for the threshold overlay, NO Lean ↔ EC bridge
# specific to Magnetar (the algebra is identical to Pulsar's
# GF(257); cross-citation is the closure plan), NO Jasmin sources —
# see PROOF-CLAIMS.md §3.1 for the honest framing of why.
#
# What this gate runs at this submission revision (v0.3.0):
#
#   1. go build ./...
#   2. go vet ./...
#   3. constant-time grep guard (warn on accidental fmt.Printf /
#      log.Println on secret-touching paths)
#   4. unit test smoke (short mode for speed; full suite runs in
#      cut-submission.sh step 5)
#
# What this gate DOES NOT run (because the artifacts do not exist
# at v0.3.0):
#
#   - EasyCrypt compile / admit-budget / regression checks for the
#     threshold overlay (roadmap v0.5.0; Pulsar Tier A reference)
#   - Lean ↔ EC bridge verification (roadmap v0.5.0; cross-citation
#     to Pulsar's GF(257) bridges)
#   - Jasmin type-check + jasmin-ct (no Jasmin sources;
#     libjade covers FIPS 205 single-party but not redistributed)
#   - dudect statistical CT validation (roadmap v0.6.0)
#
# These remain ROADMAP items; see CRYPTOGRAPHER-SIGN-OFF.md
# "Gates" section for the gate inventory and closure targets.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export GOWORK=off

echo "==> Magnetar high-assurance gate"
echo "    surface:    $REPO_ROOT (ref/go/pkg/magnetar/)"
echo "    HONESTY:    NO EC / Lean / Jasmin theories for threshold overlay (see PROOF-CLAIMS.md §3.1)"
echo

OVERALL=0

echo "==> Check 1: go build ./..."
if ! go build ./...; then
    echo "==> FAIL: go build"
    OVERALL=2
fi

echo
echo "==> Check 2: go vet ./..."
if ! go vet ./...; then
    echo "==> FAIL: go vet"
    OVERALL=2
fi

echo
echo "==> Check 3: secret-log grep guard"
# Warn (not fail) if logging primitives appear in code that touches
# secret-typed paths. The full DD-007-style linter from Pulsar is not
# yet ported; this is a smoke check.
HITS=$(grep -rn -E "(fmt\.Print|log\.Print|log\.Fatal|log\.Panic)" \
    ref/go/pkg/magnetar/ 2>/dev/null \
    | grep -v "_test.go" \
    | grep -v "// nolint:nosecretlog" || true)
if [[ -n "$HITS" ]]; then
    echo "    [warn] potential secret-log call sites (review manually):"
    echo "$HITS" | head -20
    echo "    (HONESTY: this is a smoke check, not a blocking gate)"
else
    echo "    [ok] no obvious secret-log call sites in ref/go/pkg/magnetar/"
fi

echo
echo "==> Check 4: unit test smoke (-short)"
if ! go test -count=1 -short -timeout 240s ./ref/go/pkg/magnetar/; then
    echo "==> FAIL: short test suite"
    OVERALL=2
fi

echo
if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — high-assurance gate green (within the documented scope)"
else
    echo "==> done — gate FAILED (rc=$OVERALL)"
fi
exit $OVERALL
