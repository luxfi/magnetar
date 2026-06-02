#!/usr/bin/env bash
# strict-atom-ast.sh --- the v1.1 AST + grep invariant gate.
#
# The strict-atom Combine path (ref/go/pkg/magnetar/thbsse_assemble.go)
# is the single line of code the v1.1 audit asserts is free of any
# named transient-seed binder. This script runs the Go-side AST gate
# (TestThbsSE_StrictAtom_NoTransientSeed) which:
#
#   1. Parses thbsse_assemble.go as Go AST.
#   2. Walks every identifier node and asserts none matches the
#      forbidden set {seed, skSeed, skPrf, SkSeed, SkPrf, PrfKey,
#      prfKey, sk_seed, sk_prf}.
#   3. Defense-in-depth: scans the comment-stripped file bytes for the
#      literal grep target from the v1.1 blocker
#      (`SK\.seed|SK\.prf|sk_seed|sk_prf`).
#
# The script also runs the raw audit grep against thbsse_assemble.go
# so the exit code reflects the same check the auditor runs by hand.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ASSEMBLE_PATH="ref/go/pkg/magnetar/thbsse_assemble.go"

echo "==> strict-atom-ast: AST + grep invariant gate"

if [[ ! -f "$ASSEMBLE_PATH" ]]; then
    echo "    [error] $ASSEMBLE_PATH not found"
    exit 2
fi

# Step 1: raw audit grep, byte-for-byte equivalent to the v1.1
# blocker's specified check.
echo "    [step 1] grep -rE \"SK\\.seed|SK\\.prf|sk_seed|sk_prf\" $ASSEMBLE_PATH"
if grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" "$ASSEMBLE_PATH"; then
    echo "    [fail] strict-atom grep invariant: $ASSEMBLE_PATH contains forbidden patterns"
    exit 2
fi
echo "    [ok] no forbidden patterns in $ASSEMBLE_PATH"

# Step 2: Go test that wraps both the AST walk and the comment-
# stripped grep.
echo "    [step 2] go test -count=1 -run TestThbsSE_StrictAtom_NoTransientSeed"
cd ref/go
if ! go test -count=1 -run TestThbsSE_StrictAtom_NoTransientSeed ./pkg/magnetar/...; then
    echo "    [fail] TestThbsSE_StrictAtom_NoTransientSeed failed"
    exit 2
fi
echo "    [ok] TestThbsSE_StrictAtom_NoTransientSeed PASS"
cd "$REPO_ROOT"

echo "==> strict-atom-ast: GATE GREEN"
exit 0
