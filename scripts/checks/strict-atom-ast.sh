#!/usr/bin/env bash
# strict-atom-ast.sh --- identifier-hygiene LINT (NOT a security gate).
#
# This runs a NAME lint over the Combine emit path
# (ref/go/pkg/magnetar/thbsse_assemble.go): it asserts the source does
# not SPELL a variable `seed`/`skSeed`/`skPrf`/... . It does NOT show
# the FIPS 205 master is absent from memory --- assembleSignatureBytes
# reconstructs the master into `derivedMaterial` regardless of variable
# naming (see ASSEMBLE-INVARIANT.md and
# BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11). Passing this lint is a style
# check, not a no-leak proof.
#
# It runs the Go-side lint (TestThbsSE_AssembleIdentHygiene) which:
#
#   1. Parses thbsse_assemble.go as Go AST.
#   2. Walks every identifier node and asserts none matches the named
#      set {seed, skSeed, skPrf, SkSeed, SkPrf, PrfKey, prfKey,
#      sk_seed, sk_prf}.
#   3. Scans the comment-stripped file bytes for the name-pattern grep
#      (`SK\.seed|SK\.prf|sk_seed|sk_prf`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ASSEMBLE_PATH="ref/go/pkg/magnetar/thbsse_assemble.go"

echo "==> strict-atom-ast: identifier-hygiene NAME lint (NOT a security gate)"

if [[ ! -f "$ASSEMBLE_PATH" ]]; then
    echo "    [error] $ASSEMBLE_PATH not found"
    exit 2
fi

# Step 1: raw name-pattern grep.
echo "    [step 1] grep -rE \"SK\\.seed|SK\\.prf|sk_seed|sk_prf\" $ASSEMBLE_PATH"
if grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" "$ASSEMBLE_PATH"; then
    echo "    [fail] ident-hygiene lint: $ASSEMBLE_PATH contains a flagged name pattern"
    exit 2
fi
echo "    [ok] no flagged name patterns in $ASSEMBLE_PATH"

# Step 2: Go lint that wraps both the AST walk and the comment-
# stripped grep.
echo "    [step 2] go test -count=1 -run TestThbsSE_AssembleIdentHygiene"
cd ref/go
if ! go test -count=1 -run TestThbsSE_AssembleIdentHygiene ./pkg/magnetar/...; then
    echo "    [fail] TestThbsSE_AssembleIdentHygiene failed"
    exit 2
fi
echo "    [ok] TestThbsSE_AssembleIdentHygiene PASS"
cd "$REPO_ROOT"

echo "==> strict-atom-ast: NAME LINT GREEN (style only; not a no-leak proof)"
exit 0
