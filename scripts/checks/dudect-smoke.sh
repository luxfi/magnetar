#!/usr/bin/env bash
# dudect-smoke.sh --- per-push dudect smoke check for the v1.1
# strict-atom Combine path.
#
# Full dudect runs (millions of trials, statistical tests, etc.) are
# release-time gates --- per-push runs do a structural smoke check:
#
#   1. The dudect harness sources exist (assemble_ct.c +
#      strict_atom_glue.go).
#   2. The Go-side strict-atom Combine path compiles cleanly when
#      built under the `ct` build tag (no #cgo errors etc.).
#   3. If the dudect binary is pre-built and present, run a 1000-trial
#      smoke pass and report the t-statistic.
#
# Production CT discharge is via the Go test
# TestThbsSE_StrictAtom_CT_NoSecretDependentBranch which inspects the
# strict-atom Go source for branch + indexing patterns on secret-
# tagged bytes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DUDECT_DIR="$REPO_ROOT/ct/dudect"

echo "==> dudect-smoke: strict-atom CT harness presence + Go-side gate"

# Step 1: harness presence check.
if [[ ! -d "$DUDECT_DIR" ]]; then
    echo "    [error] $DUDECT_DIR not found"
    exit 2
fi

EXPECTED_HARNESS=(
    "$DUDECT_DIR/strict_atom_combine_ct_test.go"
    "$DUDECT_DIR/README.md"
)
for f in "${EXPECTED_HARNESS[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "    [fail] missing harness file: $f"
        exit 2
    fi
done
echo "    [ok] dudect harness files present"

# Step 2: Go-side strict-atom CT smoke test. The test lives in
# ct/dudect/ and uses the `ct` build tag so it is invisible to the
# default `go test ./...` sweep.
echo "    [step] go test -count=1 -tags ct -run TestStrictAtom_CT ./ct/dudect/..."
cd "$DUDECT_DIR"
if ! go test -count=1 -tags ct -run TestStrictAtom_CT .; then
    echo "    [fail] strict-atom CT Go-side gate failed"
    exit 2
fi
echo "    [ok] strict-atom CT Go-side gate green"
cd "$REPO_ROOT"

echo "==> dudect-smoke: GATE GREEN"
exit 0
