#!/usr/bin/env bash
# scripts/checks/extraction.sh — Jasmin → EasyCrypt extraction sanity.
#
# Runs jasmin2ec over the threshold-layer .jazz files and confirms
# the extracted EC theories type-check standalone.
#
# Requires jasminc + easycrypt. Skips silently otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

JASMIN_ROOT="$REPO_ROOT/jasmin"

have_jasmin=0
have_ec=0
command -v jasminc   >/dev/null 2>&1 && have_jasmin=1
command -v easycrypt >/dev/null 2>&1 && have_ec=1

if [[ $have_jasmin -eq 0 || $have_ec -eq 0 ]]; then
    echo "==> Jasmin → EC extraction"
    echo "    [skip] missing jasminc / easycrypt"
    exit 0
fi

echo "==> Jasmin → EC extraction sanity check"
# Try to extract each threshold layer file to EC.
EXTRACT_FAIL=0
for f in "$JASMIN_ROOT"/threshold/*.jazz; do
    [[ -f "$f" ]] || continue
    base=$(basename "$f" .jazz)
    out_ec="/tmp/magnetar-extracted-${base}.ec"
    if ! jasminc -ec "$base" -oec "$out_ec" "$f" 2>/tmp/extract.log; then
        echo "    [FAIL] extraction of $f failed"
        tail -5 /tmp/extract.log | sed 's/^/      /'
        EXTRACT_FAIL=1
        continue
    fi
    if ! easycrypt compile -I "$REPO_ROOT/proofs/easycrypt" "$out_ec" 2>/tmp/compile.log; then
        echo "    [FAIL] compile of extracted $out_ec failed"
        tail -5 /tmp/compile.log | sed 's/^/      /'
        EXTRACT_FAIL=1
        continue
    fi
    echo "    [ok]   $f → $out_ec compiles"
done
exit $EXTRACT_FAIL
