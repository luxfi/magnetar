#!/usr/bin/env bash
# easycrypt-smoke.sh --- per-push EasyCrypt theory smoke check.
#
# Verifies the v1.1 EasyCrypt theory shells exist + parse-cleanly at
# the require/import level. The FULL EC re-run is a release-time gate
# (1+ hour); the per-push smoke check ensures the theory files are
# present and structurally well-formed.
#
# If EasyCrypt (`easycrypt`) is installed on the runner, the script
# runs the EC `check` command on each file. If not installed, the
# script does a syntactic check (regex-level) and skips with exit 0.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_DIR="$REPO_ROOT/proofs/easycrypt"

echo "==> easycrypt-smoke: theory shell smoke check"

if [[ ! -d "$EC_DIR" ]]; then
    echo "    [error] $EC_DIR not found"
    exit 2
fi

# Expected theory files at v1.1.
EXPECTED=(
    "Magnetar_N1_StrictAtom.ec"
    "Magnetar_N1_SHAKE_Expand.ec"
    "Magnetar_N1_Atom_Refinement.ec"
    "Magnetar_N4_KeyDeriveStable.ec"
    "lemmas/SLHDSA_Functional.ec"
    "lemmas/Magnetar_CT.ec"
)

for f in "${EXPECTED[@]}"; do
    if [[ ! -f "$EC_DIR/$f" ]]; then
        echo "    [fail] missing theory file: proofs/easycrypt/$f"
        exit 2
    fi
done
echo "    [ok] all v1.1 theory files present"

# Per-file structural check: every file must have at least one
# `require import` line and at least one `(* ... *)` comment block
# (the file-header status banner).
for f in "${EXPECTED[@]}"; do
    if ! grep -q "^require import" "$EC_DIR/$f"; then
        echo "    [fail] $f missing 'require import' line"
        exit 2
    fi
    if ! grep -q "(\* --" "$EC_DIR/$f"; then
        echo "    [warn] $f missing standard banner comment (low-severity)"
    fi
done
echo "    [ok] structural checks pass"

# If EasyCrypt is installed, run the proper EC check command.
if command -v easycrypt >/dev/null 2>&1; then
    echo "    [step] easycrypt detected; running per-file check"
    cd "$EC_DIR"
    for f in "${EXPECTED[@]}"; do
        if ! easycrypt check -I . "$f"; then
            echo "    [fail] easycrypt check $f"
            exit 2
        fi
    done
    cd "$REPO_ROOT"
    echo "    [ok] all EC files type-check"
else
    echo "    [skip] easycrypt not installed; skipping per-file type-check"
fi

echo "==> easycrypt-smoke: GATE GREEN"
exit 0
