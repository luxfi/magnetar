#!/usr/bin/env bash
# easycrypt-smoke.sh --- per-push EasyCrypt theory smoke check.
#
# Verifies the EasyCrypt scaffold files exist + are well-formed. Per
# proofs/easycrypt/README.md the Magnetar EC track is HONESTLY two
# 0-content scaffolds; this smoke ensures they are present and carry the
# scaffold banner. The FULL EC re-run is a release-time gate (1+ hour).
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

# Expected theory files. Per proofs/easycrypt/README.md the Magnetar EC
# track is HONESTLY two 0-content scaffolds — the earlier non-empty track
# (Magnetar_N1_SHAKE_Expand.ec, Magnetar_N1_Atom_Refinement.ec,
# Magnetar_N4_KeyDeriveStable.ec, lemmas/SLHDSA_Functional.ec,
# lemmas/Magnetar_CT.ec) was DELETED because its theorems were vacuous
# (X=X rewrites, admit-discharged CT, an axiom restating the headline).
# This list tracks what actually exists; it must not resurrect the
# deleted shells.
EXPECTED=(
    "Magnetar_N1_StrictAtom.ec"
    "Magnetar_N5_PVSS_DKG.ec"
)

for f in "${EXPECTED[@]}"; do
    if [[ ! -f "$EC_DIR/$f" ]]; then
        echo "    [fail] missing theory file: proofs/easycrypt/$f"
        exit 2
    fi
done
echo "    [ok] all expected theory files present"

# Per-file structural check. These are deliberately 0-content scaffolds
# (no axiom/admit/lemma/theorem, no `require import` — see README.md), so
# the only structural marker we assert is the file-header banner comment
# that identifies a real EC scaffold rather than an empty placeholder.
for f in "${EXPECTED[@]}"; do
    if ! grep -q "(\* --" "$EC_DIR/$f"; then
        echo "    [fail] $f missing standard banner comment (not a valid scaffold)"
        exit 2
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
