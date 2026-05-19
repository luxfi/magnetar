#!/usr/bin/env bash
# scripts/checks/ec-compile.sh — EasyCrypt compile gate for all
# tracked EC files.
#
# Runs `easycrypt compile` on each file in EC_FILES and fails the
# gate if any reports [critical] or exits non-zero. Skips silently if
# easycrypt is not installed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

EC_FILES=(
    "$EC_ROOT/Magnetar_N1.ec"
    "$EC_ROOT/Magnetar_N4.ec"
    "$EC_ROOT/lemmas/Magnetar_CT.ec"
    "$EC_ROOT/lemmas/SLHDSA_Functional.ec"
    "$EC_ROOT/Magnetar_N1_Memory.ec"
    "$EC_ROOT/Magnetar_N1_Signature_Codec.ec"
    "$EC_ROOT/Magnetar_N1_Combine_Layout.ec"
    "$EC_ROOT/Magnetar_N1_Sign_Layout.ec"
    "$EC_ROOT/Magnetar_N1_Combine_Refinement.ec"
    "$EC_ROOT/Magnetar_N1_Sign_Refinement.ec"
    "$EC_ROOT/Magnetar_N1_Combine_Wrapper.ec"
    "$EC_ROOT/Magnetar_N1_Sign_Wrapper.ec"
    "$EC_ROOT/Magnetar_N1_Extracted.ec"
)

if ! command -v easycrypt >/dev/null 2>&1; then
    echo "==> EasyCrypt compile gate"
    echo "    [skip] easycrypt not on PATH"
    echo "           install (source build): https://github.com/EasyCrypt/easycrypt"
    exit 0
fi

EC_HASH=$(easycrypt config 2>&1 | grep "git-hash" | head -1)
echo "==> easycrypt found ($EC_HASH)"

EC_FAIL=0
EC_FAIL_LIST=()
for f in "${EC_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "    [warn] missing: $f"
        continue
    fi
    log="/tmp/ec-compile-$$.$(basename "$f").log"
    rc=0
    easycrypt compile -I "$EC_ROOT" -I "$EC_ROOT/lemmas" "$f" \
        > "$log" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "    [ok]   $f compiles"
        rm -f "$log"
    else
        echo "    [FAIL] $f (rc=$rc) — last lines of easycrypt output:"
        tr '\r' '\n' < "$log" | grep -E "\[critical\]|^[[:space:]]*unknown|error" | head -5 | sed 's/^/      /'
        EC_FAIL=1
        EC_FAIL_LIST+=("$f")
    fi
done

if [[ $EC_FAIL -ne 0 ]]; then
    echo
    echo "    EasyCrypt compile gate FAILED on ${#EC_FAIL_LIST[@]} file(s):"
    for f in "${EC_FAIL_LIST[@]}"; do
        echo "      $f"
    done
    exit 2
fi
exit 0
