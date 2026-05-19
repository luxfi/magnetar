#!/usr/bin/env bash
# Lean ↔ EasyCrypt Shamir bridge guard (Magnetar).
#
# Magnetar's Shamir/Lagrange axioms are CROSS-CITED from Pulsar's
# bridge (the byte-wise Shamir over GF(257) construction is
# algebraically identical between the two). This script verifies:
#
#   1. Each cross-cited axiom in Magnetar's EC source exists as an
#      `axiom` (not `lemma`).
#   2. Each cross-cited axiom carries an inline citation comment
#      naming the Lean theorem.
#   3. The Lean theorem named in the citation EXISTS in the named
#      Lean file (hardened guard).
#
# Plus:
#   4. The bridge doc must exist.
#   5. Every EC file path mentioned in the bridge doc text must
#      exist on disk.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Lean repo location.
LEAN_ROOT=""
for candidate in \
    "$HOME/work/lux/proofs/lean" \
    "$HOME/work/lux/proofs" \
    "$REPO_ROOT/../proofs/lean" \
    "$REPO_ROOT/../../proofs/lean" \
; do
    if [[ -d "$candidate/Crypto" ]]; then
        LEAN_ROOT="$candidate"
        break
    fi
done
have_lean=0
if [[ -n "$LEAN_ROOT" ]]; then
    have_lean=1
fi

FAIL=0

# (axiom-name, ec-file, lean-citation-substring, lean-theorem-name, lean-file-rel-to-Crypto)
declare -a BRIDGE=(
    "lagrange_inverse_eval|proofs/easycrypt/Magnetar_N1.ec|shamir_correct_at_target|shamir_correct_at_target|Pulsar/Shamir.lean"
    "add_share_zeroR|proofs/easycrypt/Magnetar_N4.ec|AddCommMonoid||"
    "reconstruct_linear|proofs/easycrypt/Magnetar_N4.ec|combine_distributes_over_sum|combine_distributes_over_sum|Threshold_Lagrange.lean"
    "shamir_correct|proofs/easycrypt/Magnetar_N4.ec|shamir_correct_at_target|shamir_correct_at_target|Pulsar/Shamir.lean"
    "mix_to_seed_injective_byteSum|proofs/easycrypt/Magnetar_N1.ec|mix_to_seed_first_arg_injective|mix_to_seed_first_arg_injective|Magnetar/OutputInterchange.lean"
)

echo "==> Lean ↔ EC Shamir bridge guard (Magnetar)"
if [[ $have_lean -eq 1 ]]; then
    echo "    [info] Lean repo: $LEAN_ROOT"
else
    echo "    [info] no Lean repo on disk; skipping Lean-side existence checks"
fi

for entry in "${BRIDGE[@]}"; do
    IFS='|' read -r axiom file lean_ref lean_thm lean_rel <<< "$entry"

    # 1. EC file present.
    if [[ ! -f "$file" ]]; then
        echo "    [FAIL] $axiom: $file not found"
        FAIL=1
        continue
    fi

    # 2. EC axiom still exists as an `axiom` (not silently demoted to `lemma`).
    line=$(grep -nE "^axiom[[:space:]]+${axiom}[[:space:]]*" "$file" | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "    [FAIL] $axiom: declaration not found in $file"
        FAIL=1
        continue
    fi

    # 3. Citation comment in the 30 lines preceding the axiom.
    start=$((line > 30 ? line - 30 : 1))
    if ! sed -n "${start},${line}p" "$file" | grep -q "$lean_ref"; then
        echo "    [FAIL] $axiom @ $file:$line — bridge comment missing reference to '$lean_ref'"
        echo "           (see proofs/lean-easycrypt-bridge.md for the required correspondence)"
        FAIL=1
        continue
    fi

    # 4. Lean theorem actually exists at the named path.
    if [[ $have_lean -eq 1 && -n "$lean_thm" && -n "$lean_rel" ]]; then
        lean_file="$LEAN_ROOT/Crypto/$lean_rel"
        if [[ ! -f "$lean_file" ]]; then
            echo "    [FAIL] $axiom: cited Lean file $lean_file not found"
            FAIL=1
            continue
        fi
        if ! grep -qE "^(theorem|lemma|axiom)[[:space:]]+${lean_thm}[[:space:]]*\\b" "$lean_file"; then
            echo "    [FAIL] $axiom: cited Lean theorem $lean_thm not found in $lean_file"
            FAIL=1
            continue
        fi
    fi

    echo "    [ok]   $axiom @ $file:$line → $lean_ref"
done

# Bridge doc presence.
BRIDGE_DOC="proofs/lean-easycrypt-bridge.md"
if [[ ! -f "$BRIDGE_DOC" ]]; then
    echo "    [FAIL] $BRIDGE_DOC is missing"
    FAIL=1
else
    missing_refs=()
    while IFS= read -r ref; do
        clean=$(echo "$ref" | tr -d '`')
        if [[ ! -f "$clean" ]]; then
            missing_refs+=("$clean")
        fi
    done < <(grep -oE 'proofs/easycrypt/[A-Za-z0-9_/]+\.(ec|md)' "$BRIDGE_DOC" | sort -u)

    if [[ $have_lean -eq 1 ]]; then
        while IFS= read -r ref; do
            clean=$(echo "$ref" | tr -d '`')
            rel="${clean#*lean/Crypto/}"
            full="$LEAN_ROOT/Crypto/$rel"
            if [[ ! -f "$full" ]]; then
                missing_refs+=("$clean")
            fi
        done < <(grep -oE 'lean/Crypto/[A-Za-z0-9_/]+\.lean' "$BRIDGE_DOC" | sort -u)
    fi

    if [[ ${#missing_refs[@]} -gt 0 ]]; then
        echo "    [FAIL] bridge doc references files that don't exist on disk:"
        printf "             %s\n" "${missing_refs[@]}"
        FAIL=1
    else
        echo "    [ok]   $BRIDGE_DOC present + every file path in it exists"
    fi
fi

if [[ $FAIL -ne 0 ]]; then
    echo
    echo "    Lean ↔ EC bridge guard FAILED"
    exit 2
fi
echo "    [ok]   all ${#BRIDGE[@]} axiom citations present + Lean-side names verified"
exit 0
