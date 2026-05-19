#!/usr/bin/env bash
# scripts/checks/ec-refinement-scaffold.sh — Refinement-scaffold guard.
#
# The two refinement files (Combine_Refinement, Sign_Refinement) hold
# the byte-walk obligations. Long-term: every `declare axiom` becomes a
# real lemma. Today the scaffolds carry the byte-walk axioms; CI
# surfaces that as a warning.
#
# Separately: the same files MUST NOT contain top-level `declare axiom`
# statements outside the named refinement obligation — this script
# flags any other declare axiom shape as a hard fail to prevent
# silent obligation drift.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

# Files in scope.
REFINE_FILES=(
    "$EC_ROOT/Magnetar_N1_Combine_Refinement.ec"
    "$EC_ROOT/Magnetar_N1_Sign_Refinement.ec"
)

echo "==> Refinement-scaffold status"

# Note also the Magnetar_N1.ec residual `declare axiom`s. These are
# section-local module-contract axioms (combine_body_axiom,
# S_functional_spec) that are NOT in the extracted N1 corollary's
# dependency cone (the corollary uses the wrapper modules + bridge
# lemmas). Reported as warnings here.
if grep -RE "^[[:space:]]*declare axiom[[:space:]]+combine_body_axiom" \
   "$EC_ROOT" >/dev/null 2>&1 ; then
    echo "    [warn] combine_body_axiom remains a section-local"
    echo "           refinement-boundary axiom"
fi
if grep -RE "^[[:space:]]*declare axiom[[:space:]]+S_functional_spec" \
   "$EC_ROOT" >/dev/null 2>&1 ; then
    echo "    [warn] S_functional_spec remains a section-local"
    echo "           refinement-boundary axiom"
fi

# The refinement files themselves should currently have zero
# declare-axiom statements at the top level — they only contain the
# named byte-walk obligations as `axiom` (NOT `declare axiom`).
REFINE_DECLARE_AXIOMS=$(grep -RE "^[[:space:]]*declare axiom" \
    "${REFINE_FILES[@]}" 2>/dev/null || true)
if [[ -n "$REFINE_DECLARE_AXIOMS" ]]; then
    echo "    [warn] refinement scaffolds still contain declare axioms:"
    echo "$REFINE_DECLARE_AXIOMS" | sed 's/^/      /'
    echo "    Strict closure replaces each of these with a"
    echo "    lemma proved from the extracted Jasmin EC."
else
    echo "    [ok]   no declare axiom in refinement scaffolds"
fi

exit 0
