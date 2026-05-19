#!/usr/bin/env bash
# scripts/cut-submission.sh — produce the NIST MPTC submission tarball.
#
# The `luxfi/magnetar` repository is the single canonical home for the
# submission: spec (SPEC.md), Go reference implementation under
# ref/go/pkg/magnetar/, deterministic KAT generator under
# ref/go/cmd/genkat, KAT vectors under vectors/, the deployment runbook,
# and the Tier A submission docs (SUBMISSION, NIST-SUBMISSION, PATENTS,
# PROOF-CLAIMS, AXIOM-INVENTORY, FIPS-TRACEABILITY,
# TRUSTED-COMPUTING-BASE, CRYPTOGRAPHER-SIGN-OFF) all live in-tree.
# The cut tool produces a self-contained tarball from a clean checkout
# — no replace-directive dance or external module vendoring.
#
# Usage:
#     scripts/cut-submission.sh [TAG] [--force]
#
#         TAG       e.g. "submission-2026-11-16"
#                   omit for dry-run (no tarball, no tag)
#         --force   re-cut over an existing tag / tarball
#
# Steps:
#     1.  verify clean working tree (git status -s empty)
#     2.  verify on branch main
#     3.  verify scripts/check-high-assurance.sh exits 0
#     4.  regenerate KATs (ref/go/cmd/genkat) and verify byte-identical
#         to committed vectors/*.json
#     5.  run core Go tests
#     6.  tar czf submission-<TAG>.tar.gz (excluding .git, vendor caches)
#     7.  sha256 the tarball; print to stdout
#     8.  git tag <TAG>
#
# The script is idempotent: re-running with the same TAG without
# --force fails fast.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# -----------------------------------------------------------------------------
# Argument parsing.
# -----------------------------------------------------------------------------
TAG=""
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help)
            sed -n '4,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --*)
            echo "cut-submission: unknown flag: $arg" >&2
            exit 2
            ;;
        *)
            if [[ -n "$TAG" ]]; then
                echo "cut-submission: only one TAG allowed (got '$TAG' and '$arg')" >&2
                exit 2
            fi
            TAG="$arg"
            ;;
    esac
done

DRY_RUN=0
if [[ -z "$TAG" ]]; then
    DRY_RUN=1
    echo "==> cut-submission: DRY-RUN (no TAG given; will not write tarball or tag)"
fi

TARBALL=""
if [[ $DRY_RUN -eq 0 ]]; then
    TARBALL="$REPO_ROOT/${TAG}.tar.gz"
    if [[ "$TAG" != submission-* ]]; then
        echo "cut-submission: TAG must start with 'submission-' (got '$TAG')" >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------------
# Step 1: clean working tree.
# -----------------------------------------------------------------------------
echo
echo "==> Step 1: verify clean working tree"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "cut-submission: working tree not clean — commit or stash changes first" >&2
    git status --short >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 2: on branch main.
# -----------------------------------------------------------------------------
echo
echo "==> Step 2: verify on branch main"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "cut-submission: must run from branch 'main' (currently on '$CURRENT_BRANCH')" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 2.5: idempotency guard for tag + tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
        if [[ $FORCE -eq 0 ]]; then
            echo "cut-submission: tag '$TAG' already exists — pass --force to re-cut" >&2
            exit 2
        fi
        echo "    [force] tag '$TAG' will be re-cut (existing tag deleted later)"
    fi
    if [[ -e "$TARBALL" ]]; then
        if [[ $FORCE -eq 0 ]]; then
            echo "cut-submission: tarball '$TARBALL' already exists — pass --force to overwrite" >&2
            exit 2
        fi
        echo "    [force] tarball '$TARBALL' will be overwritten"
    fi
fi

# -----------------------------------------------------------------------------
# Step 3: high-assurance gate.
# -----------------------------------------------------------------------------
echo
echo "==> Step 3: high-assurance gate (scripts/check-high-assurance.sh)"
bash "$REPO_ROOT/scripts/check-high-assurance.sh"

# -----------------------------------------------------------------------------
# Step 4: regenerate KATs and verify byte-identical.
# -----------------------------------------------------------------------------
echo
echo "==> Step 4: regenerate KAT vectors and verify byte-identical"
export GOWORK=off
if [[ -d "$REPO_ROOT/ref/go/cmd/genkat" ]]; then
    TMP_VECTORS="$(mktemp -d)"
    trap 'rm -rf "$TMP_VECTORS"' EXIT
    cp -R vectors "$TMP_VECTORS/before"
    go run ./ref/go/cmd/genkat -out=vectors/
    for f in vectors/*.json; do
        if ! diff -q "$f" "$TMP_VECTORS/before/$(basename "$f")" >/dev/null 2>&1; then
            echo "cut-submission: regenerated $(basename "$f") differs from committed copy" >&2
            diff "$TMP_VECTORS/before/$(basename "$f")" "$f" | head -20 >&2
            exit 2
        fi
    done
    echo "    [ok] all KAT vectors are byte-identical to committed copies"
else
    echo "    [warn] ref/go/cmd/genkat not present; skipping KAT regeneration"
fi

# -----------------------------------------------------------------------------
# Step 5: core tests.
# -----------------------------------------------------------------------------
echo
echo "==> Step 5: core Go tests"
go test -count=1 -timeout 240s ./ref/go/pkg/magnetar/

# -----------------------------------------------------------------------------
# Step 6: build the tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
    echo
    echo "==> Step 6: SKIP — dry-run, no tarball will be written"
else
    echo
    echo "==> Step 6: tar czf $(basename "$TARBALL")"
    # We tar from the parent directory so the tarball expands to a
    # './magnetar/' top-level directory.
    (
        cd "$(dirname "$REPO_ROOT")"
        tar czf "$TARBALL" \
            --exclude='./.git' \
            --exclude='./.claude' \
            --exclude='./bench/results/*.txt' \
            magnetar
    )
    if [[ ! -f "$TARBALL" ]]; then
        echo "cut-submission: tarball not produced at $TARBALL" >&2
        exit 2
    fi
    echo "    [ok] $TARBALL"
fi

# -----------------------------------------------------------------------------
# Step 7: SHA-256 the tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "==> Step 7: SHA-256"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$TARBALL"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$TARBALL"
    else
        echo "cut-submission: neither shasum nor sha256sum found in PATH" >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------------
# Step 8: tag the repo.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "==> Step 8: git tag $TAG"
    if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
        git tag -d "$TAG" >/dev/null
    fi
    git tag -a "$TAG" -m "NIST MPTC submission cut $TAG"
    echo "    [ok] tag '$TAG' created (NOT pushed — push manually when ready)"
fi

echo
if [[ $DRY_RUN -eq 1 ]]; then
    echo "==> done — dry-run validated (no tarball / no tag produced)"
else
    echo "==> done — tarball cut, tag created"
    echo "    tarball: $TARBALL"
    echo "    tag:     $TAG (local; not pushed)"
fi
