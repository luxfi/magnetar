#!/usr/bin/env bash
# scripts/checks/go-tests.sh — Magnetar Go unit tests (short mode).
#
# Magnetar tests with SLH-DSA-SHAKE-192s DKG can be slow under the
# race detector (the hash-tree depth is h=63, d=7). The short-mode
# gate runs the cheap subset for per-push CI; full multi-config
# coverage runs in the nightly + cut-submission script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
export GOWORK=off

echo "==> Magnetar Go test gate (short mode, no race)"
if ! go test -count=1 -short -timeout 600s ./ref/go/pkg/magnetar/; then
    echo "    [FAIL] go test"
    exit 2
fi
echo "    [ok]   short mode test suite green"
exit 0
