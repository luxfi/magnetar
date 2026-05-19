#!/usr/bin/env bash
# Magnetar — fetch libjade SLH-DSA sources (stub).
#
# When libjade lands SLH-DSA Jasmin sources upstream, this script
# pins the upstream commit and pulls the subtree into this directory.
# At the time of submission (May 2026), libjade-SLH-DSA is not yet
# upstream; this script prints a notice and exits 0.

set -euo pipefail

echo "==> Magnetar slh-dsa fetch"
echo "    [notice] libjade-SLH-DSA is not yet upstream as of 2026-05."
echo "             See README.md in this directory for the closure plan."
echo "             Production routes through cloudflare/circl/sign/slhdsa."
exit 0
