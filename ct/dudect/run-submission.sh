#!/usr/bin/env bash
# Magnetar dudect submission-grade orchestrator.
#
# Runs the full NIST-submission-grade dudect campaign:
#   - 10^9 samples per target for verify (1000 batches * 1M samples)
#   - 5×10^8 samples per target for combine (1000 batches * 500k samples;
#     combine is heavier than verify because each sample runs full SLH-DSA
#     SignDeterministic, so the per-sample budget is smaller to stay
#     within ~12h wall-clock on a typical NIST submission host)
#
# Requirements for a defensible submission run:
#   - Host pinned to a fixed CPU governor (e.g. `performance` on Linux).
#   - Background services minimized (no concurrent CI / GC).
#   - SMT off on Intel/AMD; otherwise time on a "big" core only.
#   - macOS: use `nice -n -20` to elevate priority (`sudo` required).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure fresh build.
if ! command -v make >/dev/null 2>&1; then
    echo "==> make not found in PATH" >&2
    exit 1
fi

if [[ ! -f dudect/src/dudect.h ]]; then
    echo "==> dudect.h missing — running ./fetch.sh"
    ./fetch.sh
fi

echo "==> rebuilding harnesses"
make clean
make

# Submission-grade Verify campaign: 1000 batches * 1M samples per batch
# = 10^9 samples total. Stops early on DUDECT_LEAKAGE_FOUND.
echo
echo "==> dudect_verify (submission-grade: 10^9 samples)"
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
verify_rc=$?

# Submission-grade Combine campaign: 1000 batches * 500k samples per batch
# = 5×10^8 samples total. (Combine is heavier per-sample so we cap at half
# the verify budget.)
echo
echo "==> dudect_combine (submission-grade: 5×10^8 samples)"
DUDECT_SAMPLES=500000 DUDECT_MAX_BATCHES=1000 ./dudect_combine
combine_rc=$?

echo
echo "==> done"
echo "    dudect_verify  rc=$verify_rc"
echo "    dudect_combine rc=$combine_rc"

# Exit 2 if either campaign found leakage.
if [[ $verify_rc -ne 0 || $combine_rc -ne 0 ]]; then
    exit 2
fi
exit 0
