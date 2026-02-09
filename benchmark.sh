#!/bin/bash
# A/B benchmark suite for comparing two cleek binaries using hyperfine.
#
# Usage: bash benchmark.sh [CLEEK_A] [CLEEK_B]
#
# Defaults:
#   CLEEK_A = bin/cleek
#   CLEEK_B = bin/cleek.old
#
# Prerequisites:
#   - hyperfine installed (https://github.com/sharkdp/hyperfine)
#   - Both binaries built
#   - data/test-input/homenet-uncompressed.{zeek,json}.log present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEEK_A="${1:-${SCRIPT_DIR}/bin/cleek}"
CLEEK_B="${2:-${SCRIPT_DIR}/bin/cleek.old}"
ZEEK_INPUT="${SCRIPT_DIR}/data/test-input/homenet-uncompressed.zeek.log"
JSON_INPUT="${SCRIPT_DIR}/data/test-input/homenet-uncompressed.json.log"

# --- Preflight checks ---
if ! command -v hyperfine &>/dev/null; then
    echo "ERROR: hyperfine not found. Install from https://github.com/sharkdp/hyperfine" >&2
    exit 1
fi

for bin in "${CLEEK_A}" "${CLEEK_B}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "ERROR: ${bin} not found or not executable." >&2
        exit 1
    fi
done

for f in "${ZEEK_INPUT}" "${JSON_INPUT}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Input file not found: ${f}" >&2
        exit 1
    fi
done

LABEL_A="$(basename "${CLEEK_A}")"
LABEL_B="$(basename "${CLEEK_B}")"

# Disambiguate labels when basenames collide (e.g. both are "cleek")
if [[ "${LABEL_A}" == "${LABEL_B}" ]]; then
    LABEL_A="${CLEEK_A}"
    LABEL_B="${CLEEK_B}"
fi

echo "=== cleek A/B Benchmark Suite ==="
echo "Binary A: ${CLEEK_A}"
echo "Binary B: ${CLEEK_B}"
echo "Zeek input: ${ZEEK_INPUT}"
echo "JSON input: ${JSON_INPUT}"
echo ""

run_bench() {
    local name="$1"
    local args="$2"

    echo "--- ${name} ---"
    hyperfine \
        --warmup 1 \
        --min-runs 5 \
        --command-name "${LABEL_A}" \
            "${CLEEK_A} ${args}" \
        --command-name "${LABEL_B}" \
            "${CLEEK_B} ${args}"
    echo ""
}

run_bench "01-passthrough-tsv" \
    "${ZEEK_INPUT} > /dev/null"

run_bench "02-passthrough-json" \
    "${JSON_INPUT} > /dev/null"

run_bench "03-line-filter-tsv" \
    "-x '(~ \"tcp\" LINE)' ${ZEEK_INPUT} > /dev/null"

run_bench "04-line-filter-json" \
    "-x '(~ \"tcp\" LINE)' ${JSON_INPUT} > /dev/null"

run_bench "05-at-column-filter-tsv" \
    "-x '(string= @proto \"tcp\")' ${ZEEK_INPUT} > /dev/null"

run_bench "06-at-column-filter-json" \
    "-x '(string= @proto \"tcp\")' ${JSON_INPUT} > /dev/null"

run_bench "07-atat-column-filter-tsv" \
    "-x '(and (plusp @@orig_bytes) (plusp @@resp_bytes))' ${ZEEK_INPUT} > /dev/null"

run_bench "08-atat-column-filter-json" \
    "-x '(and (plusp @@orig_bytes) (plusp @@resp_bytes))' ${JSON_INPUT} > /dev/null"

run_bench "09-mutator-tsv" \
    "-m '(anonip! @id.orig_h @id.resp_h)' ${ZEEK_INPUT} > /dev/null"

run_bench "10-mutator-json" \
    "-m '(anonip! @id.orig_h @id.resp_h)' ${JSON_INPUT} > /dev/null"

run_bench "11-mutator-filter-tsv" \
    "-m '(setf @total_bytes (+ @@orig_bytes @@resp_bytes))' -x '(plusp @total_bytes)' ${ZEEK_INPUT} > /dev/null"

run_bench "12-mutator-filter-json" \
    "-m '(setf @total_bytes (+ @@orig_bytes @@resp_bytes))' -x '(plusp @total_bytes)' ${JSON_INPUT} > /dev/null"

run_bench "13-format-zeek-to-json" \
    "-f json ${ZEEK_INPUT} > /dev/null"

run_bench "14-format-json-to-zeek" \
    "-f zeek ${JSON_INPUT} > /dev/null"

echo "=== Benchmark complete ==="
