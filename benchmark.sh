#!/bin/bash
# Comprehensive CLI benchmark suite for cleek using hyperfine.
# Produces machine-readable CSV output in benchmark-results.csv.
#
# Usage: bash benchmark.sh [output.csv]
#
# Prerequisites:
#   - hyperfine installed (https://github.com/sharkdp/hyperfine)
#   - bin/cleek binary built
#   - data/test-input/homenet-uncompressed.{zeek,json}.log present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEEK="${SCRIPT_DIR}/bin/cleek"
ZEEK_INPUT="${SCRIPT_DIR}/data/test-input/homenet-uncompressed.zeek.log"
JSON_INPUT="${SCRIPT_DIR}/data/test-input/homenet-uncompressed.json.log"
OUTPUT_CSV="${1:-benchmark-results.csv}"

# --- Preflight checks ---
if ! command -v hyperfine &>/dev/null; then
    echo "ERROR: hyperfine not found. Install from https://github.com/sharkdp/hyperfine" >&2
    exit 1
fi

if [[ ! -x "${CLEEK}" ]]; then
    echo "ERROR: ${CLEEK} not found or not executable. Build with: ros run --eval '(progn (asdf:make :cleek) (quit))'" >&2
    exit 1
fi

for f in "${ZEEK_INPUT}" "${JSON_INPUT}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Input file not found: ${f}" >&2
        exit 1
    fi
done

echo "=== cleek CLI Benchmark Suite ==="
echo "Binary:     ${CLEEK}"
echo "Zeek input: ${ZEEK_INPUT}"
echo "JSON input: ${JSON_INPUT}"
echo "Output CSV: ${OUTPUT_CSV}"
echo ""

hyperfine \
    --warmup 1 \
    --min-runs 5 \
    --export-csv "${OUTPUT_CSV}" \
    --command-name "01-passthrough-tsv" \
        "${CLEEK} ${ZEEK_INPUT} > /dev/null" \
    --command-name "02-passthrough-json" \
        "${CLEEK} ${JSON_INPUT} > /dev/null" \
    --command-name "03-line-filter-tsv" \
        "${CLEEK} -x '(~ \"tcp\" LINE)' ${ZEEK_INPUT} > /dev/null" \
    --command-name "04-line-filter-json" \
        "${CLEEK} -x '(~ \"tcp\" LINE)' ${JSON_INPUT} > /dev/null" \
    --command-name "05-at-column-filter-tsv" \
        "${CLEEK} -x '(string= @proto \"tcp\")' ${ZEEK_INPUT} > /dev/null" \
    --command-name "06-at-column-filter-json" \
        "${CLEEK} -x '(string= @proto \"tcp\")' ${JSON_INPUT} > /dev/null" \
    --command-name "07-atat-column-filter-tsv" \
        "${CLEEK} -x '(and (plusp @@orig_bytes) (plusp @@resp_bytes))' ${ZEEK_INPUT} > /dev/null" \
    --command-name "08-atat-column-filter-json" \
        "${CLEEK} -x '(and (plusp @@orig_bytes) (plusp @@resp_bytes))' ${JSON_INPUT} > /dev/null" \
    --command-name "09-mutator-tsv" \
        "${CLEEK} -m '(anonip! @id.orig_h @id.resp_h)' ${ZEEK_INPUT} > /dev/null" \
    --command-name "10-mutator-json" \
        "${CLEEK} -m '(anonip! @id.orig_h @id.resp_h)' ${JSON_INPUT} > /dev/null" \
    --command-name "11-mutator-filter-tsv" \
        "${CLEEK} -m '(setf @total_bytes (+ @@orig_bytes @@resp_bytes))' -x '(plusp @total_bytes)' ${ZEEK_INPUT} > /dev/null" \
    --command-name "12-mutator-filter-json" \
        "${CLEEK} -m '(setf @total_bytes (+ @@orig_bytes @@resp_bytes))' -x '(plusp @total_bytes)' ${JSON_INPUT} > /dev/null" \
    --command-name "13-format-zeek-to-json" \
        "${CLEEK} -f json ${ZEEK_INPUT} > /dev/null" \
    --command-name "14-format-json-to-zeek" \
        "${CLEEK} -f zeek ${JSON_INPUT} > /dev/null"

echo ""
echo "=== Benchmark complete ==="
echo "Results written to: ${OUTPUT_CSV}"
