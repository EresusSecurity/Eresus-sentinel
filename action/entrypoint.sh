#!/usr/bin/env bash
# Eresus Sentinel GitHub Action entrypoint
set -euo pipefail

SCAN_PATH="${INPUT_SCAN_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON_SEVERITY:-high}"
FORMAT="${INPUT_FORMAT:-sarif}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-sentinel-results.${FORMAT}}"
EXTRA_ARGS="${INPUT_EXTRA_ARGS:-}"
ENABLE_AIBOM="${INPUT_ENABLE_AIBOM:-false}"

echo "::group::Eresus Sentinel — Security Scan"
echo "Scan path : $SCAN_PATH"
echo "Fail on   : $FAIL_ON"
echo "Format    : $FORMAT"
echo "Output    : $OUTPUT_FILE"
echo "::endgroup::"

EXIT_CODE=0
# shellcheck disable=SC2086
sentinel scan "$SCAN_PATH" \
  --format "$FORMAT" \
  --output "$OUTPUT_FILE" \
  --fail-on "$FAIL_ON" \
  --ci \
  $EXTRA_ARGS \
  || EXIT_CODE=$?

SARIF_FILE="sentinel-results.sarif"
if [ "$FORMAT" != "sarif" ]; then
  sentinel scan "$SCAN_PATH" \
    --format sarif \
    --output "$SARIF_FILE" \
    --ci 2>/dev/null || true
else
  SARIF_FILE="$OUTPUT_FILE"
fi

FINDING_COUNT=$(python3 -c "
import json, sys
try:
    with open('$SARIF_FILE') as f:
        d = json.load(f)
    count = sum(len(r.get('results', [])) for r in d.get('runs', []))
    print(count)
except Exception:
    print(0)
" 2>/dev/null || echo "0")

echo "sarif-file=$SARIF_FILE" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "finding-count=$FINDING_COUNT" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "exit-code=$EXIT_CODE" >> "${GITHUB_OUTPUT:-/dev/null}"

if [ "$ENABLE_AIBOM" = "true" ]; then
  echo "::group::Eresus Sentinel — AIBOM Scan"
  sentinel aibom "$SCAN_PATH" \
    --format cyclonedx \
    --output sentinel-aibom.json \
    --ci 2>/dev/null || true
  echo "::endgroup::"
fi

echo "::notice::Sentinel found $FINDING_COUNT findings (exit code: $EXIT_CODE)"
exit $EXIT_CODE
