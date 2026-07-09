#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Usage: $0 <target> <image|fs|config>}"
SCAN_TYPE="${2:?Usage: $0 <target> <image|fs|config>}"
OUTPUT_DIR="trivy-reports"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/trivy-${SCAN_TYPE}-${TIMESTAMP}.json"

case "$SCAN_TYPE" in
  image)  trivy image --format json --output "$OUTPUT_FILE" --severity HIGH,CRITICAL "$TARGET" ;;
  fs)     trivy fs --format json --output "$OUTPUT_FILE" --severity HIGH,CRITICAL "$TARGET" ;;
  config) trivy config --format json --output "$OUTPUT_FILE" --severity HIGH,CRITICAL "$TARGET" ;;
  *)      echo "Unknown scan type: $SCAN_TYPE"; exit 1 ;;
esac

echo "Scan complete: $OUTPUT_FILE"
