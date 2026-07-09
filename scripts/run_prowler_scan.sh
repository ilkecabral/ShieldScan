#!/usr/bin/env bash
set -euo pipefail

ROLE_ARN="${1:?Usage: $0 <role-arn> [category: s3|iam|ec2|rds|vpc|all]}"
CATEGORY="${2:-all}"
OUTPUT_DIR="prowler-reports"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SCAN_DIR="${OUTPUT_DIR}/prowler-${CATEGORY}-${TIMESTAMP}"

CMD=(
  prowler aws
  --role "$ROLE_ARN"
  --output-formats json-ocsf
  --output-directory "$SCAN_DIR"
  --severity "critical high"
  --status FAIL
)

case "$CATEGORY" in
  s3)    CMD+=(--services s3) ;;
  iam)   CMD+=(--services iam accessanalyzer) ;;
  ec2)   CMD+=(--services ec2 securityhub) ;;
  rds)   CMD+=(--services rds) ;;
  vpc)   CMD+=(--services vpc networkfirewall) ;;
  all)   ;; # no filter, scan everything
  *)     echo "Unknown category: $CATEGORY (expected s3|iam|ec2|rds|vpc|all)"; exit 1 ;;
esac

"${CMD[@]}"

echo "Scan complete: $SCAN_DIR"
