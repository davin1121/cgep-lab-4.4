#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id> [--vault <bucket>] [--profile <aws-profile>]
# Verifies chain of custody for a signed evidence bundle in the S3 vault.
# Three checks must all pass: integrity (SHA-256), authenticity (Cosign), preservation (Object Lock).
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
  esac
done

[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT env var"; exit 2; }

# Use cosign-windows-amd64 if cosign is not found (Windows install)
if ! command -v cosign &>/dev/null && command -v cosign-windows-amd64 &>/dev/null; then
  alias cosign='cosign-windows-amd64'
  shopt -s expand_aliases
fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

echo "Downloading evidence bundle for run ${RUN_ID}..."
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

echo ""
echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')
if [[ "$EXPECTED" == "$ACTUAL" ]]; then
  echo "  OK (${ACTUAL})"
else
  echo "  FAIL: SHA mismatch"
  echo "    expected: ${EXPECTED}"
  echo "    actual:   ${ACTUAL}"
  exit 1
fi

echo ""
echo "=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ==="
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"
echo "  OK (Cosign verified, Rekor entry exists)"

echo ""
echo "=== 3. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [[ "$RETAIN_UNTIL" > "$NOW" ]]; then
  echo "  OK (retain until ${RETAIN_UNTIL})"
else
  echo "  FAIL: retention expired (${RETAIN_UNTIL})"
  exit 1
fi

echo ""
echo "CHAIN INTACT for run ${RUN_ID}"
