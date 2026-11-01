#!/bin/bash

set -e

MANIFEST="T0.json"
DIR="$(dirname "$0")"

cd "$DIR"

if [ ! -f "$MANIFEST" ]; then
    echo "Error: $MANIFEST not found"
    exit 1
fi

echo "Verifying T0 artifacts..."

# Parse the JSON and extract the artifact entries
ARTIFACTS=$(jq -c '.artifacts[]' "$MANIFEST")

ERRORS=0

while read -r artifact; do
    PATH_VAL=$(echo "$artifact" | jq -r '.path')
    EXPECTED_HASH=$(echo "$artifact" | jq -r '.sha256')

    if [ ! -f "$PATH_VAL" ]; then
        echo "FAIL: File not found: $PATH_VAL"
        ERRORS=$((ERRORS+1))
        continue
    fi

    # Calculate sha256 hex lowercase
    ACTUAL_HASH=$(sha256sum "$PATH_VAL" | awk '{print $1}')

    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo "FAIL: Hash mismatch for $PATH_VAL"
        echo "  Expected: $EXPECTED_HASH"
        echo "  Actual:   $ACTUAL_HASH"
        ERRORS=$((ERRORS+1))
    else
        echo "OK: $PATH_VAL"
    fi
done <<< "$ARTIFACTS"

if [ $ERRORS -gt 0 ]; then
    echo "Verification failed with $ERRORS errors."
    exit 1
else
    echo "All artifacts verified successfully."
fi