#!/usr/bin/env bash
# Simple helper to approve a peer using NetBird Management API
# Usage: ./scripts/approve_peer.sh <PEER_ID> <API_TOKEN> [API_URL]
# API_URL defaults to http://localhost:33073
set -euo pipefail

PEER_ID=${1:-}
TOKEN=${2:-}
API_URL=${3:-http://localhost:33073}

if [[ -z "$PEER_ID" || -z "$TOKEN" ]]; then
    echo "Usage: $0 <PEER_ID> <API_TOKEN> [API_URL]" >&2
    exit 1
fi

curl -X PUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"approval_required":false}' \
     "$API_URL/api/peers/$PEER_ID" | jq
