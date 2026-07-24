#!/usr/bin/env bash
# Single entrypoint for deploying/upgrading the World ID Solana satellite
# program: build -> deploy -> push IDL -> initialize -> add-gateway.
#
# Fully config-driven: copy .env.example to .env at the repo root, fill in
# the values, then run this script with no arguments.
#
# initialize and add-gateway are safe to re-run: Anchor's `init` constraint
# makes a repeat call fail cleanly ("already in use") instead of corrupting
# state, so this script treats that as a soft warning, not a hard failure,
# making the whole pipeline idempotent for repeat/upgrade runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

: "${SOLANA_RPC_URL:?Set SOLANA_RPC_URL in .env (see .env.example)}"
: "${SOLANA_AUTHORITY_KEYPAIR:?Set SOLANA_AUTHORITY_KEYPAIR in .env (see .env.example)}"

if [[ ! -f "$SOLANA_AUTHORITY_KEYPAIR" ]]; then
  echo "error: SOLANA_AUTHORITY_KEYPAIR ($SOLANA_AUTHORITY_KEYPAIR) does not exist" >&2
  exit 1
fi

# declare_id!() in programs/world-id-solana/src/lib.rs.
DEFAULT_PROGRAM_ID="BxHvVSWUkStm7RsKySrzyGWV85PNF8TsGTsPEQ3PsVfK"

OWNER_PUBKEY="${OWNER_PUBKEY:-}"
ROOT_VALIDITY_WINDOW="${ROOT_VALIDITY_WINDOW:-3600}"
TREE_DEPTH="${TREE_DEPTH:-30}"
MIN_EXPIRATION_THRESHOLD="${MIN_EXPIRATION_THRESHOLD:-18000}"
GATEWAY_PUBKEY="${GATEWAY_PUBKEY:-}"

echo "==> Building programs/world-id-solana"
cargo build-sbf --manifest-path programs/world-id-solana/Cargo.toml --sbf-out-dir target/deploy

echo "==> Deploying to $SOLANA_RPC_URL"
if [[ -n "${SOLANA_PROGRAM_KEYPAIR:-}" ]]; then
  if [[ ! -f "$SOLANA_PROGRAM_KEYPAIR" ]]; then
    echo "error: SOLANA_PROGRAM_KEYPAIR ($SOLANA_PROGRAM_KEYPAIR) does not exist" >&2
    exit 1
  fi
  # First deploy: the program keypair's own pubkey becomes the program id.
  solana program deploy target/deploy/world_id_solana.so \
    --program-id "$SOLANA_PROGRAM_KEYPAIR" \
    --upgrade-authority "$SOLANA_AUTHORITY_KEYPAIR" \
    --url "$SOLANA_RPC_URL"
  PROGRAM_ID="${PROGRAM_ID:-$(solana-keygen pubkey "$SOLANA_PROGRAM_KEYPAIR")}"
else
  # Upgrade: target an already-deployed program id.
  PROGRAM_ID="${PROGRAM_ID:-$DEFAULT_PROGRAM_ID}"
  solana program deploy target/deploy/world_id_solana.so \
    --program-id "$PROGRAM_ID" \
    --upgrade-authority "$SOLANA_AUTHORITY_KEYPAIR" \
    --url "$SOLANA_RPC_URL"
fi
export PROGRAM_ID
echo "    program id: $PROGRAM_ID"

echo "==> Pushing IDL"
if command -v anchor >/dev/null 2>&1; then
  anchor idl upgrade --filepath target/idl/world_id_solana.json --provider.cluster "$SOLANA_RPC_URL" "$PROGRAM_ID" \
    || anchor idl init --filepath target/idl/world_id_solana.json --provider.cluster "$SOLANA_RPC_URL" "$PROGRAM_ID"
else
  echo "    skipping: anchor CLI not found (this step is optional)"
fi

if [[ -z "$OWNER_PUBKEY" ]]; then
  OWNER_PUBKEY="$(solana-keygen pubkey "$SOLANA_AUTHORITY_KEYPAIR")"
fi

echo "==> Initializing (owner=$OWNER_PUBKEY tree_depth=$TREE_DEPTH root_validity_window=$ROOT_VALIDITY_WINDOW min_expiration_threshold=$MIN_EXPIRATION_THRESHOLD)"
set +e
cargo run --release -p world-id-solana-deploy -- \
  "$SOLANA_RPC_URL" "$SOLANA_AUTHORITY_KEYPAIR" initialize \
  "$OWNER_PUBKEY" "$ROOT_VALIDITY_WINDOW" "$TREE_DEPTH" "$MIN_EXPIRATION_THRESHOLD"
if [[ $? -ne 0 ]]; then
  echo "    (non-fatal: already initialized, or the RPC call failed -- check the error above)"
fi
set -e

if [[ -n "$GATEWAY_PUBKEY" ]]; then
  echo "==> Authorizing gateway $GATEWAY_PUBKEY"
  set +e
  cargo run --release -p world-id-solana-deploy -- \
    "$SOLANA_RPC_URL" "$SOLANA_AUTHORITY_KEYPAIR" add-gateway "$GATEWAY_PUBKEY"
  if [[ $? -ne 0 ]]; then
    echo "    (non-fatal: already authorized, or the RPC call failed -- check the error above)"
  fi
  set -e
else
  echo "==> Skipping add-gateway (GATEWAY_PUBKEY not set in .env)"
fi

echo "==> Done"
