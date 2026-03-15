#!/usr/bin/env bash
#
# End-to-end MCP auth demo.
#
# Shows the full flow: generate keys, create delegation chain,
# create proofs, send tool calls to an MCP server, see verified
# and denied results.
#
# Usage:
#   cd agent-auth
#   bash examples/mcp-demo/demo.sh
#
# Requirements:
#   npm install @kanoniv/agent-auth (or npx handles it)

set -euo pipefail

GOLD='\033[33m'
BLUE='\033[34m'
GREEN='\033[32m'
RED='\033[31m'
CYAN='\033[36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

CLI="node $(dirname "$0")/../../js/dist/cli.js"

# Clean up from previous runs
rm -rf /tmp/mcp-demo
mkdir -p /tmp/mcp-demo
export HOME_BACKUP="$HOME"

# Use temp dir for keys so we don't pollute real ~/.kanoniv
export KANONIV_KEYS_DIR="/tmp/mcp-demo/keys"
mkdir -p "$KANONIV_KEYS_DIR"

echo ""
echo -e "${BOLD}${GOLD}============================================================${RESET}"
echo -e "${BOLD}${GOLD}  MCP Auth Demo - End to End${RESET}"
echo -e "${BOLD}${GOLD}============================================================${RESET}"
echo ""
echo -e "${DIM}Every MCP tool call carries a cryptographic delegation proof.${RESET}"
echo -e "${DIM}The server verifies identity, scope, and cost limits.${RESET}"
echo ""

# ── Step 1: Generate identities ─────────────────────────────

echo -e "${BOLD}${CYAN}[1]${RESET} Generate agent identities"
echo ""

ROOT_DID=$($CLI generate --name root 2>/dev/null)
echo -e "    Root authority: ${GOLD}${ROOT_DID}${RESET}"

MANAGER_DID=$($CLI generate --name manager 2>/dev/null)
echo -e "    Manager agent:  ${BLUE}${MANAGER_DID}${RESET}"

WORKER_DID=$($CLI generate --name worker 2>/dev/null)
echo -e "    Worker agent:   ${BLUE}${WORKER_DID}${RESET}"

# Get root public key for server config
ROOT_PK=$(cat ~/.kanoniv/keys/root.key | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")

# ── Step 2: Create delegation chain ─────────────────────────

echo ""
echo -e "${BOLD}${CYAN}[2]${RESET} Create delegation chain"
echo ""

$CLI delegate \
  --from root \
  --to manager \
  --scope search,analyze,report \
  --max-cost 50 \
  --expires 24h \
  --output /tmp/mcp-demo/delegation-manager.json 2>/dev/null

echo -e "    Root -> Manager: ${GREEN}[search, analyze, report]${RESET}, max \$50, 24h"

$CLI delegate \
  --from manager \
  --to worker \
  --scope search \
  --max-cost 10 \
  --parent /tmp/mcp-demo/delegation-manager.json \
  --output /tmp/mcp-demo/delegation-worker.json 2>/dev/null

echo -e "    Manager -> Worker: ${GREEN}[search]${RESET}, max \$10"

# ── Step 3: Inspect the chain ────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}[3]${RESET} Inspect delegation chain"
echo ""
$CLI inspect /tmp/mcp-demo/delegation-worker.json 2>/dev/null | sed 's/^/    /'

# ── Step 4: Create proofs ───────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}[4]${RESET} Create MCP proofs for tool calls"
echo ""

# Proof 1: Worker searches (allowed)
$CLI prove \
  --action search \
  --args '{"query": "AI agent security", "cost": 2.0}' \
  --delegation /tmp/mcp-demo/delegation-worker.json \
  --key worker \
  --output /tmp/mcp-demo/proof-search.json 2>/dev/null
echo -e "    Proof 1: Worker calls ${GREEN}search${RESET} (\$2.00) -> saved"

# Proof 2: Worker tries analyze (not in scope)
$CLI prove \
  --action analyze \
  --args '{"data": "results", "cost": 1.0}' \
  --delegation /tmp/mcp-demo/delegation-worker.json \
  --key worker \
  --output /tmp/mcp-demo/proof-analyze.json 2>/dev/null
echo -e "    Proof 2: Worker calls ${RED}analyze${RESET} (\$1.00) -> saved"

# Proof 3: Worker tries expensive search (over cap)
$CLI prove \
  --action search \
  --args '{"query": "expensive query", "cost": 25.0}' \
  --delegation /tmp/mcp-demo/delegation-worker.json \
  --key worker \
  --output /tmp/mcp-demo/proof-expensive.json 2>/dev/null
echo -e "    Proof 3: Worker calls search (${RED}\$25.00${RESET} - over \$10 cap) -> saved"

# Proof 4: Manager analyzes (allowed - broader scope)
$CLI prove \
  --action analyze \
  --args '{"data": "findings", "cost": 5.0}' \
  --delegation /tmp/mcp-demo/delegation-manager.json \
  --key manager \
  --output /tmp/mcp-demo/proof-manager-analyze.json 2>/dev/null
echo -e "    Proof 4: Manager calls ${GREEN}analyze${RESET} (\$5.00) -> saved"

# ── Step 5: Verify proofs ───────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}[5]${RESET} Verify proofs against root authority"
echo ""

# Verify search (should pass)
echo -e "    ${BOLD}Worker search (\$2.00):${RESET}"
if $CLI verify --proof /tmp/mcp-demo/proof-search.json --root "$ROOT_DID" 2>/dev/null | sed 's/^/      /'; then
  echo ""
else
  echo ""
fi

# Verify analyze (should fail - scope)
echo -e "    ${BOLD}Worker analyze (\$1.00):${RESET}"
$CLI verify --proof /tmp/mcp-demo/proof-analyze.json --root "$ROOT_DID" 2>/dev/null | sed 's/^/      /' || true
echo ""

# Verify expensive search (should fail - cost)
echo -e "    ${BOLD}Worker search (\$25.00):${RESET}"
$CLI verify --proof /tmp/mcp-demo/proof-expensive.json --root "$ROOT_DID" 2>/dev/null | sed 's/^/      /' || true
echo ""

# Verify manager analyze (should pass)
echo -e "    ${BOLD}Manager analyze (\$5.00):${RESET}"
$CLI verify --proof /tmp/mcp-demo/proof-manager-analyze.json --root "$ROOT_DID" 2>/dev/null | sed 's/^/      /' || true
echo ""

# ── Step 6: DID Document ────────────────────────────────────

echo -e "${BOLD}${CYAN}[6]${RESET} Agent DID Document (W3C standard)"
echo ""
$CLI did --key worker 2>/dev/null | head -12 | sed 's/^/    /'
echo -e "    ${DIM}...${RESET}"

# ── Summary ─────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GOLD}============================================================${RESET}"
echo -e "${BOLD}${GOLD}  Summary${RESET}"
echo -e "${BOLD}${GOLD}============================================================${RESET}"
echo ""
echo -e "    ${GREEN}2 proofs verified${RESET}  (Worker search \$2, Manager analyze \$5)"
echo -e "    ${RED}2 proofs denied${RESET}   (Worker analyze - wrong scope, Worker search \$25 - over cap)"
echo -e ""
echo -e "    ${BOLD}3 agents${RESET}: Root -> Manager -> Worker"
echo -e "    ${BOLD}Caveats${RESET}: action_scope, max_cost, expires_at"
echo -e "    ${BOLD}Proofs${RESET}: self-contained, no external lookups"
echo -e "    ${BOLD}Crypto${RESET}: Ed25519 signatures, did:agent: DIDs"
echo ""
echo -e "    ${CYAN}github.com/kanoniv/agent-auth${RESET} (MIT)"
echo ""
