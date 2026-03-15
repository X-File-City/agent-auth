/**
 * Example MCP client that creates delegation proofs for tool calls.
 *
 * This demonstrates the agent side: how to create a delegation chain
 * and attach proofs to MCP tool calls.
 *
 * Usage:
 *   npx tsx client.ts
 *
 * Prints the JSON-RPC requests you'd send to the MCP server.
 */

import {
  generateKeyPair,
  createRootDelegation,
  delegateAuthority,
  McpProof,
} from "@kanoniv/agent-auth";

// --- Setup: create identities ---
const root = generateKeyPair();
const manager = generateKeyPair();
const worker = generateKeyPair();

console.log("=== Identities ===");
console.log(`Root:    ${root.identity.did}`);
console.log(`Manager: ${manager.identity.did}`);
console.log(`Worker:  ${worker.identity.did}`);
console.log();

// --- Delegation chain ---
// Root grants manager: greet + add, max cost $10
const d1 = createRootDelegation(root, manager.identity.did, [
  { type: "action_scope", value: ["greet", "add"] },
  { type: "max_cost", value: 10.0 },
]);

// Manager narrows for worker: greet only, max cost $5
const d2 = delegateAuthority(manager, worker.identity.did, [
  { type: "action_scope", value: ["greet"] },
  { type: "max_cost", value: 5.0 },
], d1);

console.log("=== Delegation Chain ===");
console.log(`Root -> Manager: [greet, add], max $10`);
console.log(`Manager -> Worker: [greet], max $5`);
console.log();

// --- Worker makes a tool call ---
const proof = McpProof.create(worker, "greet", { name: "Alice", cost: 1.0 }, d2);
const args = McpProof.inject(proof, { name: "Alice", cost: 1.0 });

const request = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "greet",
    arguments: args,
  },
};

console.log("=== JSON-RPC Request (send to MCP server stdin) ===");
console.log(JSON.stringify(request));
console.log();

// --- What the server sees ---
console.log("=== Server verifies ===");
console.log(`  Agent DID: ${worker.identity.did}`);
console.log(`  Action: greet`);
console.log(`  Chain: Worker -> Manager -> Root (depth 2)`);
console.log(`  Caveats: action_scope=[greet,add] + action_scope=[greet] + max_cost(10) + max_cost(5)`);
console.log(`  Cost 1.0 <= 5.0: PASS`);
console.log(`  Action "greet" in [greet]: PASS`);
console.log();

// --- What happens if worker tries "add" (blocked) ---
try {
  McpProof.create(worker, "add", { a: 1, b: 2, cost: 1.0 }, d2);
  console.log("=== Worker tries 'add' ===");
  console.log("  Proof created, but server would reject (action_scope caveat)");
} catch {
  console.log("=== Worker tries 'add' ===");
  console.log("  Blocked at proof creation (not in delegate's scope)");
}

console.log();
console.log(`Root public key (hex): ${Buffer.from(root.identity.publicKeyBytes).toString("hex")}`);
console.log("Set KANONIV_ROOT_PUBLIC_KEY to this value on the server.");
