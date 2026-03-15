/**
 * Minimal MCP server with cryptographic agent auth.
 *
 * Every tool call is verified against a root authority before execution.
 * Agents must attach a delegation proof (_proof) to their tool arguments.
 *
 * Usage:
 *   npm install @kanoniv/agent-auth
 *   npx tsx server.ts
 *
 * Then send JSON-RPC over stdin:
 *   {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"greet","arguments":{"name":"Alice","_proof":{...}}}}
 */

import * as readline from "node:readline";
import {
  generateKeyPair,
  createRootDelegation,
  McpProof,
  verifyMcpToolCall,
  type AgentIdentity,
} from "@kanoniv/agent-auth";

// --- Setup: generate root authority (in production, load from config) ---
const root = generateKeyPair();
const rootIdentity = root.identity;
console.error(`Root DID: ${rootIdentity.did}`);
console.error(`Root public key: ${Buffer.from(rootIdentity.publicKeyBytes).toString("hex")}`);

// --- Tool definitions ---
const TOOLS = [
  {
    name: "greet",
    description: "Greet a person by name",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Name to greet" },
      },
      required: ["name"],
    },
  },
  {
    name: "add",
    description: "Add two numbers",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "number" },
        b: { type: "number" },
      },
      required: ["a", "b"],
    },
  },
];

// --- Tool handlers ---
function handleTool(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case "greet":
      return `Hello, ${args.name}!`;
    case "add":
      return `${Number(args.a) + Number(args.b)}`;
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// --- JSON-RPC transport over stdin/stdout ---
const rl = readline.createInterface({ input: process.stdin });

rl.on("line", (line) => {
  const request = JSON.parse(line);
  const id = request.id;

  if (request.method === "initialize") {
    respond(id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "example-auth-server", version: "0.1.0" },
    });
    return;
  }

  if (request.method === "tools/list") {
    respond(id, { tools: TOOLS });
    return;
  }

  if (request.method === "tools/call") {
    const toolName = request.params.name;
    const rawArgs = request.params.arguments || {};

    // --- Auth: verify delegation proof ---
    try {
      const outcome = verifyMcpToolCall(toolName, rawArgs, rootIdentity, "required");

      if (outcome.verified) {
        console.error(
          `Verified: ${outcome.verified.invoker_did} ` +
          `(chain: ${outcome.verified.chain.length} DIDs, depth: ${outcome.verified.depth})`
        );
      }

      const result = handleTool(toolName, outcome.args);
      respond(id, {
        content: [{ type: "text", text: result }],
      });
    } catch (err: any) {
      respond(id, {
        content: [{ type: "text", text: `Auth failed: ${err.message}` }],
        isError: true,
      });
    }
    return;
  }

  // Unknown method
  if (id != null) {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Unknown method: ${request.method}` },
      }) + "\n"
    );
  }
});

function respond(id: unknown, result: unknown) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
