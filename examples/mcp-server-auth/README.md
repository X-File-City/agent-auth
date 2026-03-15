# MCP Server Auth Example

A minimal MCP server with cryptographic agent identity and delegation.

## What this demonstrates

1. **Server** verifies every tool call against a root authority
2. **Client** (agent) creates delegation proofs and attaches them to tool calls
3. **Delegation chain**: Root -> Manager -> Worker, with caveats narrowing at each step

## Run

```bash
npm install @kanoniv/agent-auth

# See what the client sends
npx tsx client.ts

# Run the server (reads JSON-RPC from stdin)
npx tsx server.ts
```

## How it works

The client creates a delegation chain:
```
Root -> Manager: [greet, add], max cost $10
Manager -> Worker: [greet], max cost $5
```

The worker calls the `greet` tool with a `_proof` field in the arguments. The server extracts and verifies the proof before executing the tool.

If the worker tries to call `add` (not in its scope) or exceed the cost limit, the server rejects the call.

## Files

- `server.ts` - MCP server with auth (40 lines of actual logic)
- `client.ts` - Agent creating delegation proofs
