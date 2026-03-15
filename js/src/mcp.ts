/**
 * MCP (Model Context Protocol) authentication middleware.
 *
 * Adds cryptographic agent identity and delegation verification to any MCP server.
 * Agents attach a `_proof` field to tool arguments containing a self-contained
 * invocation proof. The MCP server extracts and verifies the proof before executing
 * the tool - no external key resolver needed.
 *
 * ## For MCP server authors (5 lines to add auth)
 *
 * ```typescript
 * import { verifyMcpCall, McpProof } from "@kanoniv/agent-auth";
 *
 * function handleToolCall(args: Record<string, unknown>) {
 *   const { proof, cleanArgs } = McpProof.extract(args);
 *   if (proof) {
 *     const result = verifyMcpCall(proof, rootIdentity);
 *     console.log(`Verified agent: ${result.invoker_did}`);
 *   }
 *   // use cleanArgs for your tool logic
 * }
 * ```
 *
 * ## For agents (attaching proofs to MCP calls)
 *
 * ```typescript
 * import { generateKeyPair, createRootDelegation, McpProof } from "@kanoniv/agent-auth";
 *
 * const root = generateKeyPair();
 * const agent = generateKeyPair();
 * const delegation = createRootDelegation(root, agent.identity.did, [
 *   { type: "action_scope", value: ["resolve"] },
 * ]);
 *
 * const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
 * const args = proof.inject({ source: "crm", external_id: "123" });
 * // args now contains _proof field - send to MCP server
 * ```
 */

import type { AgentIdentity, AgentKeyPair } from "./identity.js";
import { identityFromBytes, bytesToHex } from "./identity.js";
import {
  type Delegation,
  type Invocation,
  type VerificationResult,
  createInvocation,
  verifyInvocationWithRevocation,
} from "./delegation.js";
import { CryptoError } from "./error.js";

/**
 * A self-contained invocation proof for MCP transport.
 *
 * Contains everything an MCP server needs to verify the agent's identity
 * and authority without any external key resolver or database lookup.
 */
export interface McpProofData {
  invocation: Invocation;
  /** The invoker's Ed25519 public key (hex-encoded, 64 chars). */
  invoker_public_key: string;
}

/** MCP auth mode for server configuration. */
export type McpAuthMode = "required" | "optional" | "disabled";

/** Result of MCP auth verification for a single tool call. */
export interface McpAuthOutcome {
  /** The verified identity chain, if a proof was present and valid. */
  verified: VerificationResult | null;
  /** The tool arguments with `_proof` stripped out. */
  args: Record<string, unknown>;
}

export const McpProof = {
  /**
   * Create an MCP proof for a tool call.
   *
   * The agent signs an invocation proving they have authority (via the
   * delegation chain) to perform the given action with the given arguments.
   */
  create(
    invokerKeypair: AgentKeyPair,
    action: string,
    args: Record<string, unknown>,
    delegation: Delegation,
  ): McpProofData {
    const invocation = createInvocation(invokerKeypair, action, args, delegation);
    return {
      invocation,
      invoker_public_key: bytesToHex(invokerKeypair.identity.publicKeyBytes),
    };
  },

  /**
   * Extract an MCP proof from tool arguments.
   *
   * Looks for a `_proof` field in the arguments object. Returns the proof
   * (if present) and a copy of the arguments with `_proof` stripped out.
   */
  extract(
    args: Record<string, unknown>,
  ): { proof: McpProofData | null; cleanArgs: Record<string, unknown> } {
    const proofValue = args._proof;

    let proof: McpProofData | null = null;
    if (proofValue && typeof proofValue === "object") {
      const candidate = proofValue as Record<string, unknown>;
      if (candidate.invocation && candidate.invoker_public_key) {
        proof = proofValue as McpProofData;
      }
    }

    // Always strip _proof from args - it's a reserved protocol field
    // and should never be forwarded to tool handlers or upstream APIs.
    if ("_proof" in args) {
      const { _proof, ...cleanArgs } = args;
      return { proof, cleanArgs };
    }

    return { proof: null, cleanArgs: { ...args } };
  },

  /**
   * Inject the proof into tool arguments.
   *
   * Returns a new object with the proof added as a `_proof` field.
   */
  inject(
    proof: McpProofData,
    args: Record<string, unknown>,
  ): Record<string, unknown> {
    return { ...args, _proof: proof };
  },
};

/**
 * Verify an MCP proof against a root authority.
 *
 * This is the main entry point for MCP server authors. It:
 * 1. Reconstructs the invoker's identity from the embedded public key
 * 2. Verifies the public key matches the claimed invoker DID
 * 3. Verifies the invocation signature
 * 4. Walks the entire delegation chain back to the root
 * 5. Checks every caveat against the invocation action/args
 *
 * No external lookups needed - everything is in the proof.
 */
export function verifyMcpCall(
  proof: McpProofData,
  rootIdentity: AgentIdentity,
): VerificationResult {
  return verifyMcpCallWithRevocation(proof, rootIdentity, () => false);
}

/**
 * Verify an MCP proof with optional revocation checking.
 */
export function verifyMcpCallWithRevocation(
  proof: McpProofData,
  rootIdentity: AgentIdentity,
  isRevoked: (hash: string) => boolean,
): VerificationResult {
  // Reconstruct invoker identity from embedded public key
  const pkBytes = hexToUint8Array(proof.invoker_public_key);
  const invokerIdentity = identityFromBytes(pkBytes);

  // Verify the embedded key matches the claimed invoker DID
  if (invokerIdentity.did !== proof.invocation.invoker_did) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      `Embedded public key produces DID '${invokerIdentity.did}' but invocation claims '${proof.invocation.invoker_did}'`,
    );
  }

  return verifyInvocationWithRevocation(
    proof.invocation,
    invokerIdentity,
    rootIdentity,
    isRevoked,
  );
}

/**
 * All-in-one MCP tool call verification.
 *
 * Combines proof extraction, verification, and argument cleaning.
 * Respects the auth mode:
 * - `required`: returns error if no proof or invalid proof
 * - `optional`: verifies if present, passes through if absent
 * - `disabled`: always passes through, strips proof if present
 */
export function verifyMcpToolCall(
  toolName: string,
  args: Record<string, unknown>,
  rootIdentity: AgentIdentity,
  mode: McpAuthMode,
): McpAuthOutcome {
  return verifyMcpToolCallWithRevocation(
    toolName,
    args,
    rootIdentity,
    mode,
    () => false,
  );
}

/**
 * All-in-one MCP tool call verification with revocation support.
 */
export function verifyMcpToolCallWithRevocation(
  _toolName: string,
  args: Record<string, unknown>,
  rootIdentity: AgentIdentity,
  mode: McpAuthMode,
  isRevoked: (hash: string) => boolean,
): McpAuthOutcome {
  const { proof, cleanArgs } = McpProof.extract(args);

  switch (mode) {
    case "disabled":
      return { verified: null, args: cleanArgs };

    case "optional":
      if (proof) {
        const result = verifyMcpCallWithRevocation(proof, rootIdentity, isRevoked);
        return { verified: result, args: cleanArgs };
      }
      return { verified: null, args: cleanArgs };

    case "required":
      if (!proof) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          "MCP auth required but no _proof provided in tool arguments",
        );
      }
      const result = verifyMcpCallWithRevocation(proof, rootIdentity, isRevoked);
      return { verified: result, args: cleanArgs };
  }
}

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
