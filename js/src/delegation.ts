import type { AgentIdentity, AgentKeyPair } from "./identity.js";
import { identityFromBytes, bytesToHex } from "./identity.js";
import {
  type SignedMessage,
  signMessage,
  verifyMessage,
  contentHash,
} from "./signing.js";
import { CryptoError } from "./error.js";

/** Maximum delegation chain depth to prevent DoS. */
export const MAX_CHAIN_DEPTH = 32;

/** A constraint on delegated authority. */
export type Caveat =
  | { type: "action_scope"; value: string[] }
  | { type: "expires_at"; value: string }
  | { type: "max_cost"; value: number }
  | { type: "resource"; value: string }
  | { type: "context"; value: { key: string; value: string } }
  | { type: "custom"; value: { key: string; value: unknown } };

/** A cryptographic delegation of authority from one agent to another. */
export interface Delegation {
  issuer_did: string;
  subject_did: string;
  /** Issuer's public key bytes (hex) for self-verifying chains. */
  issuer_public_key: string;
  caveats: Caveat[];
  parent: Delegation | null;
  signed_envelope: SignedMessage;
}

/** An agent exercising delegated authority. */
export interface Invocation {
  invoker_did: string;
  action: string;
  args: Record<string, unknown>;
  delegation: Delegation;
  signed_envelope: SignedMessage;
}

/** Result of a successful verification. */
export interface VerificationResult {
  invoker_did: string;
  root_did: string;
  chain: string[];
  depth: number;
}

/** Create a root delegation (issuer is the root authority). */
export function createRootDelegation(
  issuerKeypair: AgentKeyPair,
  subjectDid: string,
  caveats: Caveat[],
): Delegation {
  const issuerDid = issuerKeypair.identity.did;
  const payload = {
    issuer_did: issuerDid,
    subject_did: subjectDid,
    caveats,
    parent_hash: null,
  };
  const signedEnvelope = signMessage(issuerKeypair, payload);

  return {
    issuer_did: issuerDid,
    subject_did: subjectDid,
    issuer_public_key: bytesToHex(issuerKeypair.identity.publicKeyBytes),
    caveats,
    parent: null,
    signed_envelope: signedEnvelope,
  };
}

/** Create a delegated delegation (with parent chain). Caveats accumulate. */
export function delegateAuthority(
  issuerKeypair: AgentKeyPair,
  subjectDid: string,
  additionalCaveats: Caveat[],
  parent: Delegation,
): Delegation {
  const issuerDid = issuerKeypair.identity.did;

  if (parent.subject_did !== issuerDid) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Delegation chain broken: issuer is not the subject of parent delegation",
    );
  }

  const allCaveats = [...parent.caveats, ...additionalCaveats];
  const parentHash = contentHash(parent.signed_envelope);
  const payload = {
    issuer_did: issuerDid,
    subject_did: subjectDid,
    caveats: allCaveats,
    parent_hash: parentHash,
  };
  const signedEnvelope = signMessage(issuerKeypair, payload);

  return {
    issuer_did: issuerDid,
    subject_did: subjectDid,
    issuer_public_key: bytesToHex(issuerKeypair.identity.publicKeyBytes),
    caveats: allCaveats,
    parent,
    signed_envelope: signedEnvelope,
  };
}

/** Create an invocation exercising delegated authority. */
export function createInvocation(
  invokerKeypair: AgentKeyPair,
  action: string,
  args: Record<string, unknown>,
  delegation: Delegation,
): Invocation {
  const invokerDid = invokerKeypair.identity.did;

  if (delegation.subject_did !== invokerDid) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Delegation chain broken: invoker is not the subject of the delegation",
    );
  }

  const payload = {
    invoker_did: invokerDid,
    action,
    args,
    delegation_hash: contentHash(delegation.signed_envelope),
  };
  const signedEnvelope = signMessage(invokerKeypair, payload);

  return {
    invoker_did: invokerDid,
    action,
    args,
    delegation,
    signed_envelope: signedEnvelope,
  };
}

/** Verify an invocation's entire authority chain. Every signature checked. */
export function verifyInvocation(
  invocation: Invocation,
  invokerIdentity: AgentIdentity,
  rootIdentity: AgentIdentity,
): VerificationResult {
  // 1. Verify invocation signature
  verifyMessage(invocation.signed_envelope, invokerIdentity);

  // 2. Verify invoker matches delegation subject
  if (invocation.invoker_did !== invocation.delegation.subject_did) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Delegation chain broken: invoker is not the subject of the delegation",
    );
  }

  // 3. Walk and verify the full delegation chain
  const chain: string[] = [invocation.invoker_did];
  const allCaveats: Caveat[] = [];
  let current: Delegation | null = invocation.delegation;
  let steps = 0;

  while (current !== null) {
    steps++;
    if (steps > MAX_CHAIN_DEPTH) {
      throw new CryptoError(
        "SIGNATURE_INVALID",
        `Chain depth exceeds maximum of ${MAX_CHAIN_DEPTH}`,
      );
    }

    chain.push(current.issuer_did);

    // Reconstruct identity from embedded public key and verify DID matches
    const issuerPkBytes = hexToUint8Array(current.issuer_public_key);
    const issuerIdentity = identityFromBytes(issuerPkBytes);

    if (issuerIdentity.did !== current.issuer_did) {
      throw new CryptoError(
        "SIGNATURE_INVALID",
        `Embedded public key produces DID '${issuerIdentity.did}' but delegation claims '${current.issuer_did}'`,
      );
    }

    // Verify this delegation's signature
    verifyMessage(current.signed_envelope, issuerIdentity);

    // Extract caveats from SIGNED PAYLOAD (not outer fields)
    const signedPayload = current.signed_envelope.payload as Record<
      string,
      unknown
    >;
    if (Array.isArray(signedPayload.caveats)) {
      allCaveats.push(...(signedPayload.caveats as Caveat[]));
    }

    if (current.issuer_did === rootIdentity.did) {
      // Verify root public key matches
      if (
        bytesToHex(issuerPkBytes) !== bytesToHex(rootIdentity.publicKeyBytes)
      ) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          "Root public key mismatch",
        );
      }
      current = null;
    } else if (current.parent) {
      if (current.parent.subject_did !== current.issuer_did) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Delegation chain broken: issuer '${current.issuer_did}' is not subject of parent`,
        );
      }
      current = current.parent;
    } else {
      throw new CryptoError(
        "SIGNATURE_INVALID",
        `Chain terminates at '${current.issuer_did}', expected root '${rootIdentity.did}'`,
      );
    }
  }

  // 4. Check caveats from signed payloads
  const now = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  for (const caveat of allCaveats) {
    checkCaveat(caveat, invocation.action, invocation.args, now);
  }

  return {
    invoker_did: invocation.invoker_did,
    root_did: rootIdentity.did,
    chain,
    depth: chain.length - 1,
  };
}

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function checkCaveat(
  caveat: Caveat,
  action: string,
  args: Record<string, unknown>,
  now: string,
): void {
  switch (caveat.type) {
    case "action_scope":
      if (!caveat.value.includes(action)) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: action '${action}' not in allowed scope`,
        );
      }
      break;
    case "expires_at":
      if (now > caveat.value) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: delegation expired at ${caveat.value}`,
        );
      }
      break;
    case "max_cost": {
      const cost = args.cost;
      if (typeof cost !== "number") {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          "Caveat violation: max_cost caveat requires 'cost' field in args",
        );
      }
      if (cost > caveat.value) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: cost ${cost} exceeds max ${caveat.value}`,
        );
      }
      break;
    }
    case "resource": {
      const resource = args.resource;
      if (typeof resource !== "string") {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          "Caveat violation: resource caveat requires 'resource' field in args",
        );
      }
      if (!matchesGlob(caveat.value, resource)) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: resource '${resource}' does not match '${caveat.value}'`,
        );
      }
      break;
    }
    case "context": {
      const actual = args[caveat.value.key];
      if (actual !== caveat.value.value) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: context '${caveat.value.key}' mismatch`,
        );
      }
      break;
    }
    case "custom": {
      const actual = args[caveat.value.key];
      if (JSON.stringify(actual) !== JSON.stringify(caveat.value.value)) {
        throw new CryptoError(
          "SIGNATURE_INVALID",
          `Caveat violation: custom caveat '${caveat.value.key}' not satisfied`,
        );
      }
      break;
    }
  }
}

function matchesGlob(pattern: string, value: string): boolean {
  if (pattern.endsWith("*")) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}
