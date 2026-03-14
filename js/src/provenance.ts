import type { AgentIdentity, AgentKeyPair } from "./identity.js";
import {
  type SignedMessage,
  signMessage,
  verifyMessage,
  contentHash,
} from "./signing.js";
import { CryptoError } from "./error.js";

/** Standard action types. */
export const ACTION_TYPES = [
  "resolve",
  "merge",
  "split",
  "mutate",
  "ingest",
  "delegate",
  "revoke",
] as const;

/** Action type - either a standard type or a custom string. */
export type ActionType = (typeof ACTION_TYPES)[number] | { custom: string };

/** A signed provenance entry in the audit chain. */
export interface ProvenanceEntry {
  /** The DID of the agent that performed the action */
  agent_did: string;
  /** What action was performed */
  action: ActionType;
  /** Entity IDs affected by this action */
  entity_ids: string[];
  /** Parent provenance entry content hashes (for DAG chaining) */
  parent_ids: string[];
  /** Additional context */
  metadata: unknown;
  /** The signed envelope proving authenticity */
  signed_envelope: SignedMessage;
}

/** Create and sign a new provenance entry. */
export function createProvenanceEntry(
  keypair: AgentKeyPair,
  action: ActionType,
  entityIds: string[],
  parentIds: string[],
  metadata: unknown,
): ProvenanceEntry {
  const payload = {
    agent_did: keypair.identity.did,
    action,
    entity_ids: entityIds,
    parent_ids: parentIds,
    metadata,
  };

  const signedEnvelope = signMessage(keypair, payload);

  return {
    agent_did: keypair.identity.did,
    action,
    entity_ids: entityIds,
    parent_ids: parentIds,
    metadata,
    signed_envelope: signedEnvelope,
  };
}

/**
 * Verify a provenance entry: signature AND outer field integrity.
 *
 * Checks that the signature is valid and that outer fields match
 * what was actually signed in the envelope payload.
 */
export function verifyProvenanceEntry(
  entry: ProvenanceEntry,
  identity: AgentIdentity,
): void {
  // 1. Verify the cryptographic signature
  verifyMessage(entry.signed_envelope, identity);

  // 2. Verify outer fields match the signed payload
  const payload = entry.signed_envelope.payload as Record<string, unknown>;

  if (payload.agent_did !== entry.agent_did) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Integrity check failed: outer field 'agent_did' does not match signed payload",
    );
  }

  if (JSON.stringify(payload.action) !== JSON.stringify(entry.action)) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Integrity check failed: outer field 'action' does not match signed payload",
    );
  }

  if (JSON.stringify(payload.entity_ids) !== JSON.stringify(entry.entity_ids)) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Integrity check failed: outer field 'entity_ids' does not match signed payload",
    );
  }

  if (JSON.stringify(payload.parent_ids) !== JSON.stringify(entry.parent_ids)) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Integrity check failed: outer field 'parent_ids' does not match signed payload",
    );
  }

  if (JSON.stringify(payload.metadata) !== JSON.stringify(entry.metadata)) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "Integrity check failed: outer field 'metadata' does not match signed payload",
    );
  }
}

/**
 * Verify only the cryptographic signature, without checking field integrity.
 *
 * Use verifyProvenanceEntry() instead unless you have a specific reason to skip integrity checks.
 */
export function verifyProvenanceSignatureOnly(
  entry: ProvenanceEntry,
  identity: AgentIdentity,
): void {
  verifyMessage(entry.signed_envelope, identity);
}

/** Get the content hash of a provenance entry (usable as parent_id). */
export function provenanceContentHash(entry: ProvenanceEntry): string {
  return contentHash(entry.signed_envelope);
}
