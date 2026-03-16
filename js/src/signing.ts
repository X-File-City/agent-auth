import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { v4 as uuidv4 } from "uuid";
import type { AgentIdentity, AgentKeyPair } from "./identity.js";
import { bytesToHex, hexToBytes } from "./identity.js";
import { CryptoError } from "./error.js";

/** A cryptographically signed message envelope. */
export interface SignedMessage {
  /** The message payload (arbitrary JSON) */
  payload: unknown;
  /** DID of the signer */
  signer_did: string;
  /** Unique nonce for replay protection */
  nonce: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Hex-encoded Ed25519 signature */
  signature: string;
}

/**
 * Produce the canonical byte representation for signing/verification.
 *
 * Canonical form: sorted-key JSON of {nonce, payload, signer_did, timestamp}.
 * Only the top-level envelope keys are sorted. The payload is serialized as-is.
 */
function canonicalBytes(
  payload: unknown,
  signerDid: string,
  nonce: string,
  timestamp: string,
): Uint8Array {
  // Build canonical JSON string with keys in alphabetical order.
  // We manually construct this to guarantee key ordering (not relying on
  // JS object key ordering which is implementation-dependent for integer keys).
  const payloadJson = JSON.stringify(payload);
  const canonical =
    `{"nonce":${JSON.stringify(nonce)}` +
    `,"payload":${payloadJson}` +
    `,"signer_did":${JSON.stringify(signerDid)}` +
    `,"timestamp":${JSON.stringify(timestamp)}}`;
  return new TextEncoder().encode(canonical);
}

/** Sign a payload with the given keypair. */
export function signMessage(
  keypair: AgentKeyPair,
  payload: unknown,
): SignedMessage {
  const nonce = uuidv4();
  const now = new Date();
  const timestamp = now.toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");

  const canonical = canonicalBytes(
    payload,
    keypair.identity.did,
    nonce,
    timestamp,
  );
  const signature = ed.sign(canonical, keypair.secretKey);
  const signatureHex = bytesToHex(signature);

  return {
    payload,
    signer_did: keypair.identity.did,
    nonce,
    timestamp,
    signature: signatureHex,
  };
}

/** Verify a signed message against a known public identity. */
export function verifyMessage(
  message: SignedMessage,
  identity: AgentIdentity,
): void {
  if (message.signer_did !== identity.did) {
    throw CryptoError.signatureInvalid();
  }

  const canonical = canonicalBytes(
    message.payload,
    message.signer_did,
    message.nonce,
    message.timestamp,
  );

  let sigBytes: Uint8Array;
  try {
    sigBytes = hexToBytes(message.signature);
  } catch {
    throw CryptoError.invalidSignatureEncoding("invalid hex");
  }

  if (sigBytes.length !== 64) {
    throw CryptoError.invalidSignatureEncoding("expected 64 bytes");
  }

  const valid = ed.verify(sigBytes, canonical, identity.publicKeyBytes);
  if (!valid) {
    throw CryptoError.signatureInvalid();
  }
}

/** Compute the SHA-256 content hash of a signed message.
 *
 * Uses canonical field ordering (alphabetical) to ensure cross-language
 * determinism: {nonce, payload, signature, signer_did, timestamp}.
 *
 * Throws if the input is not a valid SignedMessage (e.g. a Delegation
 * object passed by mistake). Without this guard every non-SignedMessage
 * hashes to the same constant because all fields are undefined.
 */
export function contentHash(message: SignedMessage): string {
  // Runtime guard: TypeScript interfaces are erased at runtime, so callers
  // can accidentally pass a Delegation (which has none of the SignedMessage
  // fields). When every field is undefined the hash is constant - a silent,
  // dangerous bug. Fail fast instead.
  if (
    typeof message.nonce !== "string" ||
    typeof message.signature !== "string" ||
    typeof message.signer_did !== "string" ||
    typeof message.timestamp !== "string" ||
    message.payload === undefined
  ) {
    throw new CryptoError(
      "SIGNATURE_INVALID",
      "contentHash requires a SignedMessage with nonce, payload, signature, signer_did, and timestamp fields",
    );
  }

  // Rust's serde_json (without preserve_order) uses BTreeMap for ALL objects,
  // sorting keys alphabetically at every nesting level. We must match that.
  const serialized =
    `{"nonce":${JSON.stringify(message.nonce)}` +
    `,"payload":${sortedStringify(message.payload)}` +
    `,"signature":${JSON.stringify(message.signature)}` +
    `,"signer_did":${JSON.stringify(message.signer_did)}` +
    `,"timestamp":${JSON.stringify(message.timestamp)}}`;
  const hash = sha256(new TextEncoder().encode(serialized));
  return bytesToHex(hash);
}

/**
 * Recursively serialize a value with sorted object keys (matching Rust's BTreeMap).
 *
 * Rust's serde_json serializes whole floats with a trailing `.0` (e.g. `500.0`),
 * while JS's JSON.stringify drops it (e.g. `500`). We match Rust's behavior
 * so content hashes are identical across languages.
 */
function sortedStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return String(value);
  if (typeof value === "number") {
    // Rust's serde_json serializes f64 whole numbers with .0 suffix
    if (Number.isFinite(value) && Number.isInteger(value)) return value + ".0";
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(sortedStringify).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const entries = keys.map(
      (k) => JSON.stringify(k) + ":" + sortedStringify((value as Record<string, unknown>)[k]),
    );
    return "{" + entries.join(",") + "}";
  }
  return JSON.stringify(value);
}
