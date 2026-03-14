import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { base58 } from "@scure/base";
import { CryptoError } from "./error.js";

// ed25519 requires sha512 for internal operations
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

/** Convert bytes to lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert hex string to bytes. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Ed25519 multicodec prefix bytes. */
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** Encode an Ed25519 public key as multibase (z + base58btc(0xed01 + key)). */
export function encodeMultibaseEd25519(publicKeyBytes: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKeyBytes, 2);
  return `z${base58.encode(prefixed)}`;
}

/** Decode a multibase-encoded Ed25519 public key back to an AgentIdentity. */
export function identityFromMultibase(multibase: string): AgentIdentity {
  if (!multibase.startsWith("z")) {
    throw CryptoError.invalidSignatureEncoding(
      "multibase must start with 'z' (base58btc)",
    );
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(multibase.slice(1));
  } catch {
    throw CryptoError.invalidSignatureEncoding("invalid base58btc");
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== 0xed ||
    decoded[1] !== 0x01
  ) {
    throw CryptoError.invalidSignatureEncoding(
      "expected ed25519-pub multicodec prefix (0xed01) + 32 bytes",
    );
  }
  return identityFromBytes(decoded.slice(2));
}

/** Public identity derived from a keypair - safe to share and store. */
export interface AgentIdentity {
  /** Decentralized identifier: did:kanoniv:{hex(sha256(pubkey)[..16])} */
  did: string;
  /** Raw public key bytes (32 bytes, Ed25519) */
  publicKeyBytes: Uint8Array;
}

/** Compute the DID from public key bytes. */
export function computeDid(publicKeyBytes: Uint8Array): string {
  const hash = sha256(publicKeyBytes);
  const shortHash = bytesToHex(hash.slice(0, 16));
  return `did:kanoniv:${shortHash}`;
}

/** Create an AgentIdentity from public key bytes. */
export function identityFromBytes(bytes: Uint8Array): AgentIdentity {
  if (bytes.length !== 32) {
    throw CryptoError.invalidKeyLength(bytes.length);
  }
  return {
    did: computeDid(bytes),
    publicKeyBytes: new Uint8Array(bytes),
  };
}

/** An agent's Ed25519 keypair. */
export interface AgentKeyPair {
  /** 32-byte secret key */
  secretKey: Uint8Array;
  /** Derived public identity */
  identity: AgentIdentity;
}

/** Generate a new random Ed25519 keypair. */
export function generateKeyPair(): AgentKeyPair {
  const secretKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(secretKey);
  const identity: AgentIdentity = {
    did: computeDid(publicKey),
    publicKeyBytes: publicKey,
  };
  return { secretKey, identity };
}

/** Reconstruct a keypair from 32-byte secret key. */
export function keyPairFromBytes(secret: Uint8Array): AgentKeyPair {
  if (secret.length !== 32) {
    throw CryptoError.invalidKeyLength(secret.length);
  }
  const publicKey = ed.getPublicKey(secret);
  const identity: AgentIdentity = {
    did: computeDid(publicKey),
    publicKeyBytes: publicKey,
  };
  return { secretKey: new Uint8Array(secret), identity };
}

/** A service endpoint for a DID Document (W3C DID Core). */
export interface ServiceEndpoint {
  /** Fragment ID (e.g. "#messaging") or full URI. Fragments are auto-prefixed with the DID. */
  id: string;
  /** Service type (e.g. "AgentMessaging", "KanonivResolve") */
  serviceType: string;
  /** The endpoint URL */
  endpoint: string;
}

/** Generate a W3C DID Document for an identity (no service endpoints). */
export function didDocument(identity: AgentIdentity): Record<string, unknown> {
  return didDocumentWithServices(identity, []);
}

/** Generate a W3C DID Document with optional service endpoints. */
export function didDocumentWithServices(
  identity: AgentIdentity,
  services: ServiceEndpoint[],
): Record<string, unknown> {
  const pkMultibase = encodeMultibaseEd25519(identity.publicKeyBytes);
  const doc: Record<string, unknown> = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: identity.did,
    verificationMethod: [
      {
        id: `${identity.did}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: identity.did,
        publicKeyMultibase: pkMultibase,
      },
    ],
    authentication: [`${identity.did}#key-1`],
    assertionMethod: [`${identity.did}#key-1`],
  };

  if (services.length > 0) {
    doc.service = services.map((s) => ({
      id: s.id.startsWith("#") ? `${identity.did}${s.id}` : s.id,
      type: s.serviceType,
      serviceEndpoint: s.endpoint,
    }));
  }

  return doc;
}
