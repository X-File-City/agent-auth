export { CryptoError } from "./error.js";
export {
  type AgentIdentity,
  type AgentKeyPair,
  type ServiceEndpoint,
  generateKeyPair,
  keyPairFromBytes,
  computeDid,
  identityFromBytes,
  didDocument,
  didDocumentWithServices,
  bytesToHex,
  hexToBytes,
} from "./identity.js";
export {
  type SignedMessage,
  signMessage,
  verifyMessage,
  contentHash,
} from "./signing.js";
export {
  type ActionType,
  type ProvenanceEntry,
  createProvenanceEntry,
  verifyProvenanceEntry,
  provenanceContentHash,
  ACTION_TYPES,
} from "./provenance.js";
