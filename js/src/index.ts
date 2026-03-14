export { CryptoError } from "./error.js";
export {
  type AgentIdentity,
  type AgentKeyPair,
  type ServiceEndpoint,
  generateKeyPair,
  keyPairFromBytes,
  computeDid,
  identityFromBytes,
  identityFromMultibase,
  encodeMultibaseEd25519,
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
  verifyProvenanceSignatureOnly,
  provenanceContentHash,
  ACTION_TYPES,
} from "./provenance.js";
export {
  type Caveat,
  type Delegation,
  type Invocation,
  type VerificationResult,
  createRootDelegation,
  delegateAuthority,
  createInvocation,
  verifyInvocation,
} from "./delegation.js";
