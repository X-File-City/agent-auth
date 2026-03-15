"""Type stubs for the native Rust extension."""

class AgentKeyPair:
    """An agent's Ed25519 keypair."""

    @staticmethod
    def generate() -> AgentKeyPair:
        """Generate a new random keypair."""
        ...

    @staticmethod
    def from_bytes(secret: bytes) -> AgentKeyPair:
        """Reconstruct from 32-byte secret key."""
        ...

    def secret_bytes(self) -> bytes:
        """Export the 32-byte secret key."""
        ...

    def identity(self) -> AgentIdentity:
        """Derive the public identity."""
        ...

    def sign(self, payload_json: str) -> SignedMessage:
        """Sign a JSON payload."""
        ...

class AgentIdentity:
    """Public identity derived from a keypair."""

    @property
    def did(self) -> str:
        """The DID string."""
        ...

    @property
    def public_key_bytes(self) -> bytes:
        """The raw 32-byte public key."""
        ...

    @property
    def created_at(self) -> str | None:
        """When this key was created (RFC 3339), or None if unknown."""
        ...

    @staticmethod
    def from_bytes(bytes: bytes) -> AgentIdentity:
        """Reconstruct from raw public key bytes."""
        ...

    def did_document(self) -> str:
        """Generate a W3C DID Document as JSON string."""
        ...

    def did_document_with_services(self, services: list[PyServiceEndpoint]) -> str:
        """Generate a W3C DID Document with service endpoints."""
        ...

class PyServiceEndpoint:
    """A service endpoint for DID Documents."""

    def __init__(self, id: str, service_type: str, endpoint: str) -> None: ...

    @property
    def id(self) -> str: ...

    @property
    def service_type(self) -> str: ...

    @property
    def endpoint(self) -> str: ...

class SignedMessage:
    """A cryptographically signed message envelope."""

    @property
    def payload(self) -> str:
        """The payload as JSON string."""
        ...

    @property
    def signer_did(self) -> str:
        """The signer's DID."""
        ...

    @property
    def nonce(self) -> str:
        """The nonce."""
        ...

    @property
    def timestamp(self) -> str:
        """The timestamp."""
        ...

    @property
    def signature(self) -> str:
        """Hex-encoded Ed25519 signature."""
        ...

    def verify(self, identity: AgentIdentity) -> None:
        """Verify against a known identity. Raises ValueError on failure."""
        ...

    def content_hash(self) -> str:
        """Compute the SHA-256 content hash."""
        ...

    def to_json(self) -> str:
        """Serialize to JSON string."""
        ...

    @staticmethod
    def from_json(json: str) -> SignedMessage:
        """Deserialize from JSON string."""
        ...

class ProvenanceEntry:
    """A signed provenance entry in the audit chain."""

    @staticmethod
    def create(
        keypair: AgentKeyPair,
        action: str,
        entity_ids: list[str],
        parent_ids: list[str],
        metadata_json: str,
    ) -> ProvenanceEntry:
        """Create and sign a new provenance entry."""
        ...

    @property
    def agent_did(self) -> str: ...

    @property
    def action(self) -> str: ...

    @property
    def entity_ids(self) -> list[str]: ...

    @property
    def parent_ids(self) -> list[str]: ...

    @property
    def metadata(self) -> str: ...

    @property
    def signed_envelope(self) -> SignedMessage: ...

    def verify(self, identity: AgentIdentity) -> None:
        """Verify against a known identity."""
        ...

    def content_hash(self) -> str:
        """Get the content hash (usable as parent_id)."""
        ...

class Delegation:
    """A cryptographic delegation of authority from one agent to another."""

    @staticmethod
    def create_root(
        issuer_keypair: AgentKeyPair,
        delegate_did: str,
        caveats_json: str,
    ) -> Delegation:
        """Create a root delegation (issuer is the root authority).

        caveats_json is a JSON array of caveat objects, e.g.:
        '[{"type": "action_scope", "value": ["resolve", "search"]}]'
        """
        ...

    @staticmethod
    def delegate(
        issuer_keypair: AgentKeyPair,
        delegate_did: str,
        additional_caveats_json: str,
        parent: Delegation,
    ) -> Delegation:
        """Create a delegated delegation (with parent chain). Caveats accumulate."""
        ...

    @property
    def issuer_did(self) -> str:
        """DID of the agent that granted authority."""
        ...

    @property
    def delegate_did(self) -> str:
        """DID of the agent that received authority."""
        ...

    @property
    def depth(self) -> int:
        """Chain depth (0 for root)."""
        ...

    def content_hash(self) -> str:
        """Content hash of this delegation's proof (for revocation)."""
        ...

class Invocation:
    """An agent exercising delegated authority."""

    @staticmethod
    def create(
        invoker_keypair: AgentKeyPair,
        action: str,
        args_json: str,
        delegation: Delegation,
    ) -> Invocation:
        """Create an invocation exercising delegated authority."""
        ...

    @property
    def invoker_did(self) -> str:
        """DID of the agent performing the action."""
        ...

    @property
    def action(self) -> str:
        """The action being performed."""
        ...

class McpProof:
    """Self-contained invocation proof for MCP transport.

    Contains everything an MCP server needs to verify the agent's identity
    and authority without any external key resolver.
    """

    @staticmethod
    def create(
        invoker_keypair: AgentKeyPair,
        action: str,
        args_json: str,
        delegation: Delegation,
    ) -> McpProof:
        """Create an MCP proof for a tool call.

        Args:
            invoker_keypair: The agent's keypair.
            action: The tool/action name (e.g. "resolve").
            args_json: JSON string of tool arguments.
            delegation: The delegation chain proving authority.
        """
        ...

    @property
    def invoker_public_key(self) -> str:
        """The invoker's Ed25519 public key as hex string (64 chars)."""
        ...

    @property
    def invoker_did(self) -> str:
        """The invoker's DID."""
        ...

    @property
    def action(self) -> str:
        """The action this proof authorizes."""
        ...

    def to_json(self) -> str:
        """Serialize to JSON string (for embedding in MCP tool arguments)."""
        ...

    @staticmethod
    def from_json(json: str) -> McpProof:
        """Deserialize from JSON string."""
        ...

def verify_invocation(
    invocation: Invocation,
    invoker_identity: AgentIdentity,
    root_identity: AgentIdentity,
) -> tuple[str, str, list[str], int]:
    """Verify an invocation's full authority chain.

    Returns (invoker_did, root_did, chain, depth).
    Raises ValueError on verification failure.
    """
    ...

def verify_mcp_call(
    proof: McpProof,
    root_identity: AgentIdentity,
) -> tuple[str, str, list[str], int]:
    """Verify an MCP proof against a root authority.

    Returns (invoker_did, root_did, chain, depth).
    Raises ValueError on verification failure.
    """
    ...

def extract_mcp_proof(args_json: str) -> tuple[McpProof | None, str]:
    """Extract an MCP proof from tool arguments JSON.

    Returns (proof_or_none, clean_args_json).
    The _proof field is always stripped from the returned args.
    """
    ...

def inject_mcp_proof(proof: McpProof, args_json: str) -> str:
    """Inject an MCP proof into tool arguments JSON.

    Returns the arguments JSON string with _proof field added.
    """
    ...
