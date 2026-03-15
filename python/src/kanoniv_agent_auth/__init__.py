"""Cryptographic identity and delegation for AI agents."""

from kanoniv_agent_auth._native import (
    AgentKeyPair,
    AgentIdentity,
    SignedMessage,
    ProvenanceEntry,
    PyServiceEndpoint as ServiceEndpoint,
    Delegation,
    Invocation,
    verify_invocation,
    McpProof,
    verify_mcp_call,
    extract_mcp_proof,
    inject_mcp_proof,
)

__all__ = [
    "AgentKeyPair",
    "AgentIdentity",
    "SignedMessage",
    "ProvenanceEntry",
    "ServiceEndpoint",
    "Delegation",
    "Invocation",
    "verify_invocation",
    "McpProof",
    "verify_mcp_call",
    "extract_mcp_proof",
    "inject_mcp_proof",
]
