"""Tests for MCP auth module - Python bindings."""

import json
import pytest
from kanoniv_agent_auth import (
    AgentKeyPair, Delegation,
    McpProof, verify_mcp_call, extract_mcp_proof, inject_mcp_proof,
)


class TestMcpProofCreate:
    def test_create_and_verify(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()

        d = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "action_scope", "value": ["resolve"]}]',
        )
        proof = McpProof.create(agent, "resolve", '{"source": "crm"}', d)

        invoker_did, root_did, chain, depth = verify_mcp_call(proof, root.identity())
        assert invoker_did == agent.identity().did
        assert root_did == root.identity().did
        assert depth == 1

    def test_invoker_public_key_is_hex(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)

        pk = proof.invoker_public_key
        assert len(pk) == 64
        assert all(c in "0123456789abcdef" for c in pk)

    def test_properties(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)

        assert proof.invoker_did == agent.identity().did
        assert proof.action == "resolve"

    def test_create_fails_wrong_delegate(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        wrong = AgentKeyPair.generate()

        d = Delegation.create_root(root, agent.identity().did, "[]")
        with pytest.raises(ValueError):
            McpProof.create(wrong, "resolve", "{}", d)

    def test_repr(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)
        assert "McpProof" in repr(proof)
        assert "resolve" in repr(proof)


class TestMcpProofSerialization:
    def test_json_roundtrip(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", '{"source": "crm"}', d)

        json_str = proof.to_json()
        restored = McpProof.from_json(json_str)

        invoker_did, root_did, _, _ = verify_mcp_call(restored, root.identity())
        assert invoker_did == agent.identity().did
        assert root_did == root.identity().did

    def test_json_format_cross_language(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)

        parsed = json.loads(proof.to_json())
        # invoker_public_key must be a hex string, not an array
        pk = parsed["invoker_public_key"]
        assert isinstance(pk, str), f"expected string, got {type(pk)}"
        assert len(pk) == 64

    def test_from_json_invalid(self):
        with pytest.raises(ValueError):
            McpProof.from_json("not-valid-json")

        with pytest.raises(ValueError):
            McpProof.from_json('{"wrong": "shape"}')


class TestMcpVerification:
    def test_wrong_root_rejected(self):
        root = AgentKeyPair.generate()
        fake = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()

        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)

        with pytest.raises(ValueError):
            verify_mcp_call(proof, fake.identity())

    def test_action_scope_enforced(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()

        d = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "action_scope", "value": ["resolve"]}]',
        )
        # Allowed
        proof_ok = McpProof.create(agent, "resolve", "{}", d)
        verify_mcp_call(proof_ok, root.identity())

        # Blocked
        d2 = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "action_scope", "value": ["resolve"]}]',
        )
        proof_bad = McpProof.create(agent, "merge", "{}", d2)
        with pytest.raises(ValueError, match="action"):
            verify_mcp_call(proof_bad, root.identity())

    def test_max_cost_enforced(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()

        d = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "max_cost", "value": 5.0}]',
        )
        proof_ok = McpProof.create(agent, "resolve", '{"cost": 3.0}', d)
        verify_mcp_call(proof_ok, root.identity())

        d2 = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "max_cost", "value": 5.0}]',
        )
        proof_bad = McpProof.create(agent, "resolve", '{"cost": 10.0}', d2)
        with pytest.raises(ValueError, match="cost"):
            verify_mcp_call(proof_bad, root.identity())

    def test_expires_at_enforced(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()

        # Expired
        d = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "expires_at", "value": "2020-01-01T00:00:00.000Z"}]',
        )
        proof = McpProof.create(agent, "resolve", "{}", d)
        with pytest.raises(ValueError, match="expired"):
            verify_mcp_call(proof, root.identity())

        # Future - passes
        d2 = Delegation.create_root(
            root, agent.identity().did,
            '[{"type": "expires_at", "value": "2099-12-31T23:59:59.999Z"}]',
        )
        proof2 = McpProof.create(agent, "resolve", "{}", d2)
        verify_mcp_call(proof2, root.identity())

    def test_chained_delegation(self):
        root = AgentKeyPair.generate()
        manager = AgentKeyPair.generate()
        worker = AgentKeyPair.generate()

        d1 = Delegation.create_root(
            root, manager.identity().did,
            '[{"type": "action_scope", "value": ["resolve", "search"]}]',
        )
        d2 = Delegation.delegate(
            manager, worker.identity().did,
            '[{"type": "action_scope", "value": ["resolve"]}]',
            d1,
        )

        proof = McpProof.create(worker, "resolve", "{}", d2)
        invoker_did, root_did, chain, depth = verify_mcp_call(proof, root.identity())
        assert invoker_did == worker.identity().did
        assert root_did == root.identity().did
        assert depth == 2


class TestExtractInject:
    def test_inject_and_extract(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", '{"source": "crm"}', d)

        # Inject
        injected = inject_mcp_proof(proof, '{"source": "crm", "id": "123"}')
        parsed = json.loads(injected)
        assert "_proof" in parsed
        assert parsed["source"] == "crm"

        # Extract
        extracted_proof, clean_json = extract_mcp_proof(injected)
        assert extracted_proof is not None
        clean = json.loads(clean_json)
        assert "_proof" not in clean
        assert clean["source"] == "crm"
        assert clean["id"] == "123"

        # Verify extracted
        verify_mcp_call(extracted_proof, root.identity())

    def test_extract_no_proof(self):
        proof, clean_json = extract_mcp_proof('{"source": "crm"}')
        assert proof is None
        clean = json.loads(clean_json)
        assert clean["source"] == "crm"

    def test_extract_invalid_proof_still_strips(self):
        proof, clean_json = extract_mcp_proof('{"source": "crm", "_proof": "garbage"}')
        assert proof is None
        clean = json.loads(clean_json)
        assert "_proof" not in clean
        assert clean["source"] == "crm"

    def test_extract_null_proof_strips(self):
        proof, clean_json = extract_mcp_proof('{"source": "crm", "_proof": null}')
        assert proof is None
        clean = json.loads(clean_json)
        assert "_proof" not in clean

    def test_inject_invalid_json_fails(self):
        root = AgentKeyPair.generate()
        agent = AgentKeyPair.generate()
        d = Delegation.create_root(root, agent.identity().did, "[]")
        proof = McpProof.create(agent, "resolve", "{}", d)

        with pytest.raises(ValueError):
            inject_mcp_proof(proof, "not-json")
