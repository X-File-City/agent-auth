"""
kanoniv-agent-auth integration for AutoGen.

Adds cryptographic delegation to AutoGen conversations. When Agent A
asks Agent B to act, the request carries a verifiable authority chain.
Sub-delegation and revocation are supported.

    pip install kanoniv-agent-auth autogen-agentchat
"""

import json
from datetime import datetime, timezone, timedelta
from kanoniv_agent_auth import (
    AgentKeyPair, Delegation, Invocation, verify_invocation,
)


class DelegatedAgent:
    """An AutoGen agent with cryptographic identity and delegation."""

    def __init__(self, name, actions=None, max_cost=None, expires_in_hours=None):
        self.name = name
        self.keypair = AgentKeyPair.generate()
        self.delegation = None
        self.authority_manager = None
        self.requested_actions = actions or []
        self.requested_max_cost = max_cost
        self.requested_expires_in_hours = expires_in_hours
        self.history = []

    @property
    def did(self):
        return self.keypair.identity().did

    def act(self, action, args=None):
        """Execute an action with verified authority chain."""
        if self.delegation is None:
            raise ValueError(f"Agent '{self.name}' not authorized.")
        args = args or {}

        # Pre-check revocation
        if self.authority_manager and self.authority_manager.is_revoked(self.delegation.content_hash()):
            raise ValueError(f"Agent '{self.name}' delegation has been revoked.")

        invocation = Invocation.create(self.keypair, action, json.dumps(args), self.delegation)
        result = verify_invocation(invocation, self.keypair.identity(), self.authority_manager.root_identity)

        self.history.append({
            "action": action, "args": args, "chain": result[2],
            "depth": result[3], "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return result

    def delegate_to(self, other_agent, actions=None, max_cost=None):
        """Sub-delegate to another agent."""
        if self.delegation is None:
            raise ValueError(f"Agent '{self.name}' has no delegation to sub-delegate.")
        caveats = []
        if actions:
            caveats.append({"type": "action_scope", "value": actions})
        if max_cost is not None:
            caveats.append({"type": "max_cost", "value": max_cost})

        delegation = Delegation.delegate(self.keypair, other_agent.did, json.dumps(caveats), self.delegation)
        other_agent.delegation = delegation
        other_agent.authority_manager = self.authority_manager
        return delegation


class AuthorityManager:
    """Root authority that delegates to agents and manages revocation."""

    def __init__(self, root_keypair):
        self.root_keypair = root_keypair
        self.root_identity = root_keypair.identity()
        self.agents = {}
        self._revoked = set()

    def authorize(self, agent):
        caveats = []
        if agent.requested_actions:
            caveats.append({"type": "action_scope", "value": agent.requested_actions})
        if agent.requested_max_cost is not None:
            caveats.append({"type": "max_cost", "value": agent.requested_max_cost})
        if agent.requested_expires_in_hours is not None:
            expiry = (datetime.now(timezone.utc) + timedelta(hours=agent.requested_expires_in_hours)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
            caveats.append({"type": "expires_at", "value": expiry})

        delegation = Delegation.create_root(self.root_keypair, agent.did, json.dumps(caveats))
        agent.delegation = delegation
        agent.authority_manager = self
        self.agents[agent.did] = agent
        return delegation

    def revoke_agent(self, agent):
        if agent.delegation:
            self._revoked.add(agent.delegation.content_hash())

    def is_revoked(self, hash):
        return hash in self._revoked

    def audit_report(self):
        entries = []
        for agent in self.agents.values():
            for e in agent.history:
                entries.append({"agent": agent.name, **e})
        entries.sort(key=lambda e: e["timestamp"])
        return entries


if __name__ == "__main__":
    print("=== AutoGen Delegation Demo ===\n")

    human = AgentKeyPair.generate()
    authority = AuthorityManager(human)
    print(f"Human DID: {human.identity().did}")

    researcher = DelegatedAgent("researcher", actions=["search", "summarize"], max_cost=5.0)
    writer = DelegatedAgent("writer", actions=["write", "edit"], max_cost=3.0)
    authority.authorize(researcher)
    authority.authorize(writer)
    print(f"Researcher: {researcher.did}")
    print(f"Writer:     {writer.did}")
    print("[1] Both authorized\n")

    result = researcher.act("search", {"query": "AI delegation", "cost": 0.50})
    print(f"[2] Researcher searched. Chain: {' -> '.join(result[2])}")

    result = writer.act("write", {"content": "draft", "cost": 1.0})
    print(f"[3] Writer wrote. Chain: {' -> '.join(result[2])}")

    print("\n[4] Researcher tries to write...")
    try:
        researcher.act("write", {"content": "sneaky", "cost": 0.10})
    except ValueError as e:
        print(f"    Blocked: {e}")

    helper = DelegatedAgent("helper")
    researcher.delegate_to(helper, actions=["search"], max_cost=2.0)
    result = helper.act("search", {"query": "specific paper", "cost": 0.25})
    print(f"\n[5] Helper (sub-delegated) searched. Depth: {result[3]}, chain: {' -> '.join(result[2])}")

    print("\n[6] Revoking writer...")
    authority.revoke_agent(writer)
    try:
        writer.act("write", {"content": "revoked", "cost": 0.50})
    except ValueError as e:
        print(f"    Blocked: {e}")

    report = authority.audit_report()
    print(f"\nAudit: {len(report)} entries. Done.")
