"""
kanoniv-agent-auth integration for CrewAI.

Adds cryptographic delegation to CrewAI workflows. A human delegates
authority to a Crew manager, who sub-delegates to agents with caveats.
Every tool call is backed by a verifiable authority chain.

    pip install kanoniv-agent-auth crewai
"""

import json
from datetime import datetime, timezone, timedelta
from kanoniv_agent_auth import (
    AgentKeyPair, Delegation, Invocation, verify_invocation,
)


class DelegatedCrewManager:
    """Manages delegation chains for a CrewAI crew."""

    def __init__(self):
        self.keypair = AgentKeyPair.generate()
        self.crew_delegation = None
        self.agent_delegations = {}
        self.audit_log = []

    @property
    def did(self):
        return self.keypair.identity().did

    def delegate_to_crew(self, human_keypair, actions=None, max_cost=None, expires_in_hours=None):
        """Human delegates authority to this crew manager."""
        caveats = _build_caveats(actions, max_cost, expires_in_hours)
        self.crew_delegation = Delegation.create_root(
            human_keypair, self.did, json.dumps(caveats)
        )
        return self.crew_delegation

    def delegate_to_agent(self, agent_did, actions=None, max_cost=None):
        """Crew manager sub-delegates to an agent (narrower scope)."""
        if self.crew_delegation is None:
            raise ValueError("No delegation from human. Call delegate_to_crew first.")
        caveats = _build_caveats(actions, max_cost)
        delegation = Delegation.delegate(
            self.keypair, agent_did, json.dumps(caveats), self.crew_delegation
        )
        self.agent_delegations[agent_did] = delegation
        return delegation

    def execute_with_proof(self, agent_keypair, action, args, human_identity=None):
        """Agent executes an action with verified authority chain."""
        agent_did = agent_keypair.identity().did
        delegation = self.agent_delegations.get(agent_did)
        if delegation is None:
            raise ValueError(f"No delegation for agent {agent_did}")

        invocation = Invocation.create(agent_keypair, action, json.dumps(args), delegation)

        result = None
        if human_identity is not None:
            result = verify_invocation(invocation, agent_keypair.identity(), human_identity)

        self.audit_log.append({
            "agent_did": agent_did, "action": action, "args": args,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return invocation, result


def _build_caveats(actions=None, max_cost=None, expires_in_hours=None):
    caveats = []
    if actions:
        caveats.append({"type": "action_scope", "value": actions})
    if max_cost is not None:
        caveats.append({"type": "max_cost", "value": max_cost})
    if expires_in_hours is not None:
        expiry = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        caveats.append({"type": "expires_at", "value": expiry})
    return caveats


if __name__ == "__main__":
    print("=== CrewAI Delegation Demo ===\n")

    human = AgentKeyPair.generate()
    manager = DelegatedCrewManager()
    researcher = AgentKeyPair.generate()
    print(f"Human DID:  {human.identity().did}")
    print(f"Crew DID:   {manager.did}")
    print(f"Agent DID:  {researcher.identity().did}")

    # Human -> Crew -> Researcher
    manager.delegate_to_crew(human, actions=["search", "summarize", "write"], max_cost=10.0, expires_in_hours=2)
    print("\n[1] Human delegated to crew: search, summarize, write (max $10, 2hr)")

    manager.delegate_to_agent(researcher.identity().did, actions=["search"], max_cost=5.0)
    print("[2] Crew delegated to researcher: search only (max $5)")

    # Allowed action
    _, result = manager.execute_with_proof(
        researcher, "search", {"query": "AI safety", "cost": 0.50}, human.identity()
    )
    print(f"\n[3] Search verified. Chain: {' -> '.join(result[2])}")

    # Blocked: wrong action
    print("\n[4] Researcher tries to write...")
    try:
        manager.execute_with_proof(researcher, "write", {"content": "draft", "cost": 1.0}, human.identity())
    except ValueError as e:
        print(f"    Blocked: {e}")

    # Blocked: over budget
    print("\n[5] Researcher tries $8 search...")
    try:
        manager.execute_with_proof(researcher, "search", {"query": "expensive", "cost": 8.0}, human.identity())
    except ValueError as e:
        print(f"    Blocked: {e}")

    print(f"\nAudit log: {len(manager.audit_log)} entries. Done.")
