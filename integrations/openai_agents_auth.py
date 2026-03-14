"""
kanoniv-agent-auth integration for OpenAI Agents SDK.

Wraps tool calls and agent handoffs with cryptographic delegation.
Every tool call carries a verifiable proof of authority with caveats.

    pip install kanoniv-agent-auth openai-agents
"""

import json
import functools
from datetime import datetime, timezone, timedelta
from kanoniv_agent_auth import (
    AgentKeyPair, Delegation, Invocation, verify_invocation,
)


def delegated_tool(actions=None, require_cost=False, require_resource=False):
    """Decorator: wrap a tool with delegation metadata."""
    def decorator(func):
        func._delegation_actions = actions or [func.__name__]
        func._delegation_require_cost = require_cost
        func._delegation_require_resource = require_resource

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper._delegation_actions = func._delegation_actions
        wrapper._delegation_require_cost = func._delegation_require_cost
        wrapper._delegation_require_resource = func._delegation_require_resource
        return wrapper
    return decorator


class DelegatedRunner:
    """Runs tools with cryptographic delegation verification."""

    def __init__(self, root_keypair):
        self.root_keypair = root_keypair
        self.root_identity = root_keypair.identity()
        self.delegations = {}
        self._revoked = set()
        self.audit_log = []
        self.tools = {}

    def register_tool(self, tool_func):
        self.tools[tool_func.__name__] = tool_func
        return tool_func

    def authorize_agent(self, agent_keypair, actions=None, max_cost=None, expires_in_hours=None):
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

        delegation = Delegation.create_root(
            self.root_keypair, agent_keypair.identity().did, json.dumps(caveats)
        )
        self.delegations[agent_keypair.identity().did] = delegation
        return delegation

    def handoff(self, from_keypair, to_keypair, actions=None, max_cost=None):
        """Agent-to-agent handoff with sub-delegation."""
        from_did = from_keypair.identity().did
        parent = self.delegations.get(from_did)
        if parent is None:
            raise ValueError(f"Agent {from_did} has no delegation.")
        caveats = []
        if actions:
            caveats.append({"type": "action_scope", "value": actions})
        if max_cost is not None:
            caveats.append({"type": "max_cost", "value": max_cost})

        delegation = Delegation.delegate(from_keypair, to_keypair.identity().did, json.dumps(caveats), parent)
        self.delegations[to_keypair.identity().did] = delegation
        return delegation

    def run_tool(self, agent_keypair, tool_name, args=None):
        """Execute a tool with delegation verification."""
        tool = self.tools.get(tool_name)
        if tool is None:
            raise ValueError(f"Unknown tool: {tool_name}")

        agent_did = agent_keypair.identity().did
        delegation = self.delegations.get(agent_did)
        if delegation is None:
            raise ValueError(f"Agent {agent_did} has no delegation.")

        # Pre-check revocation
        if delegation.content_hash() in self._revoked:
            raise ValueError(f"Delegation revoked for agent {agent_did}")

        args = args or {}
        if tool._delegation_require_cost and "cost" not in args:
            raise ValueError(f"Tool '{tool_name}' requires 'cost'.")
        if tool._delegation_require_resource and "resource" not in args:
            raise ValueError(f"Tool '{tool_name}' requires 'resource'.")

        action = tool._delegation_actions[0]
        invocation = Invocation.create(agent_keypair, action, json.dumps(args), delegation)
        result = verify_invocation(invocation, agent_keypair.identity(), self.root_identity)

        self.audit_log.append({
            "agent_did": agent_did, "tool": tool_name, "action": action,
            "args": args, "depth": result[3],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return tool(**args, _delegation_proof=result)

    def revoke(self, agent_keypair):
        did = agent_keypair.identity().did
        delegation = self.delegations.get(did)
        if delegation:
            self._revoked.add(delegation.content_hash())


if __name__ == "__main__":
    print("=== OpenAI Agents SDK Delegation Demo ===\n")

    human = AgentKeyPair.generate()
    runner = DelegatedRunner(human)
    orchestrator = AgentKeyPair.generate()
    search_agent = AgentKeyPair.generate()
    print(f"Human:        {human.identity().did}")
    print(f"Orchestrator: {orchestrator.identity().did}")
    print(f"Search Agent: {search_agent.identity().did}")

    @delegated_tool(actions=["web_search"], require_cost=True)
    def web_search(query, cost, _delegation_proof=None, **kw):
        return f"Results for: {query}"

    @delegated_tool(actions=["code_exec"])
    def code_exec(code, _delegation_proof=None, **kw):
        return f"Executed: {code}"

    @delegated_tool(actions=["deploy"])
    def deploy(service, _delegation_proof=None, **kw):
        return f"Deployed: {service}"

    runner.register_tool(web_search)
    runner.register_tool(code_exec)
    runner.register_tool(deploy)

    runner.authorize_agent(orchestrator, actions=["web_search", "code_exec"], max_cost=10.0)
    print("\n[1] Orchestrator authorized: web_search, code_exec (max $10)")

    runner.handoff(orchestrator, search_agent, actions=["web_search"], max_cost=3.0)
    print("[2] Handoff to search agent: web_search only (max $3)")

    result = runner.run_tool(search_agent, "web_search", {"query": "AI agents", "cost": 0.5})
    print(f"\n[3] Search agent searched: {result}")

    print("\n[4] Search agent tries code_exec...")
    try:
        runner.run_tool(search_agent, "code_exec", {"code": "rm -rf /", "cost": 0})
    except ValueError as e:
        print(f"    Blocked: {e}")

    result = runner.run_tool(orchestrator, "code_exec", {"code": "print('hello')", "cost": 0})
    print(f"\n[5] Orchestrator ran code: {result}")

    print("\n[6] Orchestrator tries deploy...")
    try:
        runner.run_tool(orchestrator, "deploy", {"service": "production", "cost": 0})
    except ValueError as e:
        print(f"    Blocked: {e}")

    print("\n[7] Search agent tries $5 search (over $3 cap)...")
    try:
        runner.run_tool(search_agent, "web_search", {"query": "expensive", "cost": 5.0})
    except ValueError as e:
        print(f"    Blocked: {e}")

    print(f"\nAudit: {len(runner.audit_log)} verified calls. Done.")
