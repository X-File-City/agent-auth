"""
kanoniv-agent-auth integration for LangGraph.

Adds cryptographic delegation to LangGraph nodes via a
@requires_delegation decorator. Before a node executes, the
delegation chain is verified against the root authority.

    pip install kanoniv-agent-auth langgraph
"""

import json
import functools
from kanoniv_agent_auth import (
    AgentKeyPair, Delegation, Invocation, verify_invocation,
)


class DelegationContext:
    """Holds delegation state for a LangGraph execution."""

    def __init__(self, agent_keypair, delegation, root_identity):
        self.agent_keypair = agent_keypair
        self.delegation = delegation
        self.root_identity = root_identity
        self.invocations = []


def requires_delegation(actions=None, require_cost=False, require_resource=False):
    """Decorator: gate a LangGraph node behind delegation verification."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(state):
            ctx = state.get("delegation_context")
            if ctx is None:
                return {**state, "error": "No delegation context."}

            action = state.get("action", func.__name__)
            args = state.get("args", {})

            if require_cost and "cost" not in args:
                return {**state, "error": f"Node '{action}' requires 'cost' in args."}
            if require_resource and "resource" not in args:
                return {**state, "error": f"Node '{action}' requires 'resource' in args."}

            try:
                invocation = Invocation.create(ctx.agent_keypair, action, json.dumps(args), ctx.delegation)
                result = verify_invocation(invocation, ctx.agent_keypair.identity(), ctx.root_identity)
                ctx.invocations.append({"action": action, "chain": result[2], "depth": result[3]})
            except ValueError as e:
                return {**state, "error": f"Delegation denied: {e}"}

            return func(state)

        return wrapper
    return decorator


if __name__ == "__main__":
    print("=== LangGraph Delegation Demo ===\n")

    human = AgentKeyPair.generate()
    orchestrator = AgentKeyPair.generate()
    print(f"Human DID:        {human.identity().did}")
    print(f"Orchestrator DID: {orchestrator.identity().did}")

    root_delegation = Delegation.create_root(
        human, orchestrator.identity().did,
        json.dumps([
            {"type": "action_scope", "value": ["search", "analyze", "report"]},
            {"type": "max_cost", "value": 10.0},
        ]),
    )
    print("[1] Human delegated: search, analyze, report (max $10)\n")

    ctx = DelegationContext(orchestrator, root_delegation, human.identity())

    @requires_delegation(actions=["search"], require_cost=True)
    def search_node(state):
        print(f"    search_node: queried '{state['args']['query']}'")
        return {**state, "results": ["paper1", "paper2"]}

    @requires_delegation(actions=["analyze"])
    def analyze_node(state):
        print(f"    analyze_node: analyzed {len(state.get('results', []))} results")
        return {**state, "analysis": "AI safety improving"}

    @requires_delegation(actions=["deploy"])
    def deploy_node(state):
        print("    deploy_node: THIS SHOULD NOT RUN")
        return state

    state = {"delegation_context": ctx, "args": {"query": "AI safety", "cost": 0.5}}

    print("[2] search_node...")
    state["action"] = "search"
    state = search_node(state)
    print(f"    {'BLOCKED: ' + state['error'] if 'error' in state else 'OK'}")

    print("\n[3] analyze_node...")
    state["action"] = "analyze"
    state["args"] = {"cost": 0}
    if "error" in state:
        del state["error"]
    state = analyze_node(state)
    print(f"    {'BLOCKED: ' + state['error'] if 'error' in state else 'OK - ' + state['analysis']}")

    print("\n[4] deploy_node (not authorized)...")
    state["action"] = "deploy"
    state["args"] = {"cost": 0}
    if "error" in state:
        del state["error"]
    state = deploy_node(state)
    print(f"    {'BLOCKED: ' + state['error'] if 'error' in state else 'OK'}")

    print(f"\nAudit: {len(ctx.invocations)} verified invocations. Done.")
