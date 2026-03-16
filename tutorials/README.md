# Tutorials

## Multi-Agent Handoff with Scoped Authority

[`langgraph_multi_agent_handoff.py`](langgraph_multi_agent_handoff.py)

LangGraph agents can call tools. But tools cannot verify who the agent is, whether it is authorized, or what budget it has.

This tutorial adds cryptographic delegation to a LangGraph `StateGraph`. Each specialist node is gated by a single decorator:

```python
@requires_delegation(actions=["draft"], require_cost=True)
def draft_node(state):
    ...
```

### Delegation chain

```
Human
  |
  +-- Coordinator (max $10)
        |
        +-- Researcher (search, summarize | $5)
        +-- Writer (draft, edit | $3)
        +-- Reviewer (review | $1)
```

### What it demonstrates

- **Identity** - each agent has an Ed25519 keypair and `did:agent:` DID
- **Delegation** - authority flows Human -> Coordinator -> Specialists, narrowing at each step
- **Budget constraints** - each agent has a max cost caveat enforced cryptographically
- **Scope enforcement** - agents are blocked when acting outside their delegated actions
- **Revocation** - Writer's delegation revoked mid-pipeline, next call fails immediately, other agents unaffected
- **Audit trail** - every verified action logged with agent DID and chain depth

### Example output

```
--- Audit Trail (5 verified actions) ---

      search  did:..5ed8407ae4cc  depth=2
   summarize  did:..5ed8407ae4cc  depth=2
       draft  did:..b70da4fe5818  depth=2
        edit  did:..b70da4fe5818  depth=2
      review  did:..5ab4822a4cd9  depth=2

--- Authority Boundary Tests ---

  Researcher tries to draft:  BLOCKED (action not in scope)
  Writer tries to search:     BLOCKED (action not in scope)
  Reviewer tries to edit:     BLOCKED (action not in scope)
  Writer tries $5 draft:      BLOCKED (exceeds $3 budget)

--- Mid-Pipeline Revocation ---

  Writer drafts (before revocation): OK
  Writer delegation revoked
  Writer drafts (after revocation):  BLOCKED
  Researcher searches (unaffected):  OK
```

### Run

```bash
pip install kanoniv-agent-auth langgraph
python tutorials/langgraph_multi_agent_handoff.py
```
