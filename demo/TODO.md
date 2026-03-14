# Demo Playground - Continuation Plan

## Priority 1: Kanoniv Memory Integration

Wire shared memory into the orchestrator's planning loop:

```python
# Before planning, recall session context
context = orchestrator.recall_context(self.memory, "recent actions")
prompt = f"Previous actions:\n{context}\n\nNew request: {user_request}\n..."
```

This gives the orchestrator conversational awareness:
- "market price" -> recalls Trading asked for a price -> dispatches correctly
- "sell those shares" -> recalls the portfolio check -> knows which shares
- "check the payment status" -> recalls the $350 VENDOR-042 payment

## Priority 2: Multi-Agent Reputation (Trading Agent Alpha/Beta)

Multiple trading agents with memory-backed track records:

```
Trading Agent Alpha               Trading Agent Beta
did:agent:5da25c...                did:agent:f91bc4...
Trades: 847 | Success: 99.2%      Trades: 23 | Success: 78%
Avg return: +2.3%                  Avg return: -0.4%
Delegation: $5,000 cap             Delegation: $500 cap
```

Implementation:
1. Create TradingAgentAlpha and TradingAgentBeta with different system prompts/strategies
2. After each trade, memorize: {action, ticker, quantity, price, result, pnl}
3. Sidebar shows live stats pulled from memory: trade count, success rate, total PnL
4. Orchestrator chooses which agent to delegate based on track record
5. CFO can adjust delegation caps based on performance (Edit Cap button)

Every trade is signed + delegation-verified, so the track record is cryptographically authentic.
Alpha can't fake 847 successful trades because each one has a provenance hash.

## Priority 3: Conversation History

Store user messages and agent responses in memory:

```python
self.memory.memorize(
    agent_did=orchestrator.did,
    entry_type="conversation",
    title=f"User: {user_request}",
    content=json.dumps({"request": user_request, "plan": actions, "results": results}),
)
```

Enables:
- Follow-up questions ("what was the total cost?")
- Context-aware planning ("do it again but with MSFT")
- Session summaries ("what did we do today?")

## Priority 4: Deploy to playground.kanoniv.com

- Dockerize the demo (Flask + kanoniv-agent-auth)
- ANTHROPIC_API_KEY as env var
- Caddy route: playground.kanoniv.com -> demo container
- Rate limit: 20 requests/minute per IP (prevent API key abuse)

## Priority 5: Product Hunt Launch

- Screenshot: Finance mode with green VERIFIED + red DENIED + amber REVOKED
- Hero image: the delegation chain visualization
- Tagline: "Cryptographic delegation for AI agents. Control what your agents can do."
- Link to playground.kanoniv.com (interactive, not just a README)
