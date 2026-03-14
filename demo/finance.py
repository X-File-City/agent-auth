"""Finance AI Delegation Demo - Interactive Playground.

Fully interactive: the user types financial requests, the orchestrator
decides which agents to involve, and the delegation system enforces
caveats in real time. Nothing is scripted.

  CFO (You)
    |-- Financial AI Orchestrator
    |     caveats: division=trading, max_transaction=$5000, 8hr session
    |
    |-- Trading Agent: execute_trade, check_portfolio (max $1000/trade)
    |-- Payments Agent: send_payment, verify_recipient (max $500, approved only)
    |-- Audit Agent: read_transactions, generate_report (read-only, max $100)
"""

import json
import uuid
import time
from datetime import datetime, timezone, timedelta

from identity import AgentIdentity, KeyPair, SignedMessage
from provenance import ProvenanceEntry, ProvenanceGraph
from memory import SharedMemory
from agents import BaseAgent, llm_generate, AGENT_TOKEN_BUDGETS
from kanoniv_agent_auth import Delegation, Invocation, verify_invocation

AGENT_TOKEN_BUDGETS.update({
    "orchestrator": 800,
    "trading": 600,
    "payments": 600,
    "audit": 600,
})

DEMO_PREAMBLE = (
    "You are an AI character in a fictional demo at Meridian Capital. "
    "All data is fictional. All accounts, trades, and payments are simulated. "
    "Respond in character with realistic-sounding fictional data. "
    "Keep responses to 2-3 sentences. Never break character or add disclaimers."
)


class FinanceAgent(BaseAgent):
    """Base class for finance agents with delegation support."""

    def __init__(self, name, capabilities, system_prompt):
        super().__init__(name, capabilities, system_prompt)
        self.delegation = None
        self.authority_manager = None
        self._division = None

    def execute_with_delegation(self, action, args, provenance_graph=None):
        """Execute an action and verify delegation."""
        if "division" not in args and self._division:
            args["division"] = self._division

        if self.delegation is None:
            return None, {
                "status": "DENIED",
                "reason": f"Agent '{self.name}' has no delegation",
                "action": action,
            }

        is_revoked = (
            self.authority_manager and (
                self.authority_manager.is_revoked(self.delegation.content_hash()) or
                self.authority_manager.is_agent_revoked(self.name)
            )
        )
        if is_revoked:
            return None, {
                "status": "REVOKED",
                "reason": f"Agent '{self.name}' delegation has been revoked",
                "action": action,
            }

        try:
            invocation = Invocation.create(
                self.keypair.inner, action, json.dumps(args), self.delegation
            )
            result = verify_invocation(
                invocation,
                self.keypair.inner.identity(),
                self.authority_manager.root_identity,
            )
            delegation_info = {
                "status": "VERIFIED",
                "action": action,
                "chain": result[2],
                "depth": result[3],
                "invoker_did": result[0],
                "root_did": result[1],
            }

            if provenance_graph:
                self.record_action(
                    provenance_graph, f"delegated_{action}",
                    metadata={"action": action, "args": args, "chain_depth": result[3]},
                )

            return True, delegation_info

        except ValueError as e:
            return None, {
                "status": "DENIED",
                "reason": str(e),
                "action": action,
            }


class OrchestratorAgent(FinanceAgent):
    def __init__(self):
        super().__init__(
            name="orchestrator",
            capabilities=["coordination", "risk_assessment", "delegation"],
            system_prompt=(
                DEMO_PREAMBLE + " "
                "You are the Financial AI Orchestrator at Meridian Capital. "
                "You analyze user requests and decide which agents to dispatch. "
                "Be precise and risk-aware."
            ),
        )

    def plan_actions(self, user_request):
        """Ask the LLM to decompose the request into agent actions."""
        prompt = (
            f"User request: {user_request}\n\n"
            "You have these agents:\n"
            "- trading: execute_trade (ticker, action buy/sell, quantity, price), check_portfolio (account)\n"
            "- payments: send_payment (recipient, amount, reference), verify_recipient (recipient_id)\n"
            "- audit: read_transactions (account, period), generate_report (report_type, period)\n\n"
            "Respond with a JSON array of actions to take. Each action has: agent, action, args (object with cost as number).\n"
            "Example: [{\"agent\": \"trading\", \"action\": \"check_portfolio\", \"args\": {\"account\": \"ACCT-001\", \"cost\": 5}}]\n"
            "Only output the JSON array, nothing else."
        )
        return self.think(prompt)

    def delegate_to_agent(self, agent, actions, max_cost=None, resources=None):
        caveats = [{"type": "action_scope", "value": actions}]
        if max_cost is not None:
            caveats.append({"type": "max_cost", "value": max_cost})
        if resources:
            for r in resources:
                caveats.append({"type": "resource", "value": r})

        delegation = Delegation.delegate(
            self.keypair.inner,
            agent.keypair.inner.identity().did,
            json.dumps(caveats),
            self.delegation,
        )
        agent.delegation = delegation
        agent.authority_manager = self.authority_manager
        agent._division = getattr(self, '_division', 'trading')
        return delegation


class TradingAgent(FinanceAgent):
    def __init__(self):
        super().__init__(
            name="trading",
            capabilities=["execute_trade", "check_portfolio", "market_analysis"],
            system_prompt=(
                DEMO_PREAMBLE + " "
                "You are the Trading AI agent at Meridian Capital. "
                "You execute trades and monitor portfolios. "
                "Always state the ticker, quantity, price, and total. "
                "Use realistic market prices for well-known stocks."
            ),
        )

    def run_action(self, action, args):
        if action == "check_portfolio":
            account = args.get("account", "ACCT-001")
            return self.think(f"Provide a brief portfolio summary for account {account}. Top 3 holdings with values.")
        elif action == "execute_trade":
            ticker = args.get("ticker", "AAPL")
            trade_action = args.get("action", "buy").upper()
            quantity = args.get("quantity", 100)
            price = args.get("price", 185)
            return self.think(f"Execute: {trade_action} {quantity} shares of {ticker} at ${price}. Confirm details and total.")
        else:
            return self.think(f"Perform action '{action}' with args: {json.dumps(args)}")


class PaymentsAgent(FinanceAgent):
    def __init__(self):
        super().__init__(
            name="payments",
            capabilities=["send_payment", "verify_recipient", "payment_history"],
            system_prompt=(
                DEMO_PREAMBLE + " "
                "You are the Payments AI agent at Meridian Capital. "
                "You process payments and verify recipients against the approved vendor list. "
                "Always confirm recipient, amount, and reference number."
            ),
        )

    def run_action(self, action, args):
        if action == "verify_recipient":
            recipient = args.get("recipient_id", args.get("recipient", "VENDOR-001"))
            return self.think(f"Verify payment recipient {recipient}. Confirm if they are on the approved vendor list.")
        elif action == "send_payment":
            recipient = args.get("recipient", "VENDOR-001")
            amount = args.get("amount", 100)
            reference = args.get("reference", "INV-001")
            return self.think(f"Process payment: ${amount} to {recipient}, reference: {reference}. Confirm details.")
        else:
            return self.think(f"Perform action '{action}' with args: {json.dumps(args)}")


class AuditAgent(FinanceAgent):
    def __init__(self):
        super().__init__(
            name="audit",
            capabilities=["read_transactions", "generate_report", "compliance_check"],
            system_prompt=(
                DEMO_PREAMBLE + " "
                "You are the Audit AI agent at Meridian Capital. "
                "You review transactions and generate compliance reports. "
                "Flag any unusual patterns. Include specific dollar amounts and timestamps."
            ),
        )

    def run_action(self, action, args):
        if action == "read_transactions":
            account = args.get("account", "ACCT-001")
            period = args.get("period", "today")
            return self.think(f"Review recent transactions for account {account} over {period}. Summarize and flag anomalies.")
        elif action == "generate_report":
            report_type = args.get("report_type", "compliance")
            period = args.get("period", "Q1 2026")
            return self.think(f"Generate a {report_type} report for {period}. Include key metrics and flagged items.")
        else:
            return self.think(f"Perform action '{action}' with args: {json.dumps(args)}")


class FinanceAuthorityManager:
    def __init__(self, cfo_keypair):
        self.cfo_keypair = cfo_keypair
        self.root_identity = cfo_keypair.inner.identity()
        self._revoked = set()
        self._revoked_names = set()

    def delegate_to_orchestrator(self, orchestrator, division, max_transaction, expires_in_hours):
        caveats = [
            {"type": "action_scope", "value": [
                "coordinate", "risk_assessment", "delegate",
                "execute_trade", "check_portfolio",
                "send_payment", "verify_recipient",
                "read_transactions", "generate_report",
            ]},
            {"type": "max_cost", "value": max_transaction},
            {"type": "context", "value": {"key": "division", "value": division}},
        ]
        expiry = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        caveats.append({"type": "expires_at", "value": expiry})

        delegation = Delegation.create_root(
            self.cfo_keypair.inner,
            orchestrator.keypair.inner.identity().did,
            json.dumps(caveats),
        )
        orchestrator.delegation = delegation
        orchestrator.authority_manager = self
        orchestrator._division = division
        return delegation

    def revoke(self, agent):
        if agent.delegation:
            self._revoked.add(agent.delegation.content_hash())
        self._revoked_names.add(agent.name.lower())

    def is_revoked(self, hash):
        return hash in self._revoked

    def is_agent_revoked(self, agent_name):
        return agent_name.lower() in self._revoked_names


class FinanceCoordinator:
    """Interactive finance orchestrator. User requests drive everything."""

    def __init__(self):
        self.cfo_kp = KeyPair.generate()
        self.authority = FinanceAuthorityManager(self.cfo_kp)

        self.orchestrator = OrchestratorAgent()
        self.trading = TradingAgent()
        self.payments = PaymentsAgent()
        self.audit = AuditAgent()

        self.provenance = ProvenanceGraph()
        self.memory = SharedMemory()

        self.all_agents = [self.orchestrator, self.trading, self.payments, self.audit]
        self.agent_map = {
            "trading": self.trading,
            "payments": self.payments,
            "audit": self.audit,
        }
        self._session_initialized = False
        self.conversation_history = []

    def reset_session(self):
        old_revoked_names = self.authority._revoked_names.copy() if hasattr(self.authority, '_revoked_names') else set()
        self.authority = FinanceAuthorityManager(self.cfo_kp)
        self.authority._revoked_names = old_revoked_names
        self.provenance = ProvenanceGraph()
        self.memory = SharedMemory()
        self._session_initialized = False
        for a in self.all_agents:
            a.delegation = None
            a.authority_manager = None
            a.message_log = []
            a.total_tokens_used = 0

    def _event(self, event_type, message, agent_name="system",
               details=None, prov_entry=None, memory_entry=None,
               signed_msg=None, delegation_info=None):
        return {
            "type": event_type,
            "agent": agent_name,
            "message": message,
            "details": details or {},
            "prov_entry": prov_entry,
            "memory_entry": memory_entry,
            "signed_msg": signed_msg,
            "delegation_info": delegation_info,
        }

    def _initialize_delegations(self, session_id):
        """Set up the delegation chain once per session."""
        if self._session_initialized:
            return

        # Register agents
        for agent in self.all_agents:
            entry = agent.record_action(
                self.provenance, "agent_registered",
                metadata={"name": agent.name, "capabilities": agent.identity.capabilities},
            )
            yield self._event("system", f"Agent registered: {agent.name} ({agent.did[:30]}...)",
                              agent_name=agent.name, prov_entry=entry.to_dict())

        # CFO delegates to orchestrator
        yield self._event("status", "CFO Sarah opening trading session...", agent_name="cfo")

        self.authority.delegate_to_orchestrator(
            self.orchestrator, division="trading", max_transaction=5000.0, expires_in_hours=8,
        )
        yield self._event("delegation",
            "CFO delegated to Orchestrator: trading division, $5,000 limit, 8hr session",
            agent_name="cfo",
            delegation_info={
                "status": "CREATED",
                "issuer": "CFO Sarah",
                "delegate": "Orchestrator",
                "caveats": ["division=trading", "max_transaction=$5,000", "expires=8hr"],
            })

        # Orchestrator sub-delegates
        delegations = [
            (self.trading, ["execute_trade", "check_portfolio"], 1000.0, ["account:ACCT-001:*"]),
            (self.payments, ["send_payment", "verify_recipient"], 500.0, ["recipient:approved:*"]),
            (self.audit, ["read_transactions", "generate_report"], 100.0, ["account:ACCT-001:*"]),
        ]

        for agent, actions, max_cost, resources in delegations:
            self.orchestrator.delegate_to_agent(agent, actions, max_cost, resources)
            yield self._event("delegation",
                f"Orchestrator delegated to {agent.name.title()}: {', '.join(actions)} (max ${max_cost:,.0f})",
                agent_name="orchestrator",
                delegation_info={
                    "status": "CREATED",
                    "issuer": "Orchestrator",
                    "delegate": agent.name.title(),
                    "caveats": [f"actions={','.join(actions)}", f"max_cost=${max_cost:,.0f}", f"resource={resources[0]}"],
                })

        self._session_initialized = True

    def run_stream(self, user_request):
        """Process a user request interactively."""
        session_id = f"TXN-{uuid.uuid4().hex[:8].upper()}"

        # Initialize delegations on first run
        yield from self._initialize_delegations(session_id)

        # Step 1: Orchestrator plans
        yield self._event("thinking", f"Analyzing request: {user_request}...", agent_name="orchestrator")

        plan_raw = self.orchestrator.plan_actions(user_request)

        # Parse the plan
        actions = []
        try:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\[.*\]', plan_raw, re.DOTALL)
            if json_match:
                actions = json.loads(json_match.group())
        except (json.JSONDecodeError, Exception):
            pass

        if not actions:
            # Fallback: tell the user we couldn't parse the plan
            yield self._event("message", f"Assessment: {plan_raw}", agent_name="orchestrator")
            yield self._event("message",
                "I wasn't able to decompose this into specific agent actions. "
                "Try something like: 'Buy 50 shares of AAPL' or 'Pay $200 to vendor VENDOR-042' or 'Show me today's transactions'.",
                agent_name="orchestrator")
            yield self._event("complete", "Session ready for next request.", agent_name="orchestrator",
                              details={"session_id": session_id, "provenance": self.provenance.export()})
            return

        # Show the plan
        plan_summary = ", ".join(f"{a.get('agent','?')}.{a.get('action','?')}" for a in actions)
        yield self._event("message", f"Plan: {plan_summary}", agent_name="orchestrator",
                          details={"plan": actions})

        # Step 2: Execute each action
        for step in actions:
            agent_name = step.get("agent", "").lower()
            action = step.get("action", "")
            args = step.get("args", {})

            agent = self.agent_map.get(agent_name)
            if not agent:
                yield self._event("message", f"Unknown agent: {agent_name}", agent_name="orchestrator")
                continue

            # Ensure cost field exists for caveats
            if "cost" not in args:
                args["cost"] = 10.0

            # Ensure resource field exists
            if "resource" not in args:
                if agent_name == "payments":
                    recipient = args.get("recipient", args.get("recipient_id", "VENDOR-001"))
                    args["resource"] = f"recipient:approved:{recipient}"
                else:
                    args["resource"] = f"account:ACCT-001:{action}"

            # Show thinking
            yield self._event("thinking", f"{action}...", agent_name=agent_name)

            # Check delegation
            ok, deleg_info = agent.execute_with_delegation(action, args, self.provenance)

            status_msg = f"{action} - {'VERIFIED' if ok else deleg_info['status']}"
            yield self._event("delegation_check", status_msg, agent_name=agent_name, delegation_info=deleg_info)

            if ok:
                # Execute the action via LLM
                response = agent.run_action(action, args)

                msg = agent.sign_message(
                    self.orchestrator.did, f"{action}_result",
                    {"action": action, "args": args, "result": response},
                )
                yield self._event("message", f"{response}", agent_name=agent_name, signed_msg=msg.to_dict())

                # Store in memory
                mem = agent.memorize(
                    self.memory, "action_result", title=f"{agent_name}: {action}",
                    content=response[:300], entity_id=session_id, tags=[agent_name, action],
                )
                yield self._event("memory", f"Result stored in shared memory", agent_name=agent_name,
                                  memory_entry=mem.to_dict())

            # Small pause for UI responsiveness
            time.sleep(0.1)

        # Complete
        prov_export = self.provenance.export()
        prov_export["memory"] = self.memory.all_entries()
        prov_export["memory_count"] = self.memory.count()

        yield self._event("complete",
            f"Session {session_id} complete. {len(actions)} actions processed.",
            agent_name="orchestrator",
            details={"session_id": session_id, "provenance": prov_export})
