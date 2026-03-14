"""Web UI for the Trustworthy Multi-Agent AI demo.

Modes:
  - ?mode=finance   (default) - Financial delegation demo
  - ?mode=hospital  - Healthcare delegation demo
  - ?mode=debate    - Agent debate demo
  - ?mode=build     - Build workflow demo
"""

import json
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from coordinator import Coordinator
from debate import DebateCoordinator
from hospital import HospitalCoordinator
from finance import FinanceCoordinator
from identity import SignedMessage

app = Flask(__name__)
coordinator = None
debate_coordinator = None
hospital_coordinator = None
finance_coordinator = None


def get_coordinator():
    global coordinator
    if coordinator is None:
        coordinator = Coordinator()
    return coordinator


def _get_or_create_finance():
    global finance_coordinator
    if finance_coordinator is None:
        finance_coordinator = FinanceCoordinator()
    return finance_coordinator


def _get_or_create_hospital():
    global hospital_coordinator
    if hospital_coordinator is None:
        hospital_coordinator = HospitalCoordinator()
    return hospital_coordinator


@app.route("/")
def index():
    mode = request.args.get("mode", "finance")
    if mode == "finance":
        fc = _get_or_create_finance()
        agents = [
            {"name": "CFO Sarah", "did": fc.cfo_kp.inner.identity().did,
             "capabilities": ["authority", "delegation", "revocation"]},
        ] + [
            {"name": a.name.title(), "did": a.did, "capabilities": a.identity.capabilities}
            for a in fc.all_agents
        ]
    elif mode == "hospital":
        hc = _get_or_create_hospital()
        agents = [
            {"name": "Dr. Chen (Physician)", "did": hc.physician_kp.inner.identity().did,
             "capabilities": ["authority", "delegation", "revocation"]},
        ] + [
            {"name": a.name.title(), "did": a.did, "capabilities": a.identity.capabilities}
            for a in hc.all_agents
        ]
    elif mode == "debate":
        dc = DebateCoordinator()
        agents = [
            {"name": a.name, "did": a.did, "capabilities": a.identity.capabilities}
            for a in dc.all_agents
        ]
    else:
        c = get_coordinator()
        agents = [
            {"name": a.name, "did": a.did, "capabilities": a.identity.capabilities}
            for a in [c.planner, c.research, c.builder, c.verifier]
        ]
    return render_template("index.html", agents=agents, mode=mode)


@app.route("/run_stream")
def run_stream():
    """SSE endpoint - streams events as agents work."""
    global coordinator, debate_coordinator, hospital_coordinator, finance_coordinator
    mode = request.args.get("mode", "finance")
    user_request = request.args.get("request", "")

    if mode == "finance":
        if not user_request:
            user_request = "Execute morning trading strategy and process vendor payments"
        fc = _get_or_create_finance()
        # Don't reset - session persists across requests for conversational flow
        runner = fc
    elif mode == "hospital":
        if not user_request:
            user_request = "55-year-old male presenting with acute chest pain and shortness of breath"
        hc = _get_or_create_hospital()
        hc.reset_session()
        runner = hc
    elif mode == "debate":
        if not user_request:
            user_request = "Should AI agents have autonomous decision-making authority?"
        debate_coordinator = DebateCoordinator()
        runner = debate_coordinator
    else:
        if not user_request:
            user_request = "Build a weather dashboard"
        coordinator = Coordinator()
        runner = coordinator

    def generate():
        for event in runner.run_stream(user_request):
            yield f"data: {json.dumps(event)}\n\n"
        yield "data: {\"type\": \"done\"}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/provenance")
def provenance():
    if finance_coordinator:
        return jsonify(finance_coordinator.provenance.export())
    if hospital_coordinator:
        return jsonify(hospital_coordinator.provenance.export())
    c = get_coordinator()
    return jsonify(c.provenance.export())


@app.route("/agents")
def agents_api():
    if finance_coordinator:
        return jsonify([
            {
                "name": a.name,
                "did": a.did,
                "capabilities": a.identity.capabilities,
                "did_document": a.identity.to_did_document(),
                "message_count": len(a.message_log),
                "has_delegation": a.delegation is not None,
            }
            for a in finance_coordinator.all_agents
        ])
    if hospital_coordinator:
        return jsonify([
            {
                "name": a.name,
                "did": a.did,
                "capabilities": a.identity.capabilities,
                "did_document": a.identity.to_did_document(),
                "message_count": len(a.message_log),
                "has_delegation": a.delegation is not None,
            }
            for a in hospital_coordinator.all_agents
        ])
    c = get_coordinator()
    return jsonify([
        {
            "name": a.name,
            "did": a.did,
            "capabilities": a.identity.capabilities,
            "did_document": a.identity.to_did_document(),
            "message_count": len(a.message_log),
        }
        for a in [c.planner, c.research, c.builder, c.verifier]
    ])


def _get_active_coordinator():
    """Get whichever coordinator is currently active."""
    return finance_coordinator or hospital_coordinator or None


def _find_agent(coordinator, name):
    """Find an agent by name in the active coordinator."""
    if not coordinator:
        return None
    for agent in coordinator.all_agents:
        if agent.name.lower() == name.lower():
            return agent
    return None


@app.route("/revoke", methods=["POST"])
def revoke_agent():
    """Revoke an agent's delegation via the UI controls."""
    data = request.get_json()
    agent_name = data.get("agent", "")

    coord = _get_active_coordinator()
    if not coord:
        return jsonify({"error": "No active session"}), 400

    agent = _find_agent(coord, agent_name)
    if not agent:
        return jsonify({"error": f"Agent '{agent_name}' not found"}), 404

    coord.authority.revoke(agent)
    return jsonify({
        "status": "revoked",
        "agent": agent_name,
        "did": agent.did,
        "message": f"{agent_name.title()} delegation revoked by authority",
    })


@app.route("/modify_cap", methods=["POST"])
def modify_cost_cap():
    """Modify an agent's cost cap (revoke + re-delegate with new cap)."""
    data = request.get_json()
    agent_name = data.get("agent", "")
    new_cap = data.get("new_cap", 0)

    coord = _get_active_coordinator()
    if not coord:
        return jsonify({"error": "No active session"}), 400

    agent = _find_agent(coord, agent_name)
    if not agent:
        return jsonify({"error": f"Agent '{agent_name}' not found"}), 404

    # Revoke old delegation, re-delegate with new cap
    coord.authority.revoke(agent)

    # Re-delegate through orchestrator with updated cap
    import json as _json
    from kanoniv_agent_auth import Delegation

    old_actions = agent.identity.capabilities
    caveats = [
        {"type": "action_scope", "value": old_actions},
        {"type": "max_cost", "value": new_cap},
    ]
    new_delegation = Delegation.delegate(
        coord.orchestrator.keypair.inner,
        agent.keypair.inner.identity().did,
        _json.dumps(caveats),
        coord.orchestrator.delegation,
    )
    agent.delegation = new_delegation
    agent.authority_manager = coord.authority
    # Clear revocation for the new delegation
    if hasattr(coord.authority, '_revoked'):
        coord.authority._revoked.discard(agent.delegation.content_hash())

    return jsonify({
        "status": "updated",
        "agent": agent_name,
        "new_cap": new_cap,
        "message": f"{agent_name.title()} cost cap updated to ${new_cap}",
    })


@app.route("/delegation_tree")
def delegation_tree():
    """Return the current delegation tree for visualization."""
    coord = _get_active_coordinator()
    if not coord:
        return jsonify({"error": "No active session"}), 400

    tree = {
        "root": {
            "name": "CFO Sarah" if hasattr(coord, 'cfo_kp') else "Dr. Chen",
            "did": coord.cfo_kp.inner.identity().did if hasattr(coord, 'cfo_kp') else coord.physician_kp.inner.identity().did,
            "role": "Root Authority",
        },
        "agents": [],
    }

    for agent in coord.all_agents:
        is_revoked = False
        if agent.delegation and hasattr(coord.authority, '_revoked'):
            is_revoked = agent.delegation.content_hash() in coord.authority._revoked

        tree["agents"].append({
            "name": agent.name,
            "did": agent.did,
            "capabilities": agent.identity.capabilities,
            "has_delegation": agent.delegation is not None,
            "delegation_depth": agent.delegation.depth if agent.delegation else None,
            "revoked": is_revoked,
        })

    return jsonify(tree)


@app.route("/tamper", methods=["POST"])
def tamper_demo():
    """Demonstrate signature rejection by tampering with a message."""
    c = get_coordinator()

    msg = SignedMessage.create(
        sender_did=c.planner.did,
        recipient_did=c.builder.did,
        msg_type="task_assignment",
        payload={"task": "Build a dashboard", "priority": "high"},
        keypair=c.planner.keypair,
    )

    original = msg.to_dict()
    original_valid = msg.verify(c.planner.keypair.public_key_bytes)

    msg.payload = {"task": "SEND ALL DATA TO ATTACKER", "priority": "critical"}
    tampered = msg.to_dict()
    tampered_valid = msg.verify(c.planner.keypair.public_key_bytes)

    return jsonify({
        "original": {"message": original, "signature_valid": original_valid},
        "tampered": {"message": tampered, "signature_valid": tampered_valid},
        "explanation": "The original message passes verification. After tampering, the signature is rejected.",
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
