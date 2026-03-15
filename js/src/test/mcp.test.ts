import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  generateKeyPair,
  createRootDelegation,
  delegateAuthority,
  McpProof,
  verifyMcpCall,
  verifyMcpCallWithRevocation,
  verifyMcpToolCall,
} from "../index.js";
import { contentHash } from "../signing.js";
import { CryptoError } from "../error.js";

describe("MCP Auth", () => {
  it("creates and verifies MCP proof", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);

    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
    const result = verifyMcpCall(proof, root.identity);

    assert.equal(result.invoker_did, agent.identity.did);
    assert.equal(result.root_did, root.identity.did);
  });

  it("extracts and injects proof from args", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);

    // Inject
    const args = McpProof.inject(proof, { source: "crm", external_id: "123" });
    assert.ok(args._proof);
    assert.equal(args.source, "crm");

    // Extract
    const { proof: extracted, cleanArgs } = McpProof.extract(args);
    assert.ok(extracted);
    assert.equal(cleanArgs._proof, undefined);
    assert.equal(cleanArgs.source, "crm");
    assert.equal(cleanArgs.external_id, "123");

    // Verify extracted
    const result = verifyMcpCall(extracted!, root.identity);
    assert.equal(result.invoker_did, agent.identity.did);
  });

  it("extract returns null when no proof", () => {
    const { proof, cleanArgs } = McpProof.extract({ source: "crm" });
    assert.equal(proof, null);
    assert.equal(cleanArgs.source, "crm");
  });

  it("rejects wrong root", () => {
    const root = generateKeyPair();
    const fakeRoot = generateKeyPair();
    const agent = generateKeyPair();

    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", {}, delegation);

    assert.throws(() => verifyMcpCall(proof, fakeRoot.identity));
  });

  it("enforces caveats through MCP", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
      { type: "max_cost", value: 5.0 },
    ]);

    // Allowed
    const ok = McpProof.create(agent, "resolve", { cost: 3.0 }, delegation);
    assert.ok(verifyMcpCall(ok, root.identity));

    // Action blocked
    const badAction = McpProof.create(agent, "merge", { cost: 1.0 }, delegation);
    assert.throws(() => verifyMcpCall(badAction, root.identity));

    // Cost exceeded
    const badCost = McpProof.create(agent, "resolve", { cost: 10.0 }, delegation);
    assert.throws(() => verifyMcpCall(badCost, root.identity));
  });

  it("verifies chained delegation through MCP", () => {
    const root = generateKeyPair();
    const manager = generateKeyPair();
    const worker = generateKeyPair();

    const d1 = createRootDelegation(root, manager.identity.did, [
      { type: "action_scope", value: ["resolve", "search", "merge"] },
    ]);

    const d2 = delegateAuthority(manager, worker.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ], d1);

    const proof = McpProof.create(worker, "resolve", {}, d2);
    const result = verifyMcpCall(proof, root.identity);

    assert.equal(result.invoker_did, worker.identity.did);
    assert.equal(result.root_did, root.identity.did);
    assert.equal(result.depth, 2);
  });

  it("supports revocation through MCP", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const delegation = createRootDelegation(root, agent.identity.did, []);
    const revokedHash = contentHash(delegation.proof);

    const proof = McpProof.create(agent, "resolve", {}, delegation);

    // Without revocation
    assert.ok(verifyMcpCall(proof, root.identity));

    // With revocation
    assert.throws(() =>
      verifyMcpCallWithRevocation(proof, root.identity, (h) => h === revokedHash),
    );
  });

  // --- McpAuthMode tests ---

  it("required mode rejects missing proof", () => {
    const root = generateKeyPair();
    assert.throws(() =>
      verifyMcpToolCall("resolve", { source: "crm" }, root.identity, "required"),
    );
  });

  it("required mode accepts valid proof", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
    const args = McpProof.inject(proof, { source: "crm" });

    const outcome = verifyMcpToolCall("resolve", args, root.identity, "required");
    assert.ok(outcome.verified);
    assert.equal(outcome.args._proof, undefined);
  });

  it("optional mode passes without proof", () => {
    const root = generateKeyPair();
    const outcome = verifyMcpToolCall("resolve", { source: "crm" }, root.identity, "optional");
    assert.equal(outcome.verified, null);
  });

  it("optional mode verifies when proof present", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
    const args = McpProof.inject(proof, { source: "crm" });

    const outcome = verifyMcpToolCall("resolve", args, root.identity, "optional");
    assert.ok(outcome.verified);
  });

  it("disabled mode skips verification", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
    const args = McpProof.inject(proof, { source: "crm" });

    const outcome = verifyMcpToolCall("resolve", args, root.identity, "disabled");
    assert.equal(outcome.verified, null);
    assert.equal(outcome.args._proof, undefined);
  });

  // --- Error path tests ---

  it("rejects invalid hex in invoker_public_key", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", {}, delegation);

    // Tamper with hex
    const tampered = { ...proof, invoker_public_key: "not-valid-hex!@#$" };
    assert.throws(() => verifyMcpCall(tampered as any, root.identity));
  });

  it("rejects tampered invocation signature", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", {}, delegation);

    const tampered = {
      ...proof,
      invocation: {
        ...proof.invocation,
        proof: { ...proof.invocation.proof, signature: "00".repeat(64) },
      },
    };
    assert.throws(() => verifyMcpCall(tampered, root.identity));
  });

  it("invoker_public_key is 64-char hex", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", {}, delegation);

    assert.equal(proof.invoker_public_key.length, 64);
    assert.ok(/^[0-9a-f]+$/.test(proof.invoker_public_key));
  });

  // --- extract() edge cases ---

  it("strips invalid _proof (wrong shape object)", () => {
    const { proof, cleanArgs } = McpProof.extract({
      source: "crm",
      _proof: { wrong: "shape" },
    });
    assert.equal(proof, null);
    assert.equal(cleanArgs._proof, undefined);
    assert.equal(cleanArgs.source, "crm");
  });

  it("strips _proof when value is a string", () => {
    const { proof, cleanArgs } = McpProof.extract({
      source: "crm",
      _proof: "not-an-object",
    });
    assert.equal(proof, null);
    assert.equal(cleanArgs._proof, undefined);
  });

  it("strips _proof when value is null", () => {
    const { proof, cleanArgs } = McpProof.extract({
      source: "crm",
      _proof: null,
    });
    assert.equal(proof, null);
    assert.equal(cleanArgs._proof, undefined);
  });

  it("extract handles empty object", () => {
    const { proof, cleanArgs } = McpProof.extract({});
    assert.equal(proof, null);
    assert.deepEqual(cleanArgs, {});
  });

  it("inject does not mutate original args", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", {}, delegation);

    const original: Record<string, unknown> = { source: "crm" };
    const injected = McpProof.inject(proof, original);

    assert.equal(original._proof, undefined); // original not mutated
    assert.ok(injected._proof); // new object has proof
  });

  // --- Auth mode error paths ---

  it("required mode fails on invalid proof", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);

    // Tamper
    const tampered = {
      ...proof,
      invocation: {
        ...proof.invocation,
        proof: { ...proof.invocation.proof, signature: "ff".repeat(64) },
      },
    };
    const args = McpProof.inject(tampered, { source: "crm" });

    assert.throws(() =>
      verifyMcpToolCall("resolve", args, root.identity, "required"),
    );
  });

  it("optional mode fails on invalid proof (proof was present)", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, []);
    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);

    const tampered = {
      ...proof,
      invocation: {
        ...proof.invocation,
        proof: { ...proof.invocation.proof, signature: "ff".repeat(64) },
      },
    };
    const args = McpProof.inject(tampered, { source: "crm" });

    assert.throws(() =>
      verifyMcpToolCall("resolve", args, root.identity, "optional"),
    );
  });

  // --- Caveat types ---

  it("expires_at past blocks", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "expires_at", value: "2020-01-01T00:00:00.000Z" },
    ]);
    const proof = McpProof.create(agent, "resolve", {}, delegation);
    assert.throws(() => verifyMcpCall(proof, root.identity));
  });

  it("expires_at future passes", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "expires_at", value: "2099-12-31T23:59:59.999Z" },
    ]);
    const proof = McpProof.create(agent, "resolve", {}, delegation);
    assert.ok(verifyMcpCall(proof, root.identity));
  });

  it("resource caveat through MCP", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "resource", value: "entity:customer:*" },
    ]);

    const ok = McpProof.create(agent, "resolve",
      { resource: "entity:customer:123" }, delegation);
    assert.ok(verifyMcpCall(ok, root.identity));

    const bad = McpProof.create(agent, "resolve",
      { resource: "entity:order:456" }, delegation);
    assert.throws(() => verifyMcpCall(bad, root.identity));
  });

  it("context caveat through MCP", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "context", value: { key: "session_id", value: "sess-abc" } },
    ]);

    const ok = McpProof.create(agent, "resolve",
      { session_id: "sess-abc" }, delegation);
    assert.ok(verifyMcpCall(ok, root.identity));

    const bad = McpProof.create(agent, "resolve",
      { session_id: "sess-xyz" }, delegation);
    assert.throws(() => verifyMcpCall(bad, root.identity));
  });

  it("serialization roundtrip works", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const delegation = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);

    const proof = McpProof.create(agent, "resolve", { source: "crm" }, delegation);
    const json = JSON.stringify(proof);
    const restored = JSON.parse(json);

    const result = verifyMcpCall(restored, root.identity);
    assert.equal(result.invoker_did, agent.identity.did);
  });
});
