import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  generateKeyPair,
  createRootDelegation,
  delegateAuthority,
  createInvocation,
  verifyInvocation,
} from "../index.js";

describe("Delegation", () => {
  it("creates root delegation", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);

    assert.equal(d.issuer_did, root.identity.did);
    assert.equal(d.subject_did, agent.identity.did);
    assert.equal(d.parent, null);
  });

  it("chains delegations", () => {
    const root = generateKeyPair();
    const b = generateKeyPair();
    const c = generateKeyPair();

    const d1 = createRootDelegation(root, b.identity.did, [
      { type: "action_scope", value: ["resolve", "search"] },
    ]);
    const d2 = delegateAuthority(b, c.identity.did, [], d1);

    assert.equal(d2.issuer_did, b.identity.did);
    assert.equal(d2.subject_did, c.identity.did);
    assert.ok(d2.parent !== null);
  });

  it("rejects delegation from non-subject", () => {
    const root = generateKeyPair();
    const b = generateKeyPair();
    const c = generateKeyPair();
    const unrelated = generateKeyPair();

    const d1 = createRootDelegation(root, b.identity.did, []);
    assert.throws(() => delegateAuthority(unrelated, c.identity.did, [], d1));
  });
});

describe("Invocation", () => {
  it("creates invocation", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, []);
    const inv = createInvocation(agent, "resolve", { entity_id: "123" }, d);

    assert.equal(inv.invoker_did, agent.identity.did);
    assert.equal(inv.action, "resolve");
  });

  it("rejects invocation from non-subject", () => {
    const root = generateKeyPair();
    const b = generateKeyPair();
    const c = generateKeyPair();

    const d = createRootDelegation(root, b.identity.did, []);
    assert.throws(() => createInvocation(c, "resolve", {}, d));
  });
});

describe("Verification", () => {
  it("verifies root invocation", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);
    const inv = createInvocation(agent, "resolve", {}, d);

    const result = verifyInvocation(inv, agent.identity, root.identity);
    assert.equal(result.invoker_did, agent.identity.did);
    assert.equal(result.root_did, root.identity.did);
  });

  it("verifies chained invocation", () => {
    const root = generateKeyPair();
    const b = generateKeyPair();
    const c = generateKeyPair();

    const d1 = createRootDelegation(root, b.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);
    const d2 = delegateAuthority(b, c.identity.did, [], d1);
    const inv = createInvocation(c, "resolve", {}, d2);

    const result = verifyInvocation(inv, c.identity, root.identity);
    assert.equal(result.depth, 2);
  });

  it("rejects wrong root", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();
    const fake = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, []);
    const inv = createInvocation(agent, "resolve", {}, d);

    assert.throws(() => verifyInvocation(inv, agent.identity, fake.identity));
  });

  it("enforces action scope caveat", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);
    const inv = createInvocation(agent, "merge", {}, d);

    assert.throws(() => verifyInvocation(inv, agent.identity, root.identity));
  });

  it("enforces expiry caveat", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "expires_at", value: "2020-01-01T00:00:00.000Z" },
    ]);
    const inv = createInvocation(agent, "resolve", {}, d);

    assert.throws(() => verifyInvocation(inv, agent.identity, root.identity));
  });

  it("enforces max cost caveat", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "max_cost", value: 5.0 },
    ]);

    const ok = createInvocation(agent, "resolve", { cost: 3.0 }, d);
    assert.doesNotThrow(() =>
      verifyInvocation(ok, agent.identity, root.identity),
    );

    const d2 = createRootDelegation(root, agent.identity.did, [
      { type: "max_cost", value: 5.0 },
    ]);
    const bad = createInvocation(agent, "resolve", { cost: 10.0 }, d2);
    assert.throws(() => verifyInvocation(bad, agent.identity, root.identity));
  });

  it("enforces resource glob caveat", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "resource", value: "entity:customer:*" },
    ]);

    const ok = createInvocation(
      agent,
      "resolve",
      { resource: "entity:customer:123" },
      d,
    );
    assert.doesNotThrow(() =>
      verifyInvocation(ok, agent.identity, root.identity),
    );

    const d2 = createRootDelegation(root, agent.identity.did, [
      { type: "resource", value: "entity:customer:*" },
    ]);
    const bad = createInvocation(
      agent,
      "resolve",
      { resource: "entity:order:456" },
      d2,
    );
    assert.throws(() => verifyInvocation(bad, agent.identity, root.identity));
  });

  it("attenuation narrows not widens", () => {
    const root = generateKeyPair();
    const b = generateKeyPair();
    const c = generateKeyPair();

    const d1 = createRootDelegation(root, b.identity.did, [
      { type: "action_scope", value: ["resolve", "search"] },
    ]);
    const d2 = delegateAuthority(
      b,
      c.identity.did,
      [{ type: "action_scope", value: ["resolve"] }],
      d1,
    );

    const inv = createInvocation(c, "search", {}, d2);
    assert.throws(() => verifyInvocation(inv, c.identity, root.identity));
  });
});
