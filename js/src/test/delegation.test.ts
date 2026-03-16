import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  generateKeyPair,
  createRootDelegation,
  delegateAuthority,
  createInvocation,
  verifyInvocation,
  keyPairFromBytes,
  hexToBytes,
  contentHash,
} from "../index.js";

describe("Delegation", () => {
  it("creates root delegation", () => {
    const root = generateKeyPair();
    const agent = generateKeyPair();

    const d = createRootDelegation(root, agent.identity.did, [
      { type: "action_scope", value: ["resolve"] },
    ]);

    assert.equal(d.issuer_did, root.identity.did);
    assert.equal(d.delegate_did, agent.identity.did);
    assert.equal(d.parent_proof, null);
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
    assert.equal(d2.delegate_did, c.identity.did);
    assert.ok(d2.parent_proof !== null);
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

// ---------------------------------------------------------------------------
// Cross-language interop: delegation chain + caveat enforcement
// ---------------------------------------------------------------------------

describe("Cross-language interop - delegation", () => {
  async function loadFixture() {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const fixturePath = path.resolve(
      import.meta.dirname,
      "../../../fixtures/test-delegation-chain.json",
    );
    return JSON.parse(fs.readFileSync(fixturePath, "utf-8"));
  }

  function loadKeypair(kpFixture: any) {
    return keyPairFromBytes(hexToBytes(kpFixture.secret_key_hex));
  }

  it("DIDs match Rust-generated fixtures", async () => {
    const f = await loadFixture();
    const root = loadKeypair(f.root_keypair);
    const delegate = loadKeypair(f.delegate_keypair);
    const sub = loadKeypair(f.sub_delegate_keypair);

    assert.equal(root.identity.did, f.root_keypair.did);
    assert.equal(delegate.identity.did, f.delegate_keypair.did);
    assert.equal(sub.identity.did, f.sub_delegate_keypair.did);
  });

  it("root delegation content hash matches Rust", async () => {
    const f = await loadFixture();
    const jsHash = contentHash(f.root_delegation.proof);
    assert.equal(jsHash, f.root_delegation_content_hash,
      `Root delegation hash mismatch: JS=${jsHash}, Rust=${f.root_delegation_content_hash}`);
  });

  it("sub delegation content hash matches Rust", async () => {
    const f = await loadFixture();
    const jsHash = contentHash(f.sub_delegation.proof);
    assert.equal(jsHash, f.sub_delegation_content_hash,
      `Sub delegation hash mismatch: JS=${jsHash}, Rust=${f.sub_delegation_content_hash}`);
  });

  it("content hashes are unique per delegation", async () => {
    const f = await loadFixture();
    const rootHash = contentHash(f.root_delegation.proof);
    const subHash = contentHash(f.sub_delegation.proof);
    assert.notEqual(rootHash, subHash, "Different delegations must have different hashes");
  });

  // Rebuild delegation chains from fixture keypairs (raw JSON delegations
  // have byte-array public keys that JS can't use directly)
  function buildChains(f: any) {
    const root = loadKeypair(f.root_keypair);
    const delegate = loadKeypair(f.delegate_keypair);
    const sub = loadKeypair(f.sub_delegate_keypair);

    const rootDel = createRootDelegation(root, delegate.identity.did, [
      { type: "action_scope", value: ["write", "edit", "publish"] },
      { type: "max_cost", value: 500.0 },
    ]);
    const subDel = delegateAuthority(delegate, sub.identity.did, [
      { type: "action_scope", value: ["write"] },
      { type: "max_cost", value: 100.0 },
    ], rootDel);

    return { root, delegate, sub, rootDel, subDel };
  }

  it("pass: delegate action in scope under budget", async () => {
    const f = await loadFixture();
    const { root, delegate, rootDel } = buildChains(f);
    const tc = f.test_cases.pass_in_scope;

    const inv = createInvocation(delegate, tc.action, tc.args, rootDel);
    const result = verifyInvocation(inv, delegate.identity, root.identity);
    assert.equal(result.depth, tc.expected_depth);
  });

  it("pass: sub-delegate action in scope under budget", async () => {
    const f = await loadFixture();
    const { root, sub, subDel } = buildChains(f);
    const tc = f.test_cases.pass_sub_delegate;

    const inv = createInvocation(sub, tc.action, tc.args, subDel);
    const result = verifyInvocation(inv, sub.identity, root.identity);
    assert.equal(result.depth, tc.expected_depth);
  });

  it("fail: delegate action outside scope", async () => {
    const f = await loadFixture();
    const { root, delegate, rootDel } = buildChains(f);
    const tc = f.test_cases.fail_wrong_scope;

    const inv = createInvocation(delegate, tc.action, tc.args, rootDel);
    assert.throws(
      () => verifyInvocation(inv, delegate.identity, root.identity),
      (err: any) => err.message.includes("action") || err.message.includes("scope"),
    );
  });

  it("fail: delegate over budget", async () => {
    const f = await loadFixture();
    const { root, delegate, rootDel } = buildChains(f);
    const tc = f.test_cases.fail_over_budget;

    const inv = createInvocation(delegate, tc.action, tc.args, rootDel);
    assert.throws(
      () => verifyInvocation(inv, delegate.identity, root.identity),
      (err: any) => err.message.includes("cost") || err.message.includes("max"),
    );
  });

  it("fail: sub-delegate over budget", async () => {
    const f = await loadFixture();
    const { root, sub, subDel } = buildChains(f);
    const tc = f.test_cases.fail_sub_over_budget;

    const inv = createInvocation(sub, tc.action, tc.args, subDel);
    assert.throws(
      () => verifyInvocation(inv, sub.identity, root.identity),
      (err: any) => err.message.includes("cost") || err.message.includes("max"),
    );
  });

  it("fail: sub-delegate action outside narrowed scope", async () => {
    const f = await loadFixture();
    const { root, sub, subDel } = buildChains(f);
    const tc = f.test_cases.fail_sub_wrong_scope;

    const inv = createInvocation(sub, tc.action, tc.args, subDel);
    assert.throws(
      () => verifyInvocation(inv, sub.identity, root.identity),
      (err: any) => err.message.includes("action") || err.message.includes("scope"),
    );
  });
});
