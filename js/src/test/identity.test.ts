import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  generateKeyPair,
  keyPairFromBytes,
  computeDid,
  identityFromBytes,
  didDocument,
  didDocumentWithServices,
  hexToBytes,
  bytesToHex,
} from "../index.js";

describe("AgentKeyPair", () => {
  it("generates a keypair with valid DID", () => {
    const kp = generateKeyPair();
    assert.ok(kp.identity.did.startsWith("did:kanoniv:"));
    assert.equal(kp.identity.publicKeyBytes.length, 32);
    assert.equal(kp.secretKey.length, 32);
  });

  it("produces deterministic DID from same key", () => {
    const kp = generateKeyPair();
    const did1 = computeDid(kp.identity.publicKeyBytes);
    const did2 = computeDid(kp.identity.publicKeyBytes);
    assert.equal(did1, did2);
  });

  it("different keys produce different DIDs", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    assert.notEqual(kp1.identity.did, kp2.identity.did);
  });

  it("DID format is correct", () => {
    const kp = generateKeyPair();
    const suffix = kp.identity.did.slice("did:kanoniv:".length);
    assert.equal(suffix.length, 32); // 16 bytes = 32 hex chars
    assert.ok(/^[0-9a-f]+$/.test(suffix));
  });

  it("roundtrips through secret bytes", () => {
    const kp1 = generateKeyPair();
    const kp2 = keyPairFromBytes(kp1.secretKey);
    assert.equal(kp1.identity.did, kp2.identity.did);
  });
});

describe("AgentIdentity", () => {
  it("creates from bytes", () => {
    const kp = generateKeyPair();
    const restored = identityFromBytes(kp.identity.publicKeyBytes);
    assert.equal(restored.did, kp.identity.did);
  });

  it("rejects wrong length bytes", () => {
    assert.throws(() => identityFromBytes(new Uint8Array(16)));
    assert.throws(() => identityFromBytes(new Uint8Array(64)));
    assert.throws(() => identityFromBytes(new Uint8Array(0)));
  });
});

describe("DID Document", () => {
  it("has correct structure", () => {
    const kp = generateKeyPair();
    const doc = didDocument(kp.identity);
    assert.equal(doc["id"], kp.identity.did);
    assert.ok(Array.isArray(doc["@context"]));
    const vm = (doc["verificationMethod"] as Record<string, unknown>[])[0];
    assert.equal(vm["type"], "Ed25519VerificationKey2020");
    assert.equal(vm["controller"], kp.identity.did);
    assert.ok(typeof vm["publicKeyBase64"] === "string");
  });

  it("has no service field without services", () => {
    const kp = generateKeyPair();
    const doc = didDocument(kp.identity);
    assert.equal(doc["service"], undefined);
  });

  it("includes service endpoints", () => {
    const kp = generateKeyPair();
    const doc = didDocumentWithServices(kp.identity, [
      {
        id: "#messaging",
        serviceType: "AgentMessaging",
        endpoint: "https://example.com/agent/msg",
      },
      {
        id: "#resolve",
        serviceType: "KanonivResolve",
        endpoint: "https://api.kanoniv.com/v1/resolve",
      },
    ]);

    const svc = doc["service"] as Record<string, unknown>[];
    assert.equal(svc.length, 2);
    assert.equal(svc[0]["id"], `${kp.identity.did}#messaging`);
    assert.equal(svc[0]["type"], "AgentMessaging");
    assert.equal(svc[0]["serviceEndpoint"], "https://example.com/agent/msg");
    assert.equal(svc[1]["id"], `${kp.identity.did}#resolve`);
  });

  it("preserves full URI service IDs", () => {
    const kp = generateKeyPair();
    const doc = didDocumentWithServices(kp.identity, [
      {
        id: "https://example.com/services/agent-1",
        serviceType: "AgentMessaging",
        endpoint: "https://example.com/agent/msg",
      },
    ]);

    const svc = doc["service"] as Record<string, unknown>[];
    assert.equal(svc[0]["id"], "https://example.com/services/agent-1");
  });
});

describe("Cross-language interop - keypair", () => {
  it("matches Rust fixture", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const fixturePath = path.resolve(
      import.meta.dirname,
      "../../../fixtures/test-keypair.json",
    );
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));

    const secret = hexToBytes(fixture.secret_key_hex);
    const kp = keyPairFromBytes(secret);

    assert.equal(kp.identity.did, fixture.did);
    assert.equal(
      bytesToHex(kp.identity.publicKeyBytes),
      fixture.public_key_hex,
    );
  });
});
