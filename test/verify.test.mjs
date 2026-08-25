import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyBundleObject } from "../dist/verify.js";

function hashChain(events) {
  const chain = [];
  let previous = "genesis";
  for (const event of events) {
    previous = createHash("sha256").update(previous + event).digest("hex");
    chain.push(previous);
  }
  return chain;
}

function signedBundle({ events, outcome = "verified" }) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = {
    bundle_id: "public_test_bundle",
    capability: "memory.provenance.attached@1.0",
    run_id: "public_test_run",
    claim_ladder: "L2",
    executed_at: "2026-08-20T00:00:00.000Z",
    trace_events: events,
    trace_hash_chain: hashChain(events),
    outcome,
  };
  return {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: publicKey.export({ type: "spki", format: "pem" }),
  };
}

const verifiedEvent = "memory_write:{\"entry_id\":\"entry-1\",\"actual_agent_id\":\"agent-a\",\"provenance_agent_id\":\"agent-a\",\"actual_source_hash\":\"hash-a\",\"provenance_source_hash\":\"hash-a\"}";
const contradictoryEvent = "memory_write:{\"entry_id\":\"entry-1\",\"actual_agent_id\":\"agent-a\",\"provenance_agent_id\":\"agent-b\",\"actual_source_hash\":\"hash-a\",\"provenance_source_hash\":\"hash-a\"}";

test("accepts a correctly signed verified provenance bundle", () => {
  assert.deepEqual(verifyBundleObject(signedBundle({ events: [verifiedEvent] })), { ok: true });
});

test("rejects a bundle changed after signing", () => {
  const bundle = signedBundle({ events: [verifiedEvent] });
  bundle.trace_events[0] = contradictoryEvent;
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "invalid_signature" });
});

test("keeps missing evidence inconclusive", () => {
  const result = verifyBundleObject(signedBundle({ events: [], outcome: "inconclusive" }));
  assert.deepEqual(result, { ok: false, reason: "non_verified_outcome:inconclusive" });
});

test("rejects a verified claim contradicted by its trace", () => {
  const result = verifyBundleObject(signedBundle({ events: [contradictoryEvent] }));
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});
