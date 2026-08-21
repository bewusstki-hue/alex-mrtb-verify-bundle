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

function signedBundle({ events, outcome = "verified", capability = "memory.provenance.attached@1.0", overrides = {} }) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = {
    bundle_id: "public_test_bundle",
    capability,
    run_id: "public_test_run",
    claim_ladder: "L2",
    executed_at: "2026-08-20T00:00:00.000Z",
    trace_events: events,
    trace_hash_chain: hashChain(events),
    outcome,
    ...overrides,
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

// ── memory.delete.enforced@1.0 ────────────────────────────────────────────────

const deleteOkEvent = "memory_state_read:{\"entry_id\":\"e1\",\"exists\":false,\"phase\":\"after_delete\",\"source\":\"storage_probe\"}";
const deleteViolationEvent = "memory_state_read:{\"entry_id\":\"e1\",\"exists\":true,\"phase\":\"after_delete\",\"source\":\"storage_probe\"}";

test("delete.enforced: accepts a bundle proving the record is really gone", () => {
  const result = verifyBundleObject(signedBundle({ events: [deleteOkEvent], capability: "memory.delete.enforced@1.0" }));
  assert.deepEqual(result, { ok: true });
});

test("delete.enforced: rejects a bundle where the deleted record still exists", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [deleteViolationEvent], capability: "memory.delete.enforced@1.0" }),
  );
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

// ── memory.tenant.isolation@1.0 ───────────────────────────────────────────────

const isolationOkEvent = "tenant_access_probe:{\"entry_id\":\"e1\",\"requesting_tenant\":\"tenant_b\",\"target_tenant\":\"tenant_a\",\"allowed\":false,\"source\":\"isolation_probe\"}";
const isolationLeakEvent = "tenant_access_probe:{\"entry_id\":\"e1\",\"requesting_tenant\":\"tenant_b\",\"target_tenant\":\"tenant_a\",\"allowed\":true,\"source\":\"isolation_probe\"}";

test("tenant.isolation: accepts a bundle proving cross-tenant access was blocked", () => {
  const result = verifyBundleObject(signedBundle({ events: [isolationOkEvent], capability: "memory.tenant.isolation@1.0" }));
  assert.deepEqual(result, { ok: true });
});

test("tenant.isolation: rejects a bundle showing a cross-tenant leak", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [isolationLeakEvent], capability: "memory.tenant.isolation@1.0" }),
  );
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

// ── memory.write.integrity@1.0 ────────────────────────────────────────────────

const integrityBeforeEvent = "memory_content_change:{\"entry_id\":\"e1\",\"phase\":\"before\",\"content_hash\":\"hash-old\",\"source\":\"content_probe\"}";
const integrityAfterChangedEvent = "memory_content_change:{\"entry_id\":\"e1\",\"phase\":\"after\",\"content_hash\":\"hash-new\",\"source\":\"content_probe\"}";
const integrityAfterUnchangedEvent = "memory_content_change:{\"entry_id\":\"e1\",\"phase\":\"after\",\"content_hash\":\"hash-old\",\"source\":\"content_probe\"}";

test("write.integrity: accepts a bundle proving the write actually changed content", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [integrityBeforeEvent, integrityAfterChangedEvent], capability: "memory.write.integrity@1.0" }),
  );
  assert.deepEqual(result, { ok: true });
});

test("write.integrity: rejects a bundle where content is unchanged despite a claimed write", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [integrityBeforeEvent, integrityAfterUnchangedEvent], capability: "memory.write.integrity@1.0" }),
  );
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

// ── memory.audit.tamper_evident@1.0 ───────────────────────────────────────────

const chainOkEvent = "audit_chain_check:{\"chain_valid\":true,\"mutated_order\":false,\"source\":\"audit_chain_probe\"}";
const chainBrokenEvent = "audit_chain_check:{\"chain_valid\":false,\"mutated_order\":true,\"broken_link_at\":3,\"source\":\"audit_chain_probe\"}";

test("audit.tamper_evident: accepts a bundle with an intact audit chain", () => {
  const result = verifyBundleObject(signedBundle({ events: [chainOkEvent], capability: "memory.audit.tamper_evident@1.0" }));
  assert.deepEqual(result, { ok: true });
});

test("audit.tamper_evident: rejects a bundle with a broken audit chain", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [chainBrokenEvent], capability: "memory.audit.tamper_evident@1.0" }),
  );
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

// ── memory.recovery.verified@1.0 ──────────────────────────────────────────────

const recoveryOkEvent = "memory_recovery:{\"snapshot_id\":\"s1\",\"requested_state_hash\":\"hash-x\",\"recovered_state_hash\":\"hash-x\",\"restored\":true,\"source\":\"recovery_probe\"}";
const recoveryFailedEvent = "memory_recovery:{\"snapshot_id\":\"s1\",\"requested_state_hash\":\"hash-x\",\"recovered_state_hash\":\"hash-y\",\"restored\":true,\"source\":\"recovery_probe\"}";

test("recovery.verified: accepts a bundle proving the exact requested state was restored", () => {
  const result = verifyBundleObject(signedBundle({ events: [recoveryOkEvent], capability: "memory.recovery.verified@1.0" }));
  assert.deepEqual(result, { ok: true });
});

test("recovery.verified: rejects a bundle where the recovered state doesn't match the request", () => {
  const result = verifyBundleObject(
    signedBundle({ events: [recoveryFailedEvent], capability: "memory.recovery.verified@1.0" }),
  );
  assert.deepEqual(result, {
    ok: false,
    reason: "trace_outcome_mismatch:declared=verified:derived=failed",
  });
});

// ── Hardening: unknown capability + malformed bundle (21.08.2026 review findings) ────────────

test("rejects a self-signed bundle claiming an unrecognized capability", () => {
  const result = verifyBundleObject(signedBundle({ events: [], capability: "made.up.capability@9.9", outcome: "verified" }));
  assert.deepEqual(result, { ok: false, reason: "unknown_capability:made.up.capability@9.9" });
});

test("rejects null/non-object input as malformed", () => {
  assert.deepEqual(verifyBundleObject(null), { ok: false, reason: "malformed_bundle" });
  assert.deepEqual(verifyBundleObject("just a string"), { ok: false, reason: "malformed_bundle" });
  assert.deepEqual(verifyBundleObject(42), { ok: false, reason: "malformed_bundle" });
});

test("rejects a bundle missing required fields as malformed", () => {
  const bundle = signedBundle({ events: [verifiedEvent] });
  delete bundle.run_id;
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "malformed_bundle" });
});

test("rejects a bundle with an invalid claim_ladder value as malformed", () => {
  const bundle = signedBundle({ events: [verifiedEvent], overrides: { claim_ladder: "L99" } });
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "malformed_bundle" });
});

test("rejects a bundle with an unparseable executed_at as malformed", () => {
  const bundle = signedBundle({ events: [verifiedEvent], overrides: { executed_at: "not-a-date" } });
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "malformed_bundle" });
});

test("rejects a bundle with a non-array trace_events as malformed", () => {
  const bundle = signedBundle({ events: [verifiedEvent] });
  bundle.trace_events = "not-an-array";
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "malformed_bundle" });
});
