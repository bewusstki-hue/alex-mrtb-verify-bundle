import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyBundleObject, verifyValidationAttestation, verifyReviewerAttestation } from "../dist/verify.js";

const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}` : JSON.stringify(value);
const sha256 = value => createHash("sha256").update(value).digest("hex");

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

test("rejects a self-signed forgery that declares an unrecognized evidence-package schema version", () => {
  // 01.09.2026: Regressionstest fuer einen echten Fund -- vor dem Fix lief jeder schema_version-
  // Wert ausser exakt "evidence-package@2.0" komplett am Trust-Anchor-Pinning vorbei, die
  // Signaturpruefung verifizierte dann nur noch gegen den im Bundle selbst mitgelieferten
  // public_key. Eine Faelschung, die diese Luecke ausnutzen wollte, brauchte nie den echten
  // privaten Schluessel -- nur einen abweichenden schema_version-String.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = {
    schema_version: "evidence-package@9.9",
    bundle_id: "forged_bundle",
    capability: "devtask.execution@1.0",
    run_id: "forged_run",
    claim_ladder: "L2",
    executed_at: "2026-09-01T00:00:00.000Z",
    trace_events: [],
    trace_hash_chain: hashChain([]),
    outcome: "verified",
  };
  const forged = {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: publicKey.export({ type: "spki", format: "pem" }),
  };
  assert.deepEqual(verifyBundleObject(forged), { ok: false, reason: "unsupported_schema_version" });
});

test("accepts independent validation only for the trusted runner and exact commit", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const environment = { image_digest: `node@sha256:${"a".repeat(64)}`, network: "none" };
  const payload = { schema_version: "validation-attestation@1.0", producer: "independent_evidence_runner", repository_commit: "commit-a",
    environment, environment_sha256: sha256(canonical(environment)), started_at: "2026-08-27T00:00:00Z", completed_at: "2026-08-27T00:01:00Z",
    duration_ms: 60000, exit_code: 0, passed: true, stdout_sha256: "b".repeat(64), stderr_sha256: "c".repeat(64), report_sha256: "d".repeat(64) };
  const attestation = { ...payload, signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
    signature: sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64") };
  assert.deepEqual(verifyValidationAttestation(attestation, pem, "commit-a"), { ok: true });
  assert.equal(verifyValidationAttestation(attestation, pem, "commit-b").reason, "validation_scope_mismatch");
});

test("reviewer signature binds the exact bundle and validation bytes", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const bundle = Buffer.from("bundle"); const validation = Buffer.from("validation");
  const payload = { schema_version: "reviewer-attestation@1.0", reviewer_id: "reviewer-server-1", decision: "approved",
    reviewed_at: "2026-08-27T00:02:00Z", bundle_sha256: sha256(bundle), validation_attestation_sha256: sha256(validation) };
  const attestation = { ...payload, reviewer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
    signature: sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64") };
  assert.deepEqual(verifyReviewerAttestation(attestation, pem, bundle, validation), { ok: true });
  assert.equal(verifyReviewerAttestation(attestation, pem, Buffer.from("changed"), validation).reason, "review_scope_mismatch");
});

test("approval signature binds the exact bundle and cannot be removed or reassigned", () => {
  const bundle = signedBundle({ events: [verifiedEvent] });
  const unsignedPrimary = { ...bundle, approval_attestation_required: true };
  const primaryPair = generateKeyPairSync("ed25519");
  const { signature: _oldSignature, public_key: _oldKey, ...primaryPayload } = unsignedPrimary;
  const primaryPem = primaryPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const signedPrimary = { ...primaryPayload, signature: sign(null, Buffer.from(JSON.stringify(primaryPayload)), primaryPair.privateKey).toString("base64"), public_key: primaryPem };
  const approvalPair = generateKeyPairSync("ed25519");
  const approvalPem = approvalPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const approvalPayload = { schema_version: "approval-attestation@1.0", actor_id: "telegram:123", approved_at: "2026-08-30T16:00:00.000Z", bundle_sha256: sha256(JSON.stringify(signedPrimary)) };
  const approval_attestation = { ...approvalPayload, signer_key_id: `ed25519:${sha256(approvalPem)}`, public_key: approvalPem, signature: sign(null, Buffer.from(JSON.stringify(approvalPayload)), approvalPair.privateKey).toString("base64") };
  const completed = { ...signedPrimary, approval_attestation };
  assert.deepEqual(verifyBundleObject(completed, undefined, approvalPem), { ok: true });
  assert.equal(verifyBundleObject(signedPrimary, undefined, approvalPem).reason, "missing_approval_attestation");
  assert.equal(verifyBundleObject({ ...completed, approval_attestation: { ...approval_attestation, actor_id: "attacker" } }, undefined, approvalPem).reason, "invalid_approval_signature");
});
