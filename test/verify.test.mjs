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
  // Trust-Anchor gar nicht erst uebergeben -- eine echte Fremdpartei haette ihn ohnehin nicht.
  assert.deepEqual(verifyBundleObject(forged), { ok: false, reason: "unsupported_schema_version" });
});

// 01.09.2026: lokale Kopie von buildCustomerSummaryDe() aus verify.ts, nur zum Bau von
// Test-Fixtures (gleiches Prinzip wie canonical() oben -- das Original ist nicht exportiert).
// Diese Kopie erzeugt das erwartete Summary fuer einen GUELTIGEN Testfall; sie testet nicht sich
// selbst, sondern liefert nur die Eingabedaten fuer verifyBundleObject().
function testSummary({ brief, cost_partial, denied, approval }) {
  const lines = [brief.title, "", "Auftrag:", brief.raw_text, "", "Kosten:"];
  if (cost_partial.cost_usd_tracked && cost_partial.cost_usd !== null) {
    const parts = [`$${cost_partial.cost_usd.toFixed(2)}`];
    if (cost_partial.turns_used !== null) parts.push(`${cost_partial.turns_used} Turns`);
    if (cost_partial.duration_seconds !== null) {
      const m = Math.floor(cost_partial.duration_seconds / 60);
      const s = Math.floor(cost_partial.duration_seconds % 60);
      parts.push(`${m}m ${s}s`);
    }
    lines.push(parts.join(", "));
  } else {
    lines.push(`Kosten nicht erfasst (externe CLI-Engine \`${cost_partial.assigned_engine}\`, kein Kostentracking für diesen Pfad).`);
  }
  lines.push("Es werden ausschließlich Aggregatkosten erfasst, keine Tokenzahlen.", "", "Freigabe:");
  if (approval.actor_id === null) lines.push("Keine Freigabe protokolliert.");
  else if (approval.proven) lines.push(`Bewiesen freigegeben über Kanal \`${approval.channel}\`.`);
  else lines.push(`Freigegeben über Kanal \`${approval.channel}\`, Identität nicht unabhängig bewiesen.`);
  if (approval.confirmed_by !== null) lines.push(`Bestätigt von: ${approval.confirmed_by}`);
  if (approval.confirmed_at !== null) lines.push(`Bestätigt am: ${approval.confirmed_at}`);
  lines.push("", "Abgelehnte Aktionen:");
  if (denied.length === 0) lines.push("Keine abgelehnten Aktionen in diesem Lauf.");
  else for (const d of [...denied].sort((a, b) => (a.path < b.path ? -1 : 1))) lines.push(`- ${d.path} (${d.reason})`);
  return lines.join("\n");
}

function devTaskV21Bundle({ tamperSummary = false, omitCustomerEvidence = false, mismatchApprovalRef = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const controllerEvidence = {
    producer: "privileged_controller", task_id: "task-1", attempt_number: 1,
    base_commit: null, result_reference: null, diff_stat_sha256: null, diff_full: null, diff_full_sha256: null,
    execution_reference: null, validation_reference: null, approval_reference: "dev_tasks.approved_by",
    sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
  };
  const brief = { title: "Testauftrag", raw_text: "Bitte README ergänzen." };
  const cost_partial = { cost_usd: 1.23, cost_usd_tracked: true, turns_used: 3, duration_seconds: 90, assigned_model: "deepseek-v4-flash", assigned_engine: "deepseek", token_tracking: "not_available" };
  const denied = [];
  const approval = {
    proven: true, actor_id: "andre", channel: "pilot", confirmed_by: "andre", confirmed_at: "2026-09-01T00:00:00.000Z",
    approved_at: "2026-09-01T00:00:00.000Z", approval_reference: mismatchApprovalRef ? "WRONG" : controllerEvidence.approval_reference,
  };
  const customer_evidence = omitCustomerEvidence ? undefined : {
    schema_version: "customer-evidence@1.0", brief, cost_partial, denied, approval,
    customer_summary: tamperSummary ? "manipuliert" : testSummary({ brief, cost_partial, denied, approval }),
  };
  const payload = {
    schema_version: "evidence-package@2.1",
    bundle_id: "test_devtask_bundle", capability: "devtask.execution@1.0", run_id: "task-1:1",
    claim_ladder: "L0", executed_at: "2026-09-01T00:00:00.000Z",
    trace_events: [], trace_hash_chain: hashChain([]), outcome: "inconclusive",
    signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence: controllerEvidence,
    // riskRank() faellt bei unbekannter/fehlender risk_class (kein contract-Event) fail-safe auf
    // die hoechste Stufe (4) zurueck -- das erzwingt zusaetzlich "sandbox_attestation".
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full", "sandbox_attestation"],
    customer_evidence,
  };
  return {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: pem,
    _trustedPublicKey: pem,
  };
}

test("evidence-package@2.1: a correct customer_evidence block passes through to the standard outcome check", () => {
  const bundle = devTaskV21Bundle();
  const { _trustedPublicKey, ...clean } = bundle;
  const result = verifyBundleObject(clean, _trustedPublicKey);
  // Absichtlich "inconclusive" (leere trace_events, kein voller devtask-Lauf simuliert) -- waere
  // hier eine der NEUEN 2.1-Pruefungen faelschlich fehlgeschlagen, stuende ein anderer reason.
  assert.deepEqual(result, { ok: false, reason: "non_verified_outcome:inconclusive" });
});

test("evidence-package@2.1: rejects a bundle missing customer_evidence entirely", () => {
  const bundle = devTaskV21Bundle({ omitCustomerEvidence: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "missing_customer_evidence");
});

test("evidence-package@2.1: rejects a tampered customer_summary", () => {
  const bundle = devTaskV21Bundle({ tamperSummary: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "customer_summary_mismatch");
});

test("evidence-package@2.1: rejects a customer_evidence.approval.approval_reference that diverges from controller_evidence", () => {
  const bundle = devTaskV21Bundle({ mismatchApprovalRef: true });
  const { _trustedPublicKey, ...clean } = bundle;
  assert.equal(verifyBundleObject(clean, _trustedPublicKey).reason, "customer_approval_reference_mismatch");
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
