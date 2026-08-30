import { createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

type ClaimLadder = "L0" | "L1" | "L2" | "L3" | "L4";

export interface ValidationAttestationV1 {
  schema_version: "validation-attestation@1.0"; producer: "independent_evidence_runner"; repository_commit: string;
  environment: Record<string, unknown>; environment_sha256: string; started_at: string; completed_at: string; duration_ms: number;
  exit_code: number; passed: boolean; stdout_sha256: string; stderr_sha256: string; report_sha256: string;
  signer_key_id: string; public_key: string; signature: string;
}

export interface ReviewerAttestationV1 {
  schema_version: "reviewer-attestation@1.0"; reviewer_id: string; decision: "approved" | "rejected"; reviewed_at: string;
  bundle_sha256: string; validation_attestation_sha256: string; reviewer_key_id: string; public_key: string; signature: string;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

export function verifyValidationAttestation(attestation: ValidationAttestationV1, trustedPublicKey: string, expectedCommit: string): { ok: boolean; reason?: string } {
  const { signature, public_key, signer_key_id, ...payload } = attestation;
  if (public_key !== trustedPublicKey || signer_key_id !== `ed25519:${sha256(trustedPublicKey)}`) return { ok: false, reason: "untrusted_evidence_runner" };
  if (attestation.schema_version !== "validation-attestation@1.0" || attestation.repository_commit !== expectedCommit) return { ok: false, reason: "validation_scope_mismatch" };
  if (attestation.environment_sha256 !== sha256(canonical(attestation.environment))) return { ok: false, reason: "environment_hash_mismatch" };
  if (![attestation.stdout_sha256, attestation.stderr_sha256, attestation.report_sha256].every(h => /^[a-f0-9]{64}$/.test(h))) return { ok: false, reason: "invalid_report_hash" };
  if (!verify(null, Buffer.from(canonical(payload)), public_key, Buffer.from(signature, "base64"))) return { ok: false, reason: "invalid_validation_signature" };
  if (!attestation.passed || attestation.exit_code !== 0) return { ok: false, reason: "validation_failed" };
  return { ok: true };
}

export function verifyReviewerAttestation(attestation: ReviewerAttestationV1, trustedPublicKey: string, bundleBytes: Buffer, validationBytes: Buffer): { ok: boolean; reason?: string } {
  const { signature, public_key, reviewer_key_id, ...payload } = attestation;
  if (public_key !== trustedPublicKey || reviewer_key_id !== `ed25519:${sha256(trustedPublicKey)}`) return { ok: false, reason: "untrusted_reviewer" };
  if (attestation.bundle_sha256 !== sha256(bundleBytes) || attestation.validation_attestation_sha256 !== sha256(validationBytes)) return { ok: false, reason: "review_scope_mismatch" };
  if (!verify(null, Buffer.from(canonical(payload)), public_key, Buffer.from(signature, "base64"))) return { ok: false, reason: "invalid_reviewer_signature" };
  if (attestation.decision !== "approved") return { ok: false, reason: "review_rejected" };
  return { ok: true };
}

/** 29.08.2026: RFC-3161-Zeitstempel ueber den kompletten signierten Bundle-Inhalt, best-effort
 *  von einer oeffentlichen TSA angehaengt (siehe rfc3161Timestamp.server.ts im Alex-Monorepo,
 *  identische Definition hier). Dieser Verifier prueft nur die Hash-Bindung (Timestamp gehoert
 *  wirklich zu diesem Bundle), NICHT die CMS-Signatur der TSA oder deren Zertifikatskette --
 *  das rohe `token_der_base64` ist Standard-RFC-3161-DER und mit externen Werkzeugen pruefbar. */
export interface Rfc3161Timestamp {
  schema_version: "rfc3161-timestamp@1.0";
  tsa_url: string;
  timestamped_sha256: string;
  gen_time: string;
  token_der_base64: string;
}

export interface EvidenceBundle {
  schema_version?: "evidence-package@2.0";
  bundle_id: string;
  capability: string;
  run_id: string;
  claim_ladder: ClaimLadder;
  executed_at: string;
  trace_events: string[];
  trace_hash_chain: string[];
  outcome: "verified" | "failed" | "inconclusive";
  signature: string;
  public_key: string;
  signer_key_id?: string;
  controller_evidence?: DevTaskControllerEvidenceV2;
  required_evidence?: string[];
  rfc3161_timestamp?: Rfc3161Timestamp;
  approval_attestation_required?: boolean;
  approval_attestation?: ApprovalAttestationV1;
}

export interface ApprovalAttestationV1 {
  schema_version: "approval-attestation@1.0"; actor_id: string; approved_at: string; bundle_sha256: string;
  signer_key_id: string; public_key: string; signature: string;
}

/** Prueft nur, dass ein vorhandener Zeitstempel wirklich zu DIESEM Bundle-Inhalt gehoert
 *  (Hash-Uebereinstimmung) -- kein Ersatz fuer die eigentliche Signaturpruefung. */
export function verifyRfc3161Binding(bundle: EvidenceBundle): { ok: boolean; reason?: string } {
  if (!bundle.rfc3161_timestamp) return { ok: false, reason: "no_timestamp_present" };
  const { rfc3161_timestamp, ...withoutTimestamp } = bundle;
  const recomputed = sha256(JSON.stringify(withoutTimestamp));
  if (recomputed !== rfc3161_timestamp.timestamped_sha256) return { ok: false, reason: "timestamp_hash_mismatch" };
  return { ok: true };
}

interface DevTaskControllerEvidenceV2 {
  producer: "privileged_controller";
  task_id: string;
  attempt_number: number;
  base_commit: string | null;
  result_reference: string | null;
  diff_stat_sha256: string | null;
  diff_full: string | null;
  diff_full_sha256: string | null;
  execution_reference: string | null;
  validation_reference: string | null;
  approval_reference: string | null;
  sandbox_reference: string | null;
  sandbox_attestation: SandboxAttestationV2 | null;
  agent_run_id: string | null;
  repository_state?: RepositoryStateEvidenceV1 | null;
}

interface RepositoryStateEvidenceV1 {
  schema_version: "repository-state@1.0"; base_commit: string; result_commit: string;
  tree_before_sha256: string; tree_after_sha256: string;
  changed_files: Array<{ path: string; status: "A" | "M" | "D"; before_sha256: string | null; after_sha256: string | null }>;
}

interface NetworkCaptureEvidenceV1 {
  schema_version: "egress-capture@1.0"; dns_queries_sha256: string; connections_sha256: string;
  connection_count: number; capture_incomplete: boolean;
}

interface SandboxAttestationV2 {
  schema_version: "sandbox-attestation@2.0"; sandbox_id: string; agent_id: string;
  started_at: string; completed_at: string; snapshot_sha256: string; policy_sha256: string;
  os_isolation_available: boolean; git_metadata_absent: boolean; controller_checkout_separated: boolean;
  network_policy: "bubblewrap_unshare_net_fail_closed" | "netns_egress_logged_v1"; environment_policy: "bubblewrap_clearenv";
  process_policy: "systemd_scope_limits_and_kill"; handoff_manifest_sha256: string; rejected_manifest_sha256: string;
  network_capture: NetworkCaptureEvidenceV1 | null;
}

const SANDBOX_ATTESTATION_POLICY_NO_NETWORK = {
  schema_version: "sandbox-attestation@2.0", filesystem: "snapshot_without_git_or_symlinks",
  network: "bubblewrap_unshare_net_fail_closed", environment: "bubblewrap_clearenv",
  process: "systemd_scope_limits_and_kill", handoff: "regular_files_only_filtered",
};

// 29.08.2026 ("Code-Pruefstand"): zweites Profil, echtes Netzwerk + Verbindungsmitschnitt statt
// --unshare-net. Identische Ergaenzung wie in server/services/agentSandbox.server.ts und
// server/services/mrtb/evidenceBundle.server.ts -- bewusst von Hand dupliziert, kein Shared Import
// zwischen Server und diesem eigenstaendigen Verifier (siehe Datei-Header oben).
const SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE = {
  ...SANDBOX_ATTESTATION_POLICY_NO_NETWORK,
  network: "netns_egress_logged_v1" as const,
};

const PROVENANCE_CAPABILITY = "memory.provenance.attached@1.0";
const DELETE_ENFORCED_CAPABILITY = "memory.delete.enforced@1.0";
const TENANT_ISOLATION_CAPABILITY = "memory.tenant.isolation@1.0";
const WRITE_INTEGRITY_CAPABILITY = "memory.write.integrity@1.0";
const TAMPER_EVIDENT_CAPABILITY = "memory.audit.tamper_evident@1.0";
const RECOVERY_VERIFIED_CAPABILITY = "memory.recovery.verified@1.0";
const DEVTASK_EXECUTION_CAPABILITY = "devtask.execution@1.0";
const MEMORY_WRITE_EVENT_PREFIX = "memory_write:";
const MEMORY_STATE_READ_EVENT_PREFIX = "memory_state_read:";
const TENANT_ACCESS_PROBE_EVENT_PREFIX = "tenant_access_probe:";
const MEMORY_CONTENT_CHANGE_EVENT_PREFIX = "memory_content_change:";
const AUDIT_CHAIN_CHECK_EVENT_PREFIX = "audit_chain_check:";
const MEMORY_RECOVERY_EVENT_PREFIX = "memory_recovery:";
const DEVTASK_CONTRACT_BOUND_PREFIX = "devtask_contract_bound:";
const DEVTASK_ATTEMPT_STARTED_PREFIX = "devtask_attempt_started:";
const DEVTASK_EXECUTION_CONTEXT_PREFIX = "devtask_execution_context:";
const DEVTASK_VALIDATION_PREFIX = "devtask_validation:";
const DEVTASK_HUMAN_APPROVAL_PREFIX = "devtask_human_approval:";
const DEVTASK_OUTCOME_PREFIX = "devtask_outcome:";

interface ProvenanceTraceEvent {
  entry_id: string;
  actual_agent_id: string;
  provenance_agent_id: string;
  actual_source_hash: string;
  provenance_source_hash: string;
}

interface MemoryStateReadTraceEvent {
  entry_id: string;
  exists: boolean;
  phase: "after_delete" | "after_replay_check";
  source: "storage_probe";
}

interface TenantAccessProbeTraceEvent {
  entry_id: string;
  requesting_tenant: string;
  target_tenant: string;
  allowed: boolean;
  source: "isolation_probe";
}

interface MemoryContentChangeTraceEvent {
  entry_id: string;
  phase: "before" | "after";
  content_hash: string;
  source: "content_probe";
}

interface AuditChainCheckTraceEvent {
  chain_valid: boolean;
  mutated_order: boolean;
  broken_link_at?: number;
  source: "audit_chain_probe";
}

interface MemoryRecoveryTraceEvent {
  snapshot_id: string;
  requested_state_hash: string;
  recovered_state_hash: string;
  restored: boolean;
  source: "recovery_probe";
}

interface DevTaskContractBoundTraceEvent {
  task_id: string;
  attempt_number: number;
  contract_hash: string;
  contract_schema_version: string;
  risk_class: string | null;
}

interface DevTaskAttemptStartedTraceEvent {
  task_id: string;
  attempt_number: number;
  started_at: string;
}

interface DevTaskExecutionContextTraceEvent {
  task_id: string;
  attempt_number: number;
  sandbox_reference: string | null;
  execution_reference: string;
  executor: "deepseek" | "hermes" | "opencode" | "aider" | "cline";
  harness_id: string;
  adapter_version: string;
  adapter_version_sha256: string;
}

interface DevTaskValidationTraceEvent {
  task_id: string;
  attempt_number: number;
  validation_status: string;
  validation_reference: string;
}

interface DevTaskHumanApprovalTraceEvent {
  task_id: string;
  attempt_number: number;
  actor_id: string;
  approved_at: string | null;
  approval_reference: string;
}

interface DevTaskOutcomeTraceEvent {
  task_id: string;
  attempt_number: number;
  outcome: "COMPLETED" | "FAILED" | "ABORTED";
  completed_at: string | null;
  reference: string;
}

// Optional (25.08.2026, extended same day): always hashes the diff_stat summary line;
// diff_full_sha256 (when present) hashes the FULL `git diff --cached HEAD` content, captured in
// repoContributionPipeline.server.ts right before the commit -- the only point in the process
// where the full diff is still available. Purely informational here -- does not affect
// deriveOutcomeFromTrace, so bundles issued before this field existed keep verifying unchanged.
interface DevTaskDiffEvidenceTraceEvent {
  task_id: string;
  attempt_number: number;
  diff_stat_sha256: string;
  diff_full_sha256: string | null;
  scope: "diff_stat_only" | "diff_stat_and_full";
}

const DEVTASK_DIFF_EVIDENCE_PREFIX = "devtask_diff_evidence:";

function parseDevTaskEvent<T>(event: string, prefix: string): T | null {
  if (!event.startsWith(prefix)) return null;
  try {
    return JSON.parse(event.slice(prefix.length)) as T;
  } catch {
    return null;
  }
}

function buildHashChain(events: string[]): string[] {
  const chain: string[] = [];
  let prev = "genesis";
  for (const event of events) {
    const hash = createHash("sha256").update(prev + event).digest("hex");
    chain.push(hash);
    prev = hash;
  }
  return chain;
}

function parseProvenanceEvent(event: string): ProvenanceTraceEvent | null {
  if (!event.startsWith(MEMORY_WRITE_EVENT_PREFIX)) {
    return null;
  }

  try {
    return JSON.parse(event.slice(MEMORY_WRITE_EVENT_PREFIX.length)) as ProvenanceTraceEvent;
  } catch {
    return null;
  }
}

function deriveOutcomeFromTrace(capability: string, events: string[]): "verified" | "failed" | "inconclusive" {
  if (capability === PROVENANCE_CAPABILITY) {
    const writes = events.map(parseProvenanceEvent).filter((event): event is ProvenanceTraceEvent => Boolean(event));
    if (writes.length === 0) {
      return "inconclusive";
    }

    const hasMismatch = writes.some((write) => {
      if (!write.actual_agent_id || !write.provenance_agent_id || !write.actual_source_hash || !write.provenance_source_hash) {
        return true;
      }

      return write.actual_agent_id !== write.provenance_agent_id || write.actual_source_hash !== write.provenance_source_hash;
    });

    return hasMismatch ? "failed" : "verified";
  }

  if (capability === DELETE_ENFORCED_CAPABILITY) {
    const reads = events
      .map((event) => {
        if (!event.startsWith(MEMORY_STATE_READ_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_STATE_READ_EVENT_PREFIX.length)) as MemoryStateReadTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryStateReadTraceEvent => Boolean(event));

    const afterDeleteRead = reads.find((read) => read.phase === "after_delete" && read.source === "storage_probe");
    if (!afterDeleteRead) {
      return "inconclusive";
    }

    if (afterDeleteRead.exists) {
      return "failed";
    }

    const replayViolation = reads.some((read) => read.phase === "after_replay_check" && read.source === "storage_probe" && read.exists);
    return replayViolation ? "failed" : "verified";
  }

  if (capability === TENANT_ISOLATION_CAPABILITY) {
    const probes = events
      .map((event) => {
        if (!event.startsWith(TENANT_ACCESS_PROBE_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(TENANT_ACCESS_PROBE_EVENT_PREFIX.length)) as TenantAccessProbeTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is TenantAccessProbeTraceEvent => Boolean(event));

    if (probes.length === 0) {
      return "inconclusive";
    }

    const crossTenantProbes = probes.filter((probe) => probe.requesting_tenant !== probe.target_tenant);
    if (crossTenantProbes.length === 0) {
      return "inconclusive";
    }

    const leak = crossTenantProbes.some((probe) => probe.allowed);
    return leak ? "failed" : "verified";
  }

  if (capability === WRITE_INTEGRITY_CAPABILITY) {
    const changes = events
      .map((event) => {
        if (!event.startsWith(MEMORY_CONTENT_CHANGE_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_CONTENT_CHANGE_EVENT_PREFIX.length)) as MemoryContentChangeTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryContentChangeTraceEvent => Boolean(event));

    if (changes.length === 0) {
      return "inconclusive";
    }

    const before = changes.find((change) => change.phase === "before" && change.source === "content_probe");
    const after = changes.find((change) => change.phase === "after" && change.source === "content_probe");

    if (!before || !after) {
      return "inconclusive";
    }

    return before.content_hash === after.content_hash ? "failed" : "verified";
  }

  if (capability === TAMPER_EVIDENT_CAPABILITY) {
    const checks = events
      .map((event) => {
        if (!event.startsWith(AUDIT_CHAIN_CHECK_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(AUDIT_CHAIN_CHECK_EVENT_PREFIX.length)) as AuditChainCheckTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is AuditChainCheckTraceEvent => Boolean(event));

    if (checks.length === 0) {
      return "inconclusive";
    }

    const chainBroken = checks.some((check) => check.source === "audit_chain_probe" && !check.chain_valid);
    return chainBroken ? "failed" : "verified";
  }

  if (capability === RECOVERY_VERIFIED_CAPABILITY) {
    const recoveries = events
      .map((event) => {
        if (!event.startsWith(MEMORY_RECOVERY_EVENT_PREFIX)) return null;
        try {
          return JSON.parse(event.slice(MEMORY_RECOVERY_EVENT_PREFIX.length)) as MemoryRecoveryTraceEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is MemoryRecoveryTraceEvent => Boolean(event));

    if (recoveries.length === 0) {
      return "inconclusive";
    }

    const badRestore = recoveries.some(
      (r) => r.source !== "recovery_probe" || !r.restored || r.requested_state_hash !== r.recovered_state_hash,
    );
    return badRestore ? "failed" : "verified";
  }

  if (capability === DEVTASK_EXECUTION_CAPABILITY) {
    const contractBound = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
    const attemptStarted = events.map((e) => parseDevTaskEvent<DevTaskAttemptStartedTraceEvent>(e, DEVTASK_ATTEMPT_STARTED_PREFIX)).find(Boolean) ?? null;
    const validation = events.map((e) => parseDevTaskEvent<DevTaskValidationTraceEvent>(e, DEVTASK_VALIDATION_PREFIX)).find(Boolean) ?? null;
    const humanApproval = events.map((e) => parseDevTaskEvent<DevTaskHumanApprovalTraceEvent>(e, DEVTASK_HUMAN_APPROVAL_PREFIX)).find(Boolean) ?? null;
    const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;

    if (!contractBound || !attemptStarted || !outcome) {
      return "inconclusive";
    }

    const present = [contractBound, attemptStarted, outcome, ...(validation ? [validation] : []), ...(humanApproval ? [humanApproval] : [])];
    const sameRun = present.every((e) => e.task_id === contractBound.task_id && e.attempt_number === contractBound.attempt_number);
    if (!sameRun) {
      return "failed";
    }

    if (outcome.outcome === "COMPLETED" && !humanApproval) {
      return "failed";
    }

    if (outcome.outcome === "COMPLETED" && validation && validation.validation_status !== "passed" && validation.validation_status !== "passed_override") {
      return "failed";
    }

    return "verified";
  }

  return "inconclusive";
}

function evidenceSignerKeyId(publicKey: string): string {
  return `ed25519:${createHash("sha256").update(publicKey).digest("hex")}`;
}

function riskRank(riskClass: string | null | undefined): number {
  const match = /^R([0-4])$/.exec(riskClass ?? "");
  return match ? Number(match[1]) : 4;
}

function requiredDevTaskEvidenceV2(events: string[], controller?: DevTaskControllerEvidenceV2): string[] {
  const contract = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
  const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;
  const required = ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full"];
  if (outcome?.outcome === "COMPLETED") required.push("human_approval", "result_reference");
  if (riskRank(contract?.risk_class) >= 3) required.push("sandbox_attestation");
  if (controller?.repository_state) required.push("repository_state");
  return required;
}

function deriveDevTaskV2Outcome(events: string[], controller: DevTaskControllerEvidenceV2): "verified" | "failed" | "inconclusive" {
  const base = deriveOutcomeFromTrace(DEVTASK_EXECUTION_CAPABILITY, events);
  if (base !== "verified") return base;
  const contract = events.map((e) => parseDevTaskEvent<DevTaskContractBoundTraceEvent>(e, DEVTASK_CONTRACT_BOUND_PREFIX)).find(Boolean) ?? null;
  const context = events.map((e) => parseDevTaskEvent<DevTaskExecutionContextTraceEvent>(e, DEVTASK_EXECUTION_CONTEXT_PREFIX)).find(Boolean) ?? null;
  const validation = events.map((e) => parseDevTaskEvent<DevTaskValidationTraceEvent>(e, DEVTASK_VALIDATION_PREFIX)).find(Boolean) ?? null;
  const approval = events.map((e) => parseDevTaskEvent<DevTaskHumanApprovalTraceEvent>(e, DEVTASK_HUMAN_APPROVAL_PREFIX)).find(Boolean) ?? null;
  const diff = events.map((e) => parseDevTaskEvent<DevTaskDiffEvidenceTraceEvent>(e, DEVTASK_DIFF_EVIDENCE_PREFIX)).find(Boolean) ?? null;
  const outcome = events.map((e) => parseDevTaskEvent<DevTaskOutcomeTraceEvent>(e, DEVTASK_OUTCOME_PREFIX)).find(Boolean) ?? null;
  if (controller.task_id !== contract?.task_id || controller.attempt_number !== contract?.attempt_number) return "failed";
  if (controller.execution_reference !== context?.execution_reference) return "failed";
  const hasExecutorProvenance = Boolean(context && (context.executor || context.harness_id || context.adapter_version || context.adapter_version_sha256));
  if (hasExecutorProvenance && (!context || !["deepseek", "hermes", "opencode", "aider", "cline"].includes(context.executor) ||
      !/^[a-z0-9][a-z0-9._-]*$/.test(context.harness_id) ||
      !/^[a-z0-9][a-z0-9._@/-]*$/.test(context.adapter_version) ||
      context.adapter_version_sha256 !== sha256(context.adapter_version))) return "failed";
  if (controller.validation_reference !== validation?.validation_reference) return "failed";
  if (controller.diff_stat_sha256 !== diff?.diff_stat_sha256) return "failed";
  if (controller.diff_full_sha256 !== diff?.diff_full_sha256) return "failed";
  if (controller.diff_full !== null && controller.diff_full_sha256 !== null &&
      createHash("sha256").update(controller.diff_full).digest("hex") !== controller.diff_full_sha256) return "failed";
  if (outcome?.outcome === "COMPLETED" && controller.approval_reference !== approval?.approval_reference) return "failed";
  const repository = controller.repository_state;
  if (repository) {
    const hashOk = (value: string | null) => value === null || /^[a-f0-9]{64}$/.test(value);
    if (repository.schema_version !== "repository-state@1.0" || repository.base_commit !== controller.base_commit ||
      !repository.result_commit || !hashOk(repository.tree_before_sha256) || !hashOk(repository.tree_after_sha256) ||
      repository.tree_before_sha256 === repository.tree_after_sha256 || repository.changed_files.length === 0 ||
      repository.changed_files.some((file) => !file.path || !["A", "M", "D"].includes(file.status) ||
        !hashOk(file.before_sha256) || !hashOk(file.after_sha256) ||
        (file.status === "A" && file.before_sha256 !== null) || (file.status === "D" && file.after_sha256 !== null) ||
        (file.status !== "A" && file.before_sha256 === null) || (file.status !== "D" && file.after_sha256 === null))) return "failed";
  }
  const attestation = controller.sandbox_attestation;
  const attestationHash = attestation ? `sandbox-attestation:sha256:${createHash("sha256").update(JSON.stringify(attestation)).digest("hex")}` : null;
  if (controller.sandbox_reference !== context?.sandbox_reference || controller.sandbox_reference !== attestationHash) return "failed";
  // 29.08.2026 ("Code-Pruefstand"): welche Policy-Konstante fuer die policy_sha256-Nachrechnung gilt,
  // haengt vom behaupteten Profil ab; network_capture muss dazu konsistent sein (befuellt genau
  // dann wenn netns_egress_logged_v1 behauptet wird, sonst null) -- identische Pruefung wie in
  // server/services/mrtb/evidenceBundle.server.ts (kein Shared Import, siehe Datei-Header oben).
  const expectedPolicy = attestation?.network_policy === "netns_egress_logged_v1"
    ? SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE
    : SANDBOX_ATTESTATION_POLICY_NO_NETWORK;
  const networkCaptureConsistent = attestation
    ? (attestation.network_policy === "netns_egress_logged_v1"
      ? Boolean(attestation.network_capture &&
          attestation.network_capture.schema_version === "egress-capture@1.0" &&
          /^[a-f0-9]{64}$/.test(attestation.network_capture.dns_queries_sha256) &&
          /^[a-f0-9]{64}$/.test(attestation.network_capture.connections_sha256))
      : attestation.network_capture === null)
    : false;
  const sandboxValid = Boolean(attestation && attestation.schema_version === "sandbox-attestation@2.0" &&
    attestation.os_isolation_available && attestation.git_metadata_absent && attestation.controller_checkout_separated &&
    (attestation.network_policy === "bubblewrap_unshare_net_fail_closed" || attestation.network_policy === "netns_egress_logged_v1") &&
    networkCaptureConsistent &&
    attestation.environment_policy === "bubblewrap_clearenv" &&
    attestation.process_policy === "systemd_scope_limits_and_kill" &&
    attestation.agent_id === controller.agent_run_id &&
    attestation.policy_sha256 === createHash("sha256").update(JSON.stringify(expectedPolicy, Object.keys(expectedPolicy).sort())).digest("hex") &&
    [attestation.snapshot_sha256, attestation.policy_sha256, attestation.handoff_manifest_sha256, attestation.rejected_manifest_sha256]
      .every((hash) => /^[a-f0-9]{64}$/.test(hash)));
  const present: Record<string, boolean> = {
    contract: Boolean(contract), attempt: events.some((e) => e.startsWith(DEVTASK_ATTEMPT_STARTED_PREFIX)),
    execution_context: Boolean(context && controller.execution_reference), validation: Boolean(validation && controller.validation_reference),
    outcome: Boolean(outcome), base_commit: Boolean(controller.base_commit), result_reference: Boolean(controller.result_reference),
    diff_full: Boolean(controller.diff_full && diff?.diff_full_sha256 && controller.diff_full_sha256),
    human_approval: Boolean(approval && controller.approval_reference),
    repository_state: Boolean(repository),
    sandbox_attestation: sandboxValid,
  };
  return requiredDevTaskEvidenceV2(events, controller).every((name) => present[name]) ? "verified" : "inconclusive";
}

export function verifyBundleObject(bundle: EvidenceBundle, trustedPublicKey?: string, trustedApprovalPublicKey?: string): { ok: boolean; reason?: string } {
  // rfc3161_timestamp wird IMMER erst nach dem Signieren angehaengt -- war nie Teil der
  // signierten Nutzlast, muss hier ebenso ausgeschlossen werden (siehe verifyRfc3161Binding()
  // fuer die getrennte Pruefung der Zeitstempel-Bindung selbst).
  const { signature, public_key, rfc3161_timestamp, approval_attestation, ...payload } = bundle;

  if (bundle.schema_version === "evidence-package@2.0") {
    if (!trustedPublicKey) return { ok: false, reason: "missing_trust_anchor" };
    if (public_key !== trustedPublicKey || bundle.signer_key_id !== evidenceSignerKeyId(trustedPublicKey)) {
      return { ok: false, reason: "untrusted_signer" };
    }
    if (!bundle.controller_evidence) return { ok: false, reason: "missing_controller_evidence" };
  }

  const isValidSignature = verify(
    null,
    Buffer.from(JSON.stringify(payload)),
    public_key,
    Buffer.from(signature, "base64"),
  );

  if (!isValidSignature) {
    return { ok: false, reason: "invalid_signature" };
  }
  if (bundle.approval_attestation_required) {
    if (!approval_attestation) return { ok: false, reason: "missing_approval_attestation" };
    if (!trustedApprovalPublicKey) return { ok: false, reason: "missing_approval_trust_anchor" };
    const { signature: approvalSignature, public_key: approvalPublicKey, signer_key_id, ...approvalPayload } = approval_attestation;
    const { approval_attestation: _ignored, ...bundleWithoutApproval } = bundle;
    if (approvalPublicKey !== trustedApprovalPublicKey || signer_key_id !== evidenceSignerKeyId(trustedApprovalPublicKey)) return { ok: false, reason: "untrusted_approval_signer" };
    if (approvalPayload.bundle_sha256 !== sha256(JSON.stringify(bundleWithoutApproval))) return { ok: false, reason: "approval_bundle_hash_mismatch" };
    if (!verify(null, Buffer.from(JSON.stringify(approvalPayload)), approvalPublicKey, Buffer.from(approvalSignature, "base64"))) return { ok: false, reason: "invalid_approval_signature" };
  }

  const rebuilt = buildHashChain(bundle.trace_events);
  const chainOk = rebuilt.length === bundle.trace_hash_chain.length && rebuilt.every((h, i) => h === bundle.trace_hash_chain[i]);
  if (!chainOk) {
    return { ok: false, reason: "hash_chain_mismatch" };
  }

  if (bundle.schema_version === "evidence-package@2.0" && bundle.controller_evidence) {
    const required = requiredDevTaskEvidenceV2(bundle.trace_events, bundle.controller_evidence);
    if (JSON.stringify(bundle.required_evidence ?? []) !== JSON.stringify(required)) {
      return { ok: false, reason: "required_evidence_mismatch" };
    }
    const derived = deriveDevTaskV2Outcome(bundle.trace_events, bundle.controller_evidence);
    const ladder = derived === "verified" ? "L2" : "L0";
    if (bundle.outcome !== derived || bundle.claim_ladder !== ladder) {
      return { ok: false, reason: "v2_derived_result_mismatch" };
    }
  }

  if (bundle.schema_version !== "evidence-package@2.0" && (
    bundle.capability === PROVENANCE_CAPABILITY ||
    bundle.capability === DELETE_ENFORCED_CAPABILITY ||
    bundle.capability === TENANT_ISOLATION_CAPABILITY ||
    bundle.capability === WRITE_INTEGRITY_CAPABILITY ||
    bundle.capability === TAMPER_EVIDENT_CAPABILITY ||
    bundle.capability === RECOVERY_VERIFIED_CAPABILITY ||
    bundle.capability === DEVTASK_EXECUTION_CAPABILITY
  )) {
    const derivedOutcome = deriveOutcomeFromTrace(bundle.capability, bundle.trace_events);
    if (bundle.outcome !== derivedOutcome) {
      return {
        ok: false,
        reason: `trace_outcome_mismatch:declared=${bundle.outcome}:derived=${derivedOutcome}`,
      };
    }
  }

  if (bundle.outcome !== "verified") {
    return { ok: false, reason: `non_verified_outcome:${bundle.outcome}` };
  }

  return { ok: true };
}

function main() {
  const bundlePath = process.argv[2];
  if (!bundlePath) {
    console.error("Usage: verify <bundle.json> <controller-key.pem> [approval-key.pem] [validation.json evidence-key.pem review.json reviewer-key.pem]");
    process.exit(1);
  }

  const bundle = JSON.parse(readFileSync(bundlePath, "utf-8")) as EvidenceBundle;
  const trustedPublicKey = process.argv[3] ? readFileSync(process.argv[3], "utf-8") : undefined;
  const trustedApprovalPublicKey = process.argv[4] ? readFileSync(process.argv[4], "utf-8") : undefined;
  const result = verifyBundleObject(bundle, trustedPublicKey, trustedApprovalPublicKey);
  if (!result.ok) {
    console.error(`❌ Bundle verification failed: ${result.reason}`);
    process.exit(2);
  }

  if (process.argv[5]) {
    const validationBytes = readFileSync(process.argv[5]);
    const validation = JSON.parse(validationBytes.toString("utf8")) as ValidationAttestationV1;
    const evidenceKey = process.argv[6] ? readFileSync(process.argv[6], "utf8") : "";
    const expectedCommit = bundle.controller_evidence?.repository_state?.result_commit ?? "";
    const validationResult = verifyValidationAttestation(validation, evidenceKey, expectedCommit);
    if (!validationResult.ok) { console.error(`Validation verification failed: ${validationResult.reason}`); process.exit(3); }
    if (process.argv[7]) {
      const bundleBytes = readFileSync(bundlePath); const review = JSON.parse(readFileSync(process.argv[7], "utf8")) as ReviewerAttestationV1;
      const reviewerKey = process.argv[8] ? readFileSync(process.argv[8], "utf8") : "";
      const reviewResult = verifyReviewerAttestation(review, reviewerKey, bundleBytes, validationBytes);
      if (!reviewResult.ok) { console.error(`Reviewer verification failed: ${reviewResult.reason}`); process.exit(4); }
      console.log("   independent validation + reviewer signature verified (Claim-Ladder=L3)");
    } else {
      console.log("   independent validation verified; reviewer signature missing (Claim-Ladder remains L2)");
    }
  }

  console.log(`✅ Bundle ${bundle.bundle_id} verified. Capability=${bundle.capability}, Claim-Ladder=${bundle.claim_ladder}`);

  const diffEvidence = bundle.trace_events
    .map((e) => parseDevTaskEvent<DevTaskDiffEvidenceTraceEvent>(e, DEVTASK_DIFF_EVIDENCE_PREFIX))
    .find(Boolean);
  if (diffEvidence) {
    console.log(`   diff_stat sha256=${diffEvidence.diff_stat_sha256}`);
    if (diffEvidence.diff_full_sha256) {
      console.log(`   full diff sha256=${diffEvidence.diff_full_sha256} (scope: ${diffEvidence.scope})`);
    } else {
      console.log(`   (scope: ${diffEvidence.scope} -- no full-diff hash on this bundle)`);
    }
  }

  if (bundle.rfc3161_timestamp) {
    const tsResult = verifyRfc3161Binding(bundle);
    if (tsResult.ok) {
      console.log(`   RFC-3161 timestamp bound correctly: gen_time=${bundle.rfc3161_timestamp.gen_time}, tsa=${bundle.rfc3161_timestamp.tsa_url}`);
      console.log("   (binding only -- this tool does not verify the TSA's own CMS signature or certificate chain)");
    } else {
      console.warn(`   ⚠ RFC-3161 timestamp present but ${tsResult.reason} -- ignoring it, bundle verdict above is unaffected`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
