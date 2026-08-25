import { createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

type ClaimLadder = "L0" | "L1" | "L2" | "L3" | "L4";

export interface EvidenceBundle {
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
}

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

export function verifyBundleObject(bundle: EvidenceBundle): { ok: boolean; reason?: string } {
  const { signature, public_key, ...payload } = bundle;

  const isValidSignature = verify(
    null,
    Buffer.from(JSON.stringify(payload)),
    public_key,
    Buffer.from(signature, "base64"),
  );

  if (!isValidSignature) {
    return { ok: false, reason: "invalid_signature" };
  }

  const rebuilt = buildHashChain(bundle.trace_events);
  const chainOk = rebuilt.length === bundle.trace_hash_chain.length && rebuilt.every((h, i) => h === bundle.trace_hash_chain[i]);
  if (!chainOk) {
    return { ok: false, reason: "hash_chain_mismatch" };
  }

  if (
    bundle.capability === PROVENANCE_CAPABILITY ||
    bundle.capability === DELETE_ENFORCED_CAPABILITY ||
    bundle.capability === TENANT_ISOLATION_CAPABILITY ||
    bundle.capability === WRITE_INTEGRITY_CAPABILITY ||
    bundle.capability === TAMPER_EVIDENT_CAPABILITY ||
    bundle.capability === RECOVERY_VERIFIED_CAPABILITY ||
    bundle.capability === DEVTASK_EXECUTION_CAPABILITY
  ) {
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
    console.error("Usage: node tools/verify-bundle/verify.ts <bundle.json>");
    process.exit(1);
  }

  const bundle = JSON.parse(readFileSync(bundlePath, "utf-8")) as EvidenceBundle;
  const result = verifyBundleObject(bundle);
  if (!result.ok) {
    console.error(`❌ Bundle verification failed: ${result.reason}`);
    process.exit(2);
  }

  console.log(`✅ Bundle ${bundle.bundle_id} verified. Capability=${bundle.capability}, Claim-Ladder=${bundle.claim_ladder}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
