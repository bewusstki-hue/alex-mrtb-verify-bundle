# Independent Evidence Bundle Verifier

AI work should ship with evidence that can be checked without trusting the AI that produced it.

This repository contains a deterministic verifier for signed evidence bundles. It has no dependency
on the agent system that created a bundle.

## Try it in ten minutes

Requires Node.js 20 or newer.

```bash
npm install
npm test
npm run verify -- sample-bundle.json
npm run verify -- invalid-tampered-bundle.json
```

Expected results:

- the test suite passes;
- `sample-bundle.json` is accepted as `VERIFIED`;
- the deliberately altered bundle is rejected with exit code `2` and `invalid_signature`.

The verifier distinguishes three outcomes:

- `VERIFIED`: the supplied evidence satisfies the supported formal contract;
- `FAILED`: the supplied evidence contradicts that contract;
- `INCONCLUSIVE`: the available evidence is insufficient.

## What it verifies

- the cryptographic signature of the bundle payload;
- hash-chain integrity across raw `trace_events`;
- agreement between the declared outcome and the outcome derived from supported trace events;
- an outcome gate that accepts only `outcome="verified"` as successful.

Supported capability traces:

- `memory.provenance.attached@1.0` -> `memory_write:`
- `memory.delete.enforced@1.0` -> `memory_state_read:`
- `memory.tenant.isolation@1.0` -> `tenant_access_probe:`
- `memory.write.integrity@1.0` -> `memory_content_change:`
- `memory.audit.tamper_evident@1.0` -> `audit_chain_check:`
- `memory.recovery.verified@1.0` -> `memory_recovery:`
- `devtask.execution@1.0` -> `devtask_contract_bound:` / `devtask_attempt_started:` /
  `devtask_execution_context:` / `devtask_validation:` / `devtask_human_approval:` /
  `devtask_outcome:` (first non-`memory.*` capability: proves a real dev-task execution attempt
  ran under a specific frozen work contract, with which validation result, approved by whom, and
  with which final outcome)

## Deliberate limits

This verifier proves formal integrity and consistency of the supplied bundle. It does not prove that
the external events described by the bundle happened in the real world.

For `memory.provenance.attached@1.0`, the current verifier checks agent identity and source hash.
Task-contract identity and timestamps are part of the provenance claim, but are not independently
attested by this verifier.

If one system controls both the work and every event in the bundle, an internally consistent bundle
can still contain false claims. Stronger assurance requires an independent event source, runtime
attestation, or reproducible re-execution.

## Why this exists

This began with a practical problem: AI-generated engineering work was moving faster than experienced
human review was available. The answer was not to demand more trust. It was to make claims portable,
make evidence inspectable, and let a separate deterministic tool say when the evidence is sufficient,
contradictory, or inconclusive.

`private: true` is intentional. This repository is public source, but the package is not currently
published to the npm registry and does not install a global command.

## License

Apache License 2.0. See [LICENSE](LICENSE).

**Last updated:** 2026-08-20

**By:** Codex (MERIDIAN)

Prepared the independent public release, negative example, and standalone regression tests.

---

**Last updated:** 2026-08-24

**By:** Claude Code (MERIDIAN)

Added `devtask.execution@1.0` support, mirrored line-for-line from `server/services/mrtb/evidenceBundle.server.ts` (still a deliberate separate code copy, no shared import between server and standalone verifier). Own regression suite (`npm test`) still green, existing sample/tampered bundles still verify unchanged.
