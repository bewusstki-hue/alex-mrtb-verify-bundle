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

- structural validity of the bundle itself (required fields present, correct types, `claim_ladder`
  and `outcome` restricted to their defined value sets, `executed_at` a parseable timestamp) —
  malformed input returns a clean `FAILED: malformed_bundle`, not an exception;
- that `capability` is one of the six capabilities this verifier actually knows how to check —
  an unrecognized capability name is rejected outright, it cannot skip straight to the outcome gate;
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

## Deliberate limits

This verifier proves formal integrity and consistency of the supplied bundle. It does not prove that
the external events described by the bundle happened in the real world.

**No external trust anchor yet.** `public_key` is read from the bundle itself, not from an allowlist,
a registry, or a certificate chain. This verifier proves that the bundle is *internally* consistent —
signed by *some* key, and unmodified since — not that a specific, known, trusted party produced it.
Anyone can generate their own Ed25519 keypair, sign an arbitrary but internally-consistent bundle, and
get `VERIFIED`. A real trust anchor (key allowlist, PKI, or a transparency log such as Sigstore/Rekor)
is a later, explicitly planned step, not yet built — see the `Memory_Red_Teaming_Benchmark_Gesamtkonzept.md`
Claim Ladder / evidence-bundle sections in the companion `memory-red-teaming-benchmark` repository.

**No replay or freshness protection.** `bundle_id`, `run_id`, and `executed_at` are checked for shape
(non-empty, parseable) but not for uniqueness or recency — nothing here stops the exact same valid
bundle from being replayed, or an old bundle from being presented as current. That requires an
external ledger of previously-seen `bundle_id`s, which this stateless CLI tool intentionally does not
keep.

**No binding to a specific repository, commit, or CI run.** The bundle format has no field for git
commit SHA, source tree hash, or an independent CI run reference. A verified bundle proves the trace
events are self-consistent — it does not prove which codebase, commit, or task they came from.

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

**Last updated:** 2026-08-21

**By:** Claude (MERIDIAN)

Prepared the independent public release, negative example, and standalone regression tests (20.08).
21.08: hardened against unknown-capability and malformed-bundle inputs (both previously accepted or
crashed), extended test coverage to all six capabilities, and made the public-key/replay/provenance-
binding limits explicit above — following an external passive review.
