# Public engine-run evidence

**Zuletzt bearbeitet:** 2026-08-30
**Von:** Codex (MERIDIAN)

Diese drei Dateien sind die unveraenderten, signierten Evidence Packages der offenen
Engine-Vergleichs-PRs im oeffentlichen Demo-Repository:

- `pr-19-deepseek.json` — DeepSeek
- `pr-20-hermes.json` — Hermes
- `pr-21-cline.json` — Cline

Sie wurden vor Einfuehrung der maschinenlesbaren Executor-Bindung erzeugt. Die Engine-Zuordnung
stammt deshalb bei diesen historischen Paketen aus dem jeweiligen Task-/PR-Datensatz und ist
noch nicht Teil des signierten Trace. Neue Pakete enthalten `executor`, `harness_id`,
`adapter_version` und `adapter_version_sha256` im `devtask_execution_context`-Event.

## Fremdverifikation aus einem frischen Clone

```bash
git clone https://github.com/bewusstki-hue/alex-mrtb-verify-bundle.git
cd alex-mrtb-verify-bundle
npm ci
npm run build
curl -fsS https://bewusstki.de/.well-known/alex-pubkey.json \\
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).public_key_pem))' \\
  > trusted-public-key.pem
node dist/verify.js evidence/pr-19-deepseek.json trusted-public-key.pem
node dist/verify.js evidence/pr-20-hermes.json trusted-public-key.pem
node dist/verify.js evidence/pr-21-cline.json trusted-public-key.pem
```

Erwartung: dreimal `VERIFIED`. Der Trust-Anchor kommt bewusst aus dem Well-known-Endpunkt,
nicht aus dem jeweiligen Bundle.
