# Changelog

## 2026-11-18 — Comparison and guided review completion

- Added per-action model risk, classifier label, relevance, sensitivity, and threshold to the protection comparison timelines; the passthrough run identifies model scores as not evaluated.
- Added benign-document and protected-event assertions, strengthened same-input checks, and reset scenario pipeline state so old reports/statuses do not carry into blocked scenarios.
- Made the four-step setup/watch/log/result guide the default, grouped the permission manifest, raw schema, and scoreboard under collapsed Advanced details, and replaced the plain-text table preview with semantic Markdown tables and inline emphasis/code rendering.
- Added the requested reviewer Q&A and retained the local-only canary/outbox boundary.

## 2026-11-17 — ML transparency

- Exposed classifier label/risk, task relevance, data sensitivity, decision threshold, and combined risk on persisted API events without changing enforcement.
- Added fixed-seed held-out evaluation output with metrics, confusion matrix, SAFE false-positive rate, and per-sample predictions; added an API endpoint and runtime analysis panel.
- Documented the synthetic training source and measured results, including the high SAFE false-positive rate.

## 2026-11-17 — Protection comparison

- Added a compare-only API that runs the same simulated naive agent and identical task/document inputs through a passthrough logger and the existing AgentGuard gateway.
- Replaced the prior credential fixture contents with unmistakable fake canary values; all simulated data movement writes only to a local outbox.
- Added event-derived comparison outcomes, protected-run halt/incident actions, and live policy sample coverage reporting.
- Added tests for canary leakage only in protection-off mode, protected blocking, event persistence for both runs, document length limits, and caught/missed injection samples.
- Documented the comparison mode and its safety boundary in the root README.

## 2026-11-17 — Reviewer workflow

- Reworked the React review page around the task pipeline, gateway checkpoint, event timeline, guided demo, role manifest, incident evidence, scoreboard, and in-page report preview. This makes the security boundary and decision evidence readable without treating the page as a debug console.
- Added local gateway-backed scenarios for an unauthorized tool, poisoned document instruction, and unsupported dataset-gap claim. Each is evaluated by the shared interceptor and records its decision and incident evidence.
- Normalized API event fields and persisted structured input/output trace data so the UI can explain why an action ran or was blocked.
- Fixed battery dataset parsing for chemistry labels with and without parenthesized codes; retained exact source lines, removed raw dataset excerpts from report prose, and added a separate data-gaps section.
- Added claim provenance counts and a gateway validation action that blocks and records unsupported claims as provenance incidents.
- Added runtime tests for parsing, citations, unsupported-claim policy, scenario incidents, and event schema. Made the task allowlist test deterministic by isolating trained-model output from authorization assertions.
- Updated the root README and reviewer guide with the guided path, event schema, presentation script, and honest limitations.

## Known limitations

- Agents use deterministic local logic and a bundled sample dataset; they are not LLM agents or live research.
- Model training/evaluation is synthetic and must not be represented as production detection accuracy.
- Provenance checks line references in the local dataset; they do not validate source truth or freshness.
- Cause categories are hypotheses based on recorded signals, not proof of intent.
- The gateway protects only actions routed through its interceptor.
