# Changelog

Notable changes to Yukti. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.1] - 2026-11-07

Honesty and precision pass from a three-reviewer validity round. No decision logic
changed; outputs are identical to 0.2.0. The changes sharpen the evidence text and
documentation where independent reviewers found the wording claimed more than the
engine does.

### Changed

- **`provenance_unverifiable` evidence text.** The GATE rationale now states plainly
  that the "clean" label on the egress is the governed agent's OWN unverified claim,
  so a self-declared clean label is worth at most a route-to-human, never an ALLOW,
  while a bare or self-ungranted egress after the same read is the harder DENY. Names
  the cooperative-telemetry trust boundary instead of implying the label is trusted.
- **`model_provenance_mismatch` scope, documented precisely.** The check is active
  only when the envelope pins a `model_allowlist` (an unpinned agent is ungoverned on
  model identity), and only a span that reports running a model is checked; a span
  that names no model is not. Was previously summarised as "fail closed on a missing
  digest", which overstated the coverage.
- **`EFFECTFUL_TARGETS` documented as a built-in set, not an operator registry.** An
  out-of-scope capability named in the set is DENY; any other out-of-scope capability
  GATEs. The only per-run extension is an observation carrying `effectful=True`; the
  named set is fixed in code. Spelled out as a real limit (e.g. `wire_transfer` → DENY
  but `swift_payment` → GATE).

## [0.2.0] - 2026-11-06

Yukti governs agent-fleet behavior across five domains on a
single engine. It reads execution traces, detects behavioral patterns as they
cross end-to-end flows, ranks each finding by consequence, and routes it (allow,
monitor, escalate to a human, or contain) with a hash-chained evidence record
for every decision.

### Engine

- **Pattern × Flow → Decision runtime.** A small set of composable components
  (detector, policy, evidence store, HITL queue, flow tracker), each defined as
  an abstract interface with a working in-memory default. The rule-based
  detector matches named predicates against an observation; the policy maps the
  resulting findings to a decision (ALLOW, MONITOR, GATE, DENY).
- **Content-addressed, hash-chained evidence.** Every observation, pattern
  match, and decision is written as an evidence record addressed by the SHA-256
  of its content, including its trace id, so records are attributable per trace
  and genuine duplicates within a trace collapse. A durable backend
  (`ChainFileEvidenceStore`) appends records to a hash-chained JSONL ledger that
  replays on restart, and `yukti verify-evidence` checks two independent
  integrity properties offline (per-record content addresses and the per-line
  ledger chain), reporting the exact line if either is broken.
- **SLA-aware human-in-the-loop.** GATE and DENY decisions open interventions on
  a priority queue (GATE maps to HIGH, DENY to CRITICAL), each carrying a
  plain-language summary of the agent, flow, and consequence.
- **Binding gate for ingested traffic.** `create_app(unbound_agent_decision=…)`
  turns an ingested trace that cannot be bound to a registered envelope into a
  first-class, evidenced decision (e.g. DENY) instead of a silent ALLOW; a span
  that declares the governance contract but omits a field the engine judges is
  routed to a human as a `telemetry_contract_violation`. Default is unchanged
  (unbound → ALLOW). Built on a general `forced_decision` path in the runtime.

### Governance domains

Each domain is a scenario module under `yukti.scenarios`, with a runnable demo
and tests. All are consequence-ranked: the decision reflects how bad the outcome
is, not only that a rule matched.

- **agent-breakout (security).** Detects an agent acting outside its per-run
  task envelope, a positive-grant boundary declared out of band (target and
  egress allowlists, capability grant, identity-creation flag, durable-write
  scope). Five patterns: unsanctioned egress, envelope escape, identity
  fabrication, durable footprint, and capability escalation. Detection derives
  from the action trace rather than the model's own guardrails, so it holds when
  those guardrails are off. Grounded in the UK AI Security Institute's 2026
  incident report on unsanctioned agent behaviour during cyber testing
  (AISI incident detected 28 Jul 2026, report published 4 Aug 2026).
- **data-flow patterns (extends agent-breakout, not a new domain).** Two further
  patterns in `yukti.scenarios.agentic_dataflow` extend the same task envelope:
  `provenance_violation` flags an egress carrying a data class the run read
  earlier even when it goes to a permitted sink, by propagating read-taint across
  the trace (adds a `data_egress_grant`: what data may leave, separate from
  where); `delegation_escalation` routes a subagent handed a grant wider than its
  parent's to a human, and an agent with no registered envelope fails closed.
  Trace-level detection and escalation, not inline prevention. Served live as the
  `dataflow` API mode: `/v1/traces` builds `build_dataflow_governance()` and runs
  run-scoped read-taint propagation on ingest, so the live dashboard governs with
  the same rules as the direct path (covered by an HTTP integration test). Taint
  is keyed by `(run, agent)`, where the OTLP trace id groups a run, so two runs
  that reuse an agent name do not cross-contaminate. Provenance splits by what the
  egress declared: a bare or self-ungranted egress carrying an ungranted class is
  `provenance_violation` (DENY, the laundering shape); an egress that declares only
  granted classes while the run read an ungranted one is `provenance_unverifiable`
  (GATE): a human decides, rather than hard-denying legitimate analytics the trace
  cannot prove clean. `model_provenance_mismatch` adds model identity to the
  envelope: a `model_allowlist` pins the weight digest(s) an agent may run, and an
  unpinned or mismatched digest (or a named model with no digest, fail closed) is a
  GATE. Model identity is a grant that narrows across delegation like the others.
- **sre-reliability.** Governs a service fleet on trend-form signals: retry
  amplification, backpressure accumulation, IAM-quota storm, change-velocity
  spike, and runway exhaustion. Active or spreading degradation is contained; a
  bypassed release gate or a short capacity runway routes to a human.
- **data-leak-prevention.** Sensitivity-tiered data access (N1 to N5) judged
  against an operator-declared access profile of clearance tier, channel
  allowlist, and destination allowlist. Five patterns, including aggregation
  uplift, where a join of two lower-tier datasets produces a higher-tier result
  that exceeds the agent's clearance. Data that moved is contained; data only
  read or reshaped routes to a human.
- **risk-engineering.** A typed KRI catalog governed on both consequence and
  evidence quality: containment (DENY) requires decision-grade, fresh evidence.
  An act-line crossing carried by proxy evidence, or by a stale reading, is
  demoted to a human decision (GATE). Includes direction-aware thresholds,
  time-anchored deltas, and explicit "do not claim" clauses that travel with
  each reading into the evidence record.
- **cyber-governance.** A multi-agent assessment platform governed against a
  signed engagement scope. Out-of-scope actions and approval-gate bypasses are
  contained; registry drift (an orchestrator invoking an agent that is not in
  the engagement registry), delegation runaway, and unevidenced assessment steps
  route to a human.

### Interfaces and integrations

- **OpenTelemetry ingest.** `POST /v1/traces` converts OTLP JSON trace exports
  into observations, mapping GenAI semantic-convention attributes onto the
  runtime's fields and routing spans to named flows, so real agent traces are
  governed live alongside the built-in scenarios.
- **Task-envelope registration.** `POST /v1/envelopes` declares an agent's
  sanctioned boundary out of band; every trace that agent emits is then judged
  against it, extending breakout detection to real ingested traffic.
- **Slack escalation.** GATE and DENY decisions post to a Slack incoming webhook
  in plain language (agent, flow, consequence, trace id), with a configurable
  decision floor so lower-severity traffic stays out of the channel. A generic
  webhook integration serves as the reference implementation.
- **Live dashboard** (FastAPI + WebSocket). A consequence-ranked fleet view:
  pattern tiles showing distinct agents in a rolling window with a trend and
  click-to-drill, a plain-language timeline, an act-on queue grouped by
  priority, and a live switcher across all five domains.
- **CLI.** `version`, `doctor`, `demo`, `serve`, and `verify-evidence`.

### Examples

- **live-agent** (`examples/live_agent`): a harness that governs a real Claude
  tool-use agent live: each tool call is classified by a trusted adapter into
  the engine's vocabulary and judged through the real ingest route, with a
  hash-chained attempt ledger anchored to a published tip and a cross-artifact
  verifier. The harness and its offline proofs ship here; the committed
  recordings of real model runs are produced by `record.py` (needs a key).

### Quality

- 269 tests; `mypy --strict` and `ruff` clean; CI on Python 3.11 and 3.13 from a
  clean install, including the example demos.

## [0.1.0] - 2026-11-06

Initial same-day public tag: agent-fleet governance across five domains, the live
`dataflow` serve mode (the dashboard governs with the same rules as the direct
path), cross-span read-taint propagation, and the Muse agent-security critique.

0.2.0 adds, on top of 0.1.0: the `provenance_violation` / `provenance_unverifiable`
DENY-vs-GATE split (no hard-deny of legitimate analytics the trace cannot prove
clean); `model_provenance_mismatch` (weight-digest model-identity governance, a
grant that narrows across delegation); and assurance evidence: false-alarm runs
reported beside the catch rate, a negative-control test that neutralises suggestive
names and asserts decisions are unchanged, and a rule-ablation test. 261 → 269 tests.
