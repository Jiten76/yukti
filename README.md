# Yukti: agent-fleet governance

![CI](https://github.com/Jiten76/yukti/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Typing](https://img.shields.io/badge/mypy-strict-blueviolet)

> **Yukti** (Sanskrit *युक्ति*, "skillful means"): patterns, flows, decisions.
> Governance for a fleet of AI agents that doesn't become the bottleneck it
> prevents.

I built this around a question that observability tools don't answer:

> **Observability tells you what your agents *did*. When a thousand agents are
> acting per second, what tells you which one just broke containment: how
> badly, and who has to act, right now?**

Everything this README claims is built and runs: five worked governance
domains, a live dashboard you can start in one command, and an OTLP endpoint
that governs real agent traces. That includes a **captured, offline-verifiable
run of a real Claude tool-calling agent** judged live through that endpoint
([`examples/live_agent`](examples/live_agent/)). The engine is covered by 261
tests, enforced by CI on every push. Direction lives in
[`docs/ROADMAP.md`](docs/ROADMAP.md), and nothing there is claimed here.

---

## What this is

**The problem it governs, first: AI agent risk.** Autonomous agents taking
actions no human sanctioned, faster and wider than any human can watch. That is
what Yukti is built for. The other four domains it ships (reliability,
data-leak, risk-engineering, cyber-governance) run on the *same* engine
unchanged, which is the point worth making: the governance primitives here (a
declared envelope, a consequence-ranked decision, a named human on an SLA, an
evidence record) are reusable across risk surfaces, not rebuilt per use case.

Yukti is the **decision layer above observability** for agent fleets. It reads
the traces agents already emit, classifies each into its governance vocabulary
(which agent took which action, with which tool or toward which destination),
detects behavioral **Patterns** as they cross
end-to-end **Flows**, ranks each finding by **consequence**, and routes it
(contain, escalate to a human with an SLA deadline, or let it pass), with a
content-addressed evidence record for every decision.

```
  many agents' traces
          │
          ▼
   Pattern  ×  Flow          ← behavior × data-path
          │
          ▼
   consequence-ranked        ← ALLOW · GATE (high) · DENY (critical)
     Decision
          │
          ├──► HITL queue     ← named human, SLA deadline
          └──► evidence chain ← SHA-256, hash-chained
```

> *Data without behavior has nothing to say. Behavior without data has nothing
> to act on.*

> **For risk and compliance leaders.** Yukti applies second-line discipline to
> AI agents: the operator declares the risk appetite up front (the envelope),
> every action is judged against it and ranked by consequence, anything serious
> escalates to a human on an SLA deadline, and every decision leaves a
> replayable evidence record. It won't take its hardest action, containment, on
> weak or stale evidence; that routes to a person instead, which is effective
> challenge built into the engine. The disciplines here (a declared appetite,
> human oversight with deadlines, evidence of review, and challenge of weak
> signals) are the ones SR 11-7, the NIST AI RMF, and ISO/IEC 42001 ask for.
> (Yukti does not ship a control-by-control crosswalk to those regimes; it
> applies the discipline, decision by decision.)

## Who is accountable

Yukti executes policy and produces evidence. By design it is *not* the risk
owner, the control owner, and the independent challenger at once; those stay
with people. The engine maps onto a three-lines operating model:

| Responsibility | Accountable party |
| --- | --- |
| Operating the agent | First line / business owner |
| Declaring the envelope (the risk appetite) | Authorized risk and control owners |
| Executing the policy decision | **Yukti** |
| Independent challenge of a decision | Second line |
| Approving an exception or override | Designated risk authority |
| Enforcing the decision (the actual kill) | Authorized gateway / operational owner |
| Assurance | Internal audit |

A DENY from Yukti is a *decision*, not yet a control: it becomes an effective
control only when the gateway confirms the action was blocked. On the human
side the lifecycle is real in the engine: every GATE/DENY is stamped with a
named owner on an SLA at the moment it is raised, a person acknowledges it, and
an overdue unacknowledged item escalates to a backup. What remains on the
roadmap is the *gateway's* enforcement acknowledgement: carrying the
decided, issued, acknowledged, verified round trip back into the evidence
record.

## Where it sits (and what it is not)

The market already has two layers Yukti deliberately does **not** rebuild:

- **Observability** (LangSmith, Arize, Helicone…) tells you *what happened*.
  Yukti reads from it; it doesn't reproduce it.
- **Enforcement gateways** (MCP tool-call gateways, policy proxies) block a
  single bad tool call at the boundary. That is real, specific work, and it is
  the layer Yukti hands the actual *kill* to.

Yukti is the layer **between and above** them: fleet-wide, consequence-ranked,
human-in-the-loop **decisions** with an evidence trail. It decides and
evidences; it integrates with a gateway to enforce. That boundary is explicit,
not blurred.

## See it in 60 seconds

The `agent-breakout` example streams a live governance dashboard:

```bash
git clone https://github.com/Jiten76/yukti.git && cd yukti
python -m venv .venv && .venv/bin/pip install -e .
YUKTI_MODE=breakout .venv/bin/python \
  -m uvicorn yukti.serve.api:create_app --factory --port 8899
# then open http://localhost:8899/  (give it ~10s to stream)
```

You'll watch a six-agent fleet governed live: a headline that names the one
thing to act on (*"4 of 6 agent runs broke containment · worst: ctf-solver,
opened a PR attempting to plant a backdoor in a real repo · CRITICAL"*), pattern tiles
that show **distinct agents** exhibiting each behavior and a trend (click one to
drill into its agents), a timeline of plain-language rows (*"kyc-verifier ·
customer-onboarding, sent customer PII to an external data broker · DENY"*),
and a consequence-ranked act-on queue.

(The demo fleet is six agents; the serve API is built fleet-scale from the
start, with fleet-level aggregates and paginated drill-downs rather than
per-agent lists, and load testing toward the thousand-per-second figure above
is on the roadmap.)

**All five domains stream on the same dashboard, switchable live**: a
**domain dropdown** in the header swaps the governed fleet without a restart:
the runtime is rebuilt server-side and every connected dashboard resets to the
new domain's tiles, timeline language, and headline. Or pick the starting
domain from the CLI:

```bash
.venv/bin/yukti serve --mode breakout   # or: reliability | data-leak | risk | cyber
```

Each domain loads its own five pattern tiles and speaks its own headline ("4 of
6 agent runs broke containment" · "5 of 8 platform actions left sanction" · …),
driven entirely from `/api/meta`, with no per-domain frontend code.

## Five worked governance domains (same engine)

**1. `agent-breakout`: security.** Catches an agent doing what it was never
sanctioned to do, governed against a per-run **task envelope** (target/egress
allowlists, capability grant, durable-write scope). Five patterns (unsanctioned
egress, envelope escape, identity fabrication, durable footprint, capability
escalation), grounded in a real 2026 incident: the UK AI Security Institute's
[report on unsanctioned agent behaviour during cyber testing](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing)
(detected 28 Jul 2026 from unusual outbound transfers, report published
4 Aug 2026), where evaluated frontier models,
cyber classifiers deliberately off, took autonomous actions on the live
internet, caught when data left the sandbox. Detection derives from the trace,
so it holds when the model's own guardrails are off. Two further **data-flow
patterns** (`yukti.scenarios.agentic_dataflow`) extend the same task envelope to
two agentic blind spots an inline per-process control shares. `provenance_violation`
catches an egress to a *sanctioned* destination carrying a data class the run was
never granted to disclose (`data_egress_grant`): the taint-laundering path a
per-process taint model misses, because the data arrived through the model's
context. `delegation_escalation` catches a subagent handed a grant wider than its
parent's own envelope (grants must narrow down a delegation chain, never widen).
→ [`examples/agent-breakout`](examples/agent-breakout/)
→ [`docs/muse-agent-security.md`](docs/muse-agent-security.md): a worked analysis of
where this trace-level layer complements an inline design (Meta's Muse), with the
capabilities demonstrated running.

**2. `sre-reliability`: reliability.** Governs a service fleet's diverging
signals: retry-amplification cascades, backpressure accumulation, IAM-quota
storms, change-velocity spikes, runway exhaustion. Consequence-ranked the same
way: active or spreading degradation is contained, a bypassed release gate or a
short capacity runway routes to a human, healthy services pass. "Govern the
divergence, not the level." → [`examples/sre-reliability`](examples/sre-reliability/)

**3. `data-leak-prevention`: tiered data access.** Where breakout catches
*unsanctioned* actions, this governs *sanctioned-but-tiered* access: clearance
tiers (N1-N5), channel and destination allowlists, bulk-movement detection,
and **aggregation uplift**: a join of two modest datasets whose output tier
exceeds clearance. The discipline: data that moved is contained; data merely
touched or reshaped routes to a human.
→ [`examples/data-leak-prevention`](examples/data-leak-prevention/)

**4. `risk-engineering`: a KRI catalog with evidence-grade discipline.**
Typed indicators (direction, watch/act lines, freshness windows, honest
framework crosswalks) governed by **consequence × credibility**: containment
requires decision-grade, fresh evidence. An act-line crossing carried by a
proxy reading, or by stale data, routes to a human instead of containing;
the engine refuses to take its hardest action on its weakest evidence. Every
reading travels with its "what we do not claim" clauses.
→ [`examples/risk-engineering`](examples/risk-engineering/)

**5. `cyber-governance`: a multi-agent assessment platform.** A port of my own
separately-built 24-expert agent platform (the ported catalog runs 22, two
duplicate expert classes collapsed in the port): an operator-declared
**engagement scope** (what the customer signed: targets, agent registry,
delegation depth, approval gates) governs every platform action. Out-of-scope
touches and bypassed approval gates are contained; registry drift (an
orchestrator invoking an agent that isn't really there), delegation runaway,
and unevidenced assessment steps route to a human.
→ [`examples/cyber-governance`](examples/cyber-governance/)

```bash
.venv/bin/python examples/agent-breakout/demo.py         # security
.venv/bin/python examples/sre-reliability/demo.py        # reliability
.venv/bin/python examples/data-leak-prevention/demo.py   # data governance
.venv/bin/python examples/risk-engineering/demo.py       # risk engineering
.venv/bin/python examples/cyber-governance/demo.py       # platform governance
```

Across the five domains one discipline repeats: the sanctioned boundary
(task envelope, access profile, engagement scope) is **operator-declared,
positive-grants-only, and never carried in the agent's own telemetry.**

Both are seeded and synthetic (every agent, host, and value is invented), so
every claim above is reproducible on your machine.

## Feed it real traces

"Reads the traces agents already emit" is literal: the serve layer exposes an
OTLP/HTTP-shaped endpoint. Point an OpenTelemetry exporter (or `curl` an OTLP
JSON export) at the running dashboard and every span is normalized into the
pipeline: GenAI semantic conventions (`gen_ai.agent.name`,
`gen_ai.operation.name`, `gen_ai.tool.name`) map onto Yukti's fields, a
`yukti.flow` attribute routes the span to a named Flow, and the decisions land
on the same live dashboard:

```bash
curl -X POST http://localhost:8899/v1/traces \
  -H "Content-Type: application/json" --data-binary @traces.json
# → {"spans_ingested": 2, "decisions": {"ALLOW": 2}}
```

The converter is dependency-free (it parses the OTLP JSON mapping directly) and
lives at [`yukti.integrations.opentelemetry`](src/yukti/integrations/opentelemetry/__init__.py).

**Declare the envelope, and breakout detection fires on real traffic.** An
agent never carries its own sanction inside its own telemetry (where it could
lie), so the operator declares it out-of-band:

```bash
curl -X POST http://localhost:8899/v1/envelopes -H "Content-Type: application/json" \
  -d '{"agent": "invoice-reconciler", "task": "reconcile invoices",
       "target_allowlist": ["ledger_read"], "egress_allowlist": ["internal.corp"]}'
```

From then on, every span that agent emits is judged against its envelope. The
same span that passed ungoverned (`ALLOW`, nothing to judge against) now
comes back `DENY · unsanctioned_egress` when the agent uploads ledger extracts
to a paste site. All grants are positive: what you don't name isn't
sanctioned. Batches are retry-safe: a duplicate or malformed span errors
individually and never poisons the rest of the export.

## Escalate to a human

The last mile of HITL: set `YUKTI_SLACK_WEBHOOK` to a Slack incoming-webhook
URL and every GATE/DENY the fleet produces posts to the channel as it happens,
in the dashboard's language (*🟡 GATE · evidence-collector · compliance-evidence,
reached into an analytics warehouse outside its scope*), with the trace id
for drill-down. ALLOW/MONITOR traffic never posts (a configurable
`min_decision` floor), so the channel stays actionable. No Slack SDK: plain
HTTPS via [`yukti.integrations.slack`](src/yukti/integrations/slack/__init__.py).

## A ledger that survives, and checks its own integrity

Set `YUKTI_EVIDENCE_PATH` and every evidence record appends to a hash-chained
JSONL ledger (append-only file, in the audit-log tradition: a ledger wants
integrity and verifiability, not SQL). It replays on restart, so the dashboard
keeps its history, and it verifies offline:

```bash
yukti verify-evidence /var/lib/yukti/evidence.chain
# chain intact: 31 record(s) verified (content addresses + ledger chain)
```

Two independent properties are checked: every record's **content address**
(edit a record and its SHA no longer matches) and every line's **ledger
chain** (reorder or rewrite any line, or delete any but the last, and every
subsequent entry hash breaks). A corrupt or naively-edited ledger isn't just
detected: the verifier names the line. Deleting from the *tail*, though,
leaves nothing after it to break, so tail-truncation is caught by the
out-of-band tip anchor (below), not this offline check.

**Scope, stated plainly.** This is an **integrity checksum**: it catches
corruption and in-place edits, and reproduces on restart. It is *not*
tamper-evident against an adversary who can rewrite the whole file, because the
chain is unkeyed: such an actor can re-stitch it end to end. Full
tamper-evidence needs the tip anchored out of band (a keyed MAC, a co-signed
head, or a periodically-published hash). That's on the roadmap, and the claim
here is scoped to match what the code does today.

## How the engine works

`core/` is a small, dependency-light framework of composable ABCs, each with a
working default:

- **patterns/**: behavioral detectors. The default is a deterministic
  rule engine (`Rule` = a named predicate over an observation); an ML detector
  plugs in through the same interface.
- **flows/**: track and attribute end-to-end execution paths.
- **policy/**: map a finding to a `Decision` (ALLOW / MONITOR / GATE / DENY).
  Both examples register a **consequence-ranked** policy.
- **hitl/**: an SLA-aware intervention queue; GATE → HIGH, DENY → CRITICAL.
  Deadlines are stamped on enqueue and breaches are queryable
  (`list_overdue`); acting on a breach is the deployment's pager, not the
  library.
- **evidence/**: a content-addressed, SHA-256 hash-chained ledger; every
  observation, pattern match, and decision is a record. Durable backend:
  an append-only chain file with an offline verifier.
- **runtime/**: the orchestrator that wires them into `Pattern × Flow →
  Decision` and drives the FastAPI + WebSocket dashboard.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the package-by-package breakdown and
the Integration plugin contract.

## Verified engineering evidence

- **261 tests passing**, **mypy `--strict` clean** on the engine (`src/yukti`),
  **ruff clean** across engine, tests, and examples, enforced
  by CI on every push (clean install, Python 3.11 + 3.13, the example demos run);
  locally: `.venv/bin/python -m pytest tests -q`.
- **Deterministic**: every scenario is seeded; the same run reproduces the same
  decisions and the same evidence hashes.
- **All five governance domains** exercised end to end through the same engine,
  each producing a real decision spread (not a wall of CRITICAL) and a written
  evidence chain.

## Current scope

**Everything in this repository is built, tested, and runnable**: the CI gate
(ruff across the repo, mypy `--strict` on the engine, the full suite, the example demos,
Python 3.11 and 3.13 from a clean install) enforces that on every push:

| Area | What runs |
|---|---|
| Core engine (patterns / flows / policy / hitl / evidence / runtime) | ABCs + working defaults, exercised end to end |
| Live dashboard | FastAPI + WebSocket, consequence-ranked fleet view, drill-down |
| Governance domains | `agent-breakout` · `sre-reliability` · `data-leak-prevention` · `risk-engineering` · `cyber-governance`: five domains, each with demo + tests |
| Integrations | `opentelemetry` (OTLP JSON ingest, GenAI semconv, `POST /v1/traces`) · `slack` (GATE/DENY escalation via incoming webhook) · `webhook` (outbound reference) |
| Durable evidence | `ChainFileEvidenceStore`: append-only hash-chained ledger, restart-safe, `yukti verify-evidence` |
| CLI | `yukti version · doctor · demo · serve --mode breakout` |

Two boundaries, named explicitly: **enforcement** (the actual kill) is out of
scope by design (Yukti decides and evidences, a gateway enforces); and the
fleets are **seeded simulations** emitting realistic traces, not live LLM
loops (real traces enter via `/v1/traces`). Direction (envelope binding for
OTel runs, durable evidence stores, further domains, the integration coverage)
lives in one place: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License & author

[Apache 2.0](LICENSE). **Jitendraa Joshii**, built as a synthesis of
evidence-engineering rigor and agent-fleet operational design.

> Agent security doesn't end at the prompt. The decision that matters begins the
> moment an AI system is allowed to act, across the whole fleet, not one call
> at a time.
