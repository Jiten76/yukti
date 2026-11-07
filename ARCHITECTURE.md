# Architecture

This document describes the architecture as built — what each package is
responsible for, how the seams work, and where extension points live. Direction
and unbuilt intent live in [`docs/ROADMAP.md`](docs/ROADMAP.md), not here.

## The conceptual model: Pattern × Flow → Decision

Yukti decomposes agent-fleet risk along two axes.

**Pattern** is the **behavioral axis** — recurring signatures of risk that cut across the substrate. The five built scenarios ship twenty-five, five per domain:

- Security (`yukti.scenarios.breakout`): unsanctioned egress, envelope escape, identity fabrication, durable footprint, capability escalation — each judged against a per-run task envelope.
- Reliability (`yukti.scenarios.reliability`): retry amplification, backpressure accumulation, IAM-quota storm, change-velocity spike, runway exhaustion — trend-form signals, not raw gauges.
- Data governance (`yukti.scenarios.data_leak`): external tier egress, unsanctioned channel, bulk movement, tier overreach, aggregation uplift — judged against an operator-declared access profile.
- Risk engineering (`yukti.scenarios.risk_engineering`): act/watch threshold crossings, adverse delta, weak-evidence actuation, stale reading — consequence × credibility.
- Platform governance (`yukti.scenarios.cyber_governance`): scope-boundary violation, HITL-gate bypass, unregistered-agent invocation, delegation runaway, evidence gap — judged against the signed engagement scope.

**Flow** is the **data axis** — end-to-end execution paths through the system, from initiation to outcome.

- A customer-onboarding flow (KYC → eligibility → account-open → notify)
- A fraud-decision flow (signal-arrival → enrichment → policy-eval → decide → write-back → notify)
- A compliance-evidence flow (trigger → collect → triangulate → classify → store-with-custody → expose)

**Patterns happen across many Flows. A Flow accumulates many Pattern matches along its path.** Where a Pattern intersects a Flow at runtime, governance materializes — gated by policy, witnessed by evidence, escalated via HITL, emitted to integrations.

> *Data without behavior has nothing to say. Behavior without data has nothing to act on.*

---

## Package layout (as built)

```
yukti/
├── core/                  ← framework primitives, no external I/O
│   ├── patterns/          ← detect behavioral signatures (ABC + rule-based default)
│   ├── flows/             ← track and attribute end-to-end paths (ABC + in-memory default)
│   ├── evidence/          ← content-addressed store (in-memory + hash-chained ledger file)
│   ├── hitl/              ← SLA-aware intervention queue (ABC + in-memory default)
│   ├── policy/            ← policy-engine ABC + simple-predicate evaluator
│   └── runtime/           ← the orchestrator that wires the above
│
├── scenarios/             ← first-class governance domains on the engine
│   ├── breakout.py        ← task envelopes + the five security breakout patterns
│   ├── agent_fleet.py     ← the six-agent fleet with consequence-ranked policy
│   ├── reliability.py     ← the seven-service fleet, five reliability patterns
│   ├── data_leak.py       ← access profiles + tiered data-access governance
│   ├── risk_engineering.py← typed KRI catalog, consequence × credibility
│   └── cyber_governance.py← engagement scopes over a 22-expert platform
│
├── integrations/          ← tentacles to external systems
│   ├── base.py            ← Integration ABC + capability enum (the plugin contract)
│   ├── webhook/           ← generic webhook (reference implementation)
│   ├── opentelemetry/     ← OTLP JSON trace ingest (GenAI semconv → Observations)
│   └── slack/             ← GATE/DENY escalation via incoming webhook
│
├── serve/                 ← FastAPI app: REST + WebSocket + the live dashboard
│   ├── api.py             ← endpoints incl. POST /v1/traces (OTLP ingest)
│   ├── breakout.py        ← streams the agent fleet to the dashboard
│   ├── fleet.py           ← synthetic observation generator (default mode)
│   └── static/            ← the dashboard (vanilla JS + platinum CSS)
│
└── cli/                   ← typer CLI: version / doctor / demo / serve / verify-evidence
```

Every directory above contains working, tested code — the CI gate runs all of
it on each push.

---

## The Integration plugin contract

Every integration implements `yukti.integrations.base.Integration`:

```python
class Integration(ABC):
    name: ClassVar[str]
    capabilities: ClassVar[frozenset[Capability]]

    def __init__(self, config: IntegrationConfig) -> None: ...
    async def health(self) -> bool: ...
    async def notify(self, ctx, message, **kwargs) -> None: ...
    async def ingest_event(self, ctx, payload) -> None: ...
    # ... one method per Capability
```

**Capabilities are declared** via the `capabilities` class attribute; the
runtime routes operations only to integrations that can serve them. The three
shipped integrations exercise the contract in both directions: `webhook`
declares `NOTIFY` + `INGEST_EVENT` (outbound reference), `slack` declares
`NOTIFY` (GATE/DENY escalation with a noise floor), and `opentelemetry`
declares `INGEST_EVENT` (inbound — OTLP JSON exports become `Observation`s).

**Community-authored integrations** distribute as separate PyPI packages named
`yukti-integration-<name>` and register themselves via the
`yukti.integrations` entry-point group. No core changes needed.

See [`src/yukti/integrations/base.py`](src/yukti/integrations/base.py) for the full contract.

### Capability enum

| Capability | What it means |
|---|---|
| `NOTIFY` | Send a message/alert out to an external system |
| `INGEST_EVENT` | Receive a structured event from an external system |
| `PULL_EVIDENCE` | Query an external system for evidence data |
| `OPEN_TICKET` | Create a ticket/incident/case in a tracking system |
| `UPDATE_TICKET` | Update or comment on an existing ticket |
| `STORE_ARTIFACT` | Persist an evidence blob to an external store |
| `QUERY_LOGS` | Run a query against an external log/observability backend |
| `EMIT_TELEMETRY` | Emit a metric, span, or other telemetry signal |
| `POLICY_EVAL` | Evaluate a policy via an external engine |

---

## Extension points

**To add an integration:** implement `Integration`, declare capabilities,
register via the entry-point group (or contribute it under
`yukti.integrations`). The webhook implementation is the template.

**To add a pattern detector:** implement `PatternDetector`. Detectors are
side-effect-free; the runtime decides what to do with their matches. The
rule-based default (`Rule` = a named predicate + rationale) covers
deterministic detection; an ML detector plugs in through the same interface.

**To add a policy engine:** implement `PolicyEngine`. The shipped
`SimplePredicatePolicyEngine` maps a findings doc to a `Decision`; external
engines (OPA, Cedar) would plug in behind the same ABC.

**To add an evidence store backend:** implement `EvidenceStore`. The core
ships the in-memory default and the append-only hash-chained
`ChainFileEvidenceStore` (offline-verifiable via `yukti verify-evidence`);
SQL backends arrive when query scale demands them.

**To add a governance domain:** follow the scenario pattern — a module in
`yukti.scenarios` with rules, a consequence-ranked policy, a builder returning
a wired `Runtime`, plus a thin demo under `examples/` and tests.

---

## Design principles

1. **Async-first.** Any I/O uses `async def`. Sync code only for pure-compute.
2. **Side-effect isolation.** Pattern detectors, policy engines, and similar pure-classification components never mutate state directly. They return structured results; the runtime decides side effects.
3. **Capability-based routing.** Integrations declare what they can do; the runtime routes by capability, not by integration name. Hot-swappable.
4. **Evidence-by-default.** Every decision produces an evidence record. The cost of evidence emission is paid up-front, not bolted on.
5. **Auditable interfaces.** ABCs are narrow and stable. Every component in `core/` defines an ABC and ships a working default; sophisticated implementations plug in behind the same seams.
6. **Vendor-neutral.** No assumption about which LLM provider, which cloud, which observability stack you use. Traces arrive over open wire formats (OTLP).
7. **Claims match code.** The repo contains only what runs; direction lives in one roadmap file. CI enforces the runnable part on every push.
