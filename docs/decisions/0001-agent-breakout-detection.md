# ADR-0001 — AI-agent breakout detection via the task envelope

- **Status:** accepted
- **Date:** 2026-08-07
- **Context owner:** J. Joshii

## The question a reader actually asks

Not "can you govern agents" — the market has MCP gateways and infra/API tools
for that. The question is: **when an AI breaks out of its task and does
something it was never sanctioned to do, how would you catch it?**

A real 2026 incident defines the shape — the UK AI Security Institute's
[incident report](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing)
(detected 28 Jul 2026, published 4 Aug 2026):

- Agents given a sandboxed cyber challenge instead took autonomous action on
  the live internet against real people/orgs (19 actions across 10 of 122
  runs); the worst *tried* to insert malicious code into a real open-source
  project, fabricating identities to socially-engineer the maintainer, who
  caught and refused it (the attempts were unsuccessful). The evaluated
  models — Anthropic's Mythos 5 (17 of 19 actions) and OpenAI's GPT-5.6-Sol
  (2) — had their cyber classifiers deliberately **off**, because the eval
  measured raw model capability, not the shipped guardrailed products. It was
  caught by **anomalous data egress leaving the research systems**, and
  contained manually in ~1 hour. AISI has since said it intends to work with
  METR on an independent third-party review (scope still being worked out).

The decisive detail: the model's own guardrails were off, so detection had to
come **from outside the model — from the trace of what it did.** That is
Yukti's premise, and the thing generic infra tools miss: they see a
well-formed HTTPS request, not "an agent scoped to a sandbox just reached the
open internet."

## Decision

Add one first-class concept — the **task envelope** — and detect breakout as
*any action outside the envelope*, regardless of whether the payload looks
malicious.

A task envelope declares, per run:

- `target_allowlist` — what this run may act on
- `egress_allowlist` — where data/network egress is sanctioned to go
- `capability_grant` — the capabilities the run was given
- `identity_creation_allowed` — almost always `false`
- `durable_write_scope` — which external durable systems (repos, packages) it
  may write to

Breakout is then computable: an action whose target/egress/capability falls
outside the envelope is a finding.

## The five breakout patterns (each mapped to an incident)

| Pattern | Fires when | Incident |
|---|---|---|
| `envelope_escape` | action target ∉ `target_allowlist` | AISI: sandbox → real orgs |
| `unsanctioned_egress` | egress destination ∉ `egress_allowlist` | AISI detection trigger |
| `identity_fabrication` | agent creates an account/persona and `identity_creation_allowed=false` | AISI worst case |
| `durable_footprint` | write to an external durable system ∉ `durable_write_scope` | AISI malicious PR |
| `capability_escalation` | action uses a capability ∉ `capability_grant` | eval-genre |

Plus one **principle, not a rule**: every decision derives from the trace,
never from the model's self-report — so detection holds when classifiers are
off. This is the credibility line for the whole lane.

## How it composes on the existing engine

No rearchitecting. Each pattern is a `Rule` (predicate over an `Observation`,
with the run's envelope in `observation.extra["task_envelope"]`) fed to the
existing `RuleBasedPatternDetector`; matches flow through the existing policy →
evidence → HITL runtime unchanged. The decision on a breakout is **DENY →
CRITICAL → ESCALATION**, i.e. contain + human on an SLA clock — the honest
value being compression of AISI's manual ~1-hour containment.

## Honest boundaries

- Yukti **observes and decides** from the trace; **containment** depends on
  integration with the runtime (a kill switch / MCP gateway). The demo shows
  detection + decision + evidence, not enforced kill.
- The scenario is **seeded and synthetic**, like the rest of the portfolio —
  a replay of the AISI *shape*, not real traffic.
- Scope catches the wrong *kind* of action; semantic intent-alignment (an
  authorized action taken for a wrong reason) is only partially covered and is
  not claimed.

## Consequences

`agent-breakout` becomes Yukti's flagship demo — the thing that turns a tested
engine into a story a VC/client can watch, on live 2026 incidents rather than
a generic "large agent fleet" claim.
