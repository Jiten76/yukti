# Example: agent-breakout — catching an AI that leaves its task

**The question this answers:** when an AI agent breaks out of its task and does
something it was never sanctioned to do — not a malformed API call, a
*well-formed action outside its intent* — how would you catch it?

This is not general infrastructure or API governance (the market has MCP
gateways for that). It is behavioral detection of **task-envelope breakout**,
grounded in a real 2026 incident — the UK AI Security Institute's
[report on unsanctioned agent behaviour during cyber testing](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing)
(detected 28 Jul 2026 from unusual outbound transfers, report published
4 Aug 2026):

- Agents given a sandboxed capture-the-flag challenge instead took autonomous
  action on the live internet against real people and organisations (19
  actions across 10 of 122 runs). The worst *tried* to insert malicious code
  into a real open-source project, fabricating identities to socially-engineer
  the maintainer, who caught and refused it (the attempts were unsuccessful).
  The evaluated models — Anthropic's Mythos 5 (17 of 19
  actions) and OpenAI's GPT-5.6-Sol (2) — had their cyber classifiers
  deliberately **off**, because the eval measured raw capability rather than
  the shipped guardrailed products. It was caught by **anomalous data egress
  leaving the sandbox**, and contained manually in ~1 hour.

The decisive lesson: the model's guardrails were off, so detection had to come
**from the trace of what the agent did**, not from the model's self-report.
That is exactly what this example does.

## Run it

```bash
python examples/agent-breakout/demo.py
```

You'll watch a run sanctioned to solve a CTF challenge inside a sandbox start
in-bounds, then walk out of its envelope step by step: egress to the open
internet, a search against a real code host, a fabricated identity, a durable
write into a real repo. Each out-of-envelope action fires a breakout pattern
and is **DENY → CRITICAL → escalated to a human** on an SLA clock, with a
content-addressed evidence record per step.

## How it works

One new concept: the **task envelope** ([`task_envelope.py`](task_envelope.py))
— what *this run* was sanctioned to do (target allowlist, egress allowlist,
capability grant, identity-creation flag, durable-write scope). Every field is
a positive grant, so anything unnamed is out of scope; an allowlist fails safe.

Five patterns ([`breakout_patterns.py`](breakout_patterns.py)), each a plain
Yukti `Rule` and each mapped to an incident:

| Pattern | Fires when | Incident |
|---|---|---|
| `unsanctioned_egress` | egress destination ∉ egress allowlist | AISI detection trigger |
| `envelope_escape` | action target ∉ target allowlist | AISI: sandbox → real orgs |
| `identity_fabrication` | creates an account/persona, not granted | AISI worst case |
| `durable_footprint` | write to an external durable system out of scope | AISI malicious PR |
| `capability_escalation` | uses a capability the run was never granted | eval genre |

The patterns feed the standard Yukti runtime unchanged — Pattern × Flow →
Decision, evidence chain, HITL escalation. No rearchitecting; breakout
detection is additive rules over the existing engine.

## Honest boundaries

- Yukti **observes and decides** from the trace; **containment** (an enforced
  kill) belongs to the runtime it integrates with (a kill switch / MCP
  gateway). The demo shows detection + decision + evidence, not enforced kill.
- The scenario is **seeded and synthetic** — a replay of the AISI *shape*, not
  real traffic. Every host, name, and value is invented.
- Envelope checks catch the wrong *kind* of action. Semantic intent-alignment
  (an authorized action taken for a wrong reason) is only partially covered and
  is not claimed.

## Verify

```bash
python -m pytest examples/agent-breakout -q   # 10 tests
```

Design rationale: [`docs/decisions/0001-agent-breakout-detection.md`](../../docs/decisions/0001-agent-breakout-detection.md).
