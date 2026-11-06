# Example: cyber-governance — governing a multi-agent assessment platform

The fifth fully-built Yukti example, and the port of the author's
separately-built enterprise agent platform: 24 domain experts across four
capability groups (enterprise security, AI governance, DevSecOps, third-party
risk), composed per industry vertical by orchestrators, pointed at customer
environments. (The catalog here carries 22 — the source's two duplicate expert
classes collapsed in the port, the same honesty its own analysis applied.) This example distills that platform's governance surface — the
scope-boundary, authorization-gateway, and audit discipline that make such a
fleet safe to operate — onto the Yukti engine.

## Run it

```bash
python examples/cyber-governance/demo.py
```

One engagement across three verticals (ai-tech, critical-infrastructure,
private-equity), eight platform actions: signed-scope work passes, structural
drift routes to a human, and the two actions that touched the customer outside
sanction are contained.

## The five cyber-governance patterns

| Pattern | Fires when | Decision |
|---|---|---|
| `scope_boundary_violation` | an agent touches a target outside the signed scope | DENY / CRITICAL |
| `hitl_gate_bypass` | an approval-gated action executes while approval is pending | DENY / CRITICAL |
| `unregistered_agent_invocation` | an orchestrator calls an agent the registry doesn't contain | GATE / HIGH |
| `delegation_runaway` | an agent-to-agent chain deeper than sanctioned | GATE / HIGH |
| `evidence_gap` | an assessment step completes with no evidence attached | GATE / HIGH |

The split: **actions that touched the customer outside sanction are contained;
structural drift gets a human to re-anchor it.**

## The engagement scope

The operator declares each engagement's boundary — the third member of Yukti's
declared-boundary family (task envelope → access profile → engagement scope):

```python
EngagementScope(
    engagement_id="eng-2418", vertical="critical-infrastructure",
    target_scope=frozenset({"10.20.", "scada.customer-b."}),   # what the customer signed
    registered_agents=frozenset(...),                           # the roster for THIS engagement
    max_delegation_depth=5,
    approval_required_for=frozenset({"active_scan", "containment_execute"}),
)
```

Positive grants only, and the platform never carries its own sanction in its
own telemetry. Without a declared scope, the scope-judged patterns refuse to
fire.

## Why registry drift is a first-class pattern

The source platform's own honest accounting: it *marketed* 49 agents, *listed*
46 files, and *implemented* 39 concrete classes — with dead stubs
(`learning-framework`, `coordination-manager`) still named in rosters. That gap
between the marketed roster, the implemented roster, and the engagement
registry is exactly where a platform loses track of itself —
`unregistered_agent_invocation` holds every invocation to the registry, so the
drift surfaces the moment an orchestrator reaches for an agent that isn't
really there.

## Verify

```bash
python -m pytest tests/test_cyber_governance.py -q
```

Everything is seeded and synthetic — every agent, network, and engagement is
invented. The capability lives in
[`yukti.scenarios.cyber_governance`](../../src/yukti/scenarios/cyber_governance.py);
this is a thin runnable demo of it.
