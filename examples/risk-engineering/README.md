# Example: risk-engineering — a KRI catalog with evidence-grade discipline

The fourth fully-built Yukti example: a typed KRI (Key Risk Indicator) catalog
governed by **consequence × credibility** — the decision depends not only on
how bad the reading is, but on how good the evidence carrying it is.

## Run it

```bash
python examples/risk-engineering/demo.py
```

Seven catalog readings produce all four decisions — and the one to watch is
what does *not* happen: two act-line crossings are **not** contained. One is
carried by proxy evidence (RE-03), one is an hour stale (RE-06) — both route
to a human instead. Only RE-01 (act line crossed, decision-grade, fresh) is
contained.

## The discipline: containment requires decision-grade evidence

Every reading carries an evidence tier — `discovery` / `proxy` /
`decision_grade` (the core's `EvidenceTier`) — and the policy enforces:

| Situation | Decision |
|---|---|
| act line crossed · decision-grade · fresh | DENY / CRITICAL |
| act line crossed · **proxy or discovery evidence** | GATE / HIGH — `weak_evidence_actuation` |
| act line crossed · **stale reading** | GATE / HIGH — deciding on old data is a finding |
| worsened >25% vs the time-anchored baseline | GATE / HIGH — `adverse_delta` |
| in the early-warning band (past watch, short of act) | MONITOR |
| in tolerance | ALLOW |

The engine refuses to take its hardest action on its weakest evidence. That
refusal is credibility protection as *live policy*, not as a caveat paragraph
nobody reads.

## The typed catalog

Each `KRI` declares: direction (`higher_is_worse` / `lower_is_worse`), watch
and act lines, a freshness window, a sparse-but-honest framework crosswalk
(family-level refs, with a `"nearest —"` caveat when a mapping is approximate
rather than exact), and **`do_not_claim`** — what a reading of this indicator
can never support:

> `RE-04 fraud-model drift index` · *"a proxy: does not measure realized
> fraud losses"* · caveat: *"nearest — population-stability proxy, not
> measured fraud loss"*

The `do_not_claim` clauses travel inside every observation, into the evidence
trail — the claim limits are part of the record, not documentation.

## Verify

```bash
python -m pytest tests/test_risk_engineering.py -q
```

Everything is seeded and synthetic — every indicator, value, and date is
invented. The capability lives in
[`yukti.scenarios.risk_engineering`](../../src/yukti/scenarios/risk_engineering.py);
this is a thin runnable demo of it.
