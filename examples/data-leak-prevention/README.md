# Example: data-leak-prevention — governing tiered data access

The third fully-built Yukti example. Where [`agent-breakout`](../agent-breakout/)
governs *unsanctioned* actions (an agent outside its task envelope), this
governs *sanctioned-but-tiered* access: agents allowed to touch data — but only
up to their clearance, through sanctioned channels, toward sanctioned
destinations. Same Pattern × Flow → Decision engine, a third governance domain.

## Run it

```bash
python examples/data-leak-prevention/demo.py
```

A seven-agent fleet is governed data-touch by data-touch: sanctioned access
passes untouched, a read above clearance and a re-identifying dataset join
route to a human, and PII sent to a data broker, a personal-email channel, and
a 2.4-million-record batch export are contained.

## The five data-leak patterns

| Pattern | Fires when | Decision |
|---|---|---|
| `external_tier_egress` | tier-3+ data leaves toward an unsanctioned destination | DENY / CRITICAL |
| `unsanctioned_channel` | egress through a channel outside the allowlist — any tier | DENY / CRITICAL |
| `bulk_movement` | one egress moves >50k records — the exfiltration shape | DENY / CRITICAL |
| `tier_overreach` | a read above clearance — data touched, not moved | GATE / HIGH |
| `aggregation_uplift` | a join whose *output* tier exceeds clearance | GATE / HIGH |

The ranking is the domain's discipline: **data that moved is contained; data
merely touched or reshaped goes to a human.** Sensitivity tiers follow the
N1–N5 convention (1 = public … 5 = restricted).

## Two ideas worth stealing

**The access profile is operator-declared.** Like the breakout example's task
envelope, an agent never carries its own clearance inside its own telemetry —
the operator declares `AccessProfile` (clearance tier + channel and
destination allowlists) out-of-band, and without a declared profile the
profile-judged patterns refuse to fire (fail-safe: don't judge an agent by a
boundary nobody declared).

**Aggregation uplift.** Two individually-modest datasets can compose into
something restricted — orders (N2) joined with identities (N2) yields a
re-identifiable dataset (N4). The pattern reads the *output* tier, not the
inputs: clearance must cover what comes out of the join, not what went in.

## Verify

```bash
python -m pytest tests/test_data_leak.py -q
```

Everything is seeded and synthetic — every agent, dataset, and value is
invented. The capability lives in
[`yukti.scenarios.data_leak`](../../src/yukti/scenarios/data_leak.py); this is
a thin runnable demo of it.
