# Example: sre-reliability — governing a service fleet's reliability

The second fully-built Yukti example. Where [`agent-breakout`](../agent-breakout/)
governs *security* (an agent doing what it was never sanctioned to do), this
governs *reliability*: a fleet of services whose signals are diverging, ranked
by consequence and routed to the right response — the same Pattern × Flow →
Decision engine, a different governance domain.

## Run it

```bash
python examples/sre-reliability/demo.py
```

You'll watch a seven-service fleet get governed signal by signal: healthy
services pass, a bypassed release gate and a short capacity runway route to a
human, and active or spreading degradation (a retry storm, an IAM quota storm, a
growing backlog) is contained — with a decision spread, not a wall of red.

## The five reliability patterns

| Pattern | Fires when | Decision |
|---|---|---|
| `retry_amplification` | retry ratio over threshold — one failure echoing across boundaries | DENY / CRITICAL |
| `backpressure_accumulation` | consumer absorbing slower than arrival — backlog building | DENY / CRITICAL |
| `iam_quota_storm` | auth/quota error rate spiking | DENY / CRITICAL |
| `change_velocity_spike` | changes-per-window over the release-gate line | GATE / HIGH |
| `runway_exhaustion` | days-to-quota below the floor (forward-looking) | GATE / HIGH |

The ranking mirrors the discipline: **active or spreading degradation is
contained; a governance breach or a forward-looking warning is routed to a human
before it bites; healthy services pass** — so the governor doesn't cry wolf.

## The idea: govern the divergence, not the level

A self-healing platform keeps its level-metrics green while divergence grows —
throughput looks fine right up until the backlog tips it over. So the patterns
here read **trend-form** signals (retry ratio, absorption-vs-arrival,
days-to-quota), not raw gauges. The forward-looking runway signal ("6 days to
quota") is the point: governance that acts before the outage, not after.

## Verify

```bash
python -m pytest tests/test_reliability.py -q
```

Everything is seeded and synthetic — every service, value, and date is invented.
The capability lives in [`yukti.scenarios.reliability`](../../src/yukti/scenarios/reliability.py);
this is a thin runnable demo of it.
