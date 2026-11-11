# Roadmap: engineering direction

Everything in the repository is built, tested, and runnable; this file is the
one place that talks about what isn't yet. Nothing here is a capability claim.
(Consolidates the former example stubs, the integration matrix, and
`ENTERPRISE_ROADMAP.md`, removed in favor of this single file; their full
text lives in git history.)

## Next increments

1. **Wider live-agent runs.** The live-agent harness is built and a real
   tool-calling agent has been governed live and captured as an
   offline-verifiable run (`examples/live_agent/`). What remains: runs that
   elicit an actual breakout, and wiring the recording's replay into CI.
2. **SQL evidence backends.** The durable ledger is the append-only chain file;
   sqlite/Postgres arrive when query scale demands more than the in-memory
   index over it.
3. **Enforcement acknowledgement in the evidence record.** A DENY is a decision,
   not a control, until the enforcing gateway confirms the action was blocked.
   Carry that round trip (decided, issued, acknowledged, verified) into the
   evidence chain.
4. **Detection assurance.** Measured true and false positives and negatives,
   detection latency, and behaviour when the telemetry pipeline itself fails.
5. **Scale testing.** Load behaviour toward the fleet sizes the problem
   statement names; the serve API is already fleet-scale in shape (aggregates,
   pagination), but the numbers are not yet measured.

## Further governance domains

The five built domains (agent-breakout, sre-reliability, data-leak-prevention,
risk-engineering, cyber-governance) set the pattern for any new one: a scenario
module in `yukti.scenarios`, a consequence-ranked policy, a thin runnable demo,
and tests. A new domain, community or otherwise, follows the same shape.

## Integration matrix

`Integration` is a capability-declared plugin contract (see
`src/yukti/integrations/base.py`); `webhook`, `opentelemetry`, and `slack` implement
it today. The intended matrix arrives one implementation at a time:
notification channels (PagerDuty, Teams), ticketing (Jira, GitHub, GitLab,
ServiceNow), observability sinks (Splunk, Datadog, Elastic), queues/storage
(Kafka, S3), LLM providers, vector stores, cloud audit pulls, and policy-engine
interop (OPA, Cedar). Each lands with its SDK as an extra, its tests, and its
README. Community integrations ship as `yukti-integration-<name>`
packages via the `yukti.integrations` entry-point group.

**Integrations are never paywalled**: tentacles are adoption fuel, not
monetization fuel.

## The enterprise seam

A future `yukti-enterprise` (separate repo, commercial) would monetize
operational complexity, never adoption: multi-tenant runtime, SSO/SAML/SCIM,
certified compliance bundles, ML-based pattern detection, adaptive HITL
thresholds, SLA-grade support. The architectural seam already exists in core:
every component is an ABC with a shipped default; enterprise implementations
plug in behind the same interfaces, swapped by config.
