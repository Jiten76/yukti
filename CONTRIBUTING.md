# Contributing to Yukti

Thanks for thinking about contributing. Yukti is early-stage; substantive contributions are welcomed.

## Before you start

1. **Read the [README](README.md) and [ARCHITECTURE](ARCHITECTURE.md).** The project is opinionated; understanding the design first saves churn.
2. **Open an issue first for non-trivial changes.** A 5-minute alignment conversation prevents a 5-day rewrite.
3. **Agree to the [CLA](CLA.md).** Required for all contributions — see CLA.md for what and why.

## How to contribute

### Bug reports

Open a GitHub issue with:

- What you tried
- What you expected
- What actually happened
- Minimal reproduction (code, config, environment versions)

### Feature requests

Open a GitHub issue with the **use case** first ("I want to govern X") before proposing a design ("Yukti should have a Y subsystem"). Use cases shape the design better than implementations.

### Pull requests

1. Fork, branch, code, test.
2. Run `ruff check . && ruff format .` before committing.
3. Run `pytest` — all tests must pass.
4. Include a short PR description: what changed, why, any new dependencies.
5. Confirm CLA sign-off in your PR description (see [CLA.md](CLA.md)).
6. Be patient on review — this is a small project; reviews take days, not minutes.

## Development setup

```bash
git clone https://github.com/Jiten76/yukti
cd yukti
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
pre-commit install
pytest
```

## Adding a community integration

See `docs/EXTENDING.md` (coming soon) for how to write a community integration that distributes as `yukti-integration-<name>` on PyPI without needing changes to core.

The short version: implement `yukti.integrations.base.Integration`, declare your capabilities, register via entry point in your own `pyproject.toml`:

```toml
[project.entry-points."yukti.integrations"]
my_integration = "yukti_integration_my_integration:MyIntegration"
```

Users install your integration alongside Yukti: `pip install yukti yukti-integration-my-integration`.

## Code style

- Python ≥3.11. Use modern type hints (`list[str]`, `X | None`).
- Async-first for any I/O. Sync code only for pure-compute.
- Type-checked with `mypy` (strict mode).
- Linted + formatted with `ruff`.
- Tested with `pytest` + `pytest-asyncio`.
- One class per file unless multiple classes are tightly coupled.

## Code of conduct

Be kind, be specific, be patient. We're building governance tools — let's govern ourselves well.
