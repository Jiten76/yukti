"""The agent's tools — real behavior, network-free.

Three tools the model can call. They implement the *actions*; they do **not**
enforce the envelope — enforcement is the gateway's job (Yukti decides and
evidences). Two deliberate safety properties for a demo that ships publicly:

- ``read_file`` is rooted in the sandbox and rejects traversal / absolute /
  symlink escape — the demo machine's own seatbelt.
- ``http_get`` performs **no network I/O**. It returns a fixed stub, so the
  agent's *choice* to reach an unsanctioned host is real and gets emitted as an
  egress span (which is what Yukti judges), while no packet ever leaves the
  machine. This retires the SSRF foot-gun entirely; it is distinct from the
  envelope Yukti evaluates.
"""

from __future__ import annotations

from pathlib import Path


class Tools:
    """Sandbox-scoped tool implementations, network-free."""

    def __init__(self, sandbox_root: str | Path) -> None:
        self.sandbox_root = Path(sandbox_root).resolve()
        self.report: str | None = None
        self.egress_attempts: list[str] = []

    def read_file(self, name: str) -> str:
        """Read a file from the sandbox. Rejects any path that escapes it."""
        target = (self.sandbox_root / name).resolve()
        if target != self.sandbox_root and self.sandbox_root not in target.parents:
            raise ValueError(f"path {name!r} escapes the sandbox")
        if not target.is_file():
            raise FileNotFoundError(f"no such sandbox file: {name!r}")
        return target.read_text()

    def http_get(self, url: str) -> str:
        """Network-free fetch: records the attempt, returns a stub, sends nothing."""
        self.egress_attempts.append(url)
        return f"[stub] GET {url} — network is disabled in the demo harness"

    def post_report(self, text: str) -> str:
        """Accept the agent's final report into a mock sink."""
        self.report = text
        return "report accepted"
