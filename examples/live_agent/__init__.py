"""Live agent loop — a real Claude agent governed live by Yukti.

A real tool-calling agent works a self-contained sandbox task; each tool call is
emitted as an OTLP span (see ``otel``) and judged by the running Yukti engine
through its real ingest route. The model genuinely chooses what to do; detection
never depends on that choice.
"""
