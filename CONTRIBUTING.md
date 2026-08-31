# Contributing to RequestTrace

Thanks for your interest in improving RequestTrace. This document covers the
local development workflow, code standards and how the project is organized.

## Getting Started

```bash
git clone https://github.com/<org>/requesttrace.git
cd requesttrace

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev,pdf]"

pre-commit install
```

## Development Workflow

```bash
# Lint
ruff check .

# Format
ruff format .

# Type check
mypy requesttrace

# Unit + integration tests
pytest

# Coverage
pytest --cov=requesttrace --cov-report=term-missing
```

All four commands must pass before opening a pull request. `pre-commit`
runs the linter, formatter and hygiene checks automatically on commit.

## Project Layout

See [`README.md`](README.md#architecture) for the architecture diagram.
Key rule: **scanners collect normalized observations, analyzers derive
secondary signals from those observations, the rule engine turns
observations into findings, and report renderers turn the canonical view
model into output formats.** Report templates must never contain scan logic,
and rules must never parse rendered/presentation text.

- `requesttrace/models/` — immutable, serializable data model (Scan, Target,
  Observation, Evidence, Finding, ModuleResult).
- `requesttrace/scanners/` — DNS, connectivity, TLS and HTTP collectors.
  Each scanner returns observations; it never decides severity.
- `requesttrace/analyzers/` — redirect, header, cookie, edge/CDN and
  request-path derivations built from scanner observations.
- `requesttrace/evidence/` — evidence store and redaction/sanitization.
- `requesttrace/rules/` — versioned rule engine mapping observations to
  findings, plus remediation knowledge.
- `requesttrace/reporting/` — canonical report view model and renderers
  (JSON, Markdown, HTML, PDF) plus baseline diffing.

## Adding a New Rule

1. Add or extend a rule module under `requesttrace/rules/`.
2. Give it a stable ID following `RT-<AREA>-<NNN>` (e.g. `RT-TLS-014`).
3. Reference the evidence ID(s) that justify the finding — never invent
   evidence.
3. Add unit tests covering the triggering condition and the negative case
   (i.e. the rule does **not** fire when the control is correctly
   configured).
4. Add remediation and verification text in
   `requesttrace/rules/remediation.py`.
5. Bump the ruleset version in `requesttrace/rules/engine.py` if the change
   alters existing finding behavior.

## Adding a New Scanner or Analyzer

- Scanners must be timeout-bounded and must not raise on expected network
  failure states (timeout, refused, NXDOMAIN, TLS handshake failure) — they
  should report a `ModuleResult` error/observation instead.
- Never shell out with target-derived input. Use the standard library or
  vetted dependencies (`socket`, `ssl`, `dnspython`, `requests`) directly.
- Never persist full response bodies or secret material in evidence.

## Testing Philosophy

- Unit tests should not depend on live internet access. Use `responses`
  for HTTP mocking and local fixtures under `tests/fixtures/` for TLS/DNS
  scenarios.
- Integration tests that exercise a real network stack must be explicitly
  marked and skippable so CI stays deterministic.

## Commit / PR Guidelines

- Keep PRs scoped to one concern (one rule, one scanner capability, one
  report fix).
- Update `CHANGELOG.md` under "Unreleased" for user-facing changes.
- Update `README.md` when CLI flags, output formats or exit codes change.

## Code of Conduct

Be respectful, assume good faith, and keep discussion focused on the
technical merits of a change. Reports of harassment can be sent to the
security contact listed in `SECURITY.md`.
