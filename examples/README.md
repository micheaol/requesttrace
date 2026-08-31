# Examples

## `sample-report/`

A full report bundle produced by scanning the public domain `example.com`
(no authentication, no destructive actions, no synthetic/fabricated data —
this is a real scan of a domain that exists precisely to be safely used in
examples like this one). Demonstrates every output format from the same
scan:

- `report.md` — Markdown report (readable directly on GitHub)
- `report.html` — self-contained HTML report (open directly in a browser)
- `report.json` — schema-versioned JSON (validates against
  `schemas/report.schema.v1.json`)
- `report.pdf` — PDF report

Regenerate it yourself with:

```bash
requesttrace scan https://example.com --report --format all --output examples/sample-report
```

## `requesttrace.config.json`

A sample `--config` overlay file. Use it with:

```bash
requesttrace scan https://example.com --config examples/requesttrace.config.json
```

## Baseline / drift comparison

Use any previously generated JSON report as a baseline for a later scan:

```bash
requesttrace scan https://example.com --baseline examples/sample-report/report.json
```
