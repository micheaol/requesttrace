# RequestTrace

**Production request-path, TLS and HTTP security assessment CLI**

RequestTrace takes a production or staging domain/URL and turns the
externally observable request path — DNS, TCP connectivity, TLS, HTTP,
redirects, security headers, cookies and CDN/edge indicators — into
evidence-backed, remediation-ready findings.

```
Domain / URL → DNS → TCP → TLS → HTTP → Headers/Cookies/Edge → Findings → Report
```

> **One domain in. An evidence-traceable, repeatable TLS/HTTP security
> assessment out.**

Built for DevSecOps engineers, AppSec engineers, developers, SREs, security
leads and CI/CD pipelines.

---

## Why RequestTrace?

Investigating a production request path today usually means stitching
together `dig`, `openssl s_client`, `curl -v`, browser dev tools and manual
notes — repetitive, hard to reproduce, and rarely produces something you can
hand to a developer or an auditor as-is.

RequestTrace automates that workflow and refuses to stop at `HSTS: FAIL`.
Every actionable issue is a professional finding with:

- **Severity** (Critical / High / Medium / Low / Informational)
- **Evidence** — the exact observation(s) that triggered it, with a stable
  evidence ID
- **Security impact** — what actually goes wrong, in context
- **Recommendation + how to fix** — technology-labeled examples (never
  claiming a technology it didn't detect)
- **Verification** — a concrete way to confirm the fix

Every observation is either a directly observed fact or an explicitly
confidence-scored inference ("indicators are consistent with Cloudflare") —
never presented as more certain than it is.

## Features

- **DNS** — A/AAAA resolution, CNAME chain (loop-bounded), NS records
- **Connectivity** — single bounded TCP connect to the target port only
  (never a port scan)
- **TLS** — handshake (SNI, protocol, cipher, ALPN), certificate parsing
  (subject/issuer/SANs/validity/fingerprint/signature/key size), independent
  hostname-match and trust-chain checks, TLS 1.0–1.3 protocol-support
  probing with honest "not testable" reporting, cryptography rules, and
  configurable certificate-expiry thresholds
- **HTTP/HTTPS** — safe bounded GET, per-hop redirect chain, loop and
  HTTPS→HTTP downgrade detection, a separate HTTP→HTTPS upgrade probe, TTFB
  and total duration
- **Security headers** — HSTS, CSP (plus high-risk pattern detection),
  X-Content-Type-Options, Referrer-Policy, frame protection
  (CSP `frame-ancestors` / `X-Frame-Options`), Permissions-Policy
  (informational only)
- **Cookies** — Secure/HttpOnly/SameSite, values always redacted; never
  claims every cookie must be HttpOnly
- **CDN/edge indicators** — confidence-scored fingerprinting from DNS,
  headers and TLS metadata; unknown is a valid result
- **Evidence model** — every finding cites the evidence ID(s) that produced
  it
- **Reports** — Markdown, HTML, PDF and schema-versioned JSON, all rendered
  from one canonical view model so they stay equivalent
- **Baseline / drift detection** — compare against a previous JSON report;
  a baseline can never suppress currently observed risk
- **CI/CD ready** — clean JSON stdout mode, `--fail-on` policy, deterministic
  exit codes

---

## Quick Start

### Docker (no local dependencies beyond Docker)

```bash
docker build -t requesttrace:local .

docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  requesttrace:local \
  scan https://example.com --report --format all
```

(Published images will be available at `ghcr.io/<org>/requesttrace` once
this repository has a registry configured — see [Release workflow](#release-engineering).)

### From source

```bash
git clone https://github.com/<org>/requesttrace.git
cd requesttrace

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[pdf]"   # drop the [pdf] extra to skip PDF support

requesttrace scan https://example.com --report
```

Requires Python 3.10+.

---

## CLI Reference

```text
requesttrace scan <target>

--report                          Write report file(s) to --output.
--format md|html|pdf|json|all     Report format(s) to write (default: md).
--output <dir>                    Directory for written reports (default: reports).
--fail-on critical|high|medium|low|never
                                   Minimum severity that causes a policy-breach exit code (default: high).
--baseline <file.json>            Previous JSON report to diff against.
--config <file>                   JSON config file overlay.
--timeout <seconds>                Per-operation timeout (default: 10).
--max-redirects <n>                Maximum redirect hops to follow (default: 10).
--json                            Print only the JSON scan result to stdout (CI/CD mode).
--verbose                         Print per-module diagnostics.
--quiet                           Suppress non-essential terminal output.
--version                         Show the installed version.
```

`<target>` accepts a bare hostname, `host:port`, or a full `http(s)://` URL.
Scheme defaults to HTTPS. Unsupported schemes and malformed targets are
rejected before any network call is made.

### Config file overlay

`--config` accepts a JSON file; CLI flags always take precedence over it.
See [`examples/requesttrace.config.json`](examples/requesttrace.config.json).

---

## Reports

Every report format is rendered from the same canonical view model, so they
carry identical security meaning — only presentation differs.

| Format | Use |
|---|---|
| `md` | Readable directly on GitHub/GitLab, good for PRs |
| `html` | Self-contained, offline, print-friendly, no external JS |
| `pdf` | Paginated document for sharing outside a dev tool |
| `json` | Schema-versioned (`schemas/report.schema.v1.json`), for CI/CD and tooling |

A report contains: cover/metadata, executive summary, scope, methodology,
limitations, request-path summary, per-module assessment (DNS,
connectivity, TLS, HTTP, headers, cookies, edge indicators), performance
observations, findings summary, detailed findings, prioritized
recommendations, conclusion, and an evidence appendix.

See a real example bundle in [`examples/sample-report/`](examples/sample-report/)
(generated from a scan of `example.com`).

### Assessment labels

| Label | Meaning |
|---|---|
| `PASS` | No findings; all critical modules completed |
| `PASS WITH OBSERVATIONS` | Only Low/Informational findings |
| `REMEDIATION REQUIRED` | At least one High finding |
| `HIGH RISK` | At least one Critical finding |
| `ASSESSMENT INCOMPLETE` | A critical module (TLS/HTTP) could not complete and no findings were otherwise surfaced — never reported as PASS |

## Exit Codes

| Exit | Meaning |
|---:|---|
| `0` | Scan completed; no finding breached `--fail-on`. |
| `1` | Scan completed; a finding breached `--fail-on`. |
| `2` | Invalid command, target or configuration. |
| `3` | Scan could not produce a valid assessment (e.g. target completely unreachable). |
| `4` | Internal application/reporting error. |

---

## CI/CD

Clean JSON to stdout, plus a deterministic exit code, is the integration
point:

```bash
requesttrace scan https://example.com --json --fail-on high > report.json
```

### GitHub Actions

```yaml
- name: RequestTrace security scan
  run: |
    docker run --rm -v "$PWD/reports:/app/reports" \
      ghcr.io/<org>/requesttrace:latest \
      scan https://example.com --report --format json --fail-on high

- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: requesttrace-report
    path: reports/
```

### Generic Docker pipeline

```bash
docker run --rm -v "$PWD/reports:/app/reports" \
  requesttrace:local scan https://example.com \
  --report --format json --fail-on high --baseline reports/previous.json
```

A non-zero exit from `--fail-on` fails the pipeline step; exit `3` should be
treated as a scan/runtime failure, not a security-policy failure — see
[Exit Codes](#exit-codes).

---

## Architecture

```text
CLI / Config
    |
    v
Target Normalizer
    |
    +--> DNS Scanner
    +--> Connectivity Scanner
    +--> TLS Scanner
    +--> HTTP Scanner
             |
             +--> Redirect Analyzer
             +--> Header Analyzer
             +--> Cookie Analyzer
             +--> Edge Fingerprint Analyzer
    |
    v
Evidence Store (observations -> sanitized evidence)
    |
    v
Versioned Rule Engine (evidence -> findings)
    |
    +--> Markdown / HTML / PDF / JSON renderers
    |
    v
Baseline Comparison + --fail-on Policy -> Exit Code
```

Layering rules (enforced by design, see [`CONTRIBUTING.md`](CONTRIBUTING.md)):

- Scanners perform network I/O and emit normalized **observations** only —
  never a severity judgment.
- Analyzers derive secondary signals (redirects, headers, cookies, edge,
  request path) from observations already collected.
- The evidence store is the single choke point for redaction — secrets
  never reach an `Observation`, let alone a report.
- The rule engine reads observations through a `RuleContext` and emits
  evidence-linked findings; rules never parse rendered report text.
- Report renderers all build from one canonical view model, so Markdown,
  HTML, PDF and JSON stay semantically equivalent.

## Repository Layout

```text
requesttrace/
├── cli.py                # CLI entry point, exit-code wiring
├── config.py              # ScanConfig construction + validation
├── target.py               # Target normalizer/validator
├── orchestrator.py          # Wires scanners -> analyzers -> rules -> Scan
├── policy.py                 # --fail-on evaluation
├── models/                    # Scan/Target/Observation/Evidence/Finding/ModuleResult
├── scanners/                   # dns, connectivity, tls, http
├── analyzers/                    # redirects, headers, cookies, edge, request path
├── evidence/                      # EvidenceStore + redaction
├── rules/                          # versioned rule engine + per-area rules
└── reporting/                       # view model, md/html/pdf/json renderers, baseline
schemas/report.schema.v1.json
tests/{unit,integration,fixtures}/
examples/sample-report/
```

---

## Limitations

- RequestTrace observes only what is **externally visible**. It cannot see
  internal services, databases or private network hops.
- It is **not** an exploitation or penetration-testing tool: no
  authentication bypass, brute force, fuzzing or destructive requests.
- It does **not** replace authenticated DAST/SAST/SCA, cloud configuration
  review, WAF testing or full penetration testing.
- It does **not** certify compliance with PCI DSS, ISO 27001, NIST or any
  regulatory framework.
- CDN/edge provider identification is confidence-scored inference, never
  asserted as fact; "unknown" is a valid, honest result.
- "Not Tested" (e.g. a TLS version the local runtime's OpenSSL policy
  refuses to negotiate) is never converted into a passing result.

## Security

- Only scan targets you own or are explicitly authorized to assess.
- Default request volume is low and bounded; every network operation has a
  timeout.
- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and similar
  sensitive header values are redacted everywhere — terminal, JSON, and
  every report format. Cookie *values* are never parsed into evidence at
  all, only name + security-relevant attributes.
- Response bodies are never persisted; only a small bounded sample is read
  per request.
- Output filenames are sanitized and path-traversal-checked before any
  report is written.
- Target input is never interpolated into a shell command.
- See [`SECURITY.md`](SECURITY.md) for responsible disclosure.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the local dev workflow, code
layout, and how to add a new rule or scanner.

```bash
pip install -e ".[dev,pdf]"
ruff check . && ruff format --check . && mypy requesttrace && pytest
```

## Release Engineering

- `.github/workflows/ci.yml` — lint, type-check, test across Python
  3.10–3.13, Docker build + non-root smoke test against a local fixture.
- `.github/workflows/release.yml` — on a `v*.*.*` tag: multi-arch
  (linux/amd64, linux/arm64) image build, keyless cosign signing, SBOM
  generation, vulnerability scan, and GitHub Release publishing.

## Roadmap

Correlation-ID trace integrations, OpenTelemetry correlation, scheduled
monitoring/drift alerts, SARIF output, organizational policy packs, a
REST API/web UI, a plugin SDK, and signed evidence/attestation bundles.

## License

[MIT](LICENSE)
