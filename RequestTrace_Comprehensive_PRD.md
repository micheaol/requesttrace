# RequestTrace — Comprehensive Product Requirements Document

**Version:** 1.0  
**Product Type:** Open-source production request-path, TLS and HTTP security assessment CLI  
**Primary Distribution:** Docker image + GitHub source installation  
**Primary Users:** DevSecOps engineers, AppSec engineers, developers, SREs, security teams and auditors  
**Status:** Build-ready specification

---

## 1. Product Overview

RequestTrace is an open-source command-line security and diagnostics tool that accepts a production or staging domain/URL and automatically traces the externally observable request path from DNS resolution through network connectivity, TLS negotiation, CDN/reverse-proxy indicators, HTTP processing and the final application response.

It converts raw technical observations into evidence-backed findings and professional human-readable remediation reports.

The product supports two first-class execution models:

1. **Docker:** zero project dependencies on the host beyond Docker.
2. **GitHub/source:** clone the repository, install dependencies in an isolated environment, and run the same CLI locally.

---

## 2. Problem Statement

Engineers commonly investigate DNS, TLS, redirects, HTTP headers, CDN behavior and response timing using separate utilities such as `dig`, `openssl` and `curl`. This creates several problems:

- Manual request tracing is repetitive and difficult to reproduce consistently.
- TLS checks are often reduced to certificate expiry rather than protocol, chain, cipher, hostname, HTTPS and HSTS posture.
- Raw command output does not provide professional findings, impact, remediation and verification.
- Evidence is fragmented across commands and screenshots.
- CI/CD systems need structured JSON and deterministic exit codes.
- Security teams need a defensible distinction between externally observed facts and infrastructure inference.
- Developers need actionable fixes rather than a simple PASS/FAIL.

---

## 3. Product Vision

> **One production domain in; an evidence-traceable, repeatable request-path and TLS/HTTP security assessment out.**

RequestTrace should be safe enough for low-impact external assessment, useful for daily DevSecOps diagnostics, structured enough for CI/CD automation, and readable enough for engineers, security leads, auditors and management.

---

## 4. Goals and Success Criteria

| Goal | Success Criterion |
|---|---|
| Zero-friction execution | A user can run a scan with Docker without installing Python, OpenSSL tooling or project dependencies on the host. |
| Developer-friendly source mode | A contributor can clone the repository, create an isolated environment, install dependencies and run the same CLI. |
| Professional reporting | Every actionable issue includes severity, description, evidence, impact, remediation, implementation guidance, verification and priority. |
| Evidence traceability | Every finding references the observation/evidence that triggered it. |
| Safe external assessment | Default scanning avoids destructive actions, exploitation, credential attacks and high-volume traffic. |
| Automation ready | JSON output, stable schema, machine-readable status and configurable exit codes support CI/CD. |
| Defensible output | Observed facts are separated from heuristics/inference and confidence is shown where appropriate. |
| Portable deployment | Release Docker images support Linux/amd64 and Linux/arm64. |

---

## 5. Non-Goals

- RequestTrace is not a vulnerability exploitation framework or penetration-testing suite.
- It does not claim to reconstruct private application, service, database or network hops from an external domain alone.
- It does not replace authenticated DAST, SAST, SCA, cloud configuration review, WAF testing or full penetration testing.
- It does not certify compliance with PCI DSS, ISO 27001, NIST or regulatory frameworks.
- It will not bypass authentication, brute-force credentials, fuzz arbitrary parameters or intentionally trigger destructive behavior by default.
- It will not assign a security grade from a single signal such as TLS version.

---

## 6. Personas and Core Use Cases

| Persona | Primary Need | Example |
|---|---|---|
| DevSecOps Engineer | Repeatable post-deployment verification | Run after production deployment and fail a pipeline if a new high-severity transport finding appears. |
| AppSec Engineer | External TLS/HTTP posture assessment | Assess certificates, protocols, redirects, headers and cookie controls. |
| Developer | Clear fix instructions | Understand why a control matters, how to fix it and how to verify remediation. |
| SRE / Platform Engineer | Request-path diagnostics | Inspect DNS, connectivity, redirects, ALPN, TTFB and edge indicators. |
| Security Lead / Auditor | Readable evidence-backed report | Review executive summary, findings and evidence without reading raw scanner output. |
| Open-source Contributor | Reproducible development environment | Clone GitHub, install development dependencies, run tests and extend checks. |

---

## 7. User Experience

### 7.1 Docker Quick Path

```bash
docker run --rm   -v "$(pwd)/reports:/app/reports"   ghcr.io/<org>/requesttrace:latest   scan https://example.com --report
```

### 7.2 Source / GitHub Path

```bash
git clone https://github.com/<org>/requesttrace.git
cd requesttrace

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e .

requesttrace scan https://example.com --report
```

### 7.3 Expected Output

- Concise terminal assessment summary.
- Professional Markdown report.
- Professional HTML report.
- PDF report from the same canonical report model.
- JSON evidence/result document.
- Deterministic exit code based on configured policy threshold.

---

## 8. Functional Requirements

### 8.1 Target Parsing and Scan Configuration

- Accept hostname, domain or full HTTP/HTTPS URL.
- Normalize scheme, hostname, port, path and query safely.
- Default to HTTPS when no scheme is supplied.
- Support explicit ports and paths.
- Support IPv4/IPv6 preference where applicable.
- Support configurable connect/read/overall timeouts.
- Use a clearly identifiable default RequestTrace user agent.
- Support `--format`, `--output`, `--report`, `--json`, `--verbose`, `--quiet`, `--baseline` and `--fail-on`.
- Reject unsupported schemes and malformed targets.
- Limit redirect traversal.

### 8.2 DNS Assessment Engine

- Resolve A and AAAA records.
- Collect CNAME chain where exposed.
- Collect authoritative NS records.
- Measure resolver lookup duration.
- Record all returned addresses.
- Record the address used by the HTTP client where observable.
- Detect NXDOMAIN, timeout and empty/inconsistent answers.
- Record resolver/environment limitations.
- Do not identify IP ownership/CDN as fact without supporting evidence.

### 8.3 Network Connectivity

- Attempt TCP connection to the selected service port.
- Measure connection duration.
- Record selected IP and address family.
- Differentiate timeout, refused and unreachable states.
- Do not perform broad port scanning.

### 8.4 TLS Security Assessment

RequestTrace must treat TLS as a first-class assessment area.

#### Protocol support

- Probe TLS 1.0, TLS 1.1, TLS 1.2 and TLS 1.3 where the runtime permits explicit negotiation.
- Detect deprecated protocol support.
- Record when a protocol cannot be tested because of runtime limitations.
- Never convert "not testable" into PASS.

#### Primary handshake

- SNI.
- Negotiated TLS version.
- Negotiated cipher.
- ALPN.
- HTTP/2 or HTTP/1.1 negotiation.
- Handshake duration.
- Handshake errors.

#### Certificate

- Subject.
- Issuer.
- SANs.
- Valid-from and valid-until dates.
- Days remaining.
- Fingerprint.
- Signature algorithm.
- Public-key algorithm.
- Key size where available.
- Hostname match.
- Trust-chain validation.
- Expired/not-yet-valid detection.
- Self-signed/untrusted conditions.
- Incomplete chain conditions where reliably observable.

#### Cryptography

- Versioned rules for weak/deprecated choices.
- Forward-secrecy characteristics where determinable.
- Certificate-key/signature assessment.
- Configurable certificate-expiry thresholds.

Protocol, certificate, cryptography and HTTPS-policy scoring must remain separate so one good control cannot hide another serious failure.

### 8.5 HTTP and HTTPS Assessment

- Issue a bounded safe GET request by default.
- Capture status code, final URL, HTTP version and content type.
- Test HTTP-to-HTTPS behavior separately.
- Capture redirect chain.
- Detect redirect loops.
- Detect HTTPS-to-HTTP downgrade redirects.
- Measure TTFB and total request duration where supported.
- Do not persist complete response bodies by default.
- Apply response-size limits where sampling is needed.
- Redact sensitive header values.

### 8.6 Security Header Assessment

Assess:

- `Strict-Transport-Security`
- HSTS `max-age`
- `includeSubDomains`
- `preload` as applicable
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- frame protection using CSP `frame-ancestors` and/or `X-Frame-Options`
- `Permissions-Policy`

Legacy headers may be recognized but must not be recommended as the preferred modern control.

### 8.7 Cookie Security

- Parse `Set-Cookie` metadata safely.
- Completely redact cookie values.
- Assess `Secure`.
- Assess `HttpOnly`.
- Assess `SameSite`.
- Handle multiple cookies.
- Avoid claiming every cookie must be `HttpOnly` when client-side access may be intentional.

### 8.8 CDN / Reverse Proxy / Edge Indicators

- Inspect DNS, response headers, TLS metadata and other safe external indicators.
- Provider detection must use confidence and supporting evidence.
- Use wording such as "indicators are consistent with" for heuristic matches.
- Never invent private reverse proxies, services or databases.
- Fingerprints should be independently maintainable.

### 8.9 Evidence Model

Every relevant observation must have a stable evidence ID.

Evidence should include:

- evidence ID
- observation ID
- module
- timestamp
- normalized value
- source method
- confidence
- sanitized raw metadata

Findings must reference one or more evidence IDs.

Scan metadata must include:

- scanner version
- ruleset version
- runtime
- container image version where applicable
- target
- scan configuration
- timestamps

### 8.10 Finding and Rule Engine

- Rules consume normalized observations.
- Rules never parse presentation/report text.
- Each rule has a stable ID.
- Each rule contains title, severity, rationale, condition, remediation and verification guidance.
- Supported severities: Critical, High, Medium, Low, Informational.
- Rulesets are versioned.
- Policy overrides are supported without modifying application source.
- Findings support future-compatible suppression/accepted-risk metadata without hiding observations.

Every actionable finding must contain:

1. Finding ID
2. Title
3. Severity
4. Status
5. Affected asset
6. Description
7. Evidence
8. Security impact
9. Recommendation
10. How to fix
11. Verification
12. Remediation priority

### 8.11 Professional Report Engine

Initial report formats:

- Markdown
- HTML
- JSON
- PDF when renderer quality is stable

Human-readable report sections:

1. Cover / metadata
2. Executive summary
3. Scope
4. Methodology
5. Limitations
6. Request-path summary
7. DNS assessment
8. Connectivity assessment
9. TLS security assessment
10. HTTP/HTTPS assessment
11. Security headers
12. Cookie security
13. CDN/proxy indicators
14. Performance observations
15. Findings summary
16. Detailed findings
17. Prioritized recommendations
18. Conclusion
19. Evidence appendix

Reports must distinguish:

- PASS
- Observation
- Finding
- Not Tested
- Error

### 8.12 JSON / CI/CD Output

- Publish a versioned JSON schema.
- Include metadata, target, observations, evidence, findings, severity summary and module status.
- Support clean stdout JSON mode.
- Support `--fail-on critical|high|medium|low|never`.
- Differentiate policy failure from runtime/scanner failure.
- Keep output deterministic except expected ephemeral fields.

### 8.13 Baseline and Drift Detection

- Load a previous JSON report as baseline.
- Compare DNS/TLS/HTTP/header posture.
- Classify findings as new, unchanged or resolved.
- Highlight certificate, protocol, redirect, header and edge-indicator changes.
- Never allow a baseline to suppress current risk.

---

## 9. Professional Finding Standard

| Field | Requirement |
|---|---|
| Finding ID | Stable rule identifier such as `RT-TLS-001`. |
| Title | Clear failed-control description. |
| Severity | Critical / High / Medium / Low / Informational. |
| Status | Open / Resolved / future Accepted Risk metadata. |
| Affected Asset | Normalized target and relevant port/path. |
| Description | What was observed and what the control means. |
| Evidence | Sanitized observations and evidence IDs. |
| Security Impact | Realistic conditional impact. |
| Recommendation | Desired secure state. |
| How to Fix | Technology-aware examples where appropriate. |
| Verification | Concrete command/check after remediation. |
| Priority | Recommended remediation priority/timeframe. |
| References | Optional authoritative reference identifiers. |

---

## 10. CLI Specification

```text
requesttrace scan <target>

--report
--format md|html|pdf|json|all
--output <dir>
--fail-on critical|high|medium|low|never
--baseline <file.json>
--config <file>
--timeout <seconds>
--max-redirects <n>
--verbose
--quiet
--version
```

---

## 11. Exit Code Contract

| Exit | Meaning |
|---:|---|
| 0 | Scan completed and configured security threshold was not breached. |
| 1 | Scan completed and a finding breached the configured `--fail-on` threshold. |
| 2 | Invalid command, target or configuration. |
| 3 | Network/scan execution failed before a valid assessment completed. |
| 4 | Internal application/reporting error. |

---

## 12. Architecture

```text
CLI / Config
    |
    v
Target Normalizer
    |
    +--> DNS Engine
    +--> Connectivity Engine
    +--> TLS Engine
    +--> HTTP Engine
             |
             +--> Redirect Analyzer
             +--> Header Analyzer
             +--> Cookie Analyzer
             +--> Edge Fingerprints
    |
    v
Normalized Observation Store
    |
    v
Evidence Store
    |
    v
Versioned Rule / Finding Engine
    |
    +--> Terminal Summary
    +--> JSON
    +--> Markdown
    +--> HTML
    +--> PDF
    |
    v
Baseline Comparison / Exit Policy
```

---

## 13. Proposed Repository Structure

```text
requesttrace/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requesttrace/
│   ├── cli.py
│   ├── config.py
│   ├── target.py
│   ├── models/
│   ├── scanners/
│   │   ├── dns.py
│   │   ├── network.py
│   │   ├── tls.py
│   │   └── http.py
│   ├── analyzers/
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── redirects.py
│   │   └── edge.py
│   ├── rules/
│   ├── evidence/
│   ├── reporting/
│   └── util/
├── schemas/
├── templates/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── examples/
└── .github/workflows/
```

---

## 14. Docker and Distribution Requirements

- Multi-stage build where practical.
- Non-root runtime user.
- Pinned runtime dependencies.
- Minimal maintained runtime image.
- Required CA certificates included.
- No privileged mode.
- No host networking requirement for standard scanning.
- Persistent `/app/reports` output path.
- Linux/amd64 and Linux/arm64.
- Versioned image tags.
- Automated image publishing.
- SBOM generation.
- Dependency/container security scanning.
- Release/image signing when release engineering supports it.
- `pyproject.toml` source installation.
- Separate development dependencies.

---

## 15. Security and Safety Requirements

- Users must only scan targets they own or are authorized to assess.
- Default request volume must be low and bounded.
- No brute force.
- No credential attacks.
- No exploitation.
- No destructive requests.
- No response-body persistence by default.
- Redact `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` values and configured sensitive headers.
- Validate output filenames and prevent path traversal.
- Escape untrusted strings in HTML.
- Never construct shell commands from target input.
- Maintain `SECURITY.md` and responsible disclosure.

---

## 16. Non-Functional Requirements

| Area | Requirement |
|---|---|
| Performance | Typical scans complete within a bounded practical window; every network operation has a timeout. |
| Reliability | One module failure does not erase successful evidence from other modules. |
| Portability | Docker is the universal path; source mode supports declared maintained Python versions. |
| Maintainability | Scanner, rule, evidence and reporting layers are decoupled. |
| Testability | Network interactions are mockable and controlled integration fixtures are available. |
| Observability | Verbose mode provides useful diagnostics without exposing secrets. |
| Accessibility | Human reports use readable semantic hierarchy and tables. |
| Determinism | Same evidence + same ruleset produces the same finding result. |

---

## 17. Data Model

| Object | Key Fields |
|---|---|
| Scan | scan_id, started_at, completed_at, scanner_version, ruleset_version, config, target |
| Target | input, scheme, host, port, path, normalized_url |
| Observation | observation_id, module, type, value, timestamp, confidence |
| Evidence | evidence_id, observation_id, sanitized_raw, source_method, metadata |
| Finding | finding_id, rule_id, title, severity, status, affected_asset, evidence_ids, impact, remediation, verification |
| Module Result | module, status, duration, errors, observation_ids |
| Baseline Diff | control/finding, previous_state, current_state, change_type |

---

## 18. Assessment Labels

Severity remains the authoritative risk signal.

Default overall labels:

- PASS
- PASS WITH OBSERVATIONS
- REMEDIATION REQUIRED
- HIGH RISK
- ASSESSMENT INCOMPLETE

A scan that cannot complete important TLS/HTTP checks must not be reported as PASS.

Any optional numeric score must be transparent and subordinate to individual finding severity.

---

## 19. Testing Strategy

- Unit tests for normalization, rules, evidence linkage, redaction, severity and report rendering.
- TLS fixtures for valid, expired, hostname mismatch, untrusted and protocol cases.
- HTTP fixtures for redirects, downgrade, headers and cookies.
- Controlled local TLS/HTTP integration services.
- Golden-file tests for JSON and professional reports.
- Docker smoke tests.
- HTML escaping/path/secret-redaction security tests.
- CI matrix for supported Python versions.
- Multi-architecture container build tests.

---

## 20. Acceptance Criteria for v1.0

- A Docker user can scan a public HTTPS domain and persist reports without installing project dependencies.
- A source user can clone, install and run the same assessment.
- DNS, TCP, TLS, HTTP, redirect, header and cookie checks produce normalized evidence.
- TLS includes protocol support, certificate validity/hostname/expiry, negotiated cipher and ALPN where available.
- Markdown, HTML and JSON outputs are production quality.
- PDF is included when renderer quality is stable.
- Every security finding contains evidence, impact, remediation and verification.
- Sensitive values are redacted in terminal, JSON and reports.
- Edge/provider identification distinguishes inference from observation.
- CI/CD `--fail-on` behavior is tested and documented.
- Docker runs as non-root.
- README documents quick start, source installation, architecture, limitations, security and CI/CD.

---

## 21. Future Roadmap

- Correlation-ID based internal trace integrations.
- OpenTelemetry correlation.
- Scheduled monitoring and drift alerts.
- SARIF output.
- Organizational policy packs.
- REST API / web UI.
- Plugin SDK.
- Signed evidence/attestation bundles.
- Additional DNS/TLS controls where portability and evidence quality justify them.

---

## 22. Definition of Done

RequestTrace v1.0 is done when a new user can run it through Docker or source, assess an authorized real domain, receive accurate evidence-linked DNS/TLS/HTTP findings, understand what needs remediation and how to verify it, consume the result in CI/CD, and reproduce the workflow from public documentation without undocumented host dependencies.
