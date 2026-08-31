# RequestTrace — Detailed 8-Week Trello Engineering Plan

**Version:** 1.0  
**Duration:** 8 weeks  
**Primary Release:** RequestTrace v1.0  
**Board Flow:** Backlog → Ready → In Progress → Review → QA → Done

---

## Delivery Principles

- Every ticket produces code, tests, documentation or a verifiable release artifact.
- Security findings are evidence-driven.
- Docker and source workflows are developed in parallel.
- No ticket is Done without acceptance criteria and tests.
- Network behavior is bounded by safe defaults and timeouts.
- Reports distinguish observed facts, inference, not-tested states and errors.

---

# Week 1 — Foundation, CLI, Data Model, Docker & CI

## RT-001 — Initialize repository and engineering standards

### Implementation Checklist
- [ ] Create production package/repository structure.
- [ ] Add LICENSE, SECURITY.md, CONTRIBUTING.md and CHANGELOG.md.
- [ ] Configure formatter, linter, type checking and tests.
- [ ] Add .editorconfig, .gitignore and pre-commit configuration.
- [ ] Document supported Python versions.

### Acceptance Criteria
- [ ] Repository installs in editable mode.
- [ ] Quality commands run locally and in CI.
- [ ] Report templates are not coupled to core application logic.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-002 — Define normalized scan/evidence/finding models

### Implementation Checklist
- [ ] Define Scan, Target, Observation, Evidence, Finding and ModuleResult models.
- [ ] Add stable IDs and serialization.
- [ ] Add severity/status enums.
- [ ] Add evidence-to-finding references.
- [ ] Write serialization tests.

### Acceptance Criteria
- [ ] Models serialize cleanly to JSON.
- [ ] Findings reference evidence IDs.
- [ ] Invalid values are test-covered.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-003 — Build target normalizer and validation

### Implementation Checklist
- [ ] Parse hostname, scheme, port, path and query.
- [ ] Default scheme to HTTPS.
- [ ] Reject unsupported schemes and malformed targets.
- [ ] Normalize IDN/IP cases safely.
- [ ] Add edge-case tests.

### Acceptance Criteria
- [ ] Domains and full URLs normalize correctly.
- [ ] Malformed target returns exit 2.
- [ ] Target input is never interpolated into shell commands.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-004 — Implement CLI skeleton

### Implementation Checklist
- [ ] Add `scan` command.
- [ ] Add output/report/JSON/verbose/quiet/timeout/version options.
- [ ] Create progress/status abstraction.
- [ ] Wire exit-code framework.
- [ ] Add CLI tests.

### Acceptance Criteria
- [ ] `requesttrace --help` is complete.
- [ ] CLI accepts normalized targets.
- [ ] Errors are actionable.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-005 — Create non-root Docker runtime

### Implementation Checklist
- [ ] Create multi-stage Dockerfile.
- [ ] Install CA/runtime requirements.
- [ ] Create non-root user.
- [ ] Define report output path.
- [ ] Add `.dockerignore`.
- [ ] Create container smoke command/test.

### Acceptance Criteria
- [ ] Docker build succeeds.
- [ ] Container runs non-root.
- [ ] Mounted reports persist.
- [ ] No privileged mode required.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-006 — Set up GitHub Actions CI

### Implementation Checklist
- [ ] Run lint/type/unit tests.
- [ ] Build Docker image.
- [ ] Run container smoke test.
- [ ] Cache dependencies safely.
- [ ] Preserve useful failure artifacts.

### Acceptance Criteria
- [ ] PR receives deterministic CI result.
- [ ] Container smoke test produces expected output.
- [ ] CI contains no secrets.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 2 — DNS & Connectivity Engine

## RT-007 — Implement DNS A/AAAA resolution

### Implementation Checklist
- [ ] Resolve A and AAAA.
- [ ] Capture all addresses.
- [ ] Measure duration.
- [ ] Handle NXDOMAIN/timeouts.
- [ ] Create evidence objects.

### Acceptance Criteria
- [ ] Successful resolution emits evidence IDs.
- [ ] Failures are module errors, not fabricated findings.
- [ ] IPv4/IPv6 are represented separately.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-008 — Implement CNAME and NS collection

### Implementation Checklist
- [ ] Resolve bounded CNAME chain.
- [ ] Collect NS records.
- [ ] Record resolver limitations.
- [ ] Add fixtures/mocks.

### Acceptance Criteria
- [ ] CNAME loops cannot hang scan.
- [ ] Results are normalized and tested.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-009 — Implement TCP connectivity check

### Implementation Checklist
- [ ] Connect only to normalized service port.
- [ ] Record selected IP/family.
- [ ] Measure duration.
- [ ] Differentiate timeout/refused/unreachable.
- [ ] Honor configured timeout.

### Acceptance Criteria
- [ ] No port scan occurs.
- [ ] Errors are categorized.
- [ ] Success is linked to evidence.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-010 — Create DNS/connectivity report sections

### Implementation Checklist
- [ ] Render module status.
- [ ] Render DNS records/timing.
- [ ] Render connectivity.
- [ ] Show Not Tested/Error distinctly.
- [ ] Add golden tests.

### Acceptance Criteria
- [ ] Human output is readable without raw `dig`.
- [ ] JSON preserves normalized values.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-011 — Add DNS/connectivity integration fixtures

### Implementation Checklist
- [ ] Create controlled test strategy.
- [ ] Create reachable/refused/timeout fixtures where CI-safe.
- [ ] Document test boundaries.

### Acceptance Criteria
- [ ] Core CI does not depend on uncontrolled public domains.
- [ ] Tests are deterministic.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 3 — Comprehensive TLS Assessment

## RT-012 — Implement primary TLS handshake collector

### Implementation Checklist
- [ ] Connect with SNI.
- [ ] Record negotiated protocol.
- [ ] Record cipher.
- [ ] Record ALPN.
- [ ] Measure handshake.
- [ ] Capture errors.

### Acceptance Criteria
- [ ] TLS evidence emitted on success.
- [ ] Verification errors preserved.
- [ ] Timeouts bounded.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-013 — Implement certificate parser

### Implementation Checklist
- [ ] Extract subject/issuer.
- [ ] Extract SANs.
- [ ] Extract validity.
- [ ] Extract signature/public-key metadata.
- [ ] Calculate fingerprint/days remaining.

### Acceptance Criteria
- [ ] Fields normalized.
- [ ] No sensitive key material stored.
- [ ] Controlled certificate tests pass.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-014 — Implement trust, hostname and validity checks

### Implementation Checklist
- [ ] Validate trust chain.
- [ ] Validate hostname/SAN.
- [ ] Detect expired/not-yet-valid.
- [ ] Detect self-signed/untrusted.
- [ ] Represent incomplete checks separately.

### Acceptance Criteria
- [ ] Hostname mismatch triggers expected finding.
- [ ] Expired certificate triggers policy severity.
- [ ] Errors are not swallowed.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-015 — Implement TLS protocol support probing

### Implementation Checklist
- [ ] Probe TLS 1.0/1.1/1.2/1.3 where runtime permits.
- [ ] Record runtime limitations.
- [ ] Avoid broad cipher brute force.
- [ ] Trigger deprecated-protocol rules.

### Acceptance Criteria
- [ ] Deprecated enabled protocols create findings.
- [ ] Disabled protocols create passing evidence.
- [ ] Untestable never becomes false PASS.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-016 — Implement TLS cryptography rules

### Implementation Checklist
- [ ] Create versioned rule metadata.
- [ ] Assess negotiated cipher.
- [ ] Assess key size/signature.
- [ ] Represent forward secrecy where determinable.
- [ ] Attach ruleset version.

### Acceptance Criteria
- [ ] Rules use observations.
- [ ] Findings reference evidence.
- [ ] Severity mapping is tested.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-017 — Implement certificate-expiry thresholds

### Implementation Checklist
- [ ] Add warning/critical thresholds.
- [ ] Validate configuration.
- [ ] Generate remediation/verification.
- [ ] Test boundary days.

### Acceptance Criteria
- [ ] Threshold behavior deterministic.
- [ ] Report states exact expiry/days remaining.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-018 — Build professional TLS report section

### Implementation Checklist
- [ ] Protocol table.
- [ ] Certificate table.
- [ ] Cryptography table.
- [ ] Handshake/ALPN table.
- [ ] Detailed remediation findings.
- [ ] Explicit limitations.

### Acceptance Criteria
- [ ] No TLS failure is only PASS/FAIL.
- [ ] Each issue explains impact, fix and verification.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 4 — HTTP, Redirects, Headers, Cookies & Edge

## RT-019 — Implement safe HTTP request collector

### Implementation Checklist
- [ ] Use safe GET default.
- [ ] Set RequestTrace user agent.
- [ ] Capture status/final URL/version/content type.
- [ ] Measure TTFB/total where possible.
- [ ] Bound body handling.
- [ ] Honor timeouts.

### Acceptance Criteria
- [ ] Standard endpoint is assessable.
- [ ] Body not persisted by default.
- [ ] Errors explicit.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-020 — Implement redirect-chain analyzer

### Implementation Checklist
- [ ] Capture every hop.
- [ ] Enforce max redirects.
- [ ] Detect loops.
- [ ] Detect HTTPS→HTTP downgrade.
- [ ] Test HTTP→HTTPS separately.

### Acceptance Criteria
- [ ] Evidence shows each hop.
- [ ] Loops terminate safely.
- [ ] Downgrade triggers finding.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-021 — Implement security-header analyzer

### Implementation Checklist
- [ ] Parse HSTS.
- [ ] Assess CSP presence/basic high-risk patterns.
- [ ] Assess X-Content-Type-Options.
- [ ] Assess Referrer-Policy.
- [ ] Assess frame protection.
- [ ] Assess Permissions-Policy informationally.

### Acceptance Criteria
- [ ] Header matching case-insensitive.
- [ ] Findings contain evidence/remediation.
- [ ] Legacy controls not preferred.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-022 — Implement cookie attribute analyzer

### Implementation Checklist
- [ ] Parse Set-Cookie safely.
- [ ] Redact values.
- [ ] Assess Secure/HttpOnly/SameSite context.
- [ ] Handle multiple cookies.
- [ ] Create report-safe cookie labels.

### Acceptance Criteria
- [ ] Cookie values never appear in artifacts.
- [ ] Contextual findings avoid universal false claims.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-023 — Implement CDN/proxy indicator engine

### Implementation Checklist
- [ ] Create fingerprint interface.
- [ ] Use DNS/header/TLS signals.
- [ ] Attach evidence.
- [ ] Assign confidence.
- [ ] Use non-absolute wording for heuristics.

### Acceptance Criteria
- [ ] Observed/inferred labels correct.
- [ ] Unknown provider is valid.
- [ ] Internal topology is never invented.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-024 — Create request-path visualization model

### Implementation Checklist
- [ ] Build path from observed modules.
- [ ] Mark inferred edge nodes.
- [ ] Mark unavailable internal path.
- [ ] Render Markdown/HTML-safe view.

### Acceptance Criteria
- [ ] Diagram does not claim hidden services.
- [ ] Every stage status is clear.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 5 — Rule Engine, Risk, Remediation & Evidence Traceability

## RT-025 — Build versioned rule engine

### Implementation Checklist
- [ ] Define rule schema/interface.
- [ ] Implement registry.
- [ ] Implement severity/status.
- [ ] Link evidence IDs.
- [ ] Add ruleset version.

### Acceptance Criteria
- [ ] Output deterministic.
- [ ] Presentation not used for logic.
- [ ] Rules independently testable.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-026 — Create remediation knowledge model

### Implementation Checklist
- [ ] Define remediation fields.
- [ ] Add technology-neutral guidance.
- [ ] Add NGINX examples.
- [ ] Add application/Next.js examples.
- [ ] Add managed-edge guidance conditionally.

### Acceptance Criteria
- [ ] Every actionable finding has remediation/verification.
- [ ] Examples do not falsely claim detected technology.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-027 — Implement evidence sanitization/redaction

### Implementation Checklist
- [ ] Create sensitive-header registry.
- [ ] Redact auth/cookie values.
- [ ] Sanitize errors.
- [ ] HTML-escape untrusted strings.
- [ ] Test mixed-case/encoded cases.

### Acceptance Criteria
- [ ] Secrets absent from artifacts.
- [ ] Redaction applies to verbose logs and JSON.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-028 — Implement assessment labels and severity summary

### Implementation Checklist
- [ ] Define label rules.
- [ ] Count severities.
- [ ] Represent incomplete modules.
- [ ] Document any optional scoring.

### Acceptance Criteria
- [ ] High risk cannot produce misleading PASS.
- [ ] Incomplete critical module can produce ASSESSMENT INCOMPLETE.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-029 — Implement `--fail-on` policy and exit codes

### Implementation Checklist
- [ ] Parse threshold.
- [ ] Map findings to breach.
- [ ] Separate policy from runtime failure.
- [ ] Test all exit codes.

### Acceptance Criteria
- [ ] Exit 1 means completed scan/policy breach.
- [ ] Runtime failures use documented codes.
- [ ] README examples match implementation.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 6 — Professional Reports, JSON Schema & Baselines

## RT-030 — Implement canonical report view model

### Implementation Checklist
- [ ] Map scan/evidence/findings into report sections.
- [ ] Include scope/methodology/limitations.
- [ ] Include module tables.
- [ ] Include findings/priorities.

### Acceptance Criteria
- [ ] All renderers carry equivalent security meaning.
- [ ] Renderers never invent findings.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-031 — Build production Markdown report

### Implementation Checklist
- [ ] Cover metadata.
- [ ] Executive summary.
- [ ] Request path.
- [ ] Module sections.
- [ ] Detailed findings.
- [ ] Recommendations/conclusion.
- [ ] Evidence appendix.

### Acceptance Criteria
- [ ] Readable in GitHub.
- [ ] Tables/code render correctly.
- [ ] No secrets.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-032 — Build production HTML report

### Implementation Checklist
- [ ] Semantic headings/tables.
- [ ] Embedded minimal CSS.
- [ ] Severity labels.
- [ ] Escape untrusted content.
- [ ] Print-friendly layout.

### Acceptance Criteria
- [ ] Works offline.
- [ ] No external JS required.
- [ ] Injection tests pass.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-033 — Implement PDF report generation

### Implementation Checklist
- [ ] Use deterministic renderer.
- [ ] Add header/footer.
- [ ] Handle long tables/findings.
- [ ] Add smoke/golden checks.
- [ ] Fail gracefully if optional.

### Acceptance Criteria
- [ ] No clipping in test report.
- [ ] Content matches canonical report model.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-034 — Publish versioned JSON schema

### Implementation Checklist
- [ ] Create schema.
- [ ] Validate reports.
- [ ] Document compatibility policy.
- [ ] Add schema version.

### Acceptance Criteria
- [ ] Every JSON report validates.
- [ ] Breaking changes require schema version change.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-035 — Implement baseline comparison

### Implementation Checklist
- [ ] Load previous JSON.
- [ ] Validate compatibility.
- [ ] Compare stable controls/findings.
- [ ] Classify new/unchanged/resolved.
- [ ] Render change summary.

### Acceptance Criteria
- [ ] New findings obvious.
- [ ] Resolved state requires current evidence.
- [ ] Baseline never suppresses risk.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 7 — Hardening, Testing, CI/CD & Release Engineering

## RT-036 — Expand unit and integration coverage

### Implementation Checklist
- [ ] Add TLS fixtures.
- [ ] Add redirect/header/cookie fixtures.
- [ ] Add timeout/error tests.
- [ ] Add report golden tests.
- [ ] Set practical coverage threshold.

### Acceptance Criteria
- [ ] Critical paths tested.
- [ ] Core CI avoids random internet dependencies.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-037 — Security hardening review

### Implementation Checklist
- [ ] Threat-model target input/output.
- [ ] Review process/shell usage.
- [ ] Review HTML escaping.
- [ ] Review redaction.
- [ ] Review dependencies.
- [ ] Document residual risks.

### Acceptance Criteria
- [ ] No target-derived shell execution.
- [ ] Path traversal tests pass.
- [ ] Threat model stored in repo.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-038 — Container security and SBOM

### Implementation Checklist
- [ ] Pin base-image strategy.
- [ ] Run non-root.
- [ ] Generate SBOM.
- [ ] Scan dependencies/image.
- [ ] Review runtime footprint.

### Acceptance Criteria
- [ ] Release pipeline handles agreed critical issues.
- [ ] SBOM produced as release evidence.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-039 — Multi-architecture image publishing

### Implementation Checklist
- [ ] Configure buildx.
- [ ] Build amd64/arm64.
- [ ] Push version tags.
- [ ] Add provenance/signing where available.
- [ ] Document registry use.

### Acceptance Criteria
- [ ] Fresh machine can pull/run tagged image.
- [ ] Architecture matrix passes.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-040 — Add CI/CD usage examples

### Implementation Checklist
- [ ] GitHub Actions example.
- [ ] Generic Docker pipeline example.
- [ ] Artifact upload.
- [ ] `--fail-on` example.
- [ ] Baseline example.

### Acceptance Criteria
- [ ] Examples use real exit semantics.
- [ ] Workflow syntax tested where practical.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-041 — Performance and timeout tuning

### Implementation Checklist
- [ ] Measure scan duration.
- [ ] Tune defaults.
- [ ] Bound redirects/probes.
- [ ] Test slow/unreachable hosts.
- [ ] Document caveats.

### Acceptance Criteria
- [ ] No default call waits indefinitely.
- [ ] Partial evidence survives module failure.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

# Week 8 — Documentation, UX, Release Candidate & v1.0

## RT-042 — Complete production README

### Implementation Checklist
- [ ] Problem/solution.
- [ ] Features.
- [ ] Docker quick start.
- [ ] Source install.
- [ ] CLI reference.
- [ ] Reports.
- [ ] CI/CD.
- [ ] Architecture.
- [ ] Limitations.
- [ ] Security.
- [ ] Contributing/roadmap.

### Acceptance Criteria
- [ ] New user can run without external instructions.
- [ ] Docker/source paths equally clear.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-043 — Create example professional report bundle

### Implementation Checklist
- [ ] Generate synthetic `.md`.
- [ ] Generate `.html`.
- [ ] Generate `.json`.
- [ ] Generate `.pdf` if supported.
- [ ] Demonstrate remediation format.

### Acceptance Criteria
- [ ] No real secrets.
- [ ] Examples demonstrate professional findings.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-044 — Finalize SECURITY and responsible disclosure

### Implementation Checklist
- [ ] Supported versions.
- [ ] Private reporting process.
- [ ] Required report details.
- [ ] Disclosure expectations.
- [ ] Scope.

### Acceptance Criteria
- [ ] README links to SECURITY.md.
- [ ] No public disclosure of unpatched vulnerabilities is encouraged.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-045 — Release candidate end-to-end test

### Implementation Checklist
- [ ] Test Docker on clean host.
- [ ] Test fresh source install.
- [ ] Test report persistence.
- [ ] Test invalid/unreachable targets.
- [ ] Test fail-on.
- [ ] Review all formats.

### Acceptance Criteria
- [ ] All v1 acceptance criteria pass.
- [ ] No undocumented Docker dependency.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

## RT-046 — Publish RequestTrace v1.0

### Implementation Checklist
- [ ] Tag release.
- [ ] Publish images.
- [ ] Publish release notes.
- [ ] Attach schemas/SBOM.
- [ ] Verify README commands against tag.

### Acceptance Criteria
- [ ] Tagged source/image run successfully.
- [ ] Artifacts are documented/reproducible.
- [ ] Known limitations published.

### Done When
- [ ] Implementation is merged.
- [ ] Tests are green.
- [ ] Acceptance criteria are verified.
- [ ] User-facing documentation is updated where applicable.
- [ ] Relevant evidence/report artifact is attached or reproducible.

---

# Release Gate Checklist

- [ ] Docker path tested on a clean host with only Docker available.
- [ ] Source path tested from a fresh clone and clean virtual environment.
- [ ] JSON output validates against the published schema.
- [ ] Professional report formats reviewed for correctness and redaction.
- [ ] TLS invalid/expired/hostname-mismatch/deprecated-protocol fixtures pass.
- [ ] Redirect/header/cookie fixtures pass.
- [ ] Edge heuristics never present unsupported inference as fact.
- [ ] CI/CD exit codes match documentation.
- [ ] Container runs non-root without privileged capabilities.
- [ ] SBOM and dependency/container security checks complete.
- [ ] README commands executed against release candidate.
- [ ] Known limitations and authorization warning are visible.

---

# Recommended Trello Card Template

```text
CARD ID — TITLE

WHY
What problem does this card solve?

DELIVERABLE
What concrete artifact/code behavior must exist?

IMPLEMENTATION CHECKLIST
[ ] ...
[ ] ...

TESTS
[ ] Unit
[ ] Integration
[ ] Failure path
[ ] Security/redaction where applicable

ACCEPTANCE CRITERIA
[ ] Observable outcome 1
[ ] Observable outcome 2

DOCUMENTATION
[ ] README/docs updated if user-facing

DONE WHEN
Code merged, CI green, acceptance criteria verified, and evidence/report artifact attached where useful.
```
