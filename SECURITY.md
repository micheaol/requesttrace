# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x (latest) | Yes |
| < 1.0 (pre-release) | No |

Only the most recent minor release line receives security fixes. Users are
expected to track `latest` Docker tags or the newest published PyPI/source
release.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security
vulnerabilities.

Instead, report privately using one of:

- GitHub Security Advisories: use the "Report a vulnerability" button on the
  repository's Security tab.
- Email: security@requesttrace.dev (PGP key available on request).

### What to include

- A clear description of the vulnerability and its impact.
- Steps to reproduce, including the RequestTrace version, execution mode
  (Docker image tag or source commit), and target environment.
- Any proof-of-concept scan configuration or sanitized output that
  demonstrates the issue. **Do not** include secrets, credentials, or data
  belonging to third parties you are not authorized to share.

### What to expect

- Acknowledgement within 3 business days.
- An initial assessment (confirmed, needs more information, or not
  applicable) within 10 business days.
- Coordinated disclosure: we will work with you on a fix timeline and will
  credit reporters (unless anonymity is requested) in the release notes once
  a patch ships.
- Please allow 90 days from acknowledgement before any public disclosure,
  unless we agree to a different timeline together.

## Scope

In scope:

- The `requesttrace` CLI and library code in this repository.
- The published Docker images and their build process.
- Report renderers (Markdown/HTML/PDF/JSON) with respect to injection,
  secret leakage, or path traversal.

Out of scope:

- Vulnerabilities in third-party targets that a user chooses to scan.
- Findings that require the attacker to already control the machine running
  RequestTrace.
- Denial of service via extreme resource exhaustion caused by
  intentionally malformed local configuration files you control yourself.

## Responsible Use

RequestTrace performs external, low-impact reconnaissance and safety-bounded
requests. Users must only scan targets they own or are explicitly authorized
to assess. Misuse of this tool against unauthorized targets is outside the
scope of what the maintainers support or condone.
