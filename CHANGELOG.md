# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses date-based tracking during pre-1.0 development.

## [Unreleased]

## [1.0.0] - 2026-08-31

### Added

- Initial public release of RequestTrace.
- Target normalizer with scheme/host/port/path validation.
- DNS engine: A/AAAA resolution, CNAME chain, NS collection.
- Connectivity engine: bounded TCP connect checks.
- TLS engine: handshake collector, certificate parser, trust/hostname
  validation, protocol support probing (TLS 1.0–1.3), cryptography rules,
  certificate-expiry thresholds.
- HTTP engine: safe GET collector, redirect-chain analyzer, security-header
  analyzer, cookie attribute analyzer, CDN/edge indicator engine,
  request-path visualization model.
- Versioned rule engine with evidence-linked findings and remediation
  knowledge base.
- Report renderers: JSON (schema-versioned), Markdown, HTML, optional PDF.
- Baseline comparison / drift detection.
- `--fail-on` policy engine with deterministic exit codes.
- Docker image (non-root, multi-arch) and GitHub Actions CI.
