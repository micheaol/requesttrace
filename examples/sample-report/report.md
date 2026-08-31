# RequestTrace Security Assessment Report

**Target:** https://example.com/
**Scan ID:** scan-3ab309de4375
**Started:** 2026-08-31 19:05:54.377163+00:00
**Completed:** 2026-08-31 19:05:57.048120+00:00
**Scanner Version:** 1.0.0 · **Ruleset:** 2026.08.1 · **Schema:** 1.0.0
**Runtime:** Python 3.13.1 (darwin)

## Overall Assessment: REMEDIATION REQUIRED

---

## 1. Executive Summary

RequestTrace assessed https://example.com/ and produced an overall result of REMEDIATION REQUIRED, based on 6 finding(s) across DNS, connectivity, TLS, HTTP, header, cookie and edge-indicator checks.

## 2. Scope

This assessment covers the externally observable request path for https://example.com/ only: DNS resolution, TCP connectivity, TLS negotiation, and the HTTP response (headers, cookies, redirects). No authentication, exploitation or internal network access was attempted.

## 3. Methodology

RequestTrace 1.0.0 performed a single bounded scan using ruleset 2026.08.1 on Python 3.13.1 (darwin). Findings are generated exclusively from normalized observations linked to sanitized evidence — never from raw/unstructured output.

## 4. Limitations

RequestTrace observes only what is externally visible. It cannot see internal services, databases or private network hops, does not perform authenticated testing, exploitation, brute force or fuzzing, and does not certify compliance with any regulatory framework. 'Not Tested' results reflect a runtime limitation and must never be read as a passing result.

## 5. Request-Path Summary

| Stage | Status | Detail |
|---|---|---|
| Client DNS Resolution | Observed | example.com |
| TCP Connectivity | Observed | example.com |
| TLS Negotiation | Observed | example.com |
| HTTP Request/Response | Observed | https://example.com/ |
| Edge / CDN (inferred) *(inferred)* | Inferred from indicators | Indicators are consistent with Cloudflare. (confidence: high) |
| Origin Application *(inferred)* | Not directly observable | RequestTrace cannot see internal services, databases or private network hops beyond the externally observable HTTP response. |

## 6. DNS Assessment

- Status: **completed** (270.6 ms)
- `a_records`: ['104.20.23.154', '172.66.147.243']
- `aaaa_records`: ['2606:4700:10::6814:179a', '2606:4700:10::ac42:93f3']
- `ns_records`: ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']

## 7. Connectivity Assessment

- Status: **completed** (239.43 ms)
- `tcp_connection`: {'selected_ip': '172.66.147.243', 'port': 443, 'address_family': 'IPv4'}

## 8. TLS Security Assessment

- Status: **completed** (1454.42 ms)
- `sni`: example.com
- `negotiated_protocol`: TLSv1.3
- `negotiated_cipher`: {'name': 'TLS_AES_256_GCM_SHA384', 'protocol': 'TLSv1.3', 'bits': 256}
- `alpn_protocol`: h2
- `handshake_duration_ms`: 250.38
- `certificate`: {'subject': 'CN=example.com', 'issuer': 'CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US', 'subject_alternative_names': ['example.com', '*.example.com'], 'not_valid_before': '2026-07-29T22:10:08+00:00', 'not_valid_after': '2026-10-27T22:17:21+00:00', 'days_remaining': 57, 'fingerprint_sha256': '6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200', 'signature_algorithm': 'ecdsa-with-SHA256', 'public_key_algorithm': 'EC (secp256r1)', 'public_key_size_bits': 256}
- `hostname_match`: {'matches': True, 'matched_name': 'example.com'}
- `trust_chain_valid`: True
- `protocol_support`: {'TLS 1.0': {'tested': True, 'supported': False, 'reason': '[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1018)', 'note': 'Local OpenSSL security policy may also reject this legacy protocol independent of server support.'}, 'TLS 1.1': {'tested': True, 'supported': False, 'reason': '[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1018)', 'note': 'Local OpenSSL security policy may also reject this legacy protocol independent of server support.'}, 'TLS 1.2': {'tested': True, 'supported': True, 'reason': None}, 'TLS 1.3': {'tested': True, 'supported': True, 'reason': None}}

## 9. HTTP/HTTPS Assessment

- Status: **completed** (703.69 ms)
- `final_url`: https://example.com/
- `status_code`: 200
- `http_version`: HTTP/1.1
- `content_type`: text/html
- `ttfb_ms`: 423.07
- `total_duration_ms`: 431.96
- `response_headers`: {'Date': 'Mon, 31 Aug 2026 19:05:57 GMT', 'Content-Type': 'text/html', 'Transfer-Encoding': 'chunked', 'Connection': 'keep-alive', 'Server': 'cloudflare', 'last-modified': 'Mon, 31 Aug 2026 04:09:32 GMT', 'allow': 'GET, HEAD', 'Age': '6696', 'cf-cache-status': 'HIT', 'Content-Encoding': 'gzip', 'CF-RAY': 'a33e4f447cb90e00-AMS'}
- `http_to_https_redirect`: {'probed_url': 'http://example.com/', 'status_code': 200, 'location': None, 'redirects_to_https': False}

## 10. Security Headers

- `hsts`: {'present': False, 'raw': None, 'max_age': None, 'include_subdomains': False, 'preload': False}
- `content_security_policy`: {'present': False, 'raw': None, 'high_risk_patterns': []}
- `x_content_type_options`: {'present': False, 'value': None, 'valid_nosniff': False}
- `referrer_policy`: {'present': False, 'value': None}
- `frame_protection`: {'csp_frame_ancestors_present': False, 'x_frame_options_present': False, 'x_frame_options_value': None, 'protected': False}
- `permissions_policy`: {'present': False, 'value': None}

## 11. Cookie Security

- `cookies_present`: False

## 12. CDN / Proxy Indicators

- `edge_provider_indicators`: {'matches': [{'provider': 'Cloudflare', 'confidence': 'high', 'indicators': ["Response header 'CF-RAY' present", "Response header 'Server: cloudflare'", "Certificate issuer 'CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US'"], 'statement': 'Indicators are consistent with Cloudflare.'}], 'unknown': False}

## 13. Performance Observations

- TTFB: 423.07 ms
- Total request duration: 431.96 ms

## 14. Findings Summary

| Severity | Count |
|---|---|
| informational | 0 |
| low | 2 |
| medium | 2 |
| high | 2 |
| critical | 0 |

## 15. Detailed Findings

### finding-aa816a7c6968 — Plain HTTP requests are not redirected to HTTPS

- **Rule ID:** `RT-HTTP-002`
- **Severity:** HIGH
- **Status:** open
- **Affected Asset:** example.com

**Description:** A request to http://example.com/ returned status 200 without redirecting to HTTPS.

**Security Impact:** Clients that reach the site over plain HTTP (bookmarks, typed URLs, old links) will transmit requests in plaintext instead of being upgraded to a secure channel.

**Recommendation:** Redirect all plain-HTTP requests to the HTTPS equivalent (301/308).

**How to Fix:**

Add an unconditional redirect from the HTTP listener to the equivalent HTTPS URL.

Example (NGINX config — illustrative, verify against your actual origin):
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

If using a managed CDN/edge/WAF: enable the 'redirect HTTP to HTTPS' / 'force HTTPS' option in your CDN or load balancer.

**Verification:** Re-run the scan and confirm `http_to_https_redirect.redirects_to_https` is true.

**Priority:** High — remediate within the next release cycle.

**Evidence:**
- `ev-24acc7bc8154` (http, requests (plain-HTTP probe, allow_redirects=False)): {'probed_url': 'http://example.com/', 'status_code': 200, 'location': None, 'redirects_to_https': False}

---

### finding-faf91ce2f416 — Missing Strict-Transport-Security (HSTS) header

- **Rule ID:** `RT-HDR-001`
- **Severity:** HIGH
- **Status:** open
- **Affected Asset:** example.com

**Description:** No Strict-Transport-Security header was present on the HTTPS response.

**Security Impact:** Without HSTS, browsers may still attempt plain-HTTP connections first, leaving an opening for SSL-stripping style downgrade attacks.

**Recommendation:** Send a Strict-Transport-Security header with a long max-age on every HTTPS response.

**How to Fix:**

Add the HSTS header at the edge or application layer for all HTTPS responses.

Example (NGINX config — illustrative, verify against your actual origin):
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

Example (application middleware — illustrative, verify against your actual stack):
res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

If using a managed CDN/edge/WAF: enable the HSTS header injection feature if your CDN/WAF offers one.

**Verification:** Re-run the scan and confirm `hsts.present` is true with an adequate max-age.

**Priority:** High — remediate within the next release cycle.

**Evidence:**
- `ev-0d5d8b8cd588` (headers, header_analyzer.analyze_security_headers): {'present': False, 'raw': None, 'max_age': None, 'include_subdomains': False, 'preload': False}

---

### finding-d51667cb0ef0 — Missing Content-Security-Policy header

- **Rule ID:** `RT-HDR-002`
- **Severity:** MEDIUM
- **Status:** open
- **Affected Asset:** example.com

**Description:** No Content-Security-Policy header was present on the response.

**Security Impact:** Without CSP, the browser has no defense-in-depth restriction on script/resource sources, increasing the impact of any XSS.

**Recommendation:** Deploy a Content-Security-Policy appropriate to the application's actual resource needs.

**How to Fix:**

Start with a restrictive default-src and iteratively allow only the origins the application legitimately needs, ideally via report-only mode first.

Example (NGINX config — illustrative, verify against your actual origin):
add_header Content-Security-Policy "default-src 'self'" always;

**Verification:** Re-run the scan and confirm `content_security_policy.present` is true.

**Priority:** Medium — remediate as part of the next security hardening pass.

**Evidence:**
- `ev-4edbd532c0e1` (headers, header_analyzer.analyze_security_headers): {'present': False, 'raw': None, 'high_risk_patterns': []}

---

### finding-92d0c91ebf7e — Missing clickjacking / frame protection

- **Rule ID:** `RT-HDR-005`
- **Severity:** MEDIUM
- **Status:** open
- **Affected Asset:** example.com

**Description:** Neither a CSP frame-ancestors directive nor an X-Frame-Options header was present.

**Security Impact:** The page can be embedded in an attacker-controlled iframe, enabling clickjacking-style UI redress attacks.

**Recommendation:** Set CSP frame-ancestors (preferred) or X-Frame-Options to restrict framing.

**How to Fix:**

Add frame-ancestors to the CSP, or fall back to X-Frame-Options for legacy clients.

Example (NGINX config — illustrative, verify against your actual origin):
add_header Content-Security-Policy "frame-ancestors 'self'" always;

**Verification:** Re-run the scan and confirm `frame_protection.protected` is true.

**Priority:** Medium — remediate as part of the next security hardening pass.

**Evidence:**
- `ev-aa3ffcbc2c5e` (headers, header_analyzer.analyze_security_headers): {'csp_frame_ancestors_present': False, 'x_frame_options_present': False, 'x_frame_options_value': None, 'protected': False}

---

### finding-ba605c7e89ff — Missing or invalid X-Content-Type-Options header

- **Rule ID:** `RT-HDR-003`
- **Severity:** LOW
- **Status:** open
- **Affected Asset:** example.com

**Description:** X-Content-Type-Options: nosniff was not present (or had an unexpected value).

**Security Impact:** Without nosniff, some browsers may MIME-sniff responses, which can enable content-type confusion attacks.

**Recommendation:** Send X-Content-Type-Options: nosniff on all responses.

**How to Fix:**

Add the header at the edge or application layer.

Example (NGINX config — illustrative, verify against your actual origin):
add_header X-Content-Type-Options "nosniff" always;

Example (application middleware — illustrative, verify against your actual stack):
res.setHeader("X-Content-Type-Options", "nosniff");

**Verification:** Re-run the scan and confirm `x_content_type_options.valid_nosniff` is true.

**Priority:** Low — remediate opportunistically.

**Evidence:**
- `ev-f7d4ecb09d69` (headers, header_analyzer.analyze_security_headers): {'present': False, 'value': None, 'valid_nosniff': False}

---

### finding-fa0f88cb6a29 — Missing Referrer-Policy header

- **Rule ID:** `RT-HDR-004`
- **Severity:** LOW
- **Status:** open
- **Affected Asset:** example.com

**Description:** No Referrer-Policy header was present on the response.

**Security Impact:** Without an explicit policy, full referrer URLs (potentially including sensitive query parameters) may leak to third-party destinations.

**Recommendation:** Set an explicit, minimal Referrer-Policy such as strict-origin-when-cross-origin.

**How to Fix:**

Add the header at the edge or application layer.

Example (NGINX config — illustrative, verify against your actual origin):
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

Example (application middleware — illustrative, verify against your actual stack):
res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

**Verification:** Re-run the scan and confirm `referrer_policy.present` is true.

**Priority:** Low — remediate opportunistically.

**Evidence:**
- `ev-f28369a63ec8` (headers, header_analyzer.analyze_security_headers): {'present': False, 'value': None}

---


## 16. Prioritized Recommendations

1. [HIGH] Plain HTTP requests are not redirected to HTTPS — Redirect all plain-HTTP requests to the HTTPS equivalent (301/308).
2. [HIGH] Missing Strict-Transport-Security (HSTS) header — Send a Strict-Transport-Security header with a long max-age on every HTTPS response.
3. [MEDIUM] Missing Content-Security-Policy header — Deploy a Content-Security-Policy appropriate to the application's actual resource needs.
4. [MEDIUM] Missing clickjacking / frame protection — Set CSP frame-ancestors (preferred) or X-Frame-Options to restrict framing.
5. [LOW] Missing or invalid X-Content-Type-Options header — Send X-Content-Type-Options: nosniff on all responses.
6. [LOW] Missing Referrer-Policy header — Set an explicit, minimal Referrer-Policy such as strict-origin-when-cross-origin.

## 17. Conclusion

6 finding(s) require attention, 2 of which are High or Critical severity. See Detailed Findings for evidence-linked remediation guidance.

## 18. Evidence Appendix

| Evidence ID | Module | Confidence | Source Method | Normalized Value |
|---|---|---|---|---|
| ev-b0e98c8d63a6 | dns | observed | dns.resolver.resolve(A) | ['104.20.23.154', '172.66.147.243'] |
| ev-b468b6be82fe | dns | observed | dns.resolver.resolve(AAAA) | ['2606:4700:10::6814:179a', '2606:4700:10::ac42:93f3'] |
| ev-f93ef2773f85 | dns | observed | dns.resolver.resolve(NS) | ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com'] |
| ev-0c3009ddd524 | connectivity | observed | socket.create_connection | {'selected_ip': '172.66.147.243', 'port': 443, 'address_family': 'IPv4'} |
| ev-36e45e728057 | tls | observed | ssl.SSLContext.wrap_socket | example.com |
| ev-bd0c11fadcaf | tls | observed | ssl.SSLContext.wrap_socket | TLSv1.3 |
| ev-848101da10d4 | tls | observed | ssl.SSLContext.wrap_socket | {'name': 'TLS_AES_256_GCM_SHA384', 'protocol': 'TLSv1.3', 'bits': 256} |
| ev-ced208363b25 | tls | observed | ssl.SSLContext.wrap_socket | h2 |
| ev-3a82ad5ce52c | tls | observed | ssl.SSLContext.wrap_socket | 250.38 |
| ev-e3448a01a208 | tls | observed | cryptography.x509.load_der_x509_certificate | {'subject': 'CN=example.com', 'issuer': 'CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US', 'subject_alternative_names': ['example.com', '*.example.com'], 'not_valid_before': '2026-07-29T22:10:08+00:00', 'not_valid_after': '2026-10-27T22:17:21+00:00', 'days_remaining': 57, 'fingerprint_sha256': '6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200', 'signature_algorithm': 'ecdsa-with-SHA256', 'public_key_algorithm': 'EC (secp256r1)', 'public_key_size_bits': 256} |
| ev-9ff8a7afa391 | tls | observed | manual SAN comparison (independent of trust-chain validation) | {'matches': True, 'matched_name': 'example.com'} |
| ev-3ec5a93a04e3 | tls | observed | ssl.create_default_context (system trust store) | True |
| ev-600e2d19621f | tls | observed | ssl.SSLContext(minimum_version=maximum_version=<probed>) | {'TLS 1.0': {'tested': True, 'supported': False, 'reason': '[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1018)', 'note': 'Local OpenSSL security policy may also reject this legacy protocol independent of server support.'}, 'TLS 1.1': {'tested': True, 'supported': False, 'reason': '[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1018)', 'note': 'Local OpenSSL security policy may also reject this legacy protocol independent of server support.'}, 'TLS 1.2': {'tested': True, 'supported': True, 'reason': None}, 'TLS 1.3': {'tested': True, 'supported': True, 'reason': None}} |
| ev-cb97b0264d93 | redirects | observed | redirect_analyzer.analyze_redirect_chain | [{'url': 'https://example.com/', 'status_code': 200, 'location': None, 'scheme': 'https'}] |
| ev-bb68168c1ec1 | redirects | observed | redirect_analyzer.analyze_redirect_chain | False |
| ev-ba440b8ca427 | redirects | observed | redirect_analyzer.analyze_redirect_chain | False |
| ev-e187c6a6c78b | http | observed | requests.Session.get | https://example.com/ |
| ev-c7e7923c5120 | http | observed | requests.Session.get | 200 |
| ev-1fc19dd1dd0d | http | observed | requests.Session.get | HTTP/1.1 |
| ev-a6dee08b88a1 | http | observed | requests.Session.get | text/html |
| ev-bb957787f971 | http | observed | requests.Session.get | 423.07 |
| ev-86757d889320 | http | observed | requests.Session.get | 431.96 |
| ev-f06b2eb0975a | http | observed | requests.Session.get | {'Date': 'Mon, 31 Aug 2026 19:05:57 GMT', 'Content-Type': 'text/html', 'Transfer-Encoding': 'chunked', 'Connection': 'keep-alive', 'Server': 'cloudflare', 'last-modified': 'Mon, 31 Aug 2026 04:09:32 GMT', 'allow': 'GET, HEAD', 'Age': '6696', 'cf-cache-status': 'HIT', 'Content-Encoding': 'gzip', 'CF-RAY': 'a33e4f447cb90e00-AMS'} |
| ev-0d5d8b8cd588 | headers | observed | header_analyzer.analyze_security_headers | {'present': False, 'raw': None, 'max_age': None, 'include_subdomains': False, 'preload': False} |
| ev-4edbd532c0e1 | headers | observed | header_analyzer.analyze_security_headers | {'present': False, 'raw': None, 'high_risk_patterns': []} |
| ev-f7d4ecb09d69 | headers | observed | header_analyzer.analyze_security_headers | {'present': False, 'value': None, 'valid_nosniff': False} |
| ev-f28369a63ec8 | headers | observed | header_analyzer.analyze_security_headers | {'present': False, 'value': None} |
| ev-aa3ffcbc2c5e | headers | observed | header_analyzer.analyze_security_headers | {'csp_frame_ancestors_present': False, 'x_frame_options_present': False, 'x_frame_options_value': None, 'protected': False} |
| ev-a398077e898b | headers | observed | header_analyzer.analyze_security_headers | {'present': False, 'value': None} |
| ev-24acc7bc8154 | http | observed | requests (plain-HTTP probe, allow_redirects=False) | {'probed_url': 'http://example.com/', 'status_code': 200, 'location': None, 'redirects_to_https': False} |
| ev-a53735358664 | edge | high | edge_fingerprint.analyze_edge_indicators | {'matches': [{'provider': 'Cloudflare', 'confidence': 'high', 'indicators': ["Response header 'CF-RAY' present", "Response header 'Server: cloudflare'", "Certificate issuer 'CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US'"], 'statement': 'Indicators are consistent with Cloudflare.'}], 'unknown': False} |

---

*Generated by RequestTrace 1.0.0. This report reflects an external, point-in-time assessment and does not certify compliance with any regulatory framework.*