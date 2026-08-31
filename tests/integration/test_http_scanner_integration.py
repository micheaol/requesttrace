"""HTTP scanner integration tests against a local, controlled HTTP fixture server.

No live internet dependency (PRD §19 / RT-011).
"""

from __future__ import annotations

from dataclasses import replace

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.scanners.http_scanner import HttpAssessmentScanner
from requesttrace.target import normalize_target
from tests.fixtures.local_http_server import LocalHttpServer, RouteResponse


def test_redirect_chain_is_followed_and_recorded(fast_scan_config) -> None:
    routes = {
        "/start": RouteResponse(302, headers=[("Location", "/final")]),
        "/final": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"ok"),
    }
    with LocalHttpServer(routes) as server:
        target = normalize_target(f"{server.base_url}/start")
        config = replace(fast_scan_config, target_input=target.normalized_url)
        store = EvidenceStore()
        result = HttpAssessmentScanner().run(target, config, store)

    assert result.status == ModuleStatus.COMPLETED
    chain = store.observations_of_type(ModuleName.REDIRECTS, "redirect_chain")[-1].value
    assert len(chain) == 2
    assert chain[0]["status_code"] == 302
    assert chain[1]["status_code"] == 200

    final_status = store.observations_of_type(ModuleName.HTTP, "status_code")[-1].value
    assert final_status == 200


def test_security_headers_are_recorded_from_final_response(fast_scan_config) -> None:
    routes = {
        "/": RouteResponse(
            200,
            headers=[
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
    }
    with LocalHttpServer(routes) as server:
        target = normalize_target(server.base_url + "/")
        config = replace(fast_scan_config, target_input=target.normalized_url)
        store = EvidenceStore()
        HttpAssessmentScanner().run(target, config, store)

    hsts = store.observations_of_type(ModuleName.HEADERS, "hsts")[-1].value
    assert hsts["present"] is True
    assert hsts["max_age"] == 63072000

    xcto = store.observations_of_type(ModuleName.HEADERS, "x_content_type_options")[-1].value
    assert xcto["valid_nosniff"] is True


def test_multiple_set_cookie_headers_are_parsed_separately(fast_scan_config) -> None:
    routes = {
        "/": RouteResponse(
            200,
            headers=[
                ("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "tracking=xyz789; Path=/"),
            ],
        )
    }
    with LocalHttpServer(routes) as server:
        target = normalize_target(server.base_url + "/")
        config = replace(fast_scan_config, target_input=target.normalized_url)
        store = EvidenceStore()
        HttpAssessmentScanner().run(target, config, store)

    cookies = [o.value for o in store.observations_of_type(ModuleName.COOKIES, "cookie")]
    names = {c["name"] for c in cookies}
    assert names == {"session", "tracking"}

    session_cookie = next(c for c in cookies if c["name"] == "session")
    assert session_cookie["secure"] is True
    tracking_cookie = next(c for c in cookies if c["name"] == "tracking")
    assert tracking_cookie["secure"] is False

    for observation in store.observations:
        assert "abc123" not in str(observation.value)
        assert "xyz789" not in str(observation.value)


def test_redirect_loop_is_detected_and_does_not_hang(fast_scan_config) -> None:
    routes = {
        "/a": RouteResponse(302, headers=[("Location", "/b")]),
        "/b": RouteResponse(302, headers=[("Location", "/a")]),
    }
    with LocalHttpServer(routes) as server:
        target = normalize_target(f"{server.base_url}/a")
        config = replace(fast_scan_config, target_input=target.normalized_url)
        store = EvidenceStore()
        result = HttpAssessmentScanner().run(target, config, store)

    assert result.status == ModuleStatus.PARTIAL
    loop_detected = store.observations_of_type(ModuleName.REDIRECTS, "redirect_loop_detected")[-1].value
    assert loop_detected is True


def test_max_redirects_is_enforced(fast_scan_config) -> None:
    routes = {f"/hop{i}": RouteResponse(302, headers=[("Location", f"/hop{i + 1}")]) for i in range(10)}
    with LocalHttpServer(routes) as server:
        target = normalize_target(f"{server.base_url}/hop0")
        config = replace(fast_scan_config, target_input=target.normalized_url, max_redirects=3)
        store = EvidenceStore()
        result = HttpAssessmentScanner().run(target, config, store)

    assert result.status == ModuleStatus.PARTIAL
    assert any("max-redirects" in e or "Exceeded" in e for e in result.errors)
