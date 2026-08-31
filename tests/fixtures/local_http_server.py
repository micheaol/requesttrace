"""A minimal local plain-HTTP fixture server for controlled HTTP scanner tests."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer


@dataclass(frozen=True, slots=True)
class RouteResponse:
    status_code: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""


class LocalHttpServer:
    """Serves canned responses for configured paths on 127.0.0.1."""

    def __init__(self, routes: dict[str, RouteResponse]) -> None:
        self._routes = routes
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> LocalHttpServer:
        routes = self._routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 — required by BaseHTTPRequestHandler
                route = routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(route.status_code)
                for name, value in route.headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(route.body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — silence test noise
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_port}"
