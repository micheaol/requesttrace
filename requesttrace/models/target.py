"""The normalized scan target model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Target:
    """A fully normalized, validated scan target.

    Produced exclusively by :func:`requesttrace.target.normalize_target` —
    nothing downstream should re-parse the raw user input string.
    """

    raw_input: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    normalized_url: str
    is_ip_literal: bool

    @property
    def authority(self) -> str:
        """``host:port`` form, omitting the port when it is the scheme default."""
        default_port = 443 if self.scheme == "https" else 80
        if self.port == default_port:
            return self.host
        return f"{self.host}:{self.port}"
