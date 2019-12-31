"""Configuration: targets, identities, safe mode.

Safe mode is on by default and cannot be silently bypassed: a scan
only sends requests to hosts explicitly listed in ``allowed_hosts``,
only up to ``request_budget`` requests, and only at ``min_interval_s``
between requests. The default allowlist is localhost only, so the
bundled lab is the only target that works out of the box.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Identity:
    """One test identity (a role / user on the target)."""

    name: str
    role: str = "user"
    token: str = ""  # bearer token value, or "" for unauthenticated
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    extra_headers: dict[str, str] = field(default_factory=dict)

    def auth_headers(self) -> dict[str, str]:
        headers = dict(self.extra_headers)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.api_key:
            headers[self.api_key_header] = self.api_key
        return headers


@dataclass
class TargetConfig:
    base_url: str
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "testserver"])
    request_budget: int = 500
    min_interval_s: float = 0.0
    timeout_s: float = 10.0
    identities: list[Identity] = field(default_factory=list)
    audit_log_path: str | None = None

    def identity(self, name: str) -> Identity:
        for ident in self.identities:
            if ident.name == name:
                return ident
        raise KeyError(f"unknown identity: {name}")

    def unauthenticated(self) -> Identity:
        return Identity(name="anonymous", role="anonymous")
