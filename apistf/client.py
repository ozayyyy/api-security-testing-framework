"""Safe HTTP client: allowlist, request budget, rate limiting, audit, redaction.

Every request goes through here. A host outside ``allowed_hosts``
raises before any bytes are sent. Exceeding ``request_budget`` raises
instead of sending. All stored evidence is redacted.
"""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

import httpx

from apistf.audit import AuditLog, audit_record
from apistf.config import TargetConfig
from apistf.findings import Evidence
from apistf.redaction import redact_headers, redact_json_text


class AllowlistError(ValueError):
    pass


class BudgetExceededError(RuntimeError):
    pass


class SafeClient:
    def __init__(self, config: TargetConfig, transport: httpx.AsyncHTTPTransport | None = None):
        self.config = config
        self.audit = AuditLog(config.audit_log_path)
        self._count = 0
        self._last_sent = 0.0
        self._client = httpx.AsyncClient(
            base_url=config.base_url, timeout=config.timeout_s, transport=transport,
            # Never route scan traffic through an environment proxy:
            # localhost lab traffic must stay local, and target traffic
            # must go direct so the allowlist check is meaningful.
            trust_env=False,
        )

    @property
    def requests_sent(self) -> int:
        return self._count

    def _check_url(self, url: str) -> str:
        full = str(self._client.build_request("GET", url).url)
        host = urlparse(full).hostname or ""
        if host not in self.config.allowed_hosts:
            raise AllowlistError(f"host {host!r} is not in the allowlist {self.config.allowed_hosts}")
        return full

    async def request(self, method: str, url: str, *, headers: dict | None = None,
                      json_body: dict | None = None, content: str | None = None) -> tuple[httpx.Response, Evidence]:
        full_url = self._check_url(url)
        if self._count >= self.config.request_budget:
            raise BudgetExceededError(f"request budget exhausted ({self.config.request_budget})")
        if self.config.min_interval_s:
            wait = self.config.min_interval_s - (time.monotonic() - self._last_sent)
            if wait > 0:
                await asyncio.sleep(wait)
        body_text = ""
        if json_body is not None:
            import json as _json
            body_text = _json.dumps(json_body)
        elif content is not None:
            body_text = content
        self._count += 1
        self._last_sent = time.monotonic()
        response = await self._client.request(
            method, url, headers=headers or {}, json=json_body,
            content=content if json_body is None else None,
        )
        resp_text = response.text[:8192]
        self.audit.append(audit_record(method, full_url, response.status_code, headers or {}, body_text))
        evidence = Evidence(
            method=method, url=full_url,
            request_headers=redact_headers(headers or {}),
            request_body=redact_json_text(body_text) if body_text else "",
            response_status=response.status_code,
            response_headers=redact_headers(dict(response.headers)),
            response_body=redact_json_text(resp_text) if resp_text else "",
        )
        return response, evidence

    async def aclose(self) -> None:
        await self._client.aclose()
