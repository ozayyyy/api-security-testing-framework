"""Audit log: one JSON line per request sent, redacted, append-only."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from apistf.redaction import redact_headers, redact_json_text


def audit_record(method: str, url: str, status: int, headers: dict, body: str = "") -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "url": url,
        "status": status,
        "request_headers": redact_headers(headers),
        "request_body": redact_json_text(body) if body else "",
    }


class AuditLog:
    def __init__(self, path: str | None = None):
        self.path = path
        self.records: list[dict] = []

    def append(self, record: dict) -> None:
        self.records.append(record)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
