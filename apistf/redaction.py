"""Redaction of credentials and sensitive data.

Applied to every header, body, log line and report before it is stored
or written out. Redaction is denylist-based on header names and JSON
keys, plus a conservative pattern for bearer tokens in free text.
Detection logic never depends on redacted values.
"""
from __future__ import annotations

import json
import re

SENSITIVE_HEADERS = {
    "authorization", "x-api-key", "cookie", "set-cookie",
    "x-auth-token", "x-access-token", "proxy-authorization",
}

SENSITIVE_KEYS = {
    "password", "passwd", "password_hash", "passwordhash", "secret",
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "client_secret", "private_key", "ssn", "social_security_number",
    "credit_card", "card_number", "cvv", "session_token", "auth_token",
}

_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-~+/=]{8,}", re.IGNORECASE)
_TOKEN_KV_RE = re.compile(r"((?:token|secret|password|api[_-]?key)[\"'\s:=]+)[\"']?[A-Za-z0-9._\-~+/=]{8,}", re.IGNORECASE)

REDACTED = "[REDACTED]"


def redact_headers(headers: dict) -> dict:
    return {
        k: REDACTED if k.lower() in SENSITIVE_HEADERS else v
        for k, v in headers.items()
    }


def _redact_value(key: str, value):
    if key.lower() in SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, v) for v in value]
    return value


def redact_json_text(text: str) -> str:
    """Redact sensitive keys in a JSON body; fall back to pattern redaction."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return _TOKEN_KV_RE.sub(r"\1" + REDACTED, _BEARER_RE.sub(r"\1" + REDACTED, text))
    if isinstance(data, dict):
        data = {k: _redact_value(k, v) for k, v in data.items()}
    elif isinstance(data, list):
        data = [_redact_value("", v) for v in data]
    return json.dumps(data)


def redact_text(text: str) -> str:
    return _TOKEN_KV_RE.sub(r"\1" + REDACTED, _BEARER_RE.sub(r"\1" + REDACTED, text))
