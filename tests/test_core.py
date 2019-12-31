import pytest

from apistf.client import AllowlistError, BudgetExceededError
from apistf.config import TargetConfig
from apistf.openapi import load_spec, parse_spec_text
from apistf.redaction import redact_headers, redact_json_text
from tests.conftest import make_client, make_config


def test_openapi_parser_from_yaml():
    spec = load_spec("examples/openapi-lab.yaml")
    assert spec.title == "API Security Testing Lab"
    assert len(spec.endpoints) >= 6
    obj = [e for e in spec.endpoints if e.path == "/vuln/objects/{id}"][0]
    assert obj.method == "GET"
    assert obj.auth_required is True
    assert obj.id_params[0].name == "id"


def test_openapi_parser_rejects_non_spec():
    with pytest.raises(ValueError):
        parse_spec_text('{"foo": 1}')


def test_redaction_headers_and_json():
    assert redact_headers({"Authorization": "Bearer abcdefgh", "X-Ok": "1"}) == {
        "Authorization": "[REDACTED]", "X-Ok": "1"}
    out = redact_json_text('{"username": "alice", "password_hash": "sha256:x", "token": "secret123"}')
    assert "sha256:x" not in out and "secret123" not in out
    assert "alice" in out


def test_allowlist_blocks_other_hosts():
    config = make_config()
    client = make_client(config)
    with pytest.raises(AllowlistError):
        # build a client pointed at a non-allowlisted host
        from apistf.client import SafeClient
        from apistf.config import TargetConfig
        from httpx import ASGITransport
        from lab.app import app
        other = SafeClient(TargetConfig(base_url="http://evil.example"),
                           transport=ASGITransport(app=app))
        import asyncio
        asyncio.run(other.request("GET", "/"))


@pytest.mark.asyncio
async def test_budget_enforced():
    config = make_config(budget=2)
    client = make_client(config)
    await client.request("GET", "/vuln/me", headers={"Authorization": "Bearer token-alice"})
    await client.request("GET", "/vuln/me", headers={"Authorization": "Bearer token-alice"})
    with pytest.raises(BudgetExceededError):
        await client.request("GET", "/vuln/me", headers={"Authorization": "Bearer token-alice"})
    await client.aclose()
