"""Integration: the three newer detectors must fire CONFIRMED on
/vuln and stay silent (no confirmed findings) on /secure. One
regression test per detector. Lab state is reset by the autouse
fixture in conftest, and each detector probes fresh orders/tokens
so state-mutating probes do not pollute the next run.
"""
import pytest

from apistf.detectors.base import DetectorContext
from apistf.detectors.business_logic import BusinessLogicDetector
from apistf.detectors.inconsistent_authz import InconsistentAuthzDetector
from apistf.detectors.session import SessionDetector
from apistf.runner import run_detectors
from lab.app import issue_jwt, reset_lab
from tests.conftest import make_client, make_config


async def _run(detector, prefix, extra_params=None):
    config = make_config()
    client = make_client(config)
    params = {"prefix": prefix}
    params.update(extra_params or {})
    ctx = DetectorContext(client=client, config=config, params=params)
    try:
        return await detector().run(ctx)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_business_logic_vuln_confirmed_secure_clean():
    vuln = await _run(BusinessLogicDetector, "/vuln")
    titles = {f.title for f in vuln if f.status.value == "confirmed"}
    assert titles == {
        "Business logic: pay a cancelled order",
        "Business logic: refund the same order twice",
        "Business logic: ship an unpaid order",
        "Business logic: change price/quantity after payment",
    }, vuln
    secure = await _run(BusinessLogicDetector, "/secure")
    assert [f for f in secure if f.status.value == "confirmed"] == []


@pytest.mark.asyncio
async def test_inconsistent_authz_vuln_confirmed_secure_clean():
    vuln = await _run(InconsistentAuthzDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    assert "allows what" in vuln[0].title and "denies" in vuln[0].title
    secure = await _run(InconsistentAuthzDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_session_vuln_confirmed_secure_clean():
    vuln = await _run(SessionDetector, "/vuln")
    titles = {f.title for f in vuln if f.status.value == "confirmed"}
    assert titles == {
        "Revoked token still accepted",
        "Revoked token can be refreshed",
        "Expired token still accepted",
    }, vuln
    secure = await _run(SessionDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_full_run_nine_detectors_vuln_secure():
    config = make_config()
    client = make_client(config)
    valid = issue_jwt("bob", "user")
    params = {
        "bola": {"prefix": "/vuln"},
        "bfla": {"prefix": "/vuln"},
        "jwt": {"prefix": "/vuln", "valid_token": valid},
        "mass_assignment": {"prefix": "/vuln"},
        "excessive_data": {"prefix": "/vuln"},
        "rate_limit": {"prefix": "/vuln"},
        "business_logic": {"prefix": "/vuln"},
        "inconsistent_authz": {"prefix": "/vuln"},
        "session": {"prefix": "/vuln"},
    }
    findings, _ = await run_detectors(config, params=params, client=client)
    await client.aclose()
    detectors_hit = {f.detector for f in findings if f.status.value == "confirmed"}
    assert detectors_hit == {
        "bola", "bfla", "jwt", "mass_assignment", "excessive_data",
        "rate_limit", "business_logic", "inconsistent_authz", "session",
    }, findings

    reset_lab()
    config2 = make_config()
    client2 = make_client(config2)
    params2 = {k: dict(v, prefix="/secure") for k, v in params.items()}
    findings2, _ = await run_detectors(config2, params=params2, client=client2)
    await client2.aclose()
    assert [f for f in findings2 if f.status.value == "confirmed"] == [], findings2
