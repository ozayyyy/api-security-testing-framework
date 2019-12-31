"""Integration: every detector must fire CONFIRMED on /vuln and stay
silent (no confirmed findings) on /secure. One regression test per
detector, as required by the spec.
"""
import pytest

from apistf.detectors.base import DetectorContext
from apistf.detectors.bfla import BflaDetector
from apistf.detectors.bola import BolaDetector
from apistf.detectors.jwt import JwtDetector
from apistf.detectors.mass_assignment import ExcessiveDataDetector, MassAssignmentDetector
from apistf.detectors.rate_limit import RateLimitDetector
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
async def test_bola_vuln_confirmed_secure_clean():
    vuln = await _run(BolaDetector, "/vuln")
    assert [f for f in vuln if f.status.value == "confirmed"], vuln
    assert vuln[0].title.startswith("BOLA")
    secure = await _run(BolaDetector, "/secure")
    assert [f for f in secure if f.status.value == "confirmed"] == []


@pytest.mark.asyncio
async def test_bfla_vuln_confirmed_secure_clean():
    vuln = await _run(BflaDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    secure = await _run(BflaDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_jwt_vuln_confirmed_secure_clean():
    valid = issue_jwt("bob", "user")
    vuln = await _run(JwtDetector, "/vuln", {"valid_token": valid})
    titles = [f.title for f in vuln]
    assert "JWT alg=none token accepted" in titles
    assert "Tampered JWT payload accepted" in titles
    assert all(f.status.value == "confirmed" for f in vuln
               if "alg=none" in f.title or "Tampered" in f.title)
    secure = await _run(JwtDetector, "/secure", {"valid_token": valid})
    assert secure == []


@pytest.mark.asyncio
async def test_mass_assignment_vuln_confirmed_secure_clean():
    vuln = await _run(MassAssignmentDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    secure = await _run(MassAssignmentDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_excessive_data_vuln_confirmed_secure_clean():
    vuln = await _run(ExcessiveDataDetector, "/vuln")
    assert vuln and all(f.status.value == "confirmed" for f in vuln)
    assert any("password_hash" in f.description for f in vuln)
    secure = await _run(ExcessiveDataDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_rate_limit_vuln_confirmed_secure_clean():
    vuln = await _run(RateLimitDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    secure = await _run(RateLimitDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_full_run_vuln_finds_all_detectors_secure_finds_none_confirmed():
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
    assert detectors_hit == {"bola", "bfla", "jwt", "mass_assignment", "excessive_data",
                             "rate_limit", "business_logic", "inconsistent_authz", "session"}

    # Mass assignment on /vuln promotes alice to admin in the shared lab
    # state, so reset before the secure run or the BFLA control is polluted.
    reset_lab()
    config2 = make_config()
    client2 = make_client(config2)
    params2 = {k: dict(v, prefix="/secure") for k, v in params.items()}
    findings2, _ = await run_detectors(config2, params=params2, client=client2)
    await client2.aclose()
    assert [f for f in findings2 if f.status.value == "confirmed"] == []
