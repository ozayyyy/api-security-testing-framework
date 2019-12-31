import pytest
from httpx import ASGITransport

from apistf.client import SafeClient
from apistf.config import Identity, TargetConfig
from lab.app import app, reset_lab


@pytest.fixture(autouse=True)
def _reset_lab():
    reset_lab()
    yield
    reset_lab()


def make_config(prefix="/vuln", budget=500):
    return TargetConfig(
        base_url="http://testserver",
        request_budget=budget,
        identities=[
            Identity(name="alice", role="user", token="token-alice"),
            Identity(name="bob", role="user", token="token-bob"),
            Identity(name="admin", role="admin", token="token-admin"),
        ],
    )


def make_client(config):
    return SafeClient(config, transport=ASGITransport(app=app))
