"""Runner: run a named set of detectors against one target, in order."""
from __future__ import annotations

from apistf.client import SafeClient
from apistf.config import TargetConfig
from apistf.detectors import REGISTRY
from apistf.detectors.base import DetectorContext
from apistf.findings import Finding
from apistf.openapi import OpenAPISpec


async def run_detectors(
    config: TargetConfig,
    detector_names: list[str] | None = None,
    spec: OpenAPISpec | None = None,
    params: dict[str, dict] | None = None,
    client: SafeClient | None = None,
) -> tuple[list[Finding], SafeClient]:
    names = detector_names or list(REGISTRY)
    own_client = client is None
    client = client or SafeClient(config)
    findings: list[Finding] = []
    try:
        for name in names:
            cls = REGISTRY[name]
            ctx = DetectorContext(
                client=client, config=config, spec=spec,
                params=(params or {}).get(name, {}),
            )
            findings.extend(await cls().run(ctx))
    finally:
        if own_client:
            await client.aclose()
    return findings, client
