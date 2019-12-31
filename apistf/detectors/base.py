"""Detector base: every detector is a pure rule over observed responses.

A detector receives a SafeClient, a TargetConfig and (optionally) the
parsed OpenAPI spec, and returns findings. It never guesses: a
``confirmed`` finding requires a control request that behaved
differently from the attack request on the same endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from apistf.client import SafeClient
from apistf.config import TargetConfig
from apistf.findings import Finding
from apistf.openapi import OpenAPISpec


@dataclass
class DetectorContext:
    client: SafeClient
    config: TargetConfig
    spec: OpenAPISpec | None = None
    params: dict = field(default_factory=dict)


class Detector:
    name = "base"
    description = ""

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        raise NotImplementedError
