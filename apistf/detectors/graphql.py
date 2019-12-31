"""GraphQL detectors: introspection, query depth, batching, alias abuse.

Each detector runs against ``POST {prefix}/graphql`` (params: ``prefix``,
``endpoint`` default ``/graphql``, ``identity`` default ``alice``).
A schema is needed to build probes: it comes from ``params["schema"]``
(a GraphQLSchema object), from the runner/CLI via
``DetectorContext.graphql_schema``, or — for the depth, batching and
alias detectors — from an introspection round-trip first. A detector
never guesses: a ``confirmed`` finding requires a control request
that behaved differently (a shallow query that works while the probe
is not limited), or a direct observation of the missing control
(introspection data returned).
"""
from __future__ import annotations

import re

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity
from apistf.graphql import (
    GraphQLSchema,
    build_alias_query,
    build_deep_query,
    build_simple_query,
    introspection_query,
    schema_from_introspection,
)


async def _post(ctx: DetectorContext, body, identity_name: str = "alice"):
    p = ctx.params
    url = p.get("prefix", "") + p.get("endpoint", "/graphql")
    ident = ctx.config.identity(p.get("identity", identity_name))
    return await ctx.client.request("POST", url, headers=ident.auth_headers(), json_body=body)


def _is_json(resp) -> dict | list | None:
    try:
        return resp.json()
    except ValueError:
        return None


def _schema_for(ctx: DetectorContext) -> GraphQLSchema | None:
    schema = ctx.params.get("schema") or ctx.graphql_schema
    if isinstance(schema, GraphQLSchema):
        return schema
    return None


async def _schema_via_introspection(ctx: DetectorContext) -> GraphQLSchema | None:
    """Fetch the schema by asking the server to describe itself."""
    resp, _ = await _post(ctx, {"query": introspection_query()})
    data = _is_json(resp)
    if not isinstance(data, dict):
        return None
    inner = data.get("data") or {}
    schema_json = inner.get("__schema")
    if not isinstance(schema_json, dict):
        return None
    try:
        return schema_from_introspection(schema_json)
    except Exception:
        return None


def _control_failed(detector: str, endpoint: str, detail: str) -> Finding:
    return Finding(
        detector=detector,
        title=f"{detector}: control request failed, probe inconclusive",
        severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
        description=f"The control query against {endpoint} did not return usable data "
                    f"({detail}), so the probe cannot be judged.",
        endpoint=endpoint, confidence="low",
    )


class GraphQLIntrospectionDetector(Detector):
    name = "graphql_introspection"
    description = "GraphQL introspection enabled: the server describes its own schema."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        endpoint = ctx.params.get("prefix", "") + ctx.params.get("endpoint", "/graphql")
        resp, ev = await _post(ctx, {"query": introspection_query()})
        data = _is_json(resp)
        if not isinstance(data, dict):
            return []
        inner = data.get("data") or {}
        types = (inner.get("__schema") or {}).get("types")
        if resp.status_code == 200 and isinstance(types, list) and types:
            names = sorted(t.get("name", "") for t in types if isinstance(t, dict))[:8]
            return [Finding(
                detector=self.name,
                title="GraphQL introspection is enabled",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                description=f"The server answered an introspection query with its full schema "
                            f"({len(types)} types, including {', '.join(names)}). Introspection "
                            "hands an attacker the complete API surface — every type, field and "
                            "argument — with no authentication beyond the probe identity.",
                endpoint=endpoint, evidence=[ev],
                reproduction=[
                    f"POST {endpoint} with body {{\"query\": \"{{ __schema {{ types {{ name }} }} }}\"}}",
                    "Response 200 contains data.__schema.types.",
                ],
                confidence="high",
            )]
        return []


class GraphQLDepthDetector(Detector):
    name = "graphql_depth"
    description = "GraphQL query depth not limited: a deeply nested query is executed."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        endpoint = p.get("prefix", "") + p.get("endpoint", "/graphql")
        depth = int(p.get("depth", 12))
        schema = _schema_for(ctx) or await _schema_via_introspection(ctx)
        if schema is None:
            return [Finding(
                detector=self.name, title="GraphQL depth check inconclusive: no schema available",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="No schema was supplied and introspection did not return one, "
                            "so no nested query could be built.",
                endpoint=endpoint, confidence="low",
            )]
        # Control: a shallow query (depth 2) must work, or nothing can
        # be judged about depth handling.
        shallow = build_deep_query(schema, 2)
        if shallow is None:
            return [Finding(
                detector=self.name, title="GraphQL depth check inconclusive: schema has no nesting path",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="The schema has no self-referential field path, so a deeply "
                            "nested query cannot be constructed for this target.",
                endpoint=endpoint, confidence="low",
            )]
        resp_c, ev_c = await _post(ctx, {"query": shallow})
        data_c = _is_json(resp_c)
        if not (resp_c.status_code == 200 and isinstance(data_c, dict)
                and isinstance(data_c.get("data"), dict)):
            return [_control_failed(self.name, endpoint,
                                    f"shallow query returned {resp_c.status_code}")]
        deep = build_deep_query(schema, depth)
        resp, ev = await _post(ctx, {"query": deep})
        data = _is_json(resp)
        if resp.status_code == 200 and isinstance(data, dict) \
                and isinstance(data.get("data"), dict) and not data.get("errors"):
            return [Finding(
                detector=self.name,
                title=f"GraphQL query depth not limited (depth {depth} executed)",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                description=f"A query nested {depth} levels deep returned 200 with data and no "
                            "errors, while the depth-2 control also returned data. The server "
                            "enforces no query-depth limit, so a caller can make it do "
                            "exponentially more work per request than a shallow query.",
                endpoint=endpoint, evidence=[ev_c, ev],
                reproduction=[
                    f"POST {endpoint} with a query nested {depth} levels deep; response 200 with data.",
                    f"Control: the same shape nested 2 levels deep also returns 200 with data.",
                ],
                confidence="high",
            )]
        return []


class GraphQLBatchingDetector(Detector):
    name = "graphql_batching"
    description = "GraphQL query batching not limited: many queries run in one request."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        endpoint = p.get("prefix", "") + p.get("endpoint", "/graphql")
        batch_size = int(p.get("batch_size", 10))
        schema = _schema_for(ctx) or await _schema_via_introspection(ctx)
        if schema is None:
            return [Finding(
                detector=self.name, title="GraphQL batching check inconclusive: no schema available",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="No schema was supplied and introspection did not return one, "
                            "so no batch could be built.",
                endpoint=endpoint, confidence="low",
            )]
        simple = build_simple_query(schema)
        if simple is None:
            return [Finding(
                detector=self.name, title="GraphQL batching check inconclusive: schema has no query fields",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="The schema has no query fields, so no batch could be built.",
                endpoint=endpoint, confidence="low",
            )]
        # Control: the same query on its own must work.
        resp_c, ev_c = await _post(ctx, {"query": simple})
        data_c = _is_json(resp_c)
        if not (resp_c.status_code == 200 and isinstance(data_c, dict)
                and isinstance(data_c.get("data"), dict)):
            return [_control_failed(self.name, endpoint,
                                    f"single query returned {resp_c.status_code}")]
        batch = [{"query": simple} for _ in range(batch_size)]
        resp, ev = await _post(ctx, batch)
        data = _is_json(resp)
        if isinstance(data, list) and len(data) == batch_size \
                and all(isinstance(item, dict) and isinstance(item.get("data"), dict)
                        for item in data):
            return [Finding(
                detector=self.name,
                title=f"GraphQL batching not limited ({batch_size} queries in one request)",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                description=f"A single request carrying a JSON array of {batch_size} queries "
                            f"returned {batch_size} data-bearing responses. The server enforces "
                            "no batch limit, so one request can do the work of many and bypass "
                            "per-request rate limits.",
                endpoint=endpoint, evidence=[ev_c, ev],
                reproduction=[
                    f"POST {endpoint} with a JSON array of {batch_size} identical queries.",
                    f"Response is a list of {batch_size} results, each with data.",
                    "Control: the same query sent on its own also returns 200 with data.",
                ],
                confidence="high",
            )]
        return []


class GraphQLAliasAbuseDetector(Detector):
    name = "graphql_alias_abuse"
    description = "GraphQL alias abuse not limited: one query repeats a field under many aliases."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        endpoint = p.get("prefix", "") + p.get("endpoint", "/graphql")
        alias_count = int(p.get("alias_count", 20))
        schema = _schema_for(ctx) or await _schema_via_introspection(ctx)
        if schema is None:
            return [Finding(
                detector=self.name, title="GraphQL alias check inconclusive: no schema available",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="No schema was supplied and introspection did not return one, "
                            "so no aliased query could be built.",
                endpoint=endpoint, confidence="low",
            )]
        query = build_alias_query(schema, alias_count)
        if query is None:
            return [Finding(
                detector=self.name, title="GraphQL alias check inconclusive: schema has no query fields",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="The schema has no query fields, so no aliased query could be built.",
                endpoint=endpoint, confidence="low",
            )]
        # Control: the same field once, without aliases, must work.
        simple = build_simple_query(schema)
        resp_c, ev_c = await _post(ctx, {"query": simple})
        data_c = _is_json(resp_c)
        if not (resp_c.status_code == 200 and isinstance(data_c, dict)
                and isinstance(data_c.get("data"), dict)):
            return [_control_failed(self.name, endpoint,
                                    f"single query returned {resp_c.status_code}")]
        resp, ev = await _post(ctx, {"query": query})
        data = _is_json(resp)
        if resp.status_code == 200 and isinstance(data, dict):
            inner = data.get("data")
            if isinstance(inner, dict) and not data.get("errors") \
                    and sum(1 for k in inner if re.fullmatch(r"a\d+", k)) >= alias_count:
                return [Finding(
                    detector=self.name,
                    title=f"GraphQL alias abuse not limited ({alias_count} aliases of one field)",
                    severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                    description=f"One query repeating the same field under {alias_count} "
                                f"aliases returned 200 with data for all {alias_count} aliases. "
                                "The server enforces no alias limit, so one request can fetch "
                                "the same data many times over and multiply server work.",
                    endpoint=endpoint, evidence=[ev_c, ev],
                    reproduction=[
                        f"POST {endpoint} with one query aliasing the same field {alias_count} times.",
                        f"Response 200 contains data for all {alias_count} aliases.",
                        "Control: the same field sent once also returns 200 with data.",
                    ],
                    confidence="high",
                )]
        return []
