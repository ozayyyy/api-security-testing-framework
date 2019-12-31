"""GraphQL: SDL parsing / probe builders (unit) and the four detectors
against the lab (integration). Each detector must fire CONFIRMED on
/vuln and stay silent (no confirmed findings) on /secure.
"""
import pytest

from apistf.detectors.base import DetectorContext
from apistf.detectors.graphql import (
    GraphQLAliasAbuseDetector,
    GraphQLBatchingDetector,
    GraphQLDepthDetector,
    GraphQLIntrospectionDetector,
)
from apistf.graphql import (
    build_alias_query,
    build_deep_query,
    build_simple_query,
    find_nesting_path,
    introspection_query,
    load_schema,
    parse_schema_text,
    schema_from_introspection,
)
from apistf.runner import run_detectors
from lab.graphql_exec import _QueryParser, alias_count, selection_depth
from tests.conftest import make_client, make_config

LAB_SCHEMA = load_schema("examples/graphql-lab.graphql")


# ---------------------------------------------------------------- unit: schema

def test_sdl_parser_reads_lab_schema():
    schema = parse_schema_text(open("examples/graphql-lab.graphql", encoding="utf-8").read())
    assert schema.query_type == "Query"
    assert set(schema.query_fields()) == {"user", "users", "post", "posts"}
    assert schema.query_fields()["user"].args == {"id": "ID!"}
    assert schema.types["User"].fields["friends"].type_str == "[User!]!"
    assert schema.types["Post"].fields["author"].named == "User"


def test_sdl_parser_rejects_garbage():
    with pytest.raises(ValueError):
        parse_schema_text("this is not a schema !!!")


def test_introspection_round_trip_rebuilds_schema():
    # Introspection JSON built the way a server returns it.
    schema_json = {
        "queryType": {"name": "Query"},
        "mutationType": None,
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None,
                 "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}],
                 "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                {"name": "users", "args": [],
                 "type": {"kind": "LIST", "name": None,
                          "ofType": {"kind": "NON_NULL", "name": None,
                                     "ofType": {"kind": "OBJECT", "name": "User", "ofType": None}}}}]},
            {"name": "User", "kind": "OBJECT", "fields": [
                {"name": "id", "args": [], "type": {"kind": "NON_NULL", "name": None,
                 "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}},
                {"name": "friends", "args": [],
                 "type": {"kind": "NON_NULL", "name": None,
                          "ofType": {"kind": "LIST", "name": None,
                                     "ofType": {"kind": "NON_NULL", "name": None,
                                                "ofType": {"kind": "OBJECT", "name": "User",
                                                           "ofType": None}}}}},
            ]},
        ],
    }
    schema = schema_from_introspection(schema_json)
    assert schema.query_fields()["user"].args == {"id": "ID!"}
    assert schema.types["User"].fields["friends"].type_str == "[User!]!"
    assert find_nesting_path(schema) is not None


def test_find_nesting_path_none_without_cycle():
    schema = parse_schema_text("""
        type Query { greeting: String ping: Int }
    """)
    assert find_nesting_path(schema) is None
    assert build_deep_query(schema, 12) is None
    assert build_simple_query(schema) is not None


def test_probe_builders_measure_as_advertised():
    for depth in (2, 5, 12):
        query = build_deep_query(LAB_SCHEMA, depth)
        ops, frags = _QueryParser(query).parse_document()
        assert selection_depth(ops[0].selections, frags) == depth
    query = build_alias_query(LAB_SCHEMA, 20)
    ops, frags = _QueryParser(query).parse_document()
    assert alias_count(ops[0].selections, frags) == 20
    assert build_simple_query(LAB_SCHEMA) is not None
    assert "__schema" in introspection_query()
    # Balanced braces in the introspection query, and an unbalanced
    # query raises instead of looping (regression: an earlier version
    # of the query was missing a closing brace and hung the executor).
    assert introspection_query().count("{") == introspection_query().count("}")
    with pytest.raises(ValueError):
        _QueryParser("{ user { id ").parse_document()


# ---------------------------------------------------------------- integration

async def _run(detector, prefix, with_schema=True):
    config = make_config()
    client = make_client(config)
    ctx = DetectorContext(client=client, config=config, params={"prefix": prefix},
                          graphql_schema=LAB_SCHEMA if with_schema else None)
    try:
        return await detector().run(ctx)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_introspection_vuln_confirmed_secure_clean():
    vuln = await _run(GraphQLIntrospectionDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    assert vuln[0].severity.value == "medium"
    secure = await _run(GraphQLIntrospectionDetector, "/secure")
    assert secure == []


@pytest.mark.asyncio
async def test_depth_vuln_confirmed_secure_clean():
    vuln = await _run(GraphQLDepthDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    assert "depth 12" in vuln[0].title
    secure = await _run(GraphQLDepthDetector, "/secure")
    assert [f for f in secure if f.status.value == "confirmed"] == []


@pytest.mark.asyncio
async def test_batching_vuln_confirmed_secure_clean():
    vuln = await _run(GraphQLBatchingDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    secure = await _run(GraphQLBatchingDetector, "/secure")
    assert [f for f in secure if f.status.value == "confirmed"] == []


@pytest.mark.asyncio
async def test_alias_abuse_vuln_confirmed_secure_clean():
    vuln = await _run(GraphQLAliasAbuseDetector, "/vuln")
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    assert "20 aliases" in vuln[0].title
    secure = await _run(GraphQLAliasAbuseDetector, "/secure")
    assert [f for f in secure if f.status.value == "confirmed"] == []


@pytest.mark.asyncio
async def test_detectors_fetch_schema_by_introspection_when_none_supplied():
    # No schema in params or context: depth still confirms on /vuln by
    # asking the server to describe itself first.
    vuln = await _run(GraphQLDepthDetector, "/vuln", with_schema=False)
    assert len([f for f in vuln if f.status.value == "confirmed"]) == 1
    # On /secure introspection is disabled, so the depth check reports
    # inconclusive instead of a finding — never a false confirmed.
    secure = await _run(GraphQLDepthDetector, "/secure", with_schema=False)
    assert [f for f in secure if f.status.value == "confirmed"] == []
    assert secure and secure[0].status.value == "informational"


@pytest.mark.asyncio
async def test_full_graphql_run_vuln_finds_all_secure_finds_none_confirmed():
    config = make_config()
    client = make_client(config)
    params = {name: {"prefix": "/vuln"} for name in
              ["graphql_introspection", "graphql_depth", "graphql_batching", "graphql_alias_abuse"]}
    findings, _ = await run_detectors(
        config,
        ["graphql_introspection", "graphql_depth", "graphql_batching", "graphql_alias_abuse"],
        params=params, client=client, graphql_schema=LAB_SCHEMA)
    await client.aclose()
    assert {f.detector for f in findings if f.status.value == "confirmed"} == {
        "graphql_introspection", "graphql_depth", "graphql_batching", "graphql_alias_abuse"}

    config2 = make_config()
    client2 = make_client(config2)
    params2 = {k: dict(v, prefix="/secure") for k, v in params.items()}
    findings2, _ = await run_detectors(
        config2,
        ["graphql_introspection", "graphql_depth", "graphql_batching", "graphql_alias_abuse"],
        params=params2, client=client2, graphql_schema=LAB_SCHEMA)
    await client2.aclose()
    assert [f for f in findings2 if f.status.value == "confirmed"] == []
