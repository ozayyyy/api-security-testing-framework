"""CLI: apistf --target http://127.0.0.1:8000 --spec examples/openapi-lab.yaml scan ..."""
from __future__ import annotations

import argparse
import asyncio
import sys

from apistf.client import SafeClient
from apistf.config import Identity, TargetConfig
from apistf.graphql import load_schema
from apistf.openapi import load_spec
from apistf.reporting import write_report
from apistf.runner import run_detectors

REST_DETECTORS = ["bola", "bfla", "jwt", "mass_assignment", "excessive_data",
                  "rate_limit", "business_logic", "inconsistent_authz", "session"]
GRAPHQL_DETECTORS = ["graphql_introspection", "graphql_depth",
                     "graphql_batching", "graphql_alias_abuse"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apistf", description="API Security Testing Framework (rule-based)")
    p.add_argument("--target", default="http://127.0.0.1:8000", help="Base URL of the target API")
    p.add_argument("--spec", help="Path to an OpenAPI spec (JSON or YAML)")
    p.add_argument("--graphql-schema", help="Path to a GraphQL schema (SDL or introspection JSON); "
                                            "enables the GraphQL detectors")
    p.add_argument("--prefix", default="/vuln", help="Lab prefix: /vuln or /secure")
    p.add_argument("--detectors", default="", help="Comma-separated detector names (default: all)")
    p.add_argument("--budget", type=int, default=500, help="Request budget")
    p.add_argument("--report", help="Report output path")
    p.add_argument("--format", default="json", choices=["json", "md", "html"], help="Report format")
    return p


async def _run(args) -> int:
    spec = load_spec(args.spec) if args.spec else None
    graphql_schema = load_schema(args.graphql_schema) if args.graphql_schema else None
    # Lab identities: token scheme is the lab's own (see lab/README.md).
    config = TargetConfig(
        base_url=args.target, request_budget=args.budget,
        identities=[
            Identity(name="alice", role="user", token="token-alice"),
            Identity(name="bob", role="user", token="token-bob"),
            Identity(name="admin", role="admin", token="token-admin"),
        ],
    )
    names = [n.strip() for n in args.detectors.split(",") if n.strip()] or None
    # Per-detector params default to the lab layout; prefix is shared.
    # GraphQL detectors join the default set only when a schema is
    # supplied; naming them explicitly via --detectors also runs them
    # (they fetch the schema by introspection when none is supplied).
    # The resolved list — not None — goes to the runner, so params and
    # the run list always agree (the runner would otherwise expand
    # None to the whole registry, including detectors with no params).
    defaults = REST_DETECTORS + (GRAPHQL_DETECTORS if graphql_schema is not None else [])
    run_names = names or defaults
    params = {name: {"prefix": args.prefix} for name in run_names}
    # JWT detector needs a valid token to tamper with. Best-effort: ask
    # the lab's test-only issuer (absent on real targets, where the user
    # supplies a token instead). Failure here only weakens the JWT check.
    if "jwt" in params:
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(trust_env=False, timeout=5.0) as _c:
                _r = await _c.post(f"{args.target}/_lab/issue-jwt", json={"sub": "bob"})
                if _r.status_code == 200:
                    params["jwt"]["valid_token"] = _r.json().get("token", "")
        except Exception:
            pass
    findings, client = await run_detectors(config, run_names, spec=spec, params=params,
                                           graphql_schema=graphql_schema)
    print(f"requests sent: {client.requests_sent}")
    print(f"findings: {len(findings)} "
          f"({sum(1 for f in findings if f.status.value == 'confirmed')} confirmed)")
    for f in findings:
        print(f"  [{f.severity.value}] [{f.status.value}] {f.title}")
    if args.report:
        write_report(findings, args.report, args.format)
        print(f"report written: {args.report}")
    return 0


def main() -> None:
    args = build_parser().parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
