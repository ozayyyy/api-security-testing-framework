"""OpenAPI 3 parser: endpoints, parameters, bodies, auth requirements."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import yaml


@dataclass
class Parameter:
    name: str
    location: str  # path | query | header | cookie
    required: bool = False
    schema_type: str = ""


@dataclass
class Endpoint:
    path: str
    method: str  # upper-case
    operation_id: str = ""
    parameters: list[Parameter] = field(default_factory=list)
    request_body: dict = field(default_factory=dict)
    auth_required: bool = False
    auth_schemes: list[str] = field(default_factory=list)
    responses: list[str] = field(default_factory=list)

    @property
    def path_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def id_params(self) -> list[Parameter]:
        """Path parameters that look like object identifiers."""
        return [
            p for p in self.path_params
            if p.name.lower() in {"id", "object_id", "user_id", "account_id", "resource_id"}
            or p.name.lower().endswith("_id")
        ]


@dataclass
class OpenAPISpec:
    title: str = ""
    version: str = ""
    servers: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    security_schemes: dict = field(default_factory=dict)

    def endpoints_for(self, method: str | None = None, path_substring: str = "") -> list[Endpoint]:
        out = self.endpoints
        if method:
            out = [e for e in out if e.method == method.upper()]
        if path_substring:
            out = [e for e in out if path_substring in e.path]
        return out


def parse_spec_text(text: str) -> OpenAPISpec:
    try:
        data = json.loads(text)
    except ValueError:
        data = yaml.safe_load(text)
    return parse_spec_dict(data)


def parse_spec_dict(data: dict) -> OpenAPISpec:
    if not isinstance(data, dict) or "openapi" not in data and "swagger" not in data:
        raise ValueError("not an OpenAPI/Swagger document (missing 'openapi'/'swagger' key)")
    spec = OpenAPISpec(
        title=data.get("info", {}).get("title", ""),
        version=str(data.get("info", {}).get("version", "")),
        servers=[s.get("url", "") for s in data.get("servers", []) if isinstance(s, dict)],
        security_schemes=data.get("components", {}).get("securitySchemes", {}) or {},
    )
    global_security = data.get("security", [])
    for path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(op, dict):
                continue
            params = []
            for p in op.get("parameters", []) or []:
                if isinstance(p, dict):
                    schema = p.get("schema") or {}
                    params.append(Parameter(
                        name=p.get("name", ""), location=p.get("in", ""),
                        required=bool(p.get("required", False)),
                        schema_type=schema.get("type", ""),
                    ))
            security = op.get("security", global_security)
            schemes: list[str] = []
            for req in security or []:
                if isinstance(req, dict):
                    schemes.extend(req.keys())
            spec.endpoints.append(Endpoint(
                path=path, method=method.upper(),
                operation_id=op.get("operationId", ""),
                parameters=params,
                request_body=op.get("requestBody") or {},
                auth_required=bool(security),
                auth_schemes=schemes,
                responses=list((op.get("responses") or {}).keys()),
            ))
    return spec


def load_spec(path: str) -> OpenAPISpec:
    with open(path, encoding="utf-8") as f:
        return parse_spec_text(f.read())
