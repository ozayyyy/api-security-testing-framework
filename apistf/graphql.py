"""GraphQL schema model: SDL parser, introspection reader, probe builders.

Stdlib only. The SDL parser covers the subset of schema definition
language the lab and the detectors need: ``type`` / ``input`` /
``enum`` / ``scalar`` / ``interface`` / ``union`` definitions, field
arguments, list/non-null wrappers, and ``schema { query: ... }``.
Directives and descriptions are skipped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

BUILTIN_SCALARS = {"String", "Int", "Float", "Boolean", "ID"}


def named_type(type_str: str) -> str:
    """Unwrap list / non-null markers: ``[User!]!`` -> ``User``."""
    return type_str.replace("[", "").replace("]", "").replace("!", "").strip()


@dataclass
class FieldDef:
    name: str
    type_str: str = "String"
    args: dict[str, str] = field(default_factory=dict)  # arg name -> type string

    @property
    def named(self) -> str:
        return named_type(self.type_str)


@dataclass
class TypeDef:
    name: str
    kind: str = "OBJECT"  # OBJECT | INPUT_OBJECT | ENUM | SCALAR | INTERFACE | UNION
    fields: dict[str, FieldDef] = field(default_factory=dict)


@dataclass
class GraphQLSchema:
    types: dict[str, TypeDef] = field(default_factory=dict)
    query_type: str = "Query"
    mutation_type: str = ""

    def is_object(self, name: str) -> bool:
        t = self.types.get(name)
        return t is not None and t.kind in ("OBJECT", "INTERFACE")

    def query_fields(self) -> dict[str, FieldDef]:
        t = self.types.get(self.query_type)
        return dict(t.fields) if t else {}


# ---------------------------------------------------------------- SDL parsing

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|#.*$|[A-Za-z_][A-Za-z0-9_]*|[{}\[\]():=!|&]|\.\.\.', re.M)


def _tokenize(text: str) -> list[str]:
    out = []
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if tok.startswith("#") or tok.startswith('"'):
            continue  # comment or description string
        out.append(tok)
    return out


class _Parser:
    def __init__(self, tokens: list[str]):
        self.toks = tokens
        self.i = 0

    def peek(self) -> str:
        return self.toks[self.i] if self.i < len(self.toks) else ""

    def next(self) -> str:
        tok = self.peek()
        self.i += 1
        return tok

    def expect(self, tok: str) -> None:
        got = self.next()
        if got != tok:
            raise ValueError(f"expected {tok!r}, got {got!r}")

    def skip_directives(self) -> None:
        while self.peek() == "@":
            self.next()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.peek() or ""):
                self.next()
            if self.peek() == "(":
                self._skip_balanced("(", ")")

    def _skip_balanced(self, open_tok: str, close_tok: str) -> None:
        depth = 0
        while self.i < len(self.toks):
            tok = self.next()
            if tok == open_tok:
                depth += 1
            elif tok == close_tok:
                depth -= 1
                if depth == 0:
                    return

    def parse_type_str(self) -> str:
        # A type is: Name | [ Type ] | Type! (possibly nested).
        tok = self.next()
        if tok == "[":
            inner = self.parse_type_str()
            self.expect("]")
            out = f"[{inner}]"
        else:
            out = tok
        if self.peek() == "!":
            self.next()
            out += "!"
        return out

    def parse_args(self) -> dict[str, str]:
        args: dict[str, str] = {}
        self.expect("(")
        while self.peek() != ")":
            name = self.next()
            self.expect(":")
            args[name] = self.parse_type_str()
            if self.peek() == "=":  # default value: skip one token / literal
                self.next()
                self.next()
            self.skip_directives()
        self.expect(")")
        return args

    def parse_fields(self) -> dict[str, FieldDef]:
        self.expect("{")
        fields: dict[str, FieldDef] = {}
        while self.peek() != "}":
            name = self.next()
            args: dict[str, str] = {}
            if self.peek() == "(":
                args = self.parse_args()
            self.expect(":")
            type_str = self.parse_type_str()
            self.skip_directives()
            fields[name] = FieldDef(name=name, type_str=type_str, args=args)
        self.expect("}")
        return fields


def parse_schema_text(text: str) -> GraphQLSchema:
    """Parse SDL text into a GraphQLSchema. Raises ValueError on bad input."""
    schema = GraphQLSchema()
    p = _Parser(_tokenize(text))
    while p.i < len(p.toks):
        kw = p.next()
        if kw in ("type", "input", "interface"):
            name = p.next()
            kind = {"type": "OBJECT", "input": "INPUT_OBJECT", "interface": "INTERFACE"}[kw]
            if p.peek() == "implements":
                p.next()
                while p.peek() not in ("{", "@", ""):
                    p.next()  # interface names, optionally &-separated
            p.skip_directives()
            fields = p.parse_fields() if p.peek() == "{" else {}
            schema.types[name] = TypeDef(name=name, kind=kind, fields=fields)
        elif kw == "enum":
            name = p.next()
            p.skip_directives()
            p.expect("{")
            while p.peek() != "}":
                p.next()
                p.skip_directives()
            p.expect("}")
            schema.types[name] = TypeDef(name=name, kind="ENUM")
        elif kw == "scalar":
            name = p.next()
            p.skip_directives()
            schema.types[name] = TypeDef(name=name, kind="SCALAR")
        elif kw == "union":
            name = p.next()
            p.expect("=")
            while p.peek() not in ("", "type", "input", "enum", "scalar", "union", "interface", "schema", "directive"):
                p.next()
            schema.types[name] = TypeDef(name=name, kind="UNION")
        elif kw == "schema":
            p.skip_directives()
            p.expect("{")
            while p.peek() != "}":
                op = p.next()
                p.expect(":")
                tname = p.next()
                if op == "query":
                    schema.query_type = tname
                elif op == "mutation":
                    schema.mutation_type = tname
            p.expect("}")
        elif kw == "directive":
            # "directive @name(...) on ..." — skip to the next definition.
            while p.i < len(p.toks) and p.peek() not in (
                    "type", "input", "enum", "scalar", "union", "interface", "schema"):
                p.next()
        elif kw == "extend":
            # "extend type Name { ... }" — treat like a type definition,
            # merging fields into the existing type.
            sub = p.next()
            if sub in ("type", "input", "interface"):
                name = p.next()
                p.skip_directives()
                fields = p.parse_fields() if p.peek() == "{" else {}
                existing = schema.types.setdefault(name, TypeDef(name=name))
                existing.fields.update(fields)
            else:
                while p.i < len(p.toks) and p.peek() != "{":
                    p.next()
                if p.peek() == "{":
                    p._skip_balanced("{", "}")
        else:
            raise ValueError(f"unexpected token in schema: {kw!r}")
    for scalar in BUILTIN_SCALARS:
        schema.types.setdefault(scalar, TypeDef(name=scalar, kind="SCALAR"))
    return schema


def load_schema(path: str) -> GraphQLSchema:
    """Load a schema from an SDL file, or from a JSON introspection result
    (``{"__schema": ...}`` or ``{"data": {"__schema": ...}}``)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            inner = data.get("data", data)
            if isinstance(inner, dict) and "__schema" in inner:
                return schema_from_introspection(inner["__schema"])
    except ValueError:
        pass
    return parse_schema_text(text)


# ---------------------------------------------------------------- introspection

def _unwrap_type_ref(ref: dict) -> str:
    """Introspection type reference -> named type, e.g. ``[User!]``."""
    kind = ref.get("kind")
    if kind == "NON_NULL":
        return _unwrap_type_ref(ref.get("ofType") or {}) + "!"
    if kind == "LIST":
        return "[" + _unwrap_type_ref(ref.get("ofType") or {}) + "]"
    return ref.get("name") or "String"


def schema_from_introspection(schema_json: dict) -> GraphQLSchema:
    """Build a GraphQLSchema from a ``__schema`` introspection result."""
    schema = GraphQLSchema()
    query_type = (schema_json.get("queryType") or {}).get("name") or "Query"
    schema.query_type = query_type
    mutation_type = (schema_json.get("mutationType") or {}).get("name") or ""
    schema.mutation_type = mutation_type
    for t in schema_json.get("types") or []:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        name = t["name"]
        if name.startswith("__"):
            continue
        fields: dict[str, FieldDef] = {}
        for f in t.get("fields") or []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = {}
            for a in f.get("args") or []:
                if isinstance(a, dict) and a.get("name"):
                    args[a["name"]] = _unwrap_type_ref(a.get("type") or {})
            fields[f["name"]] = FieldDef(
                name=f["name"],
                type_str=_unwrap_type_ref(f.get("type") or {}),
                args=args,
            )
        schema.types[name] = TypeDef(name=name, kind=t.get("kind") or "OBJECT", fields=fields)
    for scalar in BUILTIN_SCALARS:
        schema.types.setdefault(scalar, TypeDef(name=scalar, kind="SCALAR"))
    return schema


def introspection_query() -> str:
    # ofType is nested four deep so wrapped types up to
    # NON_NULL(LIST(NON_NULL(Named))) — e.g. [User!]! — round-trip.
    ref = "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"
    return ("{ __schema { queryType { name } mutationType { name } "
            f"types {{ name kind fields {{ name args {{ name type {{ {ref} }} }} "
            f"type {{ {ref} }} }} }} }} }}")


# ---------------------------------------------------------------- probe builders

def _example_value(type_str: str) -> str:
    base = named_type(type_str)
    if base in ("Int", "Float"):
        return "1"
    if base == "Boolean":
        return "true"
    if base == "ID":
        return "1"
    return '"x"'


def _scalar_subfields(schema: GraphQLSchema, type_name: str) -> str:
    """Scalar field names of an object type, for a minimal selection set."""
    t = schema.types.get(type_name)
    if not t:
        return "id"
    names = [f.name for f in t.fields.values()
             if not schema.is_object(f.named) and not f.name.startswith("__")]
    return " ".join(names[:4]) or "id"


def _field_call(field: FieldDef) -> str:
    """A field invocation with example values for its required arguments."""
    if not field.args:
        return field.name
    args = ", ".join(f"{name}: {_example_value(t)}" for name, t in field.args.items())
    return f"{field.name}({args})"


def find_nesting_path(schema: GraphQLSchema) -> list[tuple[str, FieldDef]] | None:
    """A path from a Query field down into a type cycle, e.g.
    ``[("Query", user), ("User", friends)]``. Returns None when the
    schema has no self-referential path (a deep query cannot be built).
    """
    # Direct self-reference first: an object type with a field returning
    # itself (or a list of itself).
    for qname, qfield in schema.query_fields().items():
        target = qfield.named
        if not schema.is_object(target):
            continue
        t = schema.types[target]
        for fname, f in t.fields.items():
            if f.named == target:
                return [("Query", qfield), (target, f)]
        # Two-step cycle: T -> U -> T.
        for fname, f in t.fields.items():
            if not schema.is_object(f.named):
                continue
            u = schema.types.get(f.named)
            if not u:
                continue
            for gname, g in u.fields.items():
                if g.named == target:
                    return [("Query", qfield), (target, f), (f.named, g)]
    return None


def build_deep_query(schema: GraphQLSchema, depth: int) -> str | None:
    """A query nested to ``depth`` levels, counting every field level
    down to the deepest leaf field (the measure the lab enforces: a
    root field selecting scalars is depth 2). Returns None when the
    schema has no self-referential path."""
    path = find_nesting_path(schema)
    if not path or depth < 2:
        return None
    root_field = path[0][1]
    cycle = [f for _, f in path[1:]]
    # Types along the cycle: cycle_types[0] is the type the root field
    # returns; cycle_types[i+1] is the return type of cycle[i]. The
    # last entry equals the first: the cycle is a closed loop.
    cycle_types = [path[1][0]] + [f.named for f in cycle]
    # The query is: root field, then (depth - 2) nested object fields
    # walking the cycle in order, then scalar leaves. That totals
    # depth levels: 1 (root) + (depth - 2) + 1 (leaves).
    seq = [cycle[i % len(cycle)] for i in range(depth - 2)]
    # Type reached after applying the whole sequence: the cycle repeats
    # every len(cycle) steps, so the position is len(seq) mod len(cycle).
    inner_type = cycle_types[len(seq) % len(cycle)]
    body = _scalar_subfields(schema, inner_type)
    for f in reversed(seq):
        body = f"{_field_call(f)} {{ {body} }}"
    return f"{{ {_field_call(root_field)} {{ {body} }} }}"


def build_alias_query(schema: GraphQLSchema, count: int) -> str | None:
    """One query with ``count`` aliases of the same root field."""
    fields = schema.query_fields()
    if not fields:
        return None
    # Prefer a field with a scalar argument (e.g. user(id: 1)); fall back
    # to any field.
    chosen = None
    for f in fields.values():
        if f.args:
            chosen = f
            break
    chosen = chosen or next(iter(fields.values()))
    sub = _scalar_subfields(schema, chosen.named) if schema.is_object(chosen.named) else ""
    call = _field_call(chosen)
    parts = [f"a{i}: {call} {{ {sub} }}" if sub else f"a{i}: {call}"
             for i in range(1, count + 1)]
    return "{ " + " ".join(parts) + " }"


def build_simple_query(schema: GraphQLSchema) -> str | None:
    """The smallest valid query against the schema (for controls and
    batching probes). Returns None when the schema has no query fields."""
    fields = schema.query_fields()
    if not fields:
        return None
    f = next(iter(fields.values()))
    sub = _scalar_subfields(schema, f.named) if schema.is_object(f.named) else ""
    call = _field_call(f)
    return f"{{ {call} {{ {sub} }} }}" if sub else f"{{ {call} }}"
