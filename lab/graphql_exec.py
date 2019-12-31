"""Minimal GraphQL executor for the lab only.

This is not a GraphQL implementation: it parses the query subset the
detectors send (fields, aliases, arguments with scalar values,
nested selections, named and inline fragments, ``__schema`` /
``__type`` introspection) and resolves it against the lab's seeded
users and posts. Anything outside that subset returns a GraphQL-style
errors payload instead of data.

Behaviour differs by variant:
- vuln: introspection on, no depth / batching / alias limits.
- secure: introspection disabled, max depth 5, max 5 aliases per
  operation, batching (a JSON array body) rejected with 400.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from apistf.graphql import GraphQLSchema, named_type

MAX_DEPTH_SECURE = 5
MAX_ALIASES_SECURE = 5

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_]*|-?\d+(?:\.\d+)?|[{}\[\]():!$=]|\.\.\.|@', re.M)


def _tokenize(text: str) -> list[str]:
    return [m.group(0) for m in _TOKEN.finditer(text)]


@dataclass
class FieldSel:
    name: str
    alias: str | None = None
    args: dict = field(default_factory=dict)
    selections: list = field(default_factory=list)


@dataclass
class FragmentSpread:
    name: str


@dataclass
class InlineFragment:
    type_condition: str = ""
    selections: list = field(default_factory=list)


@dataclass
class Operation:
    kind: str = "query"  # query | mutation
    name: str = ""
    selections: list = field(default_factory=list)


@dataclass
class FragmentDef:
    name: str
    type_condition: str = ""
    selections: list = field(default_factory=list)


class _QueryParser:
    def __init__(self, text: str):
        self.toks = _tokenize(text)
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

    def parse_value(self):
        tok = self.next()
        if tok.startswith('"'):
            return tok[1:-1]
        if tok == "$":
            raise ValueError("variables are not supported by the lab")
        if tok in ("true", "false"):
            return tok == "true"
        if tok == "null":
            return None
        try:
            return int(tok)
        except ValueError:
            pass
        try:
            return float(tok)
        except ValueError:
            pass
        return tok  # enum value: returned as its name

    def parse_args(self) -> dict:
        args = {}
        self.expect("(")
        while self.peek() != ")":
            name = self.next()
            self.expect(":")
            args[name] = self.parse_value()
        self.expect(")")
        return args

    def parse_selection_set(self) -> list:
        self.expect("{")
        sels = []
        while self.peek() != "}":
            if self.peek() == "":
                raise ValueError("unexpected end of query inside selection set")
            sels.append(self.parse_selection())
        self.expect("}")
        return sels

    def parse_selection(self):
        tok = self.peek()
        if tok == "...":
            self.next()
            if self.peek() == "on":
                self.next()
                cond = self.next()
                self.skip_directives()
                return InlineFragment(type_condition=cond, selections=self.parse_selection_set())
            name = self.next()
            self.skip_directives()
            return FragmentSpread(name=name)
        name = self.next()
        alias = None
        if self.peek() == ":":
            self.next()
            alias = name
            name = self.next()
        args = self.parse_args() if self.peek() == "(" else {}
        self.skip_directives()
        sels = self.parse_selection_set() if self.peek() == "{" else []
        return FieldSel(name=name, alias=alias, args=args, selections=sels)

    def parse_document(self) -> tuple[list[Operation], dict[str, FragmentDef]]:
        ops: list[Operation] = []
        frags: dict[str, FragmentDef] = {}
        while self.i < len(self.toks):
            tok = self.peek()
            if tok == "fragment":
                self.next()
                name = self.next()
                self.expect("on")
                cond = self.next()
                self.skip_directives()
                frags[name] = FragmentDef(name=name, type_condition=cond,
                                          selections=self.parse_selection_set())
            else:
                kind = "query"
                if tok in ("query", "mutation"):
                    kind = self.next()
                name = ""
                if self.peek() not in ("{", "(", "@"):
                    name = self.next()
                if self.peek() == "(":
                    self._skip_balanced("(", ")")
                self.skip_directives()
                ops.append(Operation(kind=kind, name=name,
                                     selections=self.parse_selection_set()))
        if not ops:
            raise ValueError("no operation in query")
        return ops, frags


def _expanded(selections: list, frags: dict, _seen: frozenset | None = None) -> list:
    """Fragment spreads replaced by the fragment's selections."""
    seen = _seen or frozenset()
    out = []
    for sel in selections:
        if isinstance(sel, FragmentSpread):
            if sel.name in seen or sel.name not in frags:
                continue
            out.extend(_expanded(frags[sel.name].selections, frags, seen | {sel.name}))
        elif isinstance(sel, InlineFragment):
            out.extend(_expanded(sel.selections, frags, seen))
        else:
            out.append(sel)
    return out


def selection_depth(selections: list, frags: dict) -> int:
    depth = 0
    for sel in _expanded(selections, frags):
        if isinstance(sel, FieldSel):
            sub = selection_depth(sel.selections, frags) if sel.selections else 0
            depth = max(depth, 1 + sub)
    return depth


def alias_count(selections: list, frags: dict) -> int:
    count = 0
    for sel in _expanded(selections, frags):
        if isinstance(sel, FieldSel):
            if sel.alias:
                count += 1
            count += alias_count(sel.selections, frags)
    return count


def _contains_introspection(selections: list, frags: dict) -> bool:
    for sel in _expanded(selections, frags):
        if isinstance(sel, FieldSel):
            if sel.name in ("__schema", "__type"):
                return True
            if _contains_introspection(sel.selections, frags):
                return True
    return False


# ---------------------------------------------------------------- introspection

def _type_ref(type_str: str, schema: GraphQLSchema) -> dict:
    if type_str.endswith("!"):
        return {"kind": "NON_NULL", "name": None, "ofType": _type_ref(type_str[:-1], schema)}
    if type_str.startswith("[") and type_str.endswith("]"):
        return {"kind": "LIST", "name": None, "ofType": _type_ref(type_str[1:-1], schema)}
    t = schema.types.get(type_str)
    kind = t.kind if t else "SCALAR"
    return {"kind": kind, "name": type_str, "ofType": None}


def _type_json(name: str, schema: GraphQLSchema) -> dict | None:
    t = schema.types.get(name)
    if t is None:
        return None
    out: dict = {"name": name, "kind": t.kind}
    if t.kind in ("OBJECT", "INTERFACE", "INPUT_OBJECT"):
        fields = []
        for f in t.fields.values():
            fields.append({
                "name": f.name,
                "args": [{"name": a, "type": _type_ref(at, schema)}
                         for a, at in f.args.items()],
                "type": _type_ref(f.type_str, schema),
            })
        out["fields"] = fields
    else:
        out["fields"] = None
    return out


def _schema_json(schema: GraphQLSchema) -> dict:
    types = [_type_json(name, schema) for name in sorted(schema.types)
             if not name.startswith("__")]
    return {
        "queryType": {"name": schema.query_type},
        "mutationType": {"name": schema.mutation_type} if schema.mutation_type else None,
        "types": [t for t in types if t is not None],
    }


# ---------------------------------------------------------------- execution

class _Executor:
    def __init__(self, schema: GraphQLSchema, users: dict, posts: dict):
        self.schema = schema
        self.users = users
        self.posts = posts
        self.errors: list[dict] = []

    def _resolve_root(self, f: FieldSel):
        if f.name == "__typename":
            return "Query"
        if f.name == "__schema":
            return _schema_json(self.schema)
        if f.name == "__type":
            name = f.args.get("name")
            result = _type_json(str(name), self.schema) if name else None
            if result is None:
                self.errors.append({"message": f"unknown type {name!r}"})
            return result
        if f.name == "user":
            return self.users.get(int(f.args["id"])) if "id" in f.args else None
        if f.name == "users":
            return list(self.users.values())
        if f.name == "post":
            return self.posts.get(int(f.args["id"])) if "id" in f.args else None
        if f.name == "posts":
            return list(self.posts.values())
        self.errors.append({"message": f"Cannot query field {f.name!r} on type 'Query'."})
        return None

    def _resolve_field(self, parent_type: str, parent: dict, f: FieldSel):
        if f.name == "__typename":
            return parent_type
        if parent_type == "User":
            if f.name in ("id", "username", "email", "role"):
                return parent.get(f.name)
            if f.name == "friends":
                return [u for u in self.users.values() if u["id"] != parent["id"]]
            if f.name == "posts":
                return [p for p in self.posts.values() if p["author_id"] == parent["id"]]
        if parent_type == "Post":
            if f.name in ("id", "title", "content"):
                return parent.get(f.name)
            if f.name == "author":
                return self.users.get(parent["author_id"])
        self.errors.append({"message": f"Cannot query field {f.name!r} on type {parent_type!r}."})
        return None

    def _execute_selections(self, parent_type: str, parent, selections: list, frags: dict) -> dict:
        result: dict = {}
        for sel in _expanded(selections, frags):
            if not isinstance(sel, FieldSel):
                continue
            key = sel.alias or sel.name
            if parent_type == "Query":
                value = self._resolve_root(sel)
                if sel.name in ("__schema", "__type", "__typename"):
                    next_type = ""
                else:
                    fdef = self.schema.query_fields().get(sel.name)
                    next_type = fdef.named if fdef else ""
            elif isinstance(parent, dict) and parent_type not in self.schema.types:
                # Introspection result objects are plain dicts: their
                # sub-fields are plain keys, not schema fields.
                value = parent.get(sel.name)
                next_type = ""
            else:
                value = self._resolve_field(parent_type, parent, sel)
                tdef = self.schema.types.get(parent_type)
                fdef = tdef.fields.get(sel.name) if tdef else None
                next_type = fdef.named if fdef else ""
            if sel.selections and value is not None:
                if isinstance(value, list):
                    result[key] = [self._execute_selections(next_type, item, sel.selections, frags)
                                   for item in value]
                elif isinstance(value, dict):
                    result[key] = self._execute_selections(next_type, value, sel.selections, frags)
                else:
                    result[key] = value
            else:
                result[key] = value
        return result

    def execute(self, op: Operation, frags: dict) -> dict:
        if op.kind != "query":
            return {"data": None,
                    "errors": [{"message": "mutations are not supported by the lab"}]}
        data = self._execute_selections("Query", None, op.selections, frags)
        payload: dict = {"data": data}
        if self.errors:
            payload["errors"] = self.errors
        return payload


def execute_graphql(body, *, secure: bool, schema: GraphQLSchema,
                    users: dict, posts: dict) -> tuple[int, dict | list]:
    """Execute one decoded JSON request body. Returns (status, payload)."""
    if isinstance(body, list):
        if secure:
            return 400, {"errors": [{"message": "batching not allowed: send one operation per request"}]}
        out = []
        for item in body:
            _, payload = execute_graphql(item, secure=secure, schema=schema, users=users, posts=posts)
            out.append(payload)
        return 200, out
    if not isinstance(body, dict):
        return 400, {"errors": [{"message": "request body must be a JSON object"}]}
    query = body.get("query")
    if not isinstance(query, str):
        return 400, {"errors": [{"message": "request must contain a string 'query' field"}]}
    try:
        ops, frags = _QueryParser(query).parse_document()
    except ValueError as e:
        return 400, {"errors": [{"message": f"query parse error: {e}"}], "data": None}
    op = ops[0]
    if secure and _contains_introspection(op.selections, frags):
        return 200, {"data": None, "errors": [{"message": "introspection is disabled"}]}
    if secure:
        depth = selection_depth(op.selections, frags)
        if depth > MAX_DEPTH_SECURE:
            return 200, {"data": None, "errors": [
                {"message": f"query depth {depth} exceeds maximum {MAX_DEPTH_SECURE}"}]}
        aliases = alias_count(op.selections, frags)
        if aliases > MAX_ALIASES_SECURE:
            return 200, {"data": None, "errors": [
                {"message": f"query uses {aliases} aliases, maximum is {MAX_ALIASES_SECURE}"}]}
    executor = _Executor(schema, users, posts)
    return 200, executor.execute(op, frags)
