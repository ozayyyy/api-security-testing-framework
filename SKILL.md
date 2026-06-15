---
name: api-security-testing-framework
description: Scan a REST or GraphQL API for authorisation, authentication and business-logic weaknesses and read the findings — use when someone asks to test an API, check an endpoint, or review API security findings.
---

# API Security Testing Framework

A rule-based, deterministic scanner for REST and GraphQL APIs. Every
detector is an explicit rule over observed request/response pairs, and
every finding carries the request/response evidence that produced it,
a reproduction, and a confidence level. Findings are graded
`confirmed` / `suspected` / `informational`.

## What it does

- Parses OpenAPI 3 specs (endpoints, methods, parameters, auth
  requirements) and GraphQL schemas (SDL or introspection JSON).
- Runs 9 REST detectors: BOLA/IDOR, BFLA, JWT validation, mass
  assignment, excessive data exposure, rate limiting, business-logic
  state transitions, inconsistent authorisation, session
  (revocation/expiry/refresh).
- Runs 4 GraphQL detectors: introspection enabled, query depth not
  limited, query batching not limited, alias abuse not limited.
- Safe mode: localhost-only allowlist by default, request budget,
  rate limiting between requests, audit log, redaction of credentials
  and sensitive data in all evidence, logs and reports.
- Reports in JSON, Markdown and HTML.

## Install

Requires Python 3.10 or later. From the repo root:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Quick start — scan the bundled lab

The lab is a deliberately vulnerable API with a secure variant of the
same endpoints, localhost only, synthetic data. Start it first:

```bash
# Terminal 1
.venv/bin/uvicorn lab.app:app --host 127.0.0.1 --port 8000

# Terminal 2: vulnerable variant (expect 17 findings, 16 confirmed)
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix /vuln \
  --spec examples/openapi-lab.yaml --report findings.json

# Secure variant (expect 0 findings)
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix /secure \
  --spec examples/openapi-lab.yaml --report findings-secure.json

# GraphQL endpoint too (adds the 4 GraphQL detectors; expect 21
# findings, 20 confirmed on /vuln, 0 on /secure)
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix /vuln \
  --spec examples/openapi-lab.yaml \
  --graphql-schema examples/graphql-lab.graphql \
  --report findings-graphql.json
```

Reset the lab between runs so one detector's mutations do not leak
into the next run:

```bash
curl -X POST http://127.0.0.1:8000/_lab/reset
```

## Scanning a target of your own

```bash
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix "" \
  --spec path/to/openapi.yaml --report findings.json --format json
```

Useful flags: `--detectors bola,jwt` (comma-separated subset),
`--budget 500` (request budget, max 2000), `--format md|html`
(report format). The GraphQL detectors join the default set only
when `--graphql-schema` is given; naming them in `--detectors`
runs them too (they fetch the schema by introspection when none is
supplied, and report inconclusive if introspection is off).

Detectors need the target's identity/object mapping supplied as
parameters; they do not discover object IDs on their own. See
`docs/detectors.md` for one section per detector: its rule, probes,
expected behaviour and limitations.

Or run detectors in Python:

```python
from apistf.config import Identity, TargetConfig
from apistf.runner import run_detectors
import asyncio

config = TargetConfig(
    base_url="http://127.0.0.1:8000",
    identities=[
        Identity(name="alice", role="user", token="token-alice"),
        Identity(name="bob", role="user", token="token-bob"),
        Identity(name="admin", role="admin", token="token-admin"),
    ],
)
findings, _ = asyncio.run(run_detectors(
    config, params={"bola": {"prefix": "/vuln"}}))
```

## Reading the output

- The CLI prints `requests sent` and `findings: N (M confirmed)`,
  then one line per finding: `[severity] [status] title`.
- `confirmed` means the vulnerable behaviour was observed and a
  control request on the same endpoint behaved differently.
  `suspected` means anomalous behaviour that was not reproduced as a
  boundary violation. `informational` means an observation with no
  boundary violation demonstrated (for example, a probe that could
  not run because a control failed).
- Severity is `high` / `medium` / `low` / `informational`. A finding
  is only as strong as its evidence: open the report and read the
  `evidence` (request/response pairs) and `reproduction` steps
  before acting on it.
- Reports: `--report findings.json --format json` (default),
  `--format md` or `--format html`. Sample reports from a lab run
  are in `examples/` (`findings-vuln.*`, 17 findings;
  `findings-secure.*`, 0 findings).
- Measured lab evaluation: `docs/EVALUATION.md` (lab only — not a
  benchmark against other tools, and not general precision/recall).

## Safety rules, in plain words

- Only point a scan at a target you are allowed to test. Safe mode
  refuses any host not in the allowlist before any request is sent;
  the default allowlist is localhost only.
- Every scan stops at a request budget (500 by default, 2000 at
  most). Probes are bursty by design (rate-limit and batching
  detectors); keep the budget low on a target you do not own.
- The scanner takes no real credentials. Scans use the lab's
  built-in test identities only — never pass real tokens, keys or
  passwords to it.
- The lab is localhost only with synthetic data. Never expose it
  beyond localhost.
- The lab's `/secure` variant is the control: a detector that fires
  on `/secure` is a false positive until proven otherwise.

## What it must never be used for

- Never scan a target you are not authorised to test. This includes
  public websites and public APIs you do not own or have written
  permission to test.
- Never use it to attack a live service, degrade a real site, or
  access another person's data. The lab and your own authorised
  targets are the only in-scope targets.
- Never feed it real credentials, real user data, or production
  traffic, and never point it at a production system.
- Never treat a `suspected` or `informational` result as a proven
  vulnerability, and never report a finding without its evidence
  and reproduction steps.
- Never use a finding to access, copy, or change data that is not
  yours.

## Layout

```
apistf/            framework (parser, client, detectors, reporting)
apistf/detectors/  one module per detector, registered in __init__.py
apistf/graphql.py  GraphQL SDL parser, introspection reader, probe builders
lab/               deliberately vulnerable FastAPI lab + secure variants
lab/graphql_exec.py  minimal GraphQL executor for the lab only
tests/             unit + integration tests against the lab
examples/          OpenAPI spec and GraphQL schema for the lab, sample findings
docs/              detector docs, roadmap, evaluation notes
```
