# Advanced API Security Testing Framework

Extensible framework for assessing REST APIs: authorisation,
authentication and business-logic weaknesses.

Detection is **rule-based and deterministic only — no AI/LLM** is used
anywhere. Each detector is an explicit rule over observed
request/response pairs, and every finding carries the request/response
evidence that produced it, a reproduction, and a confidence level.
Findings are graded `confirmed` / `suspected` / `informational`.

## What it does

- Import and parse OpenAPI 3 specifications (endpoints, methods,
  parameters, request bodies, auth requirements).
- Authenticated and unauthenticated test sessions (bearer token,
  API key, per-role identities).
- Detectors (one module each, in `apistf/detectors/`):
  - `bola` — cross-user object access (BOLA/IDOR)
  - `bfla` — low-privilege role calling admin endpoints
  - `jwt` — missing / `alg=none` / tampered / expired tokens
  - `mass_assignment` — privileged fields settable via profile update
  - `excessive_data` — sensitive fields returned in responses
  - `rate_limit` — burst probe for missing 429 enforcement
- Safe mode: explicit target allowlist (localhost by default),
  request budget, rate limiting between requests, audit log, and
  redaction of credentials and sensitive response data in all
  evidence, logs and reports.
- Reports in JSON, Markdown and HTML.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Quick start (against the bundled lab)

```bash
# Terminal 1: start the lab (localhost only, synthetic data)
.venv/bin/uvicorn lab.app:app --host 127.0.0.1 --port 8000

# Terminal 2: scan the vulnerable variant
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix /vuln \
  --spec examples/openapi-lab.yaml --report findings.json

# Scan the secure variant (expect no confirmed findings)
.venv/bin/apistf --target http://127.0.0.1:8000 --prefix /secure \
  --report findings-secure.json
```

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

## Threat model

Attacker model: an authenticated low-privilege user (or no user at
all) probing another user's objects, admin functions, and token
handling, plus a caller abusing missing rate limits. The framework
tests what the server enforces; it does not test the client, the
network, or the lab's host.

## Safety

Do not point this at a target you are not authorised to test. Safe
mode refuses any host not in `allowed_hosts` and stops at
`request_budget`. The default allowlist is localhost only.

## Limitations

- Detectors need the lab's (or the target's) identity/object mapping
  supplied as parameters; they do not discover object IDs on their own.
- The rate-limit probe only detects a limit below the burst size
  (default 20).
- JWT checks observe acceptance/rejection; they do not brute-force
  secrets and cannot prove a strong token is unforgeable.
- Business-logic tests beyond the detectors above are not yet
  implemented (see `docs/ROADMAP.md`).

## Tests

```bash
.venv/bin/pytest -q
```

## Layout

```
apistf/            framework (parser, client, detectors, reporting)
lab/               deliberately vulnerable FastAPI lab + secure variants
tests/             unit + integration tests against the lab
examples/          OpenAPI spec for the lab
docs/              roadmap / evaluation notes
```
