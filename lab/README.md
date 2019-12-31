# Lab

Deliberately vulnerable API plus secure variants, localhost only.

```bash
.venv/bin/uvicorn lab.app:app --host 127.0.0.1 --port 8000
```

Seeded identities (opaque bearer tokens):

| user | token | owns |
| --- | --- | --- |
| alice (user) | `token-alice` | object 1 |
| bob (user) | `token-bob` | object 2 |
| admin | `token-admin` | — |

Endpoints exist under both `/vuln` (flawed) and `/secure` (fixed):

- `GET /objects/{id}` — BOLA in `/vuln`, owner-checked in `/secure`
- `GET /admin/users` — any authenticated user in `/vuln`, admin-only in `/secure`
- `GET /me` — accepts opaque tokens and JWTs; `/vuln` accepts `alg=none`, tampered and expired JWTs, `/secure` verifies HS256 signature and expiry
- `PATCH /users/me` — `/vuln` applies `role`/`is_admin` from the request body, `/secure` ignores privileged fields
- `GET /users/{id}` and `GET /users/me` — `/vuln` returns `password_hash` and `ssn`, `/secure` returns only id/username/role
- `GET /rate-test` — never rate-limited in `/vuln`, 429 after 5 requests in `/secure`

`POST /_lab/reset` restores seeded users/objects and rate counters.
All data is synthetic. Never expose this lab beyond localhost.
