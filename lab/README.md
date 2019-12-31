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
- `GET /profile/{id}` — second path to the same user resource: `/vuln` checks ownership (403 for a non-owner) while `/users/{id}` does not, `/secure` returns the same public view on both paths
- `GET /rate-test` — never rate-limited in `/vuln`, 429 after 5 requests in `/secure`
- Orders (`POST /orders`, `GET/PATCH /orders/{id}`, `POST /orders/{id}/pay|ship|cancel|refund`) — draft -> paid -> shipped, cancel from draft/paid, one refund from paid/shipped. `/vuln` allows pay-after-cancel, double refund, ship-unpaid and price/quantity changes after payment; `/secure` rejects all of them with 409
- `POST /auth/refresh` — `/vuln` refreshes any JWT-shaped token including revoked/expired ones, `/secure` requires a valid, unexpired, unrevoked token

`POST /_lab/reset` restores seeded users/objects, orders and rate counters, and clears revocations.
`POST /_lab/issue-jwt` issues a signed JWT (optional `exp`); `POST /_lab/revoke` revokes a token string (`/secure` rejects it afterwards, `/vuln` ignores revocation).
All data is synthetic. Never expose this lab beyond localhost.
