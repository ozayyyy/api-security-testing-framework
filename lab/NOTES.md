# Lab notes

The lab is a FastAPI app for localhost only, with synthetic data.

- Same endpoints exist under `/vuln` (flawed) and `/secure` (fixed).
- Seeded identities: alice owns object 1, bob owns object 2, plus an admin.
- `POST /_lab/reset` restores orders, objects and revocations to the
  seeded state. Run it between scans, because some detectors mutate
  lab state (for example, mass-assignment promotes alice to admin).
- `POST /_lab/issue-jwt` is a test-only token issuer. It accepts an
  `exp` value and issues a unique `jti` per token.
- `POST /_lab/revoke` records a revoked token. The secure variant
  rejects revoked tokens; the vulnerable variant ignores revocation.
