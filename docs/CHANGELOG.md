# Changelog

## 0.1.0 — 2026-11-24

- OpenAPI 3 parser and per-role authenticated sessions.
- Detectors: BOLA, BFLA, JWT, mass-assignment, excessive data, rate-limit,
  business-logic, inconsistent authorisation, session lifecycle.
- Vulnerable lab with secure variants for the same endpoints, plus
  order workflow, second resource path, and revocable test tokens.
- Reports in JSON, Markdown and HTML, with redacted evidence.
- Measured evaluation on the bundled lab: 17 findings, 16 confirmed
  on the vulnerable variant, 0 on the secure variant.
