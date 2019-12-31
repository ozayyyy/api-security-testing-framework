# Roadmap / not yet done (Phase 1)

Implemented in Phase 1: OpenAPI parser, safe client, BOLA, BFLA, JWT,
mass-assignment, excessive-data, rate-limit detectors, vulnerable lab
with secure variants, JSON/Markdown/HTML reporting, pytest suite.

Not yet done (from the project spec):
- Business-logic test cases beyond the six detectors (e.g. state-machine
  / workflow violations, inconsistent access control across endpoints).
- Broader JWT/session checks (session revocation/expiry lifecycle,
  refresh-token handling).
- Detection coverage / false-positive / false-negative measurement
  against a larger corpus and against established tools — the lab
  evaluation in `docs/EVALUATION.md` is the starting point, not a
  benchmark.
- Incremental / baseline / suppression handling beyond per-run reports.
- GraphQL / gRPC support; REST only for now.
- CI configuration.
