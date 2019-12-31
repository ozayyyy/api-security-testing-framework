# Roadmap / not yet done

Implemented: OpenAPI parser, safe client, nine detectors (bola, bfla,
jwt, mass_assignment, excessive_data, rate_limit, business_logic,
inconsistent_authz, session), vulnerable lab with secure variants,
JSON/Markdown/HTML reporting, detector documentation, measured lab
evaluation, sample findings, pytest suite, CI.

Not yet done (from the project spec):
- Detection coverage / false-positive / false-negative measurement
  against a larger corpus and against established tools — the lab
  evaluation in `docs/EVALUATION.md` measures the bundled lab only;
  that comparison is still open.
- Incremental / baseline / suppression handling beyond per-run reports.
- GraphQL / gRPC support; REST only for now.
- Session checks beyond revocation/expiry/refresh (for example,
  refresh-token rotation and concurrent-session handling) are not
  covered by the lab.
- Business-logic coverage beyond the lab order workflow needs
  per-workflow detector parameters.
