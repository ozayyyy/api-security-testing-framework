# Evaluation — measured on the bundled lab only

Method: the full CLI scan (`apistf --target http://127.0.0.1:8000
--prefix /vuln|--secure --spec examples/openapi-lab.yaml`) was run
against the lab server on localhost, with `POST /_lab/reset`
between runs. The same scan was repeated for the Markdown and HTML
sample reports; the counts were identical on every repeat. The
pytest suite runs the same detectors in-process via ASGI transport.
Expected outcome per detector: at least one CONFIRMED finding on
`/vuln`, zero CONFIRMED findings on `/secure`.

## Measured CLI run

| Variant | Findings | Confirmed | Suspected | Requests sent | Wall time |
| --- | --- | --- | --- | --- | --- |
| `/vuln` | 17 | 16 | 1 | 64 | 0.58 s |
| `/secure` | 0 | 0 | 0 | 66 | 0.55 s |

Wall time is the `time` measurement of the whole CLI invocation,
including interpreter startup, against the lab on localhost. The
pytest suite (18 tests, in-process) took 0.54 s on the same machine.

## Measured CLI run — GraphQL detectors included

Same command with `--graphql-schema examples/graphql-lab.graphql`
added (REST detectors plus the 4 GraphQL detectors):

| Variant | Findings | Confirmed | Suspected | Requests sent |
| --- | --- | --- | --- | --- |
| `/vuln` | 21 | 20 | 1 | 71 |
| `/secure` | 0 | 0 | 0 | 73 |

The 4 extra confirmed findings on `/vuln` are the GraphQL detectors
(`graphql_introspection`, `graphql_depth`, `graphql_batching`,
`graphql_alias_abuse`), one each; none fires on `/secure`. The
GraphQL detectors send 7 requests per run (1 introspection probe,
2 each for depth, batching and alias: a control plus the probe),
because the schema is supplied and no introspection round-trip is
needed. The pytest suite (44 tests, in-process) took 2.97 s on the
same machine.

## Per-detector results (CLI run)

| Detector | Confirmed on `/vuln` | Confirmed on `/secure` |
| --- | --- | --- |
| bola | 1 | 0 |
| bfla | 1 | 0 |
| jwt | 2 confirmed, 1 suspected (expired token) | 0 |
| mass_assignment | 1 | 0 |
| excessive_data | 2 | 0 |
| rate_limit | 1 | 0 |
| business_logic | 4 | 0 |
| inconsistent_authz | 1 | 0 |
| session | 3 | 0 |
| **Total** | **16 confirmed, 1 suspected** | **0** |

The one suspected finding is the JWT detector's expired-token probe,
which uses a token with an invalid signature and therefore cannot
separate expiry enforcement from signature enforcement. The session
detector's expired-token probe uses a properly signed expired token
and is confirmed on `/vuln`, 0 on `/secure`.

Sample findings from this run are in `examples/`:
`findings-vuln.json` / `.md` / `.html` (17 findings) and
`findings-secure.json` / `.md` / `.html` (0 findings). All evidence
in them is redacted — checked: no test tokens, no lab secret and no
password-hash values appear in any of the six files.

## What this does and does not show

- Coverage on the lab: 9 of 9 detectors fire on `/vuln` and none
  fire confirmed on `/secure`. On this lab only, that is a
  false-positive rate of 0 confirmed findings on the secure variant
  and a false-negative rate of 0 missed detectors on the vulnerable
  variant.
- These rates are measured on the bundled lab only, with one
  seeded flaw per detector. They are not general precision/recall
  figures, and they say nothing about other targets, other flaws,
  or other tools.
- No comparison against established tools was run; that is still
  open (see `docs/ROADMAP.md`). No larger corpus was used.
- Runtime is lab-local only; a real target with network latency,
  a larger OpenAPI spec, or a lower request budget will differ.
