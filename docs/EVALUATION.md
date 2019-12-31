# Evaluation (Phase 1, lab only)

Method: each detector is run against the vulnerable lab (`/vuln`) and
against the secure variant (`/secure`) of the same endpoints, in
process, via `pytest`. Expected outcome per detector: at least one
CONFIRMED finding on `/vuln`, zero CONFIRMED findings on `/secure`.

Results are whatever `pytest -q` reports on this machine — see the
Phase 1 summary delivered with the code, not this file, for the
numbers from the last run. This is a lab evaluation, not a benchmark
against other tools; that comparison is listed as not yet done in
`docs/ROADMAP.md`.
