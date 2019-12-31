# Juice Shop run — BLOCKED, no run took place

Status: **blocked**. No Juice Shop instance ran in this environment,
no scan ran against it, and there are no findings to report. Nothing
in this file is a scan result.

## What was tried

1. **Docker** (first choice). Docker is installed
   (`/usr/bin/docker`, `docker.service` present) but the daemon
   cannot start here. `sudo systemctl start docker` fails, and
   running `dockerd` directly fails with:
   > `failed to start daemon: Error initializing network controller:
   > error obtaining controller instance: failed to register "bridge"
   > driver: failed to create NAT chain DOCKER: iptables failed:
   > iptables --wait -t nat -N DOCKER: iptables v1.8.10 (nf_tables):
   > Could not fetch rule set generation id: Permission denied (you
   > must be root)`
   The environment does not grant the privileges Docker needs to set
   up its iptables NAT rules, so no container can run.
2. **npm** (fallback). There is no runnable Juice Shop package on
   the npm registry:
   - `npm install juice-shop` fails: `404 Unpublished on
     2019-01-15T20:53:27.314Z` — `'juice-shop' is not in this
     registry.` (the package was unpublished in 2019).
   - `npm view @juice-shop/juice-shop version` fails: `404 Not Found`.
   - `npm search juice-shop` returns only CTF tooling
     (`juice-shop-ctf-cli`) and unrelated packages — no runnable
     Juice Shop package.
3. **On disk.** A search of the home directory, `/tmp` and `/opt`
   found no Juice Shop copy (only an unrelated `orange-juice.webp`
   icon).

## What was deliberately not tried

The remaining distribution channel is GitHub (releases/source).
That was not used: the task's fallback was Docker, else npm, and
new GitHub fetches are stopped by the user's standing rule
(2026-11-23). Downloading a release archive would have needed
that rule to be lifted first.

## What is ready for a run when an instance exists

The GraphQL detectors were built to work against a real target
without a supplied schema: when no `--graphql-schema` is given,
the depth, batching and alias detectors fetch the schema by
introspection first (introspection is on in Juice Shop by default),
and the introspection detector reports it directly. The planned
run, once Juice Shop is reachable on localhost:

```bash
.venv/bin/apistf --target http://127.0.0.1:3000 \
  --detectors graphql_introspection,graphql_depth,graphql_batching,graphql_alias_abuse \
  --report examples/juice-shop-report.json
```

plus a rate-limit probe against a public read endpoint
(`--detectors rate_limit`, probe path `/rest/products/search`).
The REST detectors that need the lab's identities and object
mapping (bola, bfla, jwt, mass assignment, business logic,
session) do not apply to Juice Shop and are not part of the plan.
