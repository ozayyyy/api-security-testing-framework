# Detector documentation

Every detector is a deterministic rule over observed request/response
pairs. A `confirmed` finding requires a control request that behaved
differently from the attack request on the same endpoint. No detector
guesses from a single response, and none infers a vulnerability from
a dangerous-looking endpoint name alone.

Lab paths below use the `{prefix}` placeholder: `/vuln` for the
flawed variant, `/secure` for the corrected variant. The lab is
localhost only, with synthetic data.

## bola — cross-user object access

- Rule: fetch an object as its owner (control, expect 200 with the
  owner's data), then fetch the same object as a different
  authenticated user and unauthenticated.
- Confirmed: the other user (or anonymous caller) gets 200 with the
  identical object body as the owner.
- Suspected: 200 with a different body — it may be a filtered view;
  manual review is needed.
- No finding: 403/404 for the non-owner, 200 for the owner.
- Lab: `GET /objects/{id}`. In `/vuln` any authenticated user reads
  any object; in `/secure` only the owner (or admin) reads it.
- False-positive risk: low. A 200 with an identical body is a direct
  observation of missing object-level authorisation.
- False-negative risk: the detector only probes the configured
  object ids and identities; objects reachable only through other
  ids, or objects that return 404 instead of 403, are not probed.
- Limitation: it does not discover object ids on its own.

## bfla — low-privilege role on admin endpoints

- Rule: call each configured admin endpoint as the admin (control,
  expect 200) and as a low-privilege user.
- Confirmed: the low-privilege user gets 200/201 on an endpoint the
  admin control also returns 200 for.
- No finding: 401/403 for the low-privilege user.
- Lab: `GET /admin/users`. In `/vuln` any authenticated user lists
  users; in `/secure` only admin.
- False-positive risk: low, provided the endpoint really is
  admin-only. If an endpoint is intentionally readable by all
  authenticated users, configure it out of `admin_paths`.
- False-negative risk: admin endpoints not listed in `admin_paths`
  are never probed.
- Limitation: only GET endpoints are probed in the current
  implementation.

## jwt — token validation

- Rule: against a `/me`-style endpoint, try no token, an `alg=none`
  token, a tampered payload (subject changed, original signature
  kept), and an expired token.
- Confirmed: no token returns 200; `alg=none` returns 200; tampered
  payload returns 200.
- Suspected: expired token returns 200. The expired probe here uses
  a token with an invalid signature, so expiry enforcement cannot be
  separated from signature enforcement; see `session` for a
  confirmed expired-token probe using a properly signed token.
- No finding: all probes rejected with 401 (except the no-token
  probe, which is confirmed if it returns 200).
- Lab: `GET /me`. In `/vuln` the payload is decoded without
  verifying signature, algorithm or expiry; in `/secure` the HS256
  signature and expiry are verified.
- False-positive risk: low for `alg=none` and tampered payloads.
- False-negative risk: a server that accepts a different
  misconfiguration (for example, accepting a token signed with a
  public key as HMAC) is not probed.
- Limitation: no secret is brute-forced, and a correctly verified
  strong token cannot be shown to be unforgeable by this detector.

## mass_assignment — privileged fields through a normal update

- Rule: read the caller's own profile, PATCH it with a privileged
  field (`role=admin`, then `is_admin=true`), re-read the profile.
- Confirmed: the privileged field persisted on re-read.
- No finding: the field is ignored or rejected, or the re-read
  shows the original value.
- Lab: `PATCH /users/me`. In `/vuln` any field in the body is
  applied; in `/secure` only `email` is honoured.
- False-positive risk: low — persistence on re-read is observed,
  not assumed from the PATCH status alone.
- False-negative risk: privileged fields other than `role` and
  `is_admin`, or fields settable only through a different endpoint,
  are not probed.
- Limitation: the detector mutates the test identity's profile in
  the lab; run it against a reset lab, or the promotion persists
  into later detectors in the same run.

## excessive_data — sensitive fields in responses

- Rule: GET a user/object profile and inspect the returned JSON
  for fields that should never leave the server (`password_hash`,
  `ssn`, `secret`, `api_key`, and similar; configurable via
  `sensitive_fields`).
- Confirmed: a sensitive field is present with a non-empty value.
- Suspected: a sensitive field is present but empty/null — not
  currently reported as a separate finding; only non-empty values
  are reported.
- No finding: no listed sensitive field with a value in the response.
- Lab: `GET /users/{id}` and `GET /users/me`. In `/vuln` the full
  user record is returned; in `/secure` only id, username and role.
- False-positive risk: a field name that is sensitive in one
  application and public in another (for example, a public `secret`
  label). Review the field list per target.
- False-negative risk: sensitive data under a field name not in the
  list, or sensitive data in a non-JSON response, is not detected.
- Limitation: string/key matching only; it does not judge whether
  a returned value is actually sensitive in context.

## rate_limit — burst probe

- Rule: send `burst` requests (default 20) as fast as the client
  allows to a probe endpoint and count responses.
- Confirmed: every request returns 200/201 and none returns 429.
- Suspected: mixed statuses with no 429 — the server behaved
  inconsistently.
- No finding: at least one 429.
- Lab: `GET /rate-test`. In `/vuln` there is no limit; in `/secure`
  429 is returned after 5 requests.
- False-positive risk: a limit above the burst size is not
  detected, so a confirmed finding only means no limit was observed
  within the burst, not that no limit exists at all.
- False-negative risk: a limit that applies per-account or
  per-endpoint differently from the probe endpoint is not measured.
- Limitation: the probe is deliberately bursty; only run it
  against a target you are authorised to test, within the request
  budget.

## business_logic — invalid order state transitions

- Rule: the lab order workflow is draft -> paid -> shipped, with
  cancel from draft/paid and a single refund from paid/shipped.
  The detector first runs the valid sequence (create -> pay ->
  ship) as a control, then drives each invalid transition on a
  fresh order owned by the control identity and re-reads the order.
- Confirmed, one finding per violated transition:
  - pay a cancelled order: cancel returns 200, pay then returns
    200 and a re-read shows status `paid`.
  - refund the same order twice: both refund calls return 200 and
    a re-read shows `refunds` >= 2.
  - ship an unpaid order: ship on a draft returns 200 and a
    re-read shows status `shipped`.
  - change price/quantity after payment: PATCH returns 200 and a
    re-read shows the changed price and/or quantity.
- No finding: the invalid transition is rejected (4xx) or the
  re-read shows no change.
- Informational: the valid control sequence fails, so the workflow
  itself does not work and invalid transitions cannot be judged.
- Lab: `POST /orders`, `GET/PATCH /orders/{id}`,
  `POST /orders/{id}/pay|ship|cancel|refund`. In `/vuln` any
  transition is allowed from any status and refunds are unlimited;
  in `/secure` only the intended transitions are allowed and a
  refund is allowed once.
- False-positive risk: low — each finding is a state change
  observed on re-read, not a single status code.
- False-negative risk: transitions not in the four probes, or a
  workflow with different intended states, are not covered.
- Limitation: coverage is the order workflow in the lab only;
  other workflows need their own detector parameters. The detector
  creates orders, so it mutates lab state; run it against a reset
  lab.

## inconsistent_authz — two paths, one resource

- Rule: two paths expose the same resource — `GET /users/{id}`
  and `GET /profile/{id}` in the lab. Fetch both as the target's
  owner (control: both should allow) and as a different
  authenticated user.
- Confirmed: one path allows the non-owner (200) and the other
  denies them (401/403), while the owner is allowed on both.
- No finding: both paths agree — both allow with the same body, or
  both deny.
- Informational: the owner is denied on either path; the control
  failed, so the two paths cannot be compared.
- Lab: in `/vuln`, `/users/{id}` checks nothing while
  `/profile/{id}` checks ownership; in `/secure` both paths return
  the same public view to any authenticated caller.
- False-positive risk: low when the two paths really expose the
  same resource. If the paths intentionally expose different views
  (for example, a public profile vs a private record), the
  difference is intended, not a finding — check the target's
  intended behaviour before treating it as confirmed.
- False-negative risk: only the configured pair of paths is
  compared; other alternate paths to the same resource are not
  probed.
- Limitation: the detector compares access decisions, not response
  bodies. Two paths that both allow but return different data are
  not flagged; use `excessive_data` for that.

## session — revoked and expired tokens

- Rule: obtain properly signed JWTs from the lab's test-only
  issuer (`POST /_lab/issue-jwt`), then observe the server.
- Confirmed, one finding per violated check:
  - revoked token still accepted: issue a token, revoke it via
    `POST /_lab/revoke`, present it on `/me` and get 200.
  - revoked token can be refreshed: the revoked token is
    exchanged for a fresh token via `/auth/refresh` (200 with a
    new token).
  - expired token still accepted: a properly signed token with
    `exp` one hour in the past is accepted on `/me` (200).
- No finding: all three probes are rejected with 401.
- Informational: the issuer is absent (not the lab), or a freshly
  issued token is rejected before revocation — the control failed.
- Lab: `/me`, `/auth/refresh`, `/_lab/issue-jwt` (accepts an
  optional `exp`), `/_lab/revoke`. In `/vuln`, revocation and
  expiry are ignored, including at refresh; in `/secure`, revoked
  and expired tokens are rejected everywhere, including refresh.
- False-positive risk: low — each finding uses a token issued by
  the lab itself, correctly signed, with revocation/expiry applied
  through the lab's own endpoints.
- False-negative risk: revocation/expiry handling on endpoints
  other than `/me` and `/auth/refresh` is not probed.
- Limitation: the detector needs the lab's test-only issuer; on a
  target without it, it reports inconclusive instead of a finding.
  It probes JWTs only, not opaque-token revocation, so that
  revoking a token cannot break the shared test identities used by
  other detectors in the same run.

## graphql_introspection — schema disclosure via introspection

- Rule: POST a standard introspection query (`{ __schema { types { name } } }`)
  to `{prefix}/graphql`.
- Confirmed: HTTP 200 with `data.__schema.types` a non-empty list — the
  server hands out its full schema (every type, field and argument).
- No finding: the response has no `data.__schema` (introspection
  disabled or rejected).
- Lab: `POST /graphql`. In `/vuln` introspection is answered in full;
  in `/secure` it returns an `introspection is disabled` error.
- False-positive risk: low — a returned schema is a direct observation.
  Whether exposing it matters depends on the target: on an internal
  API it may be intended; on a public API it hands an attacker the
  full surface to probe.
- False-negative risk: a server that answers introspection only for
  authenticated callers with a different identity than the probe
  identity is not covered; the detector uses the configured identity.
- Limitation: the detector reports that introspection is on, not
  what an attacker can do with the schema — that is the job of the
  other GraphQL detectors and of manual review.

## graphql_depth — missing query-depth limit

- Rule: build a nested query from the schema (a root field, then the
  same self-referential field again and again) and send it at depth
  12. The control is the same shape at depth 2, which must return data.
- Confirmed: the depth-12 query returns 200 with data and no errors
  while the depth-2 control also returns data — the server enforces
  no depth limit.
- No finding: the deep query is rejected (errors, no data) while the
  control works.
- Informational: the control fails, no schema is available, or the
  schema has no self-referential path to nest through.
- Lab: `POST /graphql`, nesting `user { friends { friends ... } }`.
  In `/vuln` any depth executes; in `/secure` depth above 5 is
  rejected with an error. Depth counts every field level down to the
  deepest leaf (a root field selecting scalars is depth 2).
- False-positive risk: low — the deep query demonstrably executed.
  A depth limit above 12 would not be detected.
- False-negative risk: a server that limits depth only for some
  operations, or that limits by a different measure (for example,
  counting only object fields), may pass this probe while still
  allowing expensive queries.
- Limitation: needs a schema (supplied with `--graphql-schema`, or
  fetched by introspection when introspection is on). Without a
  schema the detector reports inconclusive instead of a finding.

## graphql_batching — missing batch limit

- Rule: send one request whose body is a JSON array of 10 copies of
  a minimal query. The control is the same query sent on its own,
  which must return data.
- Confirmed: the response is a list of 10 data-bearing results — the
  server executes a whole batch in one request.
- No finding: the batch is rejected (400 or errors) while the single
  query works.
- Informational: the control fails or no schema is available.
- Lab: `POST /graphql`. In `/vuln` a 10-query batch returns 10
  results; in `/secure` the request is rejected with 400.
- False-positive risk: low — 10 executed queries in one response is
  a direct observation. A batch limit above 10 would not be detected.
- False-negative risk: a server that allows batching only up to a
  limit above the probe size, or that batches only for some
  operations, is not caught.
- Limitation: the probe batch is deliberately 10 queries; only run
  it against a target you are authorised to test, within the request
  budget.

## graphql_alias_abuse — missing alias limit (field duplication)

- Rule: send one query repeating the same root field under 20
  different aliases (`a1: user(id: 1) { ... }`, ... `a20: ...`).
  The control is the same field sent once, without aliases.
- Confirmed: the response is 200 with data for all 20 aliases — the
  server executes the same field 20 times in one request.
- No finding: the aliased query is rejected (errors, no data) while
  the control works.
- Informational: the control fails or no schema is available.
- Lab: `POST /graphql`. In `/vuln` all 20 aliases return data; in
  `/secure` more than 5 aliases in one operation is rejected.
- False-positive risk: low — data for all 20 aliases is observed,
  not assumed. An alias limit above 20 would not be detected.
- False-negative risk: a server that limits aliases only for some
  fields, or that deduplicates identical aliased fields, is not caught.
- Limitation: needs a schema, as with the depth detector. Alias
  counting is per operation; aliases spread across a batch are a
  batching concern, not this detector's.
