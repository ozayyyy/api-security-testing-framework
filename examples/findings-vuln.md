# API Security Findings

Total findings: 17
Confirmed: 16 | Suspected: 1 | Informational: 0

## BOLA: other user can read another user's object

- Detector: `bola`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/objects/{id}`

other user (bob) received HTTP 200 with the same object body as owner alice for object 1. Object-level authorisation is not enforced.

### Reproduction

- 1. As alice, GET /vuln/objects/1 -> 200 (control).
- 2. As other user, GET /vuln/objects/1 -> 200, identical body.

### Evidence: GET http://127.0.0.1:8000/vuln/objects/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "owner_id": 1, "title": "alice-note", "content": "alice private content"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/objects/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "owner_id": 1, "title": "alice-note", "content": "alice private content"}
```

## BFLA: low-privilege user can call admin endpoint /admin/users

- Detector: `bfla`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/admin/users`

Identity alice (role user) received 200 on /admin/users, which the admin control also returns 200 for. Function-level authorisation is not enforced.

### Reproduction

- 1. As admin, GET /vuln/admin/users -> 200 (control).
- 2. As alice (user), GET /vuln/admin/users -> 200.

### Evidence: GET http://127.0.0.1:8000/vuln/admin/users -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: [{"id": 1, "username": "alice", "role": "user"}, {"id": 2, "username": "bob", "role": "user"}, {"id": 3, "username": "admin", "role": "admin"}]
```

### Evidence: GET http://127.0.0.1:8000/vuln/admin/users -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: [{"id": 1, "username": "alice", "role": "user"}, {"id": 2, "username": "bob", "role": "user"}, {"id": 3, "username": "admin", "role": "admin"}]
```

## JWT alg=none token accepted

- Detector: `jwt`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/me`

A token with header alg=none and no signature was accepted as alice. Signature verification is missing or bypassable.

### Reproduction

- GET /me with Authorization: Bearer <alg=none token for victim> -> 200.

### Evidence: GET http://127.0.0.1:8000/vuln/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "user"}
```

## Tampered JWT payload accepted

- Detector: `jwt`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/me`

A token whose payload was altered after signing (sub changed to alice) was accepted. The signature is not verified against the payload.

### Reproduction

- Take a valid token, change sub in the payload, keep the original signature, GET /me -> 200.

### Evidence: GET http://127.0.0.1:8000/vuln/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "user"}
```

## Expired JWT accepted

- Detector: `jwt`
- Severity: medium | Status: suspected | Confidence: low
- Endpoint: `/vuln/me`

A token with exp in the past was accepted. Expiry may not be enforced; confirm against server clock before treating as confirmed.

### Evidence: GET http://127.0.0.1:8000/vuln/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "username": "bob", "role": "user"}
```

## Mass assignment: role can be set through profile update

- Detector: `mass_assignment`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/users/me`

PATCH /vuln/users/me with {"role": 'admin'} persisted: a re-read shows role='admin'. A normal user can escalate their own privileges.

### Reproduction

- 1. GET /vuln/users/me as alice -> role='user'.
- 2. PATCH /vuln/users/me with {"role": 'admin'} -> 200.
- 3. GET /vuln/users/me -> role='admin'.

### Evidence: GET http://127.0.0.1:8000/vuln/users/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "user", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

### Evidence: PATCH http://127.0.0.1:8000/vuln/users/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"role": "admin"}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/users/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

## Excessive data exposure: sensitive fields in /users/1

- Detector: `excessive_data`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/users/1`

GET /vuln/users/1 returned sensitive field(s) ['password_hash', 'ssn'] with values. These fields should never be sent to a client.

### Reproduction

- GET /vuln/users/1 as alice -> 200, response contains ['password_hash', 'ssn'].

### Evidence: GET http://127.0.0.1:8000/vuln/users/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

## Excessive data exposure: sensitive fields in /users/me

- Detector: `excessive_data`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/users/me`

GET /vuln/users/me returned sensitive field(s) ['password_hash', 'ssn'] with values. These fields should never be sent to a client.

### Reproduction

- GET /vuln/users/me as alice -> 200, response contains ['password_hash', 'ssn'].

### Evidence: GET http://127.0.0.1:8000/vuln/users/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

## No rate limiting observed on /vuln/rate-test

- Detector: `rate_limit`
- Severity: medium | Status: confirmed | Confidence: medium
- Endpoint: `/vuln/rate-test`

20 rapid requests to /vuln/rate-test all returned 200/201 and none returned 429. The endpoint does not appear to enforce rate limiting (confirmed for this probe; a limit above the burst size would not be detected).

### Reproduction

- Send 20 rapid GET /vuln/rate-test requests as alice; all return 200, none 429.

### Evidence: GET http://127.0.0.1:8000/vuln/rate-test -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"ok": true}
```

### Evidence: GET http://127.0.0.1:8000/vuln/rate-test -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"ok": true}
```

### Evidence: GET http://127.0.0.1:8000/vuln/rate-test -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"ok": true}
```

## Business logic: pay a cancelled order

- Detector: `business_logic`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/orders`

A cancelled order can be paid: cancel returned 200, pay then returned 200 and a re-read shows status=paid. A cancelled order can be paid, so money can be taken for an order the customer cancelled.

### Reproduction

- 1. POST /orders -> draft order.
- 2. POST /orders/{id}/cancel -> 200.
- 3. POST /orders/{id}/pay -> 200, re-read shows status=paid.

### Evidence: POST http://127.0.0.1:8000/vuln/orders -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"price": 100, "quantity": 1}
Response body: {"id": 2, "owner_id": 1, "status": "draft", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/2/cancel -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "owner_id": 1, "status": "cancelled", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/2/pay -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "owner_id": 1, "status": "paid", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: GET http://127.0.0.1:8000/vuln/orders/2 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "owner_id": 1, "status": "paid", "price": 100, "quantity": 1, "refunds": 0}
```

## Business logic: refund the same order twice

- Detector: `business_logic`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/orders`

The same order refunded twice: both refund calls returned 200 and a re-read shows refunds=2. The same order can be refunded twice, so the seller pays out twice for one purchase.

### Reproduction

- 1. POST /orders, POST /orders/{id}/pay -> paid.
- 2. POST /orders/{id}/refund -> 200.
- 3. POST /orders/{id}/refund again -> 200, re-read shows refunds>=2.

### Evidence: POST http://127.0.0.1:8000/vuln/orders -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"price": 100, "quantity": 1}
Response body: {"id": 3, "owner_id": 1, "status": "draft", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/3/pay -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 3, "owner_id": 1, "status": "paid", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/3/refund -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 3, "owner_id": 1, "status": "refunded", "price": 100, "quantity": 1, "refunds": 1}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/3/refund -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 3, "owner_id": 1, "status": "refunded", "price": 100, "quantity": 1, "refunds": 2}
```

### Evidence: GET http://127.0.0.1:8000/vuln/orders/3 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 3, "owner_id": 1, "status": "refunded", "price": 100, "quantity": 1, "refunds": 2}
```

## Business logic: ship an unpaid order

- Detector: `business_logic`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/orders`

A draft (unpaid) order can be shipped: ship returned 200 and a re-read shows status=shipped. An unpaid order can be shipped, so goods leave without payment.

### Reproduction

- 1. POST /orders -> draft order.
- 2. POST /orders/{id}/ship -> 200, re-read shows status=shipped.

### Evidence: POST http://127.0.0.1:8000/vuln/orders -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"price": 100, "quantity": 1}
Response body: {"id": 4, "owner_id": 1, "status": "draft", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/4/ship -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 4, "owner_id": 1, "status": "shipped", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: GET http://127.0.0.1:8000/vuln/orders/4 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 4, "owner_id": 1, "status": "shipped", "price": 100, "quantity": 1, "refunds": 0}
```

## Business logic: change price/quantity after payment

- Detector: `business_logic`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/orders`

Price/quantity can be changed after payment: PATCH returned 200 and a re-read shows price=999, quantity=99. Price or quantity can be changed after payment, so the amount charged and the amount shipped disagree.

### Reproduction

- 1. POST /orders, POST /orders/{id}/pay -> paid.
- 2. PATCH /orders/{id} with price=999, quantity=99 -> 200.
- 3. GET /orders/{id} -> price=999 and/or quantity=99.

### Evidence: POST http://127.0.0.1:8000/vuln/orders -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"price": 100, "quantity": 1}
Response body: {"id": 5, "owner_id": 1, "status": "draft", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: POST http://127.0.0.1:8000/vuln/orders/5/pay -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 5, "owner_id": 1, "status": "paid", "price": 100, "quantity": 1, "refunds": 0}
```

### Evidence: PATCH http://127.0.0.1:8000/vuln/orders/5 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Request body: {"price": 999, "quantity": 99}
Response body: {"id": 5, "owner_id": 1, "status": "paid", "price": 999, "quantity": 99, "refunds": 0}
```

### Evidence: GET http://127.0.0.1:8000/vuln/orders/5 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 5, "owner_id": 1, "status": "paid", "price": 999, "quantity": 99, "refunds": 0}
```

## Inconsistent authorisation: /vuln/users/1 allows what /vuln/profile/1 denies

- Detector: `inconsistent_authz`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/users/1`

For user 1, bob (not the owner) received 200 on /vuln/users/1 but 403 on /vuln/profile/1, while the owner is allowed on both. The same resource is protected on one path and not the other.

### Reproduction

- 1. As alice (owner), GET /vuln/users/1 -> 200 and GET /vuln/profile/1 -> 200 (control).
- 2. As bob, GET /vuln/users/1 -> 200, GET /vuln/profile/1 -> 403.

### Evidence: GET http://127.0.0.1:8000/vuln/users/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/profile/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/users/1 -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 1, "username": "alice", "role": "admin", "email": "alice@example.test", "password_hash": "[REDACTED]", "ssn": "[REDACTED]"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/profile/1 -> 403

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"detail": "not your profile"}
```

## Revoked token still accepted

- Detector: `session`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/me`

A token revoked via POST /_lab/revoke was still accepted on /vuln/me (200). Revocation is not enforced.

### Reproduction

- 1. POST /_lab/issue-jwt -> token.
- 2. POST /_lab/revoke with that token -> 200.
- 3. GET /vuln/me with the revoked token -> 200.

### Evidence: POST http://127.0.0.1:8000/_lab/issue-jwt -> 200

```
Request headers: {}
Request body: {"sub": "bob"}
Response body: {"token": "[REDACTED]"}
```

### Evidence: POST http://127.0.0.1:8000/_lab/revoke -> 200

```
Request headers: {}
Request body: {"token": "[REDACTED]"}
Response body: {"ok": true}
```

### Evidence: GET http://127.0.0.1:8000/vuln/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "username": "bob", "role": "user"}
```

## Revoked token can be refreshed

- Detector: `session`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/auth/refresh`

A revoked token could be exchanged for a fresh token via /vuln/auth/refresh (200). Revocation is bypassed by refresh.

### Reproduction

- 1. POST /_lab/issue-jwt -> token; POST /_lab/revoke with it -> 200.
- 2. POST /vuln/auth/refresh with the revoked token -> 200, new token returned.

### Evidence: POST http://127.0.0.1:8000/_lab/issue-jwt -> 200

```
Request headers: {}
Request body: {"sub": "bob"}
Response body: {"token": "[REDACTED]"}
```

### Evidence: POST http://127.0.0.1:8000/_lab/revoke -> 200

```
Request headers: {}
Request body: {"token": "[REDACTED]"}
Response body: {"ok": true}
```

### Evidence: POST http://127.0.0.1:8000/vuln/auth/refresh -> 200

```
Request headers: {}
Request body: {"token": "[REDACTED]"}
Response body: {"token": "[REDACTED]"}
```

## Expired token still accepted

- Detector: `session`
- Severity: high | Status: confirmed | Confidence: high
- Endpoint: `/vuln/me`

A properly signed token with exp one hour in the past was accepted on /vuln/me (200). Token expiry is not enforced.

### Reproduction

- 1. POST /_lab/issue-jwt with exp in the past -> token.
- 2. GET /vuln/me with that token -> 200.

### Evidence: POST http://127.0.0.1:8000/_lab/issue-jwt -> 200

```
Request headers: {}
Request body: {"sub": "bob", "exp": 1795474984}
Response body: {"token": "[REDACTED]"}
```

### Evidence: GET http://127.0.0.1:8000/vuln/me -> 200

```
Request headers: {'Authorization': '[REDACTED]'}
Response body: {"id": 2, "username": "bob", "role": "user"}
```
