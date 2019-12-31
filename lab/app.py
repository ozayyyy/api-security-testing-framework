"""Deliberately vulnerable lab API + secure variants.

Run:  uvicorn lab.app:app --host 127.0.0.1 --port 8000
Localhost only. Synthetic data only. This lab exists so detectors can
be tested against known flaws; it is not a production service and must
never be exposed publicly.

Two routers share the same seeded data:
  /vuln/...   — flawed authorisation / validation (each flaw is labelled)
  /secure/... — the corrected implementation of the same endpoints

Identities (opaque bearer tokens):
  alice  token-alice  (user, owns object 1)
  bob    token-bob    (user, owns object 2)
  admin  token-admin  (admin)

JWT tokens are also accepted on /me: HS256 signed with secret
"lab-secret-only" (see issue_jwt). The vulnerable variant accepts
alg=none and tampered payloads; the secure variant verifies the
signature and expiry.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import time
import uuid
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

SECRET = "lab-secret-only"

USERS_SEED = {
    1: {"id": 1, "username": "alice", "role": "user", "email": "alice@example.test",
        "password_hash": "sha256:deadbeef-alice", "ssn": "111-22-3333"},
    2: {"id": 2, "username": "bob", "role": "user", "email": "bob@example.test",
        "password_hash": "sha256:deadbeef-bob", "ssn": "222-33-4444"},
    3: {"id": 3, "username": "admin", "role": "admin", "email": "admin@example.test",
        "password_hash": "sha256:deadbeef-admin", "ssn": "333-44-5555"},
}
OBJECTS_SEED = {
    1: {"id": 1, "owner_id": 1, "title": "alice-note", "content": "alice private content"},
    2: {"id": 2, "owner_id": 2, "title": "bob-note", "content": "bob private content"},
}
OPAQUE_TOKENS = {"token-alice": 1, "token-bob": 2, "token-admin": 3}

USERS: dict = copy.deepcopy(USERS_SEED)
OBJECTS: dict = copy.deepcopy(OBJECTS_SEED)
RATE_COUNTER = {"vuln": 0, "secure": 0}
# Orders: id -> {id, owner_id, status, price, quantity, refunds}.
# Status machine (intended): draft -> paid -> shipped, draft/paid ->
# cancelled, paid/shipped -> refunded (once). The /vuln variant ignores
# the machine; /secure enforces it (see _register).
ORDERS: dict = {}
_NEXT_ORDER_ID = [1]
# Exact token strings revoked via POST /_lab/revoke. The /secure
# variant rejects them; /vuln ignores revocation.
REVOKED_TOKENS: set = set()


def reset_lab() -> None:
    global USERS, OBJECTS
    USERS = copy.deepcopy(USERS_SEED)
    OBJECTS = copy.deepcopy(OBJECTS_SEED)
    RATE_COUNTER.update({"vuln": 0, "secure": 0})
    ORDERS.clear()
    _NEXT_ORDER_ID[0] = 1
    REVOKED_TOKENS.clear()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def issue_jwt(sub: str, role: str = "user", exp: int | None = None) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    # jti makes every issued token unique, so revoking one token in a
    # test never revokes a different token for the same subject.
    payload = {"sub": sub, "role": role, "exp": exp or int(time.time()) + 3600,
               "jti": uuid.uuid4().hex}
    payload_b = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET.encode(), f"{header}.{payload_b}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload_b}.{_b64url(sig)}"


def _decode_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    raw = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(raw))


def _verify_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    if header.get("alg") != "HS256":
        raise ValueError("unexpected alg")
    expected = hmac.new(SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url(expected), parts[2]):
        raise ValueError("bad signature")
    payload = _decode_payload(token)
    if payload.get("exp", 0) < int(time.time()):
        raise ValueError("expired")
    return payload


def _user_from_token(authorization: str | None, *, secure: bool) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization[len("Bearer "):]
    if token in REVOKED_TOKENS and secure:
        raise HTTPException(status_code=401, detail="token revoked")
    if token in OPAQUE_TOKENS:
        return USERS[OPAQUE_TOKENS[token]]
    if token.count(".") == 2:
        if secure:
            try:
                payload = _verify_jwt(token)
            except ValueError as e:
                raise HTTPException(status_code=401, detail=str(e))
            user = next((u for u in USERS.values() if u["username"] == payload.get("sub")), None)
            if user is None:
                raise HTTPException(status_code=401, detail="unknown subject")
            return user
        # VULN: decode payload without verifying signature, alg or expiry.
        try:
            payload = _decode_payload(token)
        except Exception:
            raise HTTPException(status_code=401, detail="bad token")
        user = next((u for u in USERS.values() if u["username"] == payload.get("sub")), None)
        if user is None:
            raise HTTPException(status_code=401, detail="unknown subject")
        return user
    raise HTTPException(status_code=401, detail="bad token")


def _public_user(u: dict) -> dict:
    return {"id": u["id"], "username": u["username"], "role": u["role"]}


app = FastAPI(title="API Security Testing Lab", version="0.1.0")


@app.post("/_lab/reset")
def lab_reset():
    reset_lab()
    return {"ok": True}


@app.post("/_lab/issue-jwt")
def lab_issue_jwt(body: dict):
    """Test-only token issuer so the JWT detector has a valid token to
    tamper with. Localhost lab only; never present on a real target.
    Accepts an optional ``exp`` (unix time) so the session detector can
    obtain a properly signed but expired token."""
    sub = str(body.get("sub", "bob"))
    role = str(body.get("role", "user"))
    exp = body.get("exp")
    return {"token": issue_jwt(sub, role, exp=int(exp) if exp is not None else None)}


@app.post("/_lab/revoke")
def lab_revoke(body: dict):
    """Test-only revocation. The token string is recorded; /secure
    rejects it afterwards, /vuln ignores revocation."""
    token = str(body.get("token", ""))
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    REVOKED_TOKENS.add(token)
    return {"ok": True}


def _register(prefix: str, *, secure: bool):
    tag = "secure" if secure else "vuln"

    @app.get(f"{prefix}/objects/{{object_id}}", tags=[tag])
    def get_object(object_id: int, authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        obj = OBJECTS.get(object_id)
        if obj is None:
            raise HTTPException(status_code=404, detail="not found")
        if secure and obj["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="not your object")
        return obj

    @app.get(f"{prefix}/admin/users", tags=[tag])
    def admin_users(authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        if secure and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="admin only")
        return [_public_user(u) for u in USERS.values()]

    @app.get(f"{prefix}/me", tags=[tag])
    def me(authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        return _public_user(user)

    @app.get(f"{prefix}/users/me", tags=[tag])
    def get_me(authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        return user if not secure else _public_user(user)

    @app.patch(f"{prefix}/users/me", tags=[tag])
    async def patch_me(request: Request, authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        body = await request.json()
        if secure:
            # Only non-privileged fields are honoured.
            if "email" in body:
                user["email"] = body["email"]
        else:
            # VULN: any field, including role / is_admin, is applied.
            for k, v in body.items():
                user[k] = v
        return user if not secure else _public_user(user)

    @app.get(f"{prefix}/users/{{user_id}}", tags=[tag])
    def get_user(user_id: int, authorization: str | None = Header(default=None)):
        _user_from_token(authorization, secure=secure)
        user = USERS.get(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="not found")
        return user if not secure else _public_user(user)

    @app.post(f"{prefix}/orders", tags=[tag])
    def create_order(request_body: dict, authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        oid = _NEXT_ORDER_ID[0]
        _NEXT_ORDER_ID[0] += 1
        order = {"id": oid, "owner_id": user["id"], "status": "draft",
                 "price": request_body.get("price", 100),
                 "quantity": request_body.get("quantity", 1), "refunds": 0}
        ORDERS[oid] = order
        return dict(order)

    @app.get(f"{prefix}/orders/{{order_id}}", tags=[tag])
    def get_order(order_id: int, authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        order = ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="not found")
        if order["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="not your order")
        return dict(order)

    @app.patch(f"{prefix}/orders/{{order_id}}", tags=[tag])
    async def patch_order(order_id: int, request: Request, authorization: str | None = Header(default=None)):
        user = _user_from_token(authorization, secure=secure)
        order = ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="not found")
        if order["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="not your order")
        body = await request.json()
        if secure and order["status"] != "draft":
            raise HTTPException(status_code=409, detail="order can only be changed while draft")
        # VULN: price/quantity can be changed at any point, including
        # after payment. Secure: only while draft (enforced above).
        if "price" in body:
            order["price"] = body["price"]
        if "quantity" in body:
            order["quantity"] = body["quantity"]
        return dict(order)

    def _transition(order_id: int, user: dict, action: str) -> dict:
        order = ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="not found")
        if order["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="not your order")
        if secure:
            allowed = {
                "pay": {"draft"},
                "ship": {"paid"},
                "cancel": {"draft", "paid"},
                "refund": {"paid", "shipped"},
            }[action]
            if order["status"] not in allowed:
                raise HTTPException(status_code=409, detail=f"cannot {action} an order in status {order['status']}")
            if action == "refund" and order["refunds"] >= 1:
                raise HTTPException(status_code=409, detail="order already refunded")
        # VULN: any transition from any status, refunds unlimited.
        if action == "pay":
            order["status"] = "paid"
        elif action == "ship":
            order["status"] = "shipped"
        elif action == "cancel":
            order["status"] = "cancelled"
        elif action == "refund":
            order["status"] = "refunded"
            order["refunds"] += 1
        return dict(order)

    @app.post(f"{prefix}/orders/{{order_id}}/pay", tags=[tag])
    def pay_order(order_id: int, authorization: str | None = Header(default=None)):
        return _transition(order_id, _user_from_token(authorization, secure=secure), "pay")

    @app.post(f"{prefix}/orders/{{order_id}}/ship", tags=[tag])
    def ship_order(order_id: int, authorization: str | None = Header(default=None)):
        return _transition(order_id, _user_from_token(authorization, secure=secure), "ship")

    @app.post(f"{prefix}/orders/{{order_id}}/cancel", tags=[tag])
    def cancel_order(order_id: int, authorization: str | None = Header(default=None)):
        return _transition(order_id, _user_from_token(authorization, secure=secure), "cancel")

    @app.post(f"{prefix}/orders/{{order_id}}/refund", tags=[tag])
    def refund_order(order_id: int, authorization: str | None = Header(default=None)):
        return _transition(order_id, _user_from_token(authorization, secure=secure), "refund")

    @app.get(f"{prefix}/profile/{{user_id}}", tags=[tag])
    def get_profile(user_id: int, authorization: str | None = Header(default=None)):
        """Second path to the same user resource as GET /users/{id}.
        VULN: ownership-checked (403 for a non-owner) while /users/{id}
        is not checked at all — inconsistent authorisation.
        SECURE: same public view as /users/{id} for any authenticated
        caller, so both paths agree."""
        user = _user_from_token(authorization, secure=secure)
        target = USERS.get(user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="not found")
        if not secure and target["id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="not your profile")
        return target if not secure else _public_user(target)

    @app.post(f"{prefix}/auth/refresh", tags=[tag])
    def refresh_token(body: dict, authorization: str | None = Header(default=None)):
        """Exchange a JWT for a fresh one. SECURE: the presented token
        must be valid, unexpired and unrevoked. VULN: any JWT-shaped
        token is refreshed, including revoked and expired ones."""
        token = str(body.get("token", ""))
        if not token:
            raise HTTPException(status_code=400, detail="token required")
        if secure:
            if token in REVOKED_TOKENS:
                raise HTTPException(status_code=401, detail="token revoked")
            try:
                payload = _verify_jwt(token)
            except ValueError as e:
                raise HTTPException(status_code=401, detail=str(e))
            return {"token": issue_jwt(str(payload.get("sub")), str(payload.get("role", "user")))}
        try:
            payload = _decode_payload(token)
        except Exception:
            raise HTTPException(status_code=401, detail="bad token")
        return {"token": issue_jwt(str(payload.get("sub")), str(payload.get("role", "user")))}

    @app.get(f"{prefix}/rate-test", tags=[tag])
    def rate_test(authorization: str | None = Header(default=None)):
        _user_from_token(authorization, secure=secure)
        if secure:
            RATE_COUNTER["secure"] += 1
            if RATE_COUNTER["secure"] > 5:
                return JSONResponse(status_code=429, content={"detail": "rate limited"})
        else:
            RATE_COUNTER["vuln"] += 1
        return {"ok": True}


_register("/vuln", secure=False)
_register("/secure", secure=True)
