"""JWT / session-validation detector.

Deterministic, offline token checks against a ``/me``-style endpoint
(default ``{prefix}/me``). No secret is brute-forced and no signing key
is needed: the detector crafts tokens and observes the server.
- No token -> 200: CONFIRMED (authentication not enforced).
- ``alg=none`` token accepted (200): CONFIRMED.
- Tampered payload (valid structure, altered subject, original
  signature) accepted (200): CONFIRMED.
- Expired token accepted: SUSPECTED (depends on server clock policy;
  reported, not confirmed, unless the body shows the tampered subject).
- All rejected with 401: no finding.
Crafting helpers are in apistf.jwtutil (base64url, no crypto).
"""
from __future__ import annotations

import base64
import json

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def craft_jwt(header: dict, payload: dict, signature: str = "") -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    pl = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{pl}.{signature}"


class JwtDetector(Detector):
    name = "jwt"
    description = "JWT/session validation: missing, alg=none, tampered and expired tokens."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        me_path = prefix + p.get("me_path", "/me")
        victim = p.get("victim_subject", "alice")
        attacker = p.get("attacker_subject", "bob")
        findings: list[Finding] = []

        async def get_me(token: str | None):
            headers = {} if token is None else {"Authorization": f"Bearer {token}"}
            return await ctx.client.request("GET", me_path, headers=headers)

        # 1. No token at all.
        resp, ev = await get_me(None)
        if resp.status_code == 200:
            findings.append(Finding(
                detector=self.name, title="Missing token accepted on authenticated endpoint",
                severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                description=f"GET {me_path} without any Authorization header returned 200. "
                            "Authentication is not enforced on this endpoint.",
                endpoint=me_path, evidence=[ev],
                reproduction=[f"GET {me_path} with no Authorization header -> 200."],
                confidence="high",
            ))
            return findings  # if auth is absent entirely, token checks are moot

        # Valid token for the attacker, used as the base for tampering.
        # The lab issues tokens of the form "token-<subject>"; for JWT
        # endpoints the attacker token is a real HS256 token issued by
        # the lab helper in tests. Here we craft from the supplied
        # ``valid_token`` param when present.
        valid = p.get("valid_token", "")
        if not valid:
            return findings

        # 2. alg=none.
        none_token = craft_jwt({"alg": "none", "typ": "JWT"},
                               {"sub": victim, "role": "admin"})
        resp, ev = await get_me(none_token)
        if resp.status_code == 200:
            findings.append(Finding(
                detector=self.name, title="JWT alg=none token accepted",
                severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                description="A token with header alg=none and no signature was accepted "
                            f"as {victim}. Signature verification is missing or bypassable.",
                endpoint=me_path, evidence=[ev],
                reproduction=["GET /me with Authorization: Bearer <alg=none token for victim> -> 200."],
                confidence="high",
            ))

        # 3. Tampered payload: take the valid token, change sub, keep signature.
        try:
            parts = valid.split(".")
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            payload["sub"] = victim
            tampered = f"{parts[0]}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}.{parts[2]}"
        except Exception:
            tampered = ""
        if tampered:
            resp, ev = await get_me(tampered)
            if resp.status_code == 200:
                body = resp.text
                findings.append(Finding(
                    detector=self.name, title="Tampered JWT payload accepted",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="A token whose payload was altered after signing "
                                f"(sub changed to {victim}) was accepted. The signature "
                                "is not verified against the payload.",
                    endpoint=me_path, evidence=[ev],
                    reproduction=["Take a valid token, change sub in the payload, keep the original signature, GET /me -> 200."],
                    confidence="high",
                ))

        # 4. Expired token.
        expired = craft_jwt({"alg": "HS256", "typ": "JWT"},
                            {"sub": attacker, "exp": 1000000000}, "invalidsignature")
        resp, ev = await get_me(expired)
        if resp.status_code == 200:
            findings.append(Finding(
                detector=self.name, title="Expired JWT accepted",
                severity=Severity.MEDIUM, status=FindingStatus.SUSPECTED,
                description="A token with exp in the past was accepted. Expiry may not "
                            "be enforced; confirm against server clock before treating as confirmed.",
                endpoint=me_path, evidence=[ev], confidence="low",
            ))
        return findings
