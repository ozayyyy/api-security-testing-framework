"""Session-lifecycle detector: revoked and expired tokens.

Rule: obtain properly signed JWTs from the lab's test-only issuer
(``POST /_lab/issue-jwt``; absent on real targets, where the
detector returns no findings), then observe the server:
- Revoked token still accepted on ``/me`` (200)            -> CONFIRMED
- Expired token (signed, exp in the past) accepted (200)   -> CONFIRMED
- Revoked token can be refreshed via ``/auth/refresh`` (200 with a
  new token)                                               -> CONFIRMED
- All rejected with 401                                    -> no finding

The expired probe here uses a correctly signed token issued by the
lab, unlike the JWT detector's expired probe, which uses a token
with an invalid signature and therefore only reports suspected.
Revocation is probed on a freshly issued token with a unique id,
so revoking it cannot affect any other test identity.
``params``: ``prefix``, ``me_path`` (default "/me"),
``subject`` (default "bob").
"""
from __future__ import annotations

import time

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class SessionDetector(Detector):
    name = "session"
    description = "Session lifecycle: revoked and expired tokens, refresh of revoked tokens."

    async def _issue(self, ctx: DetectorContext, subject: str, exp: int | None = None):
        body: dict = {"sub": subject}
        if exp is not None:
            body["exp"] = exp
        resp, ev = await ctx.client.request("POST", "/_lab/issue-jwt", json_body=body)
        if resp.status_code != 200:
            return None, ev
        try:
            return resp.json().get("token"), ev
        except ValueError:
            return None, ev

    async def _get_me(self, ctx: DetectorContext, prefix: str, me_path: str, token: str):
        return await ctx.client.request(
            "GET", prefix + me_path, headers={"Authorization": f"Bearer {token}"})

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        me_path = p.get("me_path", "/me")
        subject = p.get("subject", "bob")

        # Issuer absent (not the lab): nothing to probe.
        token, ev_issue = await self._issue(ctx, subject)
        if not token:
            return [Finding(
                detector=self.name,
                title="Session check inconclusive: no test token issuer",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="POST /_lab/issue-jwt did not return a token, so revoked/expired "
                            "behaviour cannot be probed on this target.",
                endpoint="/_lab/issue-jwt", evidence=[ev_issue], confidence="low",
            )]

        findings: list[Finding] = []

        # 1. Revoked token: issue, revoke, then present it.
        resp, ev_revoked_me = await self._get_me(ctx, prefix, me_path, token)
        # Only meaningful if the token was accepted before revocation.
        if resp.status_code != 200:
            return [Finding(
                detector=self.name,
                title="Session check inconclusive: fresh token rejected",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description=f"A freshly issued token got {resp.status_code} on {prefix + me_path}; "
                            "the control failed, so revocation/expiry cannot be judged.",
                endpoint=prefix + me_path, evidence=[ev_issue, ev_revoked_me], confidence="low",
            )]
        resp_revoke, ev_revoke = await ctx.client.request(
            "POST", "/_lab/revoke", json_body={"token": token})
        if resp_revoke.status_code in (200, 201):
            resp, ev = await self._get_me(ctx, prefix, me_path, token)
            if resp.status_code == 200:
                findings.append(Finding(
                    detector=self.name, title="Revoked token still accepted",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="A token revoked via POST /_lab/revoke was still accepted on "
                                f"{prefix + me_path} (200). Revocation is not enforced.",
                    endpoint=prefix + me_path, evidence=[ev_issue, ev_revoke, ev],
                    reproduction=[
                        "1. POST /_lab/issue-jwt -> token.",
                        "2. POST /_lab/revoke with that token -> 200.",
                        f"3. GET {prefix + me_path} with the revoked token -> 200.",
                    ],
                    confidence="high",
                ))
            # 3. Refresh of the revoked token.
            resp_r, ev_r = await ctx.client.request(
                "POST", prefix + "/auth/refresh", json_body={"token": token})
            if resp_r.status_code in (200, 201):
                try:
                    new_token = resp_r.json().get("token", "")
                except ValueError:
                    new_token = ""
                if new_token:
                    findings.append(Finding(
                        detector=self.name, title="Revoked token can be refreshed",
                        severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                        description="A revoked token could be exchanged for a fresh token via "
                                    f"{prefix}/auth/refresh (200). Revocation is bypassed by refresh.",
                        endpoint=prefix + "/auth/refresh", evidence=[ev_issue, ev_revoke, ev_r],
                        reproduction=[
                            "1. POST /_lab/issue-jwt -> token; POST /_lab/revoke with it -> 200.",
                            f"2. POST {prefix}/auth/refresh with the revoked token -> 200, new token returned.",
                        ],
                        confidence="high",
                    ))

        # 2. Expired token: properly signed, exp in the past.
        expired, ev_exp_issue = await self._issue(ctx, subject, exp=int(time.time()) - 3600)
        if expired:
            resp, ev = await self._get_me(ctx, prefix, me_path, expired)
            if resp.status_code == 200:
                findings.append(Finding(
                    detector=self.name, title="Expired token still accepted",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="A properly signed token with exp one hour in the past was accepted on "
                                f"{prefix + me_path} (200). Token expiry is not enforced.",
                    endpoint=prefix + me_path, evidence=[ev_exp_issue, ev],
                    reproduction=[
                        "1. POST /_lab/issue-jwt with exp in the past -> token.",
                        f"2. GET {prefix + me_path} with that token -> 200.",
                    ],
                    confidence="high",
                ))
        return findings
