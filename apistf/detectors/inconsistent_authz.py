"""Inconsistent-authorisation detector.

Rule: two paths expose the same resource — ``/users/{id}`` and
``/profile/{id}`` in the lab. For a target user, fetch both paths
as the target's owner (control: both should allow) and as a
different authenticated user:
- One path allows (200) and the other denies (401/403) for the
  non-owner, while the owner is allowed on both -> CONFIRMED:
  the access check is enforced on one path and missing on the other.
- Both paths agree (both allow with the same body, or both deny)
  -> no finding.
- Owner is denied on either path -> informational (the control
  failed; no boundary can be judged).
``params``: ``prefix``, ``target_id`` (default 1, alice),
``owner`` (default "alice"), ``other`` (default "bob").
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class InconsistentAuthzDetector(Detector):
    name = "inconsistent_authz"
    description = "Inconsistent authorisation: two paths to the same resource disagree."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        target = str(p.get("target_id", "1"))
        owner = ctx.config.identity(p.get("owner", "alice"))
        other = ctx.config.identity(p.get("other", "bob"))
        path_a = prefix + p.get("path_a", "/users/{id}").format(id=target)
        path_b = prefix + p.get("path_b", "/profile/{id}").format(id=target)

        async def get(ident, url):
            return await ctx.client.request("GET", url, headers=ident.auth_headers())

        # Control: owner must be allowed on both paths.
        resp_a_owner, ev_a_owner = await get(owner, path_a)
        resp_b_owner, ev_b_owner = await get(owner, path_b)
        if resp_a_owner.status_code != 200 or resp_b_owner.status_code != 200:
            return [Finding(
                detector=self.name,
                title="Inconsistent-authorisation check inconclusive: owner denied on a path",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description=f"Owner {owner.name} got {resp_a_owner.status_code} on {path_a} and "
                            f"{resp_b_owner.status_code} on {path_b}; the control failed, so the two paths cannot be compared.",
                endpoint=path_a, evidence=[ev_a_owner, ev_b_owner], confidence="low",
            )]

        resp_a, ev_a = await get(other, path_a)
        resp_b, ev_b = await get(other, path_b)
        allowed_a = resp_a.status_code == 200
        allowed_b = resp_b.status_code == 200
        denied_a = resp_a.status_code in (401, 403)
        denied_b = resp_b.status_code in (401, 403)
        if (allowed_a and denied_b) or (denied_a and allowed_b):
            allowed_path, denied_path = (path_a, path_b) if allowed_a else (path_b, path_a)
            allowed_status = resp_a.status_code if allowed_a else resp_b.status_code
            denied_status = resp_b.status_code if allowed_a else resp_a.status_code
            return [Finding(
                detector=self.name,
                title=f"Inconsistent authorisation: {allowed_path} allows what {denied_path} denies",
                severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                description=f"For user {target}, {other.name} (not the owner) received "
                            f"{allowed_status} on {allowed_path} but {denied_status} on {denied_path}, "
                            "while the owner is allowed on both. The same resource is protected on one path and not the other.",
                endpoint=allowed_path, evidence=[ev_a_owner, ev_b_owner, ev_a, ev_b],
                reproduction=[
                    f"1. As {owner.name} (owner), GET {path_a} -> 200 and GET {path_b} -> 200 (control).",
                    f"2. As {other.name}, GET {allowed_path} -> {allowed_status}, GET {denied_path} -> {denied_status}.",
                ],
                confidence="high",
            )]
        return []
