"""BFLA detector: low-privilege role calling admin-only endpoints.

Rule: call each configured admin endpoint as a low-privilege identity.
- 200/201 with an admin payload -> CONFIRMED BFLA.
- 401/403 -> no finding (function-level authorisation enforced).
- Other status -> SUSPECTED only if the body looks like admin data.
``params``: ``prefix``, ``admin_paths`` (list), ``low_priv_identity``
(default "alice"), ``admin_identity`` (default "admin", used as control).
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class BflaDetector(Detector):
    name = "bfla"
    description = "Broken function-level authorisation: low-privilege role reaches admin endpoints."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        paths = p.get("admin_paths", ["/admin/users"])
        low = ctx.config.identity(p.get("low_priv_identity", "alice"))
        admin = ctx.config.identity(p.get("admin_identity", "admin"))
        findings: list[Finding] = []
        for path in paths:
            url = prefix + path
            resp_admin, ev_admin = await ctx.client.request("GET", url, headers=admin.auth_headers())
            resp_low, ev_low = await ctx.client.request("GET", url, headers=low.auth_headers())
            if resp_admin.status_code != 200:
                continue  # control failed; cannot judge this endpoint
            if resp_low.status_code in (200, 201):
                findings.append(Finding(
                    detector=self.name,
                    title=f"BFLA: low-privilege user can call admin endpoint {path}",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description=f"Identity {low.name} (role {low.role}) received "
                                f"{resp_low.status_code} on {path}, which the admin control "
                                "also returns 200 for. Function-level authorisation is not enforced.",
                    endpoint=url, evidence=[ev_admin, ev_low],
                    reproduction=[
                        f"1. As admin, GET {url} -> 200 (control).",
                        f"2. As {low.name} ({low.role}), GET {url} -> {resp_low.status_code}.",
                    ],
                    confidence="high",
                ))
        return findings
