"""Rate-limit detector.

Rule: send ``burst`` requests (default 20) as fast as the client
allows to a probe endpoint and count responses.
- Every request returns 200/201 and none returns 429 -> CONFIRMED
  (no rate limiting observed on this endpoint).
- At least one 429 -> no finding.
- Mixed 5xx / errors -> SUSPECTED (inconclusive, server behaved
  inconsistently, not demonstrably rate-limited).
``params``: ``prefix``, ``probe_path`` (default "/rate-test"),
``burst`` (default 20).
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class RateLimitDetector(Detector):
    name = "rate_limit"
    description = "Rate-limit enforcement: burst probe for missing 429 responses."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        path = prefix + p.get("probe_path", "/rate-test")
        burst = int(p.get("burst", 20))
        ident = ctx.config.identity(p.get("identity", "alice"))
        statuses: list[int] = []
        evidence = []
        for _ in range(burst):
            resp, ev = await ctx.client.request("GET", path, headers=ident.auth_headers())
            statuses.append(resp.status_code)
            evidence.append(ev)
        if 429 in statuses:
            return []
        if all(s in (200, 201) for s in statuses):
            return [Finding(
                detector=self.name,
                title=f"No rate limiting observed on {path}",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                description=f"{burst} rapid requests to {path} all returned 200/201 and "
                            "none returned 429. The endpoint does not appear to enforce "
                            "rate limiting (confirmed for this probe; a limit above the "
                            "burst size would not be detected).",
                endpoint=path, evidence=evidence[:3],
                reproduction=[f"Send {burst} rapid GET {path} requests as {ident.name}; all return 200, none 429."],
                confidence="medium",
            )]
        return [Finding(
            detector=self.name,
            title=f"Inconclusive rate-limit probe on {path}",
            severity=Severity.LOW, status=FindingStatus.SUSPECTED,
            description=f"Burst of {burst} returned mixed statuses {sorted(set(statuses))} "
                        "with no 429. The server behaved inconsistently; manual review needed.",
            endpoint=path, evidence=evidence[:3], confidence="low",
        )]
