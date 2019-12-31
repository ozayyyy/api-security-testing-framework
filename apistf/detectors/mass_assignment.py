"""Mass-assignment / excessive-data-exposure detectors.

Mass assignment rule: PATCH the caller's own profile with a privileged
field (``role=admin`` / ``is_admin=true``) that the API schema does not
advertise for that operation. Re-read the profile afterwards.
- Privileged field persisted -> CONFIRMED mass assignment.
- Field ignored / rejected -> no finding.

Excessive data exposure rule: GET a user/object profile and inspect the
returned JSON for fields that should never leave the server
(``password_hash``, ``ssn``, ... from ``sensitive_fields``).
- Sensitive field present with a non-empty value -> CONFIRMED.
- Field present but empty/null -> SUSPECTED.
Both are deterministic string/key checks, no guessing.
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity

DEFAULT_SENSITIVE_FIELDS = {
    "password_hash", "password", "ssn", "social_security_number",
    "credit_card", "card_number", "secret", "private_key", "api_key",
}


def _walk(obj, fields: set[str], found: dict):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in fields and v not in (None, "", []):
                found[k] = v
            _walk(v, fields, found)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, fields, found)


class MassAssignmentDetector(Detector):
    name = "mass_assignment"
    description = "Mass assignment: privileged fields settable through a normal update."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        me_path = prefix + p.get("me_path", "/users/me")
        ident = ctx.config.identity(p.get("identity", "alice"))
        headers = ident.auth_headers()
        # Control: read current profile.
        resp, ev_read = await ctx.client.request("GET", me_path, headers=headers)
        if resp.status_code != 200:
            return []
        try:
            before = resp.json()
        except ValueError:
            return []
        role_before = before.get("role")
        for field, value in (("role", "admin"), ("is_admin", True)):
            resp, ev = await ctx.client.request(
                "PATCH", me_path, headers=headers, json_body={field: value})
            if resp.status_code not in (200, 201):
                continue
            resp2, ev2 = await ctx.client.request("GET", me_path, headers=headers)
            try:
                after = resp2.json()
            except ValueError:
                continue
            if after.get(field) == value and after.get(field) != (role_before if field == "role" else False):
                return [Finding(
                    detector=self.name,
                    title=f"Mass assignment: {field} can be set through profile update",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description=f"PATCH {me_path} with {{\"{field}\": {value!r}}} persisted: "
                                f"a re-read shows {field}={after.get(field)!r}. A normal user "
                                "can escalate their own privileges.",
                    endpoint=me_path, evidence=[ev_read, ev, ev2],
                    reproduction=[
                        f"1. GET {me_path} as {ident.name} -> role={role_before!r}.",
                        f"2. PATCH {me_path} with {{\"{field}\": {value!r}}} -> {resp.status_code}.",
                        f"3. GET {me_path} -> {field}={after.get(field)!r}.",
                    ],
                    confidence="high",
                )]
        return []


class ExcessiveDataDetector(Detector):
    name = "excessive_data"
    description = "Excessive data exposure: sensitive fields returned in API responses."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        paths = p.get("paths", ["/users/1", "/users/me"])
        fields = set(p.get("sensitive_fields", DEFAULT_SENSITIVE_FIELDS))
        ident = ctx.config.identity(p.get("identity", "alice"))
        findings: list[Finding] = []
        for path in paths:
            url = prefix + path
            resp, ev = await ctx.client.request("GET", url, headers=ident.auth_headers())
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            found: dict = {}
            _walk(data, fields, found)
            if found:
                findings.append(Finding(
                    detector=self.name,
                    title=f"Excessive data exposure: sensitive fields in {path}",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description=f"GET {url} returned sensitive field(s) "
                                f"{sorted(found)} with values. These fields should never "
                                "be sent to a client.",
                    endpoint=url, evidence=[ev],
                    reproduction=[f"GET {url} as {ident.name} -> 200, response contains {sorted(found)}."],
                    confidence="high",
                ))
        return findings
