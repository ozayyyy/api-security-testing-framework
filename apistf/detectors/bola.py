"""BOLA / IDOR detector.

Rule: for an object endpoint ``/objects/{id}``, fetch the object as its
owner (control, expect 200 with the owner's data), then fetch the same
object as a different authenticated user and unauthenticated.
- Other user gets 200 with the same object body  -> CONFIRMED BOLA.
- Other user gets 403/404, owner gets 200        -> no finding.
- Other user gets 200 with a different / empty body -> SUSPECTED.
The detector needs two distinct identities and an object id per
identity, supplied in ``params``: ``object_path`` (default
"/objects/{id}"), ``owner_a`` / ``owner_b`` identity names, ``object_a``
/ ``object_b`` ids. Defaults match the bundled lab.
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class BolaDetector(Detector):
    name = "bola"
    description = "Cross-user object access (BOLA/IDOR) on object endpoints."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        path_tpl = p.get("object_path", "/objects/{id}")
        id_a = str(p.get("object_a", "1"))
        id_b = str(p.get("object_b", "2"))
        name_a = p.get("owner_a", "alice")
        name_b = p.get("owner_b", "bob")
        ident_a = ctx.config.identity(name_a)
        ident_b = ctx.config.identity(name_b)

        async def get(ident, obj_id):
            url = prefix + path_tpl.format(id=obj_id)
            resp, ev = await ctx.client.request("GET", url, headers=ident.auth_headers())
            return resp, ev

        # Control: owner A reads their own object.
        resp_a, ev_a = await get(ident_a, id_a)
        if resp_a.status_code != 200:
            return [Finding(
                detector=self.name, title="BOLA check inconclusive: owner cannot read own object",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description=f"Owner {name_a} got {resp_a.status_code} for object {id_a}; "
                            "the control request failed, so no boundary can be judged.",
                endpoint=prefix + path_tpl, evidence=[ev_a], confidence="low",
            )]
        try:
            body_a = resp_a.json()
        except ValueError:
            body_a = resp_a.text

        # Attack 1: other user B reads A's object.
        resp_b, ev_b = await get(ident_b, id_a)
        # Attack 2: unauthenticated reads A's object.
        resp_u, ev_u = await ctx.client.request(
            "GET", prefix + path_tpl.format(id=id_a),
            headers=ctx.config.unauthenticated().auth_headers())

        findings: list[Finding] = []
        for label, resp, ev in (("other user", resp_b, ev_b), ("unauthenticated", resp_u, ev_u)):
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError:
                    body = resp.text
                if body == body_a:
                    findings.append(Finding(
                        detector=self.name,
                        title=f"BOLA: {label} can read another user's object",
                        severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                        description=f"{label} ({name_b if label == 'other user' else 'anonymous'}) "
                                    f"received HTTP 200 with the same object body as owner {name_a} "
                                    f"for object {id_a}. Object-level authorisation is not enforced.",
                        endpoint=prefix + path_tpl, evidence=[ev_a, ev],
                        reproduction=[
                            f"1. As {name_a}, GET {prefix + path_tpl.format(id=id_a)} -> 200 (control).",
                            f"2. As {label}, GET {prefix + path_tpl.format(id=id_a)} -> 200, identical body.",
                        ],
                        confidence="high",
                    ))
                else:
                    findings.append(Finding(
                        detector=self.name,
                        title=f"BOLA suspected: {label} got 200 with different content",
                        severity=Severity.MEDIUM, status=FindingStatus.SUSPECTED,
                        description=f"{label} got 200 for object {id_a} but the body differs from "
                                    "the owner's. Manual review needed: it may be a filtered view.",
                        endpoint=prefix + path_tpl, evidence=[ev_a, ev], confidence="low",
                    ))
        return findings
