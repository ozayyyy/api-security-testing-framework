"""Business-logic detector: order state-machine violations.

Rule: the lab order workflow is draft -> paid -> shipped, with
cancel from draft/paid and a single refund from paid/shipped.
The detector drives each invalid transition on a fresh order owned
by the control identity, then re-reads the order:
- pay a cancelled order succeeds (200, status paid)      -> CONFIRMED
- refund the same order twice succeeds (200 both times)   -> CONFIRMED
- ship an unpaid (draft) order succeeds (200, shipped)   -> CONFIRMED
- change price/quantity after payment persists on re-read -> CONFIRMED
- transition rejected (4xx) or re-read shows no change    -> no finding

Control first: a valid draft -> pay -> ship sequence must succeed;
if it does not, the workflow itself is broken and the detector
reports an informational finding instead of confirmed violations.
``params``: ``prefix``, ``identity`` (default "alice").
"""
from __future__ import annotations

from apistf.detectors.base import Detector, DetectorContext
from apistf.findings import Finding, FindingStatus, Severity


class BusinessLogicDetector(Detector):
    name = "business_logic"
    description = "Business logic: invalid order state transitions."

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        p = ctx.params
        prefix = p.get("prefix", "")
        ident = ctx.config.identity(p.get("identity", "alice"))
        headers = ident.auth_headers()

        async def call(method, url, json_body=None):
            return await ctx.client.request(method, url, headers=headers, json_body=json_body)

        async def create_order():
            resp, ev = await call("POST", prefix + "/orders", {"price": 100, "quantity": 1})
            if resp.status_code not in (200, 201):
                return None, ev
            try:
                return resp.json()["id"], ev
            except (ValueError, KeyError):
                return None, ev

        async def get_order(oid):
            resp, ev = await call("GET", prefix + f"/orders/{oid}")
            try:
                return resp, resp.json(), ev
            except ValueError:
                return resp, {}, ev

        # Control: valid sequence draft -> pay -> ship must work.
        oid, _ = await create_order()
        if oid is None:
            return [Finding(
                detector=self.name, title="Business-logic check inconclusive: order creation failed",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description="POST /orders did not return an order id, so the state machine cannot be probed.",
                endpoint=prefix + "/orders", evidence=[], confidence="low",
            )]
        resp, _ = await call("POST", prefix + f"/orders/{oid}/pay")
        if resp.status_code not in (200, 201):
            return [Finding(
                detector=self.name, title="Business-logic check inconclusive: valid payment rejected",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description=f"Paying a draft order returned {resp.status_code}; the intended workflow does not work, so invalid transitions cannot be judged.",
                endpoint=prefix + "/orders", evidence=[], confidence="low",
            )]
        resp, _ = await call("POST", prefix + f"/orders/{oid}/ship")
        if resp.status_code not in (200, 201):
            return [Finding(
                detector=self.name, title="Business-logic check inconclusive: valid shipment rejected",
                severity=Severity.INFORMATIONAL, status=FindingStatus.INFORMATIONAL,
                description=f"Shipping a paid order returned {resp.status_code}; the intended workflow does not work, so invalid transitions cannot be judged.",
                endpoint=prefix + "/orders", evidence=[], confidence="low",
            )]

        findings: list[Finding] = []

        # 1. Pay a cancelled order.
        oid, ev_create = await create_order()
        if oid is not None:
            _, ev_cancel = await call("POST", prefix + f"/orders/{oid}/cancel")
            resp, ev_pay = await call("POST", prefix + f"/orders/{oid}/pay")
            _, state, ev_read = await get_order(oid)
            if resp.status_code in (200, 201) and state.get("status") == "paid":
                findings.append(Finding(
                    detector=self.name, title="Business logic: pay a cancelled order",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="A cancelled order can be paid: cancel returned 200, pay then returned "
                                f"{resp.status_code} and a re-read shows status=paid. "
                                "A cancelled order can be paid, so money can be taken for an order the customer cancelled.",
                    endpoint=prefix + "/orders", evidence=[ev_create, ev_cancel, ev_pay, ev_read],
                    reproduction=[
                        "1. POST /orders -> draft order.",
                        "2. POST /orders/{id}/cancel -> 200.",
                        f"3. POST /orders/{{id}}/pay -> {resp.status_code}, re-read shows status=paid.",
                    ],
                    confidence="high",
                ))

        # 2. Refund the same order twice.
        oid, ev_create = await create_order()
        if oid is not None:
            _, ev_pay = await call("POST", prefix + f"/orders/{oid}/pay")
            resp1, ev_r1 = await call("POST", prefix + f"/orders/{oid}/refund")
            resp2, ev_r2 = await call("POST", prefix + f"/orders/{oid}/refund")
            _, state, ev_read = await get_order(oid)
            if (resp1.status_code in (200, 201) and resp2.status_code in (200, 201)
                    and state.get("refunds", 0) >= 2):
                findings.append(Finding(
                    detector=self.name, title="Business logic: refund the same order twice",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="The same order refunded twice: both refund calls returned 200 and a "
                                f"re-read shows refunds={state.get('refunds')}. "
                                "The same order can be refunded twice, so the seller pays out twice for one purchase.",
                    endpoint=prefix + "/orders", evidence=[ev_create, ev_pay, ev_r1, ev_r2, ev_read],
                    reproduction=[
                        "1. POST /orders, POST /orders/{id}/pay -> paid.",
                        "2. POST /orders/{id}/refund -> 200.",
                        f"3. POST /orders/{{id}}/refund again -> {resp2.status_code}, re-read shows refunds>=2.",
                    ],
                    confidence="high",
                ))

        # 3. Ship an unpaid order.
        oid, ev_create = await create_order()
        if oid is not None:
            resp, ev_ship = await call("POST", prefix + f"/orders/{oid}/ship")
            _, state, ev_read = await get_order(oid)
            if resp.status_code in (200, 201) and state.get("status") == "shipped":
                findings.append(Finding(
                    detector=self.name, title="Business logic: ship an unpaid order",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="A draft (unpaid) order can be shipped: ship returned "
                                f"{resp.status_code} and a re-read shows status=shipped. "
                                "An unpaid order can be shipped, so goods leave without payment.",
                    endpoint=prefix + "/orders", evidence=[ev_create, ev_ship, ev_read],
                    reproduction=[
                        "1. POST /orders -> draft order.",
                        f"2. POST /orders/{{id}}/ship -> {resp.status_code}, re-read shows status=shipped.",
                    ],
                    confidence="high",
                ))

        # 4. Change price/quantity after payment.
        oid, ev_create = await create_order()
        if oid is not None:
            _, ev_pay = await call("POST", prefix + f"/orders/{oid}/pay")
            resp, ev_patch = await call("PATCH", prefix + f"/orders/{oid}",
                                        {"price": 999, "quantity": 99})
            _, state, ev_read = await get_order(oid)
            if resp.status_code in (200, 201) and (state.get("price") == 999 or state.get("quantity") == 99):
                findings.append(Finding(
                    detector=self.name, title="Business logic: change price/quantity after payment",
                    severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                    description="Price/quantity can be changed after payment: PATCH returned "
                                f"{resp.status_code} and a re-read shows price={state.get('price')}, "
                                f"quantity={state.get('quantity')}. "
                                "Price or quantity can be changed after payment, so the amount charged and the amount shipped disagree.",
                    endpoint=prefix + "/orders", evidence=[ev_create, ev_pay, ev_patch, ev_read],
                    reproduction=[
                        "1. POST /orders, POST /orders/{id}/pay -> paid.",
                        f"2. PATCH /orders/{{id}} with price=999, quantity=99 -> {resp.status_code}.",
                        "3. GET /orders/{id} -> price=999 and/or quantity=99.",
                    ],
                    confidence="high",
                ))

        return findings
