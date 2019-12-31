import json

from apistf.findings import Evidence, Finding, FindingStatus, Severity
from apistf.reporting import to_html, to_json, to_markdown


def _finding():
    return Finding(
        detector="bola", title="BOLA: other user can read another user's object",
        severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
        description="Cross-user read.", endpoint="/vuln/objects/{id}",
        reproduction=["GET as bob -> 200"],
        evidence=[Evidence(method="GET", url="http://testserver/vuln/objects/1",
                           request_headers={"Authorization": "[REDACTED]"},
                           response_status=200, response_body='{"id": 1}')],
    )


def test_json_round_trip():
    data = json.loads(to_json([_finding()]))
    assert data["findings"][0]["status"] == "confirmed"
    assert data["findings"][0]["evidence"][0]["request_headers"]["Authorization"] == "[REDACTED]"


def test_markdown_and_html_contain_finding():
    assert "BOLA" in to_markdown([_finding()])
    assert "BOLA" in to_html([_finding()])
    assert "<script>" not in to_html([_finding()])
