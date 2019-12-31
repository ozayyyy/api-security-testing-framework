"""Findings: the single evidence-carrying result type."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"      # reproduced: vulnerable behaviour observed, control behaved differently
    SUSPECTED = "suspected"      # anomalous behaviour, not reproduced as a boundary violation
    INFORMATIONAL = "informational"  # observation, no boundary violation demonstrated


@dataclass
class Evidence:
    method: str
    url: str
    request_headers: dict
    request_body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    note: str = ""


@dataclass
class Finding:
    detector: str
    title: str
    severity: Severity
    status: FindingStatus
    description: str
    endpoint: str
    evidence: list[Evidence] = field(default_factory=list)
    reproduction: list[str] = field(default_factory=list)
    confidence: str = "medium"  # low | medium | high — explicit, never implied

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "description": self.description,
            "endpoint": self.endpoint,
            "reproduction": self.reproduction,
            "evidence": [
                {
                    "method": e.method,
                    "url": e.url,
                    "request_headers": e.request_headers,
                    "request_body": e.request_body,
                    "response_status": e.response_status,
                    "response_headers": e.response_headers,
                    "response_body": e.response_body,
                    "note": e.note,
                }
                for e in self.evidence
            ],
        }
