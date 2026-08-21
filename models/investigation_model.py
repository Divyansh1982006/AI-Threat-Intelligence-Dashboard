from dataclasses import dataclass, field
from typing import Any


@dataclass
class Investigation:
    ioc: str
    ioc_type: str
    investigation_plan: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    threat_score: float = 0.0
    confidence: float = 0.0
    severity: str = "Unknown"
    score_breakdown: list[str] = field(default_factory=list)
    correlation_notes: list[str] = field(default_factory=list)
    corroboration_bonus: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)