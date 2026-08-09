from dataclasses import dataclass, field
from typing import Any


@dataclass
class Investigation:
    ioc: str
    ioc_type: str
    results: dict[str, Any] = field(default_factory=dict)
    threat_score: float = 0.0
    severity: str = "Unknown"
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)