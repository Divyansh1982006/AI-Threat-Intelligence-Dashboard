"""
AI Analysis layer.

IMPORTANT DESIGN RULE: this module never decides the verdict. The
threat_score and severity are already final by the time this runs --
they come from threat_score.py's weighted rules, not from the LLM.
This module's only job is to turn that finished evidence package into
a plain-English summary and concrete next steps for a human analyst.

Keeping the LLM downstream of the score (explainer, not scorer) avoids
a common failure mode in "AI SOC tool" projects: letting the model
re-judge risk and potentially hallucinate a severity that isn't
actually backed by the evidence.

Requires ANTHROPIC_API_KEY in .env.
"""

import os
import json
import requests
from dotenv import load_dotenv

from models.investigation_model import Investigation

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("ANTHROPIC_API_KEY")
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = """You are a SOC analyst assistant. You are given a completed
threat intelligence investigation: a fixed threat_score, severity, confidence,
a breakdown of which sources contributed to that score, and correlation notes
describing agreement/conflict between sources.

Your job is ONLY to explain this evidence in plain English and recommend next
steps for a human analyst. You must NOT invent a different score or severity,
you must NOT state facts that are not present in the evidence provided, and
you must NOT claim higher certainty than the confidence value supports.

Respond with ONLY valid JSON, no markdown fences, no preamble, in this exact
shape:
{
  "summary": "2-4 sentence plain-English explanation of why this IOC got this
              score, referencing the specific evidence given",
  "recommendations": ["short actionable next step", "another one", "..."]
}
Provide 2-5 recommendations. Keep the summary grounded strictly in the
evidence provided -- do not speculate beyond it."""


def _build_evidence_prompt(investigation: Investigation) -> str:
    lines = [
        f"IOC: {investigation.ioc}",
        f"Type: {investigation.ioc_type}",
        f"Threat Score: {investigation.threat_score}/100",
        f"Confidence: {investigation.confidence}%",
        f"Severity: {investigation.severity}",
        "",
        "Score breakdown:",
    ]
    lines += [f"- {b}" for b in investigation.score_breakdown] or ["- (none)"]

    lines.append("")
    lines.append("Correlation notes:")
    lines += [f"- {n}" for n in investigation.correlation_notes] or ["- (none)"]

    return "\n".join(lines)


def generate_ai_analysis(investigation: Investigation) -> Investigation:
    if not API_KEY:
        investigation.summary = (
            "AI analysis unavailable: ANTHROPIC_API_KEY is not set in .env."
        )
        investigation.recommendations = []
        return investigation

    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    payload = {
        "model": MODEL,
        "max_tokens": 500,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": _build_evidence_prompt(investigation)}
        ],
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()

        text = "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        ).strip()

        parsed = json.loads(text)

        investigation.summary = parsed.get("summary", "").strip()
        investigation.recommendations = [
            r.strip() for r in parsed.get("recommendations", []) if r.strip()
        ]

    except requests.exceptions.RequestException as exc:
        investigation.summary = f"AI analysis failed: network/API error ({exc})."
        investigation.recommendations = []

    except (json.JSONDecodeError, KeyError, ValueError):
        investigation.summary = (
            "AI analysis failed: model response was not valid JSON. "
            "Falling back to rule-based evidence only -- see score breakdown "
            "and correlation notes above."
        )
        investigation.recommendations = []

    return investigation