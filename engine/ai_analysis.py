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

PROVIDER: defaults to a local Ollama model -- no API key, no cost, and
no investigation data ever leaves the machine, which matters for a
security tool handling internal IPs/hostnames. Set AI_PROVIDER=anthropic
in .env (plus ANTHROPIC_API_KEY) to use Claude instead if you ever want
cloud-hosted analysis.

Local setup (one-time):
    1. Install Ollama: https://ollama.com
    2. Run: ollama pull llama3.2
    3. Ollama runs automatically in the background on localhost:11434
"""

import os
import json
import requests
from dotenv import load_dotenv

from models.investigation_model import Investigation

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").strip().lower()

# -- Ollama (local, free, default) --
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

# -- Anthropic (cloud, optional, paid) --
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-5"

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


def _extract_json(text: str) -> dict:
    """Local models sometimes wrap JSON in markdown fences or add stray
    text around it despite instructions. Pull out the first {...} block."""
    text = text.strip()

    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1:
        raise json.JSONDecodeError("no JSON object found", text, 0)

    return json.loads(text[start:end + 1])


def _call_ollama(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    return data.get("message", {}).get("content", "")


def _call_anthropic(prompt: str) -> str:
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 500,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }

    response = requests.post(ANTHROPIC_URL, headers=headers, json=payload, timeout=20)
    response.raise_for_status()
    data = response.json()

    return "".join(
        block.get("text", "")
        for block in data.get("content", [])
        if block.get("type") == "text"
    )


def generate_ai_analysis(investigation: Investigation) -> Investigation:
    prompt = _build_evidence_prompt(investigation)

    try:
        if AI_PROVIDER == "anthropic":
            if not ANTHROPIC_API_KEY:
                investigation.summary = (
                    "AI analysis unavailable: AI_PROVIDER=anthropic but "
                    "ANTHROPIC_API_KEY is not set in .env."
                )
                investigation.recommendations = []
                return investigation
            raw_text = _call_anthropic(prompt)
        else:
            raw_text = _call_ollama(prompt)

        parsed = _extract_json(raw_text)

        investigation.summary = parsed.get("summary", "").strip()
        investigation.recommendations = [
            r.strip() for r in parsed.get("recommendations", []) if r.strip()
        ]

    except requests.exceptions.ConnectionError:
        if AI_PROVIDER != "anthropic":
            investigation.summary = (
                "AI analysis unavailable: could not reach Ollama at "
                f"{OLLAMA_URL}. Is Ollama installed and running? "
                "(Install from https://ollama.com, then run "
                f"'ollama pull {OLLAMA_MODEL}'.)"
            )
        else:
            investigation.summary = "AI analysis unavailable: connection error."
        investigation.recommendations = []

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