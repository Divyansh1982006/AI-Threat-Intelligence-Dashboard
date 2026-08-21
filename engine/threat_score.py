"""
Threat scoring engine.

Combines the raw results already gathered by tool_executor.execute_tools()
into a single 0-100 threat_score, a 0-100 confidence value, and a
human-readable severity label.

Design:
  - Each "reputation" source (VirusTotal, AbuseIPDB, OTX, MalwareBazaar)
    contributes a 0-100 sub-score plus a fixed weight.
  - Weights are renormalized over whichever of those sources actually
    returned usable data for this IOC (so a domain, which never gets
    AbuseIPDB, isn't unfairly penalized for a "missing" source).
  - Confidence reflects how much of the investigation plan actually
    returned data, separate from how bad that data looks.
  - Context sources (WHOIS, Shodan) don't get a weighted vote of their
    own -- they act as small additive modifiers on top of the
    reputation score, the same way a human analyst would use them.
"""

from models.investigation_model import Investigation


# Base weight of each reputation source, used only when the source
# actually returned data. Weights are renormalized across whatever
# subset is available for a given IOC type.
SOURCE_WEIGHTS = {
    "VirusTotal": 0.35,
    "AbuseIPDB": 0.30,
    "OTX": 0.20,
    "MalwareBazaar": 0.15,
}

# Ports that meaningfully raise risk when found open on Shodan.
RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900}

SEVERITY_THRESHOLDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Informational"),
]


def _score_virustotal(result: dict) -> float | None:
    if not result or result.get("status") != "success":
        return None

    malicious = result.get("malicious") or 0
    suspicious = result.get("suspicious") or 0
    harmless = result.get("harmless") or 0
    undetected = result.get("undetected") or 0
    total = malicious + suspicious + harmless + undetected

    if total == 0:
        return 0.0

    weighted_hits = malicious * 1.0 + suspicious * 0.5
    return min(100.0, (weighted_hits / total) * 100)


def _score_abuseipdb(result: dict) -> float | None:
    if not result or result.get("status") != "success":
        return None

    return float(result.get("abuse_confidence") or 0)


def _score_otx(result: dict) -> float | None:
    if not result or result.get("status") != "success":
        return None

    pulse_count = result.get("pulse_count") or 0
    # 10+ pulses (independent threat-intel reports referencing this
    # IOC) is treated as maxed-out risk from this source.
    return min(100.0, pulse_count * 10)


def _score_malwarebazaar(result: dict) -> float | None:
    if not result:
        return None

    status = result.get("status")

    if status == "success":
        # A confirmed match in a malware sample database is about
        # as strong a signal as this pipeline can get.
        return 100.0

    if status == "not_found":
        # Absence of a hash from MalwareBazaar says very little --
        # it only tracks a subset of known malware families.
        return None

    return None


def _domain_age_modifier(whois_result: dict) -> tuple[float, str | None]:
    if not whois_result or whois_result.get("status") != "success":
        return 0.0, None

    creation_date = whois_result.get("creation_date")

    # whois lib sometimes returns a list of dates instead of one.
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if not creation_date or not hasattr(creation_date, "year"):
        return 0.0, None

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    created = creation_date

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age_days = (now - created).days

    if age_days < 0:
        return 0.0, None

    if age_days <= 7:
        return 15.0, "Domain registered within the last 7 days (+15)"

    if age_days <= 30:
        return 8.0, "Domain registered within the last 30 days (+8)"

    return 0.0, None


def _shodan_exposure_modifier(shodan_result: dict) -> tuple[float, str | None]:
    if not shodan_result or shodan_result.get("status") != "success":
        return 0.0, None

    open_ports = set(shodan_result.get("open_ports") or [])
    risky = open_ports & RISKY_PORTS

    if not risky:
        return 0.0, None

    bonus = min(15.0, len(risky) * 5.0)
    ports_list = ", ".join(str(p) for p in sorted(risky))
    return bonus, f"Risky service(s) exposed on port(s) {ports_list} (+{bonus:.0f})"


def _severity_for(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Unknown"


def calculate_threat_score(investigation: Investigation) -> Investigation:
    results = investigation.results

    scorers = {
        "VirusTotal": _score_virustotal,
        "AbuseIPDB": _score_abuseipdb,
        "OTX": _score_otx,
        "MalwareBazaar": _score_malwarebazaar,
    }

    available_scores = {}
    breakdown = []

    for source, scorer in scorers.items():
        if source not in investigation.investigation_plan:
            continue

        score = scorer(results.get(source, {}))

        if score is None:
            breakdown.append(f"{source}: no usable data")
            continue

        available_scores[source] = score

    # No reputation source returned anything usable -- we genuinely
    # don't know. Don't fabricate a score of 0 (which would read as
    # "confirmed clean" when it actually means "we have no idea").
    if not available_scores:
        investigation.threat_score = 0.0
        investigation.confidence = 0.0
        investigation.severity = "Unknown"
        investigation.score_breakdown = breakdown + [
            "No reputation sources returned data -- score is not reliable."
        ]
        return investigation

    total_weight = sum(SOURCE_WEIGHTS[s] for s in available_scores)
    base_score = sum(
        available_scores[s] * (SOURCE_WEIGHTS[s] / total_weight)
        for s in available_scores
    )

    for source, score in available_scores.items():
        pct_weight = round((SOURCE_WEIGHTS[source] / total_weight) * 100)
        breakdown.append(f"{source}: {score:.0f}/100 (weight {pct_weight}%)")

    # Context modifiers (don't get a weighted vote, just nudge the score).
    modifier_total = 0.0

    age_bonus, age_note = _domain_age_modifier(results.get("WHOIS", {}))
    if age_note:
        modifier_total += age_bonus
        breakdown.append(age_note)

    exposure_bonus, exposure_note = _shodan_exposure_modifier(results.get("Shodan", {}))
    if exposure_note:
        modifier_total += exposure_bonus
        breakdown.append(exposure_note)

    corroboration_bonus = getattr(investigation, "corroboration_bonus", 0.0)
    if corroboration_bonus:
        modifier_total += corroboration_bonus
        breakdown.append(
            f"Multi-source corroboration bonus (+{corroboration_bonus:.0f})"
        )

    final_score = min(100.0, base_score + modifier_total)

    # Confidence = how much of the *planned* reputation coverage we
    # actually got data back from. A single VT hit maxing out the
    # score should not read as high-confidence.
    planned_reputation_sources = [
        s for s in investigation.investigation_plan if s in SOURCE_WEIGHTS
    ]
    confidence = (
        (len(available_scores) / len(planned_reputation_sources)) * 100
        if planned_reputation_sources
        else 0.0
    )

    investigation.threat_score = round(final_score, 1)
    investigation.confidence = round(confidence, 1)
    investigation.severity = _severity_for(final_score)
    investigation.score_breakdown = breakdown

    return investigation