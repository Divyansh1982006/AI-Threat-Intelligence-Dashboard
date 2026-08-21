"""
Correlation engine.

This is the layer that makes the pipeline "intelligence" instead of
just "8 API calls stapled together." A single source saying
"malicious" is a data point. Multiple *independent* sources agreeing
-- or disagreeing -- is what a human analyst actually reasons about,
and that reasoning is what this module encodes:

  1. Reputation corroboration  -- do VT / AbuseIPDB / OTX / MalwareBazaar
     agree with each other, or contradict each other?
  2. Contextual reinforcement  -- does a malicious verdict line up with
     supporting context (brand-new domain, risky exposed services)?
     A "malicious" verdict on a 5-year-old, boring domain is a weaker
     story than the same verdict on a domain registered yesterday.

The output is a list of analyst-readable notes plus a small numeric
corroboration_bonus that threat_score.py folds into the final score --
so agreement between sources actually *matters* to the verdict,
not just to the writeup.
"""

from datetime import datetime, timezone

from models.investigation_model import Investigation

RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900}


def _reputation_verdicts(results: dict) -> tuple[list[str], list[str]]:
    """Returns (sources_saying_malicious, sources_saying_clean)."""

    malicious, clean = [], []

    vt = results.get("VirusTotal", {})
    if vt.get("status") == "success":
        if (vt.get("malicious") or 0) > 0:
            malicious.append("VirusTotal")
        elif (vt.get("malicious") or 0) == 0 and (vt.get("suspicious") or 0) == 0:
            clean.append("VirusTotal")

    abuse = results.get("AbuseIPDB", {})
    if abuse.get("status") == "success":
        confidence = abuse.get("abuse_confidence") or 0
        if confidence >= 50:
            malicious.append("AbuseIPDB")
        elif confidence == 0:
            clean.append("AbuseIPDB")

    otx = results.get("OTX", {})
    if otx.get("status") == "success":
        if (otx.get("pulse_count") or 0) > 0:
            malicious.append("OTX")
        else:
            clean.append("OTX")

    mb = results.get("MalwareBazaar", {})
    if mb.get("status") == "success":
        malicious.append("MalwareBazaar")

    return malicious, clean


def _domain_age_days(whois_result: dict) -> int | None:
    if not whois_result or whois_result.get("status") != "success":
        return None

    creation_date = whois_result.get("creation_date")
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if not creation_date or not hasattr(creation_date, "year"):
        return None

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - creation_date).days
    return age_days if age_days >= 0 else None


def correlate_evidence(investigation: Investigation) -> Investigation:
    results = investigation.results
    notes: list[str] = []
    corroboration_bonus = 0.0

    malicious_sources, clean_sources = _reputation_verdicts(results)

    if len(malicious_sources) >= 2:
        notes.append(
            f"{len(malicious_sources)} independent sources "
            f"({', '.join(malicious_sources)}) agree this IOC is malicious. "
            f"This is a corroborated signal, not a single-source flag."
        )
        corroboration_bonus = min(10.0, (len(malicious_sources) - 1) * 5.0)

    elif len(malicious_sources) == 1 and clean_sources:
        notes.append(
            f"Conflicting verdicts: {malicious_sources[0]} flags this IOC as "
            f"malicious, but {', '.join(clean_sources)} report no findings. "
            f"Could be a false positive, a very recent threat not yet indexed "
            f"elsewhere, or a source-specific blind spot -- don't take either "
            f"verdict alone as final."
        )

    elif not malicious_sources and len(clean_sources) >= 2:
        notes.append(
            f"{len(clean_sources)} sources ({', '.join(clean_sources)}) found "
            f"no malicious indicators. No corroborating evidence of a threat."
        )

    # Contextual reinforcement: malicious verdict + newly registered domain.
    age_days = _domain_age_days(results.get("WHOIS", {}))
    if age_days is not None and age_days <= 30 and malicious_sources:
        notes.append(
            f"Domain is only {age_days} day(s) old AND flagged malicious by "
            f"{', '.join(malicious_sources)} -- this matches a classic "
            f"newly-registered-domain (NRD) abuse pattern (e.g. phishing "
            f"or short-lived C2 infrastructure)."
        )

    # Contextual reinforcement: malicious verdict + risky exposed services.
    shodan = results.get("Shodan", {})
    if shodan.get("status") == "success" and malicious_sources:
        open_ports = set(shodan.get("open_ports") or [])
        risky = open_ports & RISKY_PORTS
        if risky:
            ports_list = ", ".join(str(p) for p in sorted(risky))
            notes.append(
                f"Host is flagged malicious ({', '.join(malicious_sources)}) "
                f"and exposes high-risk service(s) on port(s) {ports_list} -- "
                f"consistent with a compromised or intentionally malicious "
                f"host rather than a stale/incorrect reputation record."
            )

    if not notes:
        notes.append(
            "No cross-source correlation patterns detected -- either too "
            "little data returned, or nothing noteworthy to cross-reference."
        )

    investigation.correlation_notes = notes
    investigation.corroboration_bonus = corroboration_bonus
    return investigation