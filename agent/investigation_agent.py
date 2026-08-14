from models.investigation_model import Investigation


TOOL_MAP = {
    "IP": [
        "AbuseIPDB",
        "VirusTotal",
        "OTX",
        "GeoIP",
        "Shodan"
    ],
    "DOMAIN": [
        "VirusTotal",
        "WHOIS",
        "DNS",
        "OTX"
    ],
    "URL": [
        "VirusTotal",
        "URLScan",
        "OTX"
    ],
    "MD5": [
        "VirusTotal",
        "MalwareBazaar"
    ],
    "SHA1": [
        "VirusTotal",
        "MalwareBazaar"
    ],
    "SHA256": [
        "VirusTotal",
        "MalwareBazaar"
    ],
    "EMAIL": [
        "VirusTotal",
        "WHOIS"
    ]
}


def create_investigation_plan(investigation: Investigation) -> Investigation:
    investigation.investigation_plan = TOOL_MAP.get(
        investigation.ioc_type,
        []
    ).copy()

    return investigation