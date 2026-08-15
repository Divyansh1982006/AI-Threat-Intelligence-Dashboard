from models.investigation_model import Investigation
from tools.abuseipdb import check_ip as abuseipdb_check
from tools.virustotal import (
    check_ip as virustotal_ip,
    check_domain as virustotal_domain,
    check_url as virustotal_url,
    check_hash as virustotal_hash,
)


TOOL_HANDLERS = {
    "AbuseIPDB": {
        "IP": abuseipdb_check,
    },
    "VirusTotal": {
        "IP": virustotal_ip,
        "DOMAIN": virustotal_domain,
        "URL": virustotal_url,
        "MD5": virustotal_hash,
        "SHA1": virustotal_hash,
        "SHA256": virustotal_hash,
    },
}


def execute_tools(investigation: Investigation) -> Investigation:
    results = {}

    for tool in investigation.investigation_plan:

        if tool not in TOOL_HANDLERS:
            results[tool] = {
                "status": "pending",
                "message": f"{tool} integration not implemented yet"
            }
            continue

        handler = TOOL_HANDLERS[tool].get(investigation.ioc_type)

        if handler is None:
            results[tool] = {
                "status": "unsupported",
                "message": (
                    f"{tool} does not currently support "
                    f"{investigation.ioc_type}"
                )
            }
            continue

        results[tool] = handler(investigation.ioc)

    investigation.results = results

    return investigation