from models.investigation_model import Investigation
from tools.abuseipdb import check_ip as abuseipdb_check
from tools.virustotal import check_ip as virustotal_check


TOOL_HANDLERS = {
    "AbuseIPDB": abuseipdb_check,
    "VirusTotal": virustotal_check,
}


def execute_tools(investigation: Investigation) -> Investigation:
    results = {}

    for tool in investigation.investigation_plan:

        if tool in TOOL_HANDLERS:
            if investigation.ioc_type == "IP":
                results[tool] = TOOL_HANDLERS[tool](investigation.ioc)
            else:
                results[tool] = {
                    "status": "unsupported",
                    "message": f"{tool} does not currently support {investigation.ioc_type}"
                }
        else:
            results[tool] = {
                "status": "pending",
                "message": f"{tool} integration not implemented yet"
            }

    investigation.results = results

    return investigation