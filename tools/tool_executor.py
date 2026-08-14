from models.investigation_model import Investigation
from tools.abuseipdb import check_ip as abuseipdb_check
from tools.virustotal import check_ip as virustotal_check


def execute_tools(investigation: Investigation) -> Investigation:
    results = {}

    for tool in investigation.investigation_plan:

        if tool == "AbuseIPDB" and investigation.ioc_type == "IP":
            results[tool] = abuseipdb_check(investigation.ioc)

        elif tool == "VirusTotal" and investigation.ioc_type == "IP":
            results[tool] = virustotal_check(investigation.ioc)

        else:
            results[tool] = {
                "status": "pending",
                "message": f"{tool} integration not implemented yet"
            }

    investigation.results = results

    return investigation