from models.investigation_model import Investigation
from tools.abuseipdb import check_ip


def execute_tools(investigation: Investigation) -> Investigation:
    results = {}

    for tool in investigation.investigation_plan:

        if tool == "AbuseIPDB" and investigation.ioc_type == "IP":
            results[tool] = check_ip(investigation.ioc)

        else:
            results[tool] = {
                "status": "pending",
                "message": f"{tool} integration not implemented yet"
            }

    investigation.results = results

    return investigation