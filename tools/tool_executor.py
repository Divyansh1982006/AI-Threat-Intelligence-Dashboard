from models.investigation_model import Investigation


def execute_tools(investigation: Investigation) -> Investigation:
    results = {}

    for tool in investigation.investigation_plan:
        results[tool] = {
            "status": "pending",
            "message": f"{tool} integration not implemented yet"
        }

    investigation.results = results

    return investigation