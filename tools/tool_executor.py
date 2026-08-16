from models.investigation_model import Investigation

from tools.abuseipdb import check_ip as abuseipdb_check

from tools.virustotal import (
    check_ip as virustotal_ip,
    check_domain as virustotal_domain,
    check_url as virustotal_url,
    check_hash as virustotal_hash
)

from tools.otx import (
    check_ip as otx_ip,
    check_domain as otx_domain,
    check_url as otx_url,
    check_hash as otx_hash
)

from tools.shodan import check_ip as shodan_ip


TOOL_HANDLERS = {
    "AbuseIPDB": {
        "IP": abuseipdb_check
    },

    "VirusTotal": {
        "IP": virustotal_ip,
        "DOMAIN": virustotal_domain,
        "URL": virustotal_url,
        "MD5": virustotal_hash,
        "SHA1": virustotal_hash,
        "SHA256": virustotal_hash
    },

    "OTX": {
        "IP": otx_ip,
        "DOMAIN": otx_domain,
        "URL": otx_url,
        "MD5": otx_hash,
        "SHA1": otx_hash,
        "SHA256": otx_hash
    },

    "Shodan": {
        "IP": shodan_ip
    }
}


def execute_tools(investigation: Investigation) -> Investigation:

    results = {}

    for tool in investigation.investigation_plan:

        # Check whether the tool exists
        if tool not in TOOL_HANDLERS:
            results[tool] = {
                "status": "pending",
                "message": f"{tool} integration not implemented yet"
            }
            continue

        # Check whether this IOC type is supported by the tool
        if investigation.ioc_type not in TOOL_HANDLERS[tool]:
            results[tool] = {
                "status": "unsupported",
                "message": (
                    f"{tool} does not currently support "
                    f"{investigation.ioc_type}"
                )
            }
            continue

        # Execute the correct function
        handler = TOOL_HANDLERS[tool][investigation.ioc_type]

        results[tool] = handler(investigation.ioc)

    investigation.results = results

    return investigation