import os
import requests
from dotenv import load_dotenv

load_dotenv()


def check_ip(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "status": "error",
            "message": "ABUSEIPDB_API_KEY not configured"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "status": "success",
            "ip": data.get("ipAddress"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }