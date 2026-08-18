import os
import requests
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_ip(ip):
    if not API_KEY:
        return {
            "status": "error",
            "message": "AbuseIPDB API key not configured"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
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
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
            "total_reports": data.get("totalReports"),
            "distinct_users": data.get("numDistinctUsers"),
            "last_reported": data.get("lastReportedAt")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }