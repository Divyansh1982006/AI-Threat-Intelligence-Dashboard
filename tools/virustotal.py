import os
import requests
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_ip(ip):
    if not API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "success",
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }