import os
import base64
import requests
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json"
}


def _request(endpoint):
    if not API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    try:
        response = requests.get(
            f"{BASE_URL}/{endpoint}",
            headers=HEADERS,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }


def _analysis_result(ioc, ioc_type, data):
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "status": "success",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation")
    }


def check_ip(ip):
    result = _request(f"ip_addresses/{ip}")

    if result.get("status") == "error":
        return result

    return _analysis_result(ip, "IP", result)


def check_domain(domain):
    result = _request(f"domains/{domain}")

    if result.get("status") == "error":
        return result

    return _analysis_result(domain, "DOMAIN", result)


def check_hash(file_hash):
    result = _request(f"files/{file_hash}")

    if result.get("status") == "error":
        return result

    return _analysis_result(file_hash, "HASH", result)


def check_url(url):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    result = _request(f"urls/{url_id}")

    if result.get("status") == "error":
        return result

    return _analysis_result(url, "URL", result)