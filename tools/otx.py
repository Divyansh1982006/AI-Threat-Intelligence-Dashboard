import os
import requests
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("OTX_API_KEY")

BASE_URL = "https://otx.alienvault.com/api/v1"

HEADERS = {
    "X-OTX-API-KEY": API_KEY,
    "Accept": "application/json"
}


def _request(endpoint):
    if not API_KEY:
        return {
            "status": "error",
            "message": "OTX API key not configured"
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


def _result(ioc, ioc_type, data):
    pulse_info = data.get("pulse_info", {})

    return {
        "status": "success",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "pulse_count": pulse_info.get("count", 0),
        "reputation": data.get("reputation"),
        "country": data.get("country_name"),
        "asn": data.get("asn"),
        "city": data.get("city"),
        "continent": data.get("continent_code")
    }


def check_ip(ip):
    data = _request(f"indicators/IPv4/{ip}/general")

    if data.get("status") == "error":
        return data

    return _result(ip, "IP", data)


def check_domain(domain):
    data = _request(f"indicators/domain/{domain}/general")

    if data.get("status") == "error":
        return data

    return _result(domain, "DOMAIN", data)


def check_url(url):
    data = _request(f"indicators/url/{url}/general")

    if data.get("status") == "error":
        return data

    return _result(url, "URL", data)


def check_hash(file_hash):
    data = _request(f"indicators/file/{file_hash}/general")

    if data.get("status") == "error":
        return data

    return _result(file_hash, "HASH", data)