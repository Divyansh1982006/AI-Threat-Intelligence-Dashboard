import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1"


def get_indicator(ioc_type, indicator_type, value):

    if not API_KEY:
        return {
            "status": "error",
            "message": "OTX API key not configured"
        }

    url = f"{BASE_URL}/indicators/{ioc_type}/{value}/general"

    headers = {
        "X-OTX-API-KEY": API_KEY
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code >= 500:
            return {
                "status": "unavailable",
                "message": "OTX server temporarily unavailable"
            }

        if response.status_code == 401:
            return {
                "status": "error",
                "message": "OTX API key is invalid"
            }

        if response.status_code == 403:
            return {
                "status": "error",
                "message": "OTX access forbidden"
            }

        response.raise_for_status()

        data = response.json()
        pulse_info = data.get("pulse_info", {})

        return {
            "status": "success",
            "ioc": value,
            "ioc_type": indicator_type,
            "pulse_count": pulse_info.get("count", 0),
            "reputation": data.get("reputation"),
            "country": data.get("country_name"),
            "asn": data.get("asn"),
            "city": data.get("city"),
            "continent": data.get("continent_code")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }


def check_ip(ip):
    return get_indicator("IPv4", "IP", ip)


def check_domain(domain):
    return get_indicator("domain", "DOMAIN", domain)


def check_url(url):
    return get_indicator("URL", "URL", url)


def check_hash(file_hash):
    return get_indicator("file", "HASH", file_hash)


def check_email(email):
    return get_indicator("email", "EMAIL", email)