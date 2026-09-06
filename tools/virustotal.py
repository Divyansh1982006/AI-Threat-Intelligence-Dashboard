# import os
# import base64
# import requests
# from dotenv import load_dotenv


# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# ENV_FILE = os.path.join(BASE_DIR, ".env")

# load_dotenv(ENV_FILE)

# API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# BASE_URL = "https://www.virustotal.com/api/v3"

# HEADERS = {
#     "x-apikey": API_KEY,
#     "Accept": "application/json"
# }


# def _request(endpoint):
#     if not API_KEY:
#         return {
#             "status": "error",
#             "message": "VirusTotal API key not configured"
#         }

#     try:
#         response = requests.get(
#             f"{BASE_URL}/{endpoint}",
#             headers=HEADERS,
#             timeout=10
#         )

#         response.raise_for_status()

#         return response.json()

#     except requests.RequestException as error:
#         return {
#             "status": "error",
#             "message": str(error)
#         }


# def _analysis_result(ioc, ioc_type, data):
#     attributes = data.get("data", {}).get("attributes", {})
#     stats = attributes.get("last_analysis_stats", {})

#     return {
#         "status": "success",
#         "ioc": ioc,
#         "ioc_type": ioc_type,
#         "malicious": stats.get("malicious", 0),
#         "suspicious": stats.get("suspicious", 0),
#         "harmless": stats.get("harmless", 0),
#         "undetected": stats.get("undetected", 0),
#         "reputation": attributes.get("reputation")
#     }


# def check_ip(ip):
#     result = _request(f"ip_addresses/{ip}")

#     if result.get("status") == "error":
#         return result

#     return _analysis_result(ip, "IP", result)


# def check_domain(domain):
#     result = _request(f"domains/{domain}")

#     if result.get("status") == "error":
#         return result

#     return _analysis_result(domain, "DOMAIN", result)


# def check_hash(file_hash):
#     result = _request(f"files/{file_hash}")

#     if result.get("status") == "error":
#         return result

#     return _analysis_result(file_hash, "HASH", result)


# def check_url(url):
#     url_id = base64.urlsafe_b64encode(
#         url.encode()
#     ).decode().strip("=")

#     result = _request(f"urls/{url_id}")

#     if result.get("status") == "error":
#         return result

#     return _analysis_result(url, "URL", result)

import os
import time
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


def _submit_url_for_scan(url, poll_attempts=6, poll_delay_seconds=2):
    """VirusTotal only has data for a URL if SOMEONE has previously
    submitted it for scanning -- GET /urls/{id} 404s on any URL that
    has never been scanned before, which is common for smaller/newer
    sites. This submits the URL for a fresh scan and polls until it
    completes, so a 404 doesn't get mistaken for a system error."""

    try:
        submit_response = requests.post(
            f"{BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=10,
        )
        submit_response.raise_for_status()
        analysis_id = submit_response.json()["data"]["id"]
    except requests.RequestException as error:
        return {"status": "error", "message": f"Failed to submit URL for scanning: {error}"}
    except (KeyError, ValueError):
        return {"status": "error", "message": "Unexpected response when submitting URL for scanning"}

    for _ in range(poll_attempts):
        try:
            poll_response = requests.get(
                f"{BASE_URL}/analyses/{analysis_id}",
                headers=HEADERS,
                timeout=10,
            )
            poll_response.raise_for_status()
            poll_data = poll_response.json()
        except requests.RequestException as error:
            return {"status": "error", "message": f"Failed to poll scan status: {error}"}

        attributes = poll_data.get("data", {}).get("attributes", {})

        if attributes.get("status") == "completed":
            # Reshape to look like a normal /urls/{id} success response
            # so it can flow through _analysis_result() unchanged.
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": attributes.get("stats", {}),
                        "reputation": None,
                    }
                }
            }

        time.sleep(poll_delay_seconds)

    return {
        "status": "pending",
        "message": (
            "URL was submitted for scanning but analysis did not complete "
            "within the polling window -- try again in a minute."
        ),
    }


def check_url(url):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    result = _request(f"urls/{url_id}")

    if result.get("status") == "error" and "404" in result.get("message", ""):
        result = _submit_url_for_scan(url)

    if result.get("status") in ("error", "pending"):
        return result

    return _analysis_result(url, "URL", result)