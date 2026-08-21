import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")
BASE_URL = "https://api.shodan.io"


def check_ip(ip):

    if not API_KEY:
        return {
            "status": "error",
            "message": "Shodan API key not configured"
        }

    url = f"{BASE_URL}/shodan/host/{ip}"

    try:
        response = requests.get(
            url,
            params={"key": API_KEY},
            timeout=10
        )

        if response.status_code == 401:
            return {
                "status": "error",
                "message": "Shodan API key is invalid or unauthorized"
            }

        if response.status_code == 403:
            return {
                "status": "error",
                "message": "Shodan access forbidden. Check API key/account permissions."
            }

        response.raise_for_status()

        data = response.json()

        services = []

        for service in data.get("data", []):
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
                "banner": service.get("data"),
                "ssl": bool(service.get("ssl"))
            })

        return {
            "status": "success",
            "country": data.get("country_name"),
            "city": data.get("city"),
            "organization": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "open_ports": data.get("ports", []),
            "services": services
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }