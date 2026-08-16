import os
import requests
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE)

API_KEY = os.getenv("SHODAN_API_KEY")

BASE_URL = "https://api.shodan.io"


def check_ip(ip):
    if not API_KEY:
        return {
            "status": "error",
            "message": "Shodan API key not configured"
        }

    url = f"{BASE_URL}/shodan/host/{ip}"

    params = {
        "key": API_KEY
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        services = []

        for item in data.get("data", []):

            service = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data"),
                "ssl": item.get("ssl")
            }

            services.append(service)

        return {
            "status": "success",
            "ioc": ip,
            "ioc_type": "IP",

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