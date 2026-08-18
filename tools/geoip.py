import requests


def check_ip(ip):

    url = f"http://ip-api.com/json/{ip}"

    params = {
        "fields": "status,message,country,regionName,city,lat,lon,timezone,isp,org,as"
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            return {
                "status": "error",
                "message": data.get("message", "GeoIP lookup failed")
            }

        return {
            "status": "success",
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }