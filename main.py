from detector.ioc_detector import detect_ioc_type
from models.investigation_model import Investigation
from agent.investigation_agent import create_investigation_plan
from tools.tool_executor import execute_tools


def main():
    print("=" * 60)
    print("       AI THREAT INTELLIGENCE INVESTIGATION TOOL")
    print("=" * 60)

    ioc = input("\nEnter IOC: ").strip()

    if not ioc:
        print("\n[!] IOC cannot be empty.")
        return

    ioc_type = detect_ioc_type(ioc)

    if ioc_type is None:
        print("\n[!] Unable to identify IOC type.")
        return

    investigation = Investigation(
        ioc=ioc,
        ioc_type=ioc_type.value
    )

    investigation = create_investigation_plan(investigation)
    investigation = execute_tools(investigation)

    print("\n" + "=" * 60)
    print("                 INVESTIGATION")
    print("=" * 60)

    print(f"IOC       : {investigation.ioc}")
    print(f"Type      : {investigation.ioc_type}")
    print(f"Risk      : {investigation.threat_score}")
    print(f"Severity  : {investigation.severity}")

    print("\n" + "-" * 60)
    print("INVESTIGATION PLAN")
    print("-" * 60)

    for tool in investigation.investigation_plan:
        print(f"[+] {tool}")

    print("\n" + "-" * 60)
    print("THREAT INTELLIGENCE")
    print("-" * 60)

    for tool, result in investigation.results.items():

        print(f"\n[{tool}]")

        if result.get("status") == "success":

            if tool == "AbuseIPDB":
                print(f"IP               : {result.get('ip')}")
                print(f"Abuse Confidence : {result.get('abuse_confidence')}%")
                print(f"Country          : {result.get('country')}")
                print(f"ISP              : {result.get('isp')}")
                print(f"Domain           : {result.get('domain')}")
                print(f"Usage Type       : {result.get('usage_type')}")
                print(f"Total Reports    : {result.get('total_reports')}")
                print(f"Distinct Users   : {result.get('distinct_users')}")
                print(f"Tor              : {result.get('is_tor')}")
                print(f"Whitelisted      : {result.get('is_whitelisted')}")
                print(f"Last Reported    : {result.get('last_reported')}")

            elif tool == "VirusTotal":
                print(f"IOC              : {result.get('ioc')}")
                print(f"IOC Type         : {result.get('ioc_type')}")
                print(f"Malicious        : {result.get('malicious')}")
                print(f"Suspicious       : {result.get('suspicious')}")
                print(f"Harmless         : {result.get('harmless')}")
                print(f"Undetected       : {result.get('undetected')}")
                print(f"Reputation       : {result.get('reputation')}")

            elif tool == "MalwareBazaar":
                print(f"Hash             : {result.get('hash')}")
                print(f"File Name        : {result.get('file_name')}")
                print(f"File Type        : {result.get('file_type')}")
                print(f"Signature        : {result.get('signature')}")
                print(f"First Seen       : {result.get('first_seen')}")
                print(f"Last Seen        : {result.get('last_seen')}")
                print(f"Tags             : {result.get('tags')}")
                print(f"Delivery Method  : {result.get('delivery_method')}")

            elif tool == "OTX":
                print(f"IOC              : {result.get('ioc')}")
                print(f"Pulse Count      : {result.get('pulse_count')}")
                print(f"Reputation       : {result.get('reputation')}")
                print(f"Country          : {result.get('country')}")
                print(f"ASN              : {result.get('asn')}")
                print(f"City             : {result.get('city')}")
                print(f"Continent        : {result.get('continent')}")

            elif tool == "GeoIP":
                print(f"IP               : {result.get('ip')}")
                print(f"Country          : {result.get('country')}")
                print(f"Region           : {result.get('region')}")
                print(f"City             : {result.get('city')}")
                print(f"Latitude         : {result.get('latitude')}")
                print(f"Longitude        : {result.get('longitude')}")
                print(f"Timezone         : {result.get('timezone')}")
                print(f"ISP              : {result.get('isp')}")
                print(f"Organization     : {result.get('organization')}")
                print(f"ASN              : {result.get('asn')}")

            elif tool == "WHOIS":
                print(f"Domain           : {result.get('domain')}")
                print(f"Registrar        : {result.get('registrar')}")
                print(f"Creation Date    : {result.get('creation_date')}")
                print(f"Expiry Date      : {result.get('expiration_date')}")
                print(f"Nameservers      : {result.get('name_servers')}")
                print(f"Domain Status    : {result.get('status_info')}")

            elif tool == "DNS":
                print(f"Domain           : {result.get('domain')}")

                for record_type, values in result.get("records", {}).items():
                    print(f"{record_type:<17}: {values}")

            elif tool == "Shodan":
                print(f"Country          : {result.get('country')}")
                print(f"City             : {result.get('city')}")
                print(f"Organization     : {result.get('organization')}")
                print(f"ISP              : {result.get('isp')}")
                print(f"ASN              : {result.get('asn')}")
                print(f"Open Ports       : {result.get('open_ports')}")

                print("\nServices:")

                for service in result.get("services", []):
                    print(
                        f"  Port {service.get('port')} | "
                        f"{service.get('transport')} | "
                        f"{service.get('product') or ''} "
                        f"{service.get('version') or ''}"
                    )

                    if service.get("banner"):
                        print(f"    Banner : {service.get('banner')}")

                    if service.get("ssl"):
                        print("    SSL    : Available")

        elif result.get("status") == "pending":
            print("Status           : PENDING")

        elif result.get("status") == "not_found":
            print("Status           : NOT FOUND")
            print(f"Message          : {result.get('message')}")

        else:
            print("Status           : ERROR")
            print(f"Message          : {result.get('message')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()