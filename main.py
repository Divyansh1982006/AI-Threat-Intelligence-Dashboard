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
                print(f"IP               : {result.get('ip')}")
                print(f"Malicious        : {result.get('malicious')}")
                print(f"Suspicious       : {result.get('suspicious')}")
                print(f"Harmless         : {result.get('harmless')}")
                print(f"Undetected       : {result.get('undetected')}")
                print(f"Reputation       : {result.get('reputation')}")
                print(f"Country          : {result.get('country')}")
                print(f"AS Owner         : {result.get('as_owner')}")
                print(f"Network          : {result.get('network')}")

        elif result.get("status") == "pending":
            print("Status           : PENDING")

        else:
            print("Status           : ERROR")
            print(f"Message          : {result.get('message')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()