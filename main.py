from detector.ioc_detector import detect_ioc_type
from models.investigation_model import Investigation
from agent.investigation_agent import create_investigation_plan
from tools.tool_executor import execute_tools


def main():
    print("=" * 60)
    print("       AI Threat Intelligence Investigation Tool")
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
    print("TOOL STATUS")
    print("-" * 60)

    for tool, result in investigation.results.items():
        status = result.get("status", "unknown").upper()
        print(f"{tool:<15} {status}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()