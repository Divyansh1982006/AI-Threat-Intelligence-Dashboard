from detector.ioc_detector import detect_ioc_type
from models.investigation_model import Investigation
def main():
    print("=" * 60)
    print("       AI Threat Intelligence Investigation Tool       ")
    print("=" * 60)

    ioc = input("\nEnter IOC: ")

    ioc_type = detect_ioc_type(ioc)

    investigation = Investigation(ioc=ioc, ioc_type=ioc_type.value)

    print(f"\nIOC              : {investigation.ioc}")
    print(f"IOC Type         : {investigation.ioc_type}")
    print(f"Threat Score     : {investigation.threat_score}")
    print(f"Severity         : {investigation.severity}")

if __name__ == "__main__":
    main()