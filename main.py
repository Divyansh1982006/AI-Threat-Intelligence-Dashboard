from detector.ioc_detector import detect_ioc_type


def main():
    print("=" * 60)
    print("       IOC Identifier - Detects the type of Indicator of Compromise (IOC)")
    print("=" * 60)

    ioc = input("\nEnter IOC: ")

    ioc_type = detect_ioc_type(ioc)

    print(f"\nDetected IOC Type : {ioc_type.value}")


if __name__ == "__main__":
    main()