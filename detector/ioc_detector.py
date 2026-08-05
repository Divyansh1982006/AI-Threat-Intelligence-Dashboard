import ipaddress
import re
from collections import OrderedDict
from enum import Enum


class IOCType(Enum):
    IP = "IP"
    URL = "URL"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "UNKNOWN"


IOC_PATTERNS = OrderedDict(
    {
        IOCType.URL: re.compile(
            r"^(https?|ftp)://[^\s/$.?#].[^\s]*$",
            re.IGNORECASE,
        ),
        IOCType.EMAIL: re.compile(
            r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        ),
        IOCType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
        IOCType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
        IOCType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
        IOCType.DOMAIN: re.compile(
            r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
        ),
    }
)


def is_ip(ioc: str) -> bool:
    try:
        ipaddress.ip_address(ioc)
        return True
    except ValueError:
        return False


def detect_ioc_type(ioc: str) -> IOCType:
    ioc = ioc.strip()

    if is_ip(ioc):
        return IOCType.IP

    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.fullmatch(ioc):
            return ioc_type

    return IOCType.UNKNOWN