import ipaddress
import re
from collections import OrderedDict
from enum import Enum
from urllib.parse import urlparse


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
        IOCType.EMAIL: re.compile(
            r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        ),
        IOCType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
        IOCType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
        IOCType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
        IOCType.DOMAIN: re.compile(
            r"^(?=.{1,253}$)"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}$"
        ),
    }
)


def is_ip(ioc: str) -> bool:
    try:
        ipaddress.ip_address(ioc)
        return True
    except ValueError:
        return False


def is_url(ioc: str) -> bool:
    try:
        parsed = urlparse(ioc)

        return (
            parsed.scheme.lower() in {"http", "https", "ftp"}
            and bool(parsed.netloc)
            and " " not in ioc
        )

    except ValueError:
        return False


def detect_ioc_type(ioc: str) -> IOCType:
    ioc = ioc.strip()

    if not ioc:
        return IOCType.UNKNOWN

    if is_ip(ioc):
        return IOCType.IP

    if is_url(ioc):
        return IOCType.URL

    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.fullmatch(ioc):
            return ioc_type

    return IOCType.UNKNOWN