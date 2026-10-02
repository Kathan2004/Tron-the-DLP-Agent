"""
Checksum and structure validators for detector candidates.

A regex only finds strings that *look* like an identifier; these functions decide
whether a candidate is actually valid, which is what removes most false positives
(random 12-digit numbers are not Aadhaar numbers, random 16-digit IDs are not cards).

Every validator takes the matched string and returns bool. They are mirrored in
browser-extension/detectors.js; keep both in sync (tests/test_detection.py checks parity).
"""

import base64
import json
import math
import re
from collections import Counter

_NON_DIGIT = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")


def digits_only(value: str) -> str:
    return _NON_DIGIT.sub("", value or "")


def luhn(value: str) -> bool:
    digits = digits_only(value)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def payment_card(value: str) -> bool:
    """Luhn + a known issuer prefix (IIN) with a length that issuer uses."""
    d = digits_only(value)
    if len(set(d)) == 1 or not luhn(d):
        return False
    n = len(d)
    p2, p3, p4, p6 = int(d[:2]), int(d[:3]), int(d[:4]), int(d[:6])
    if d[0] == "4":
        return n in (13, 16, 19)                                  # Visa
    if 51 <= p2 <= 55 or 222100 <= p6 <= 272099:
        return n == 16                                            # Mastercard
    if p2 in (34, 37):
        return n == 15                                            # Amex
    if p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925:
        return 16 <= n <= 19                                      # Discover
    if 3528 <= p4 <= 3589:
        return 16 <= n <= 19                                      # JCB
    if 300 <= p3 <= 305 or p2 in (36, 38, 39) or p4 == 3095:
        return 14 <= n <= 19                                      # Diners
    if p2 == 62 or p2 == 81:
        return 16 <= n <= 19                                      # UnionPay
    if p4 in (5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763):
        return 12 <= n <= 19                                      # Maestro
    if d[:2] in ("60", "65", "81", "82") or d[:3] in ("508", "353", "356"):
        return n == 16                                            # RuPay
    return False


# Verhoeff tables (Aadhaar check digit)
_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff(value: str) -> bool:
    d = digits_only(value)
    if not d:
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _VD[c][_VP[i % 8][ord(ch) - 48]]
    return c == 0


def aadhaar(value: str) -> bool:
    d = digits_only(value)
    return len(d) == 12 and d[0] not in "01" and len(set(d)) > 2 and verhoeff(d)


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


def iban(value: str) -> bool:
    s = _NON_ALNUM.sub("", value or "").upper()
    if _IBAN_LENGTHS.get(s[:2]) != len(s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(num) % 97 == 1


def us_ssn(value: str) -> bool:
    d = digits_only(value)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    if area in ("000", "666") or area[0] == "9" or group == "00" or serial == "0000":
        return False
    # Well-known invalid / advertising numbers
    return d not in {"078051120", "219099999"}


def aba_routing(value: str) -> bool:
    d = digits_only(value)
    if len(d) != 9 or d == "000000000":
        return False
    w = (3, 7, 1) * 3
    return sum(int(x) * y for x, y in zip(d, w)) % 10 == 0


def ca_sin(value: str) -> bool:
    d = digits_only(value)
    if len(d) != 9:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin(value: str) -> bool:
    s = (value or "").upper()
    if len(s) != 15:
        return False
    total = 0
    for i, ch in enumerate(s[:14]):
        v = _GSTIN_CHARS.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return _GSTIN_CHARS[(36 - total % 36) % 36] == s[14]


def jwt(value: str) -> bool:
    """Header must decode to JSON with an "alg" field."""
    try:
        head = value.split(".", 1)[0]
        head += "=" * (-len(head) % 4)
        return "alg" in json.loads(base64.urlsafe_b64decode(head))
    except Exception:
        return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|-+|_+|0+|changeme|change[-_]?me|password|passwd|secret|example|sample|test|dummy|"
    r"redacted|null|none|undefined|true|false|todo|tbd|placeholder)$"
    r"|^(?:your|my|insert|enter|replace)[-_ ]|^<.*>$|^\$\{.*\}$|^\{\{.*\}\}$|^%\(.*\)s$|^\$[A-Z_]+$",
    re.IGNORECASE,
)


def not_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("'\"")
    return len(v) >= 6 and not _PLACEHOLDER.search(v)


_DOTTED_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")
_URL_PASSWORD = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]+:([^@\s]+)@", re.IGNORECASE)
_PLACEHOLDER_PASSWORDS = {"pass", "pwd", "password", "passwd", "secret", "changeme", "xxx", "xxxx",
                          "****", "user", "username", "example", "test", "dummy"}


def high_entropy_secret(value: str) -> bool:
    """Assigned secret value: not a placeholder, mixed charset, entropy >= 3.5 bits/char."""
    v = (value or "").strip().strip("'\"")
    if not not_placeholder(v) or len(v) < 16 or _DOTTED_IDENTIFIER.match(v):
        return False
    if v.isalpha() and len(v) < 32:   # identifiers like helperFunctionName, not secrets
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes >= 2 and shannon_entropy(v) >= 3.5


def url_credentials(value: str) -> bool:
    """URL with user:password@ where the password is not an obvious placeholder."""
    m = _URL_PASSWORD.match(value or "")
    if not m:
        return False
    pw = m.group(1)
    return pw.lower() not in _PLACEHOLDER_PASSWORDS and not _PLACEHOLDER.search(pw)


VALIDATORS = {
    "luhn": luhn,
    "payment_card": payment_card,
    "aadhaar": aadhaar,
    "iban": iban,
    "us_ssn": us_ssn,
    "aba_routing": aba_routing,
    "ca_sin": ca_sin,
    "gstin": gstin,
    "jwt": jwt,
    "not_placeholder": not_placeholder,
    "high_entropy_secret": high_entropy_secret,
    "url_credentials": url_credentials,
}
