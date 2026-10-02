"""
Synthetic test data that passes the validators (for the Lab, policy testing and the test suite).

Every value is randomly generated with correct check digits; none belongs to a real person.
Payment cards use issuer prefixes but random account digits.
"""

from __future__ import annotations

import random
import string
from typing import Callable, Dict, List, Optional

from src.detection import validators as V

_rng = random.SystemRandom()


def _digits(n: int) -> str:
    return "".join(_rng.choice(string.digits) for _ in range(n))


def _luhn_complete(body: str) -> str:
    for c in string.digits:
        if V.luhn_any(body + c):
            return body + c
    raise AssertionError


CARD_BRANDS = {
    "visa": ("4", 16), "mastercard": ("5" + str(_rng.randint(1, 5)), 16), "amex": ("37", 15),
    "discover": ("6011", 16), "jcb": ("3530", 16), "diners": ("36", 14), "unionpay": ("62", 16),
    "rupay": ("60", 16),
}


def payment_card(brand: Optional[str] = None, formatted: bool = True) -> str:
    brand = (brand or _rng.choice(list(CARD_BRANDS))).lower()
    prefix, length = CARD_BRANDS.get(brand, CARD_BRANDS["visa"])
    if brand == "mastercard":
        prefix = "5" + str(_rng.randint(1, 5))
    num = _luhn_complete(prefix + _digits(length - len(prefix) - 1))
    if not formatted:
        return num
    if length == 15:
        return f"{num[:4]} {num[4:10]} {num[10:]}"
    return " ".join(num[i:i + 4] for i in range(0, length, 4))


def luhn_number(length: int = 16, prefix: str = "") -> str:
    length = max(length, len(prefix) + 2)
    return _luhn_complete(prefix + _digits(length - len(prefix) - 1))


def aadhaar() -> str:
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    body = str(_rng.randint(2, 9)) + _digits(10)
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = V._VD[c][V._VP[(i + 1) % 8][int(ch)]]
    n = body + str(inv[c])
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def verhoeff_number(length: int = 10) -> str:
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    body = _digits(length - 1)
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = V._VD[c][V._VP[(i + 1) % 8][int(ch)]]
    return body + str(inv[c])


_IBAN_BBAN = {"GB": "{4L}{14D}", "DE": "{18D}", "FR": "{23D}", "NL": "{4L}{10D}", "ES": "{20D}", "IT": "{1L}{22D}"}


def iban(country: str = "GB", formatted: bool = True) -> str:
    country = country.upper() if country.upper() in V._IBAN_LENGTHS else "GB"
    total = V._IBAN_LENGTHS[country] - 4
    template = _IBAN_BBAN.get(country, "{%dD}" % total)
    bban = ""
    for count, kind in ((int(m[1:-2]), m[-2]) for m in __import__("re").findall(r"\{\d+[LD]\}", template)):
        bban += "".join(_rng.choice(string.ascii_uppercase if kind == "L" else string.digits) for _ in range(count))
    bban = bban[:total].ljust(total, "0")
    num = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    value = f"{country}{98 - int(num) % 97:02d}{bban}"
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4)) if formatted else value


def _mod97_number(length: int = 12) -> str:
    body = _digits(length - 2)
    return body + f"{98 - (int(body) * 100) % 97:02d}"


def us_ssn() -> str:
    while True:
        area = _rng.randint(1, 899)
        if area != 666:
            v = f"{area:03d}-{_rng.randint(1, 99):02d}-{_rng.randint(1, 9999):04d}"
            if V.us_ssn(v):
                return v


def aba_routing() -> str:
    while True:
        v = _digits(9)
        if V.aba_routing(v):
            return v


def ca_sin() -> str:
    n = luhn_number(9, str(_rng.randint(1, 7)))
    return f"{n[:3]} {n[3:6]} {n[6:]}"


def uk_nhs() -> str:
    while True:
        body = _digits(9)
        check = 11 - sum(int(x) * w for x, w in zip(body, range(10, 1, -1))) % 11
        check = 0 if check == 11 else check
        if check != 10:
            n = body + str(check)
            return f"{n[:3]} {n[3:6]} {n[6:]}"


def br_cpf() -> str:
    d = _digits(9)
    for n in (9, 10):
        total = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        d += str((total * 10) % 11 % 10)
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


def es_dni() -> str:
    n = _rng.randint(10_000_000, 99_999_999)
    return f"{n}{V._DNI_LETTERS[n % 23]}"


def au_tfn() -> str:
    while True:
        v = _digits(9)
        if V.au_tfn(v):
            return f"{v[:3]} {v[3:6]} {v[6:]}"


def cn_resident_id() -> str:
    year = _rng.randint(1950, 2005)
    body = f"110105{year}{_rng.randint(1, 12):02d}{_rng.randint(1, 28):02d}{_digits(3)}"
    total = sum(int(ch) * pow(2, 17 - i, 11) for i, ch in enumerate(body))
    check = (12 - total % 11) % 11
    return body + ("X" if check == 10 else str(check))


def imei() -> str:
    return luhn_number(15, "35")


def gstin() -> str:
    pan = "".join(_rng.choice(string.ascii_uppercase) for _ in range(3)) + "P" + _rng.choice(string.ascii_uppercase) + _digits(4) + _rng.choice(string.ascii_uppercase)
    body = f"{_rng.randint(1, 37):02d}{pan}1Z"
    total = 0
    for i, ch in enumerate(body):
        v = V._GSTIN_CHARS.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return body + V._GSTIN_CHARS[(36 - total % 36) % 36]


GENERATORS: Dict[str, Callable[..., str]] = {
    "payment_card": payment_card, "luhn": lambda: luhn_number(16), "luhn_any": luhn_number,
    "aadhaar": aadhaar, "verhoeff": verhoeff_number, "iban": iban, "iso7064_mod97": lambda: _mod97_number(),
    "us_ssn": us_ssn, "aba_routing": aba_routing, "ca_sin": ca_sin, "uk_nhs": uk_nhs, "br_cpf": br_cpf,
    "es_dni": es_dni, "au_tfn": au_tfn, "iso7064_mod11_2": cn_resident_id, "gstin": gstin,
}

# Detector name -> generator (for "generate samples for this detector")
DETECTOR_GENERATORS: Dict[str, Callable[..., str]] = {
    "CREDIT_CARD": payment_card, "IBAN": iban, "US_SSN": us_ssn, "US_BANK_ROUTING": aba_routing,
    "CA_SIN": ca_sin, "IN_AADHAAR": aadhaar, "IN_GSTIN": gstin, "UK_NHS_NUMBER": uk_nhs, "BR_CPF": br_cpf,
    "ES_DNI": es_dni, "AU_TFN": au_tfn, "CN_RESIDENT_ID": cn_resident_id, "IMEI": imei,
}


def generate(kind: str, count: int = 5, **kwargs) -> List[str]:
    fn = GENERATORS.get(kind) or DETECTOR_GENERATORS.get(kind)
    if fn is None:
        raise KeyError(kind)
    count = max(1, min(int(count), 50))
    return [fn(**kwargs) if kwargs else fn() for _ in range(count)]
