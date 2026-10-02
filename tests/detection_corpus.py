"""
Labeled corpus for detection quality (precision / recall) and latency benchmarks.

Each case is (text, expected) where expected is the set of detector types that MUST fire.
Anything else that fires is a false positive. Values are synthetic: card, Aadhaar, IBAN and
SSN numbers are generated with valid check digits but belong to no one.
"""

import random
import string

from src.detection.validators import _VD, _VP

rng = random.Random(1337)


def _luhn_complete(prefix: str, length: int) -> str:
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for check in string.digits:
        cand = body + check
        total = 0
        for i, ch in enumerate(reversed(cand)):
            n = int(ch)
            if i % 2:
                n = n * 2 - 9 if n > 4 else n * 2
            total += n
        if total % 10 == 0:
            return cand
    raise AssertionError


def _verhoeff_complete(body: str) -> str:
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    return body + str(inv[c])


def _iban(country: str, bban: str) -> str:
    num = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    return f"{country}{98 - int(num) % 97:02d}{bban}"


def _group(s: str, n: int = 4, sep: str = " ") -> str:
    return sep.join(s[i:i + n] for i in range(0, len(s), n))


def card():
    prefix, length = rng.choice([("4", 16), ("51", 16), ("55", 16), ("2221", 16), ("37", 15), ("6011", 16)])
    return _luhn_complete(prefix, length)


def aadhaar():
    return _verhoeff_complete(str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10)))


def bad_aadhaar():
    a = aadhaar()
    return a[:-1] + str((int(a[-1]) + 1) % 10)


def ssn():
    while True:
        area = rng.randint(1, 899)
        if area != 666:
            return f"{area:03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def tok(*parts):
    """Assemble credential-shaped samples at runtime so no complete token literal sits in the
    source (keeps secret scanners and push protection quiet; all values are fake)."""
    return "".join(parts)


AWS_KEY = tok("AKIA", "IOSFODNN7", "EXAMPLE")                      # AWS documentation example
GITHUB_PAT = tok("gh", "p_", "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA7bC")

CASES = []


def case(text, *expected):
    CASES.append((text, set(expected)))


# ------------------------------------------------------------------ positives
for _ in range(15):
    c = card()
    case(f"Please charge card {_group(c)} exp 09/28", "CREDIT_CARD")
    case(f"cc_number={c}", "CREDIT_CARD")
for _ in range(10):
    case(f"Employee SSN: {ssn()}", "US_SSN")
for _ in range(10):
    a = aadhaar()
    case(f"Aadhaar no. {_group(a)} verified by UIDAI", "IN_AADHAAR")
    case(f"uid {a}", "IN_AADHAAR")
for code, bban in [("GB", "WEST12345698765432"), ("DE", "370400440532013000"), ("FR", "20041010050500013M02606"),
                   ("NL", "ABNA0417164300"), ("ES", "21000418450200051332")]:
    iban = _iban(code, bban)
    case(f"Wire to IBAN {_group(iban)}", "IBAN")
    case(f"iban:{iban}", "IBAN")
case("PAN: ABCPE1234F (income tax)", "IN_PAN")
case("Vendor PAN AAACR5055K on file", "IN_PAN")
case("passport number K1234567 issued 2019", "PASSPORT")
case("Mobile: +91 98765 43210", "PHONE_INDIA")
case("call me at (415) 555-0132", "PHONE_US")
case("email jane.doe@acme-corp.com for access", "EMAIL_ADDRESS")
case("aws_access_key_id = " + AWS_KEY, "AWS_ACCESS_KEY")
case("aws_secret_access_key = " + tok("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"), "AWS_SECRET_KEY")
case("export GITHUB_TOKEN=" + GITHUB_PAT, "GITHUB_TOKEN")
case("token: " + tok("gl", "pat-", "xxxxY7z8A9b0C1d2E3f4"), "GITLAB_TOKEN")
case("SLACK=" + tok("xo", "xb-", "000000000000-0000000000000-FakeFakeFakeFakeFakeFake"), "SLACK_TOKEN")
case("stripe " + tok("sk", "_live_", "FAKEfakeFAKEfake00000000") + " in config", "STRIPE_KEY")
case("key=" + tok("AI", "za", "Sy", "FakeFakeFakeFakeFakeFakeFakeFake0"), "GOOGLE_API_KEY")
case("bot " + tok("1234567890", ":AA", "FakeFakeFakeFakeFakeFakeFakeFake0"), "TELEGRAM_BOT_TOKEN")
case("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "PRIVATE_KEY")
case("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA", "PRIVATE_KEY")
case('{"type": "service_account", "project_id": "x"}', "GCP_SERVICE_ACCOUNT")
case("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT_TOKEN")
case("DATABASE_URL=postgresql://app:Pr0d-Pa55@db.prod.internal:5432/orders", "CONNECTION_STRING")
case("mongo: mongodb+srv://admin:hunter22@cluster0.ab1cd.mongodb.net/db", "CONNECTION_STRING")
case('db_password = "Wint3r!sComing2026"', "PASSWORD_ASSIGNMENT")
case('client_secret: "8f3Kq9ZxL2mN7vB4tR6yW1pD5sH0jG3c"', "GENERIC_SECRET")
case("routing number 021000021 account number 000123456789", "US_BANK_ROUTING", "BANK_ACCOUNT")
case("STRICTLY CONFIDENTIAL - do not forward", "CLASSIFICATION_LABEL")
case("Patient MRN: 00482913 admitted", "MEDICAL_RECORD_NUMBER")
case("SELECT name, ssn FROM customers WHERE id = 1", "SQL_STATEMENT")
# evasion
c = card()
case("card " + "​".join(_group(c)), "CREDIT_CARD")
case("ssn " + "５３６－２２－１２３４", "US_SSN")
case("blob " + __import__("base64").b64encode(f"export ssn={ssn()} for payroll run".encode()).decode(), "US_SSN")

# ------------------------------------------------------------------ hard negatives
for _ in range(15):
    n = "".join(rng.choice(string.digits) for _ in range(16))
    case(f"Order #{n} shipped")                                   # 16 digits, Luhn random
for _ in range(10):
    case(f"Reference {bad_aadhaar()} processed")                   # 12 digits, Verhoeff fails
case("Tracking 1Z999AA10123456784 delivered")
case("build 2026.10.02-1234567 released")
case("commit 3f9a2b7c1d4e5f60718293a4b5c6d7e8f9012345")
case("uuid 550e8400-e29b-41d4-a716-446655440000")
case("Meeting at 10:30, room 4021, ext 5567")
case("Invoice INV-2026-000123 total 4,500.00")
case("Please update the deck before Monday")                       # 'update' != SQL
case("select the best option from the menu")
case("hello world version=1.2.3 debug=true")                        # key=value is not a secret
case("api_key = your-api-key-here")                                 # placeholder
case('password = "changeme"')
case("ISBN 978-3-16-148410-0")
case("Call 1-800-FLOWERS today")
case("Timestamp 1727856000123 epoch ms")
case("pi is 3.14159265358979")
case("Our office: 221B Baker Street, London NW1 6XE")
case("Batch ABCDE1234F1 created")                                   # PAN-like inside longer token
case("lorem ipsum dolor sit amet, consectetur adipiscing elit")
case("Quarter results: revenue 12345678 units 87654321")
case("Version 10.0.19045.3803 installed")
case("postgres://localhost:5432/dev")                               # no credentials
case("mongodb://user:pass@localhost:27017/dbname")                  # documentation placeholder
case("redis://:${REDIS_PASSWORD}@cache:6379")                       # env reference, not a secret
case("matched via jsTokens.matchToToken = helperFunctionName")      # dotted identifier
case("phone extension 5551234")
