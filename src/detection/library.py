"""
Built-in detector library (data identifiers).

Each detector = regex candidate + optional validator + optional keyword proximity.
Patterns are restricted to syntax shared by Python `re` and JavaScript RegExp
(no inline flags, no named groups, fixed-width lookbehind only), because the
same definitions are exported to the browser extension
(scripts/build_extension_detectors.py -> browser-extension/detectors.js).

Fields:
  name            stable identifier, used in findings, policies and the console
  pattern         regex source
  ignore_case     compile case-insensitively (default False: identifiers are case-sensitive)
  group           capture group holding the sensitive value (0 = whole match)
  validator       name in validators.VALIDATORS; candidate is dropped if it fails
  keywords        context terms looked up within KEYWORD_WINDOW chars of the match
  require_keyword drop the candidate unless a keyword is nearby (for ambiguous formats)
  prefilter       literal substrings; the regex only runs if one is present (speed)
  generic         broad detector; loses overlaps to specific ones (e.g. GENERIC_SECRET vs GITHUB_TOKEN)
  severity        critical | high | medium | low
  confidence      base confidence; +KEYWORD_BOOST when a keyword is nearby
  category        PII | Financial | Credentials | Health | Classification | Source Code
"""

KEYWORD_WINDOW = 64
KEYWORD_BOOST = 0.10

_DIGIT_PREFILTER = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

DETECTORS = [
    # ---------------------------------------------------------------- Financial
    {
        "name": "CREDIT_CARD",
        "pattern": r"\d(?<![\d.-]\d)(?:[ -]?\d){11,18}(?!\d)",
        "validator": "payment_card",
        "keywords": ["card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "expiry", "exp", "ccn", "pan"],
        "prefilter": _DIGIT_PREFILTER,
        "severity": "critical", "confidence": 0.90, "category": "Financial",
        "description": "Payment card number (Luhn + issuer prefix validated)",
    },
    {
        "name": "IBAN",
        "pattern": r"[A-Z](?<!\w[A-Z])[A-Z]\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b",
        "validator": "iban",
        "keywords": ["iban", "bank", "account", "swift", "bic", "transfer"],
        "severity": "high", "confidence": 0.92, "category": "Financial",
        "description": "IBAN (mod-97 and country length validated)",
    },
    {
        "name": "US_BANK_ROUTING",
        "pattern": r"\d(?<!\w\d)\d{8}\b",
        "validator": "aba_routing",
        "keywords": ["routing", "aba", "rtn", "transit"],
        "require_keyword": True,
        "prefilter": _DIGIT_PREFILTER,
        "severity": "medium", "confidence": 0.75, "category": "Financial",
        "description": "US ABA routing number (checksum validated, keyword required)",
    },
    {
        "name": "BANK_ACCOUNT",
        "pattern": r"\d(?<!\w\d)\d{8,17}\b",
        "keywords": ["account number", "account no", "acct", "a/c", "bank account", "account #"],
        "require_keyword": True,
        "generic": True,
        "prefilter": _DIGIT_PREFILTER,
        "severity": "high", "confidence": 0.70, "category": "Financial",
        "description": "Bank account number (keyword required)",
    },
    # ---------------------------------------------------------------- PII (US / CA / UK)
    {
        "name": "US_SSN",
        "pattern": r"\d(?<!\w\d)\d{2}([- ])\d{2}\1\d{4}\b",
        "validator": "us_ssn",
        "keywords": ["ssn", "social security", "social sec", "tax id", "taxpayer"],
        "prefilter": _DIGIT_PREFILTER,
        "severity": "critical", "confidence": 0.90, "category": "PII",
        "description": "US Social Security Number (area/group/serial validated)",
    },
    {
        "name": "US_SSN_UNFORMATTED",
        "pattern": r"\d(?<!\w\d)\d{8}\b",
        "validator": "us_ssn",
        "keywords": ["ssn", "social security", "social sec"],
        "require_keyword": True,
        "prefilter": _DIGIT_PREFILTER,
        "severity": "critical", "confidence": 0.80, "category": "PII",
        "description": "US SSN without separators (keyword required)",
    },
    {
        "name": "US_ITIN",
        "pattern": r"9(?<!\w9)\d{2}[- ]?(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])[- ]?\d{4}\b",
        "keywords": ["itin", "taxpayer", "tax id"],
        "require_keyword": True,
        "prefilter": ["9"],
        "severity": "critical", "confidence": 0.80, "category": "PII",
        "description": "US Individual Taxpayer Identification Number (keyword required)",
    },
    {
        "name": "CA_SIN",
        "pattern": r"\d(?<!\w\d)\d{2}[- ]?\d{3}[- ]?\d{3}\b",
        "validator": "ca_sin",
        "keywords": ["sin", "social insurance"],
        "require_keyword": True,
        "prefilter": _DIGIT_PREFILTER,
        "severity": "critical", "confidence": 0.80, "category": "PII",
        "description": "Canadian Social Insurance Number (Luhn, keyword required)",
    },
    {
        "name": "UK_NINO",
        "pattern": r"[A-CEGHJ-PR-TW-Z](?<!\w.)[A-CEGHJ-NPR-TW-Z](?<!BG|GB|NK|KN|TN|NT|ZZ) ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
        "keywords": ["national insurance", "nino", "ni number"],
        "severity": "high", "confidence": 0.75, "category": "PII",
        "description": "UK National Insurance Number",
    },
    {
        "name": "PASSPORT",
        "pattern": r"[A-Z](?<!\w[A-Z])[0-9]{7,8}\b",
        "keywords": ["passport"],
        "require_keyword": True,
        "severity": "high", "confidence": 0.80, "category": "PII",
        "description": "Passport number (keyword required)",
    },
    {
        "name": "DATE_OF_BIRTH",
        "pattern": r"(?=\d)\b(?:\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}|(?:19|20)\d{2}[/.-]\d{1,2}[/.-]\d{1,2})\b",
        "keywords": ["dob", "date of birth", "birth date", "birthdate", "born"],
        "require_keyword": True,
        "prefilter": ["19", "20"],
        "severity": "medium", "confidence": 0.75, "category": "PII",
        "description": "Date of birth (keyword required)",
    },
    # ---------------------------------------------------------------- PII (India)
    {
        "name": "IN_AADHAAR",
        "pattern": r"[2-9](?<![\d-][2-9])\d{3}([ -]?)\d{4}\1\d{4}(?![\d]|[ -]\d)",
        "validator": "aadhaar",
        "keywords": ["aadhaar", "aadhar", "uidai", "uid", "enrolment"],
        "prefilter": ["2", "3", "4", "5", "6", "7", "8", "9"],
        "severity": "critical", "confidence": 0.90, "category": "PII",
        "description": "Indian Aadhaar number (Verhoeff validated)",
    },
    {
        "name": "IN_PAN",
        "pattern": r"[A-Z](?<!\w[A-Z])[A-Z]{2}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b",
        "keywords": ["pan", "permanent account", "income tax"],
        "severity": "high", "confidence": 0.85, "category": "PII",
        "description": "Indian PAN (entity-type character validated)",
    },
    {
        "name": "IN_GSTIN",
        "pattern": r"\d(?<!\w\d)\d[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
        "validator": "gstin",
        "keywords": ["gst", "gstin"],
        "severity": "medium", "confidence": 0.90, "category": "PII",
        "description": "Indian GSTIN (checksum validated)",
    },
    {
        "name": "IN_UPI_ID",
        "pattern": r"\b[A-Za-z0-9.\-_]{2,64}@(?:okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|upi|apl|yapl|ptyes|ptaxis|pthdfc|ptsbi|waicici|wahdfcbank|axisbank|icici|sbi|hdfcbank|kotak|freecharge|airtel|jio)\b",
        "prefilter": ["@"],
        "severity": "medium", "confidence": 0.85, "category": "Financial",
        "description": "Indian UPI payment ID",
    },
    {
        "name": "IN_VOTER_ID",
        "pattern": r"[A-Z](?<!\w[A-Z])[A-Z]{2}\d{7}\b",
        "keywords": ["voter", "epic", "election"],
        "require_keyword": True,
        "severity": "high", "confidence": 0.75, "category": "PII",
        "description": "Indian voter ID / EPIC (keyword required)",
    },
    # ---------------------------------------------------------------- Contact
    {
        "name": "EMAIL_ADDRESS",
        "pattern": r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b",
        "prefilter": ["@"],
        "severity": "low", "confidence": 0.95, "category": "PII",
        "description": "Email address",
    },
    {
        "name": "PHONE_US",
        "pattern": r"(?=[+(\d])(?<![\d-])(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ][2-9]\d{2}[-. ]\d{4}(?![\d-])",
        "keywords": ["phone", "tel", "mobile", "cell", "contact", "call"],
        "prefilter": _DIGIT_PREFILTER,
        "severity": "low", "confidence": 0.70, "category": "PII",
        "description": "US phone number (formatted)",
    },
    {
        "name": "PHONE_INDIA",
        "pattern": r"[+0](?:(?<=\+)91[ -]?|(?<=0)(?<!\w0))[6-9]\d{4}[ -]?\d{5}\b",
        "keywords": ["phone", "mobile", "cell", "contact", "whatsapp"],
        "prefilter": ["+91", "0"],
        "severity": "low", "confidence": 0.80, "category": "PII",
        "description": "Indian mobile number (+91 or 0 prefix)",
    },
    {
        "name": "PHONE_INDIA_BARE",
        "pattern": r"\b[6-9]\d{9}\b",
        "keywords": ["phone", "mobile", "cell", "contact", "whatsapp", "mob"],
        "require_keyword": True,
        "prefilter": ["6", "7", "8", "9"],
        "severity": "low", "confidence": 0.70, "category": "PII",
        "description": "Indian mobile number without prefix (keyword required)",
    },
    # ---------------------------------------------------------------- Health
    {
        "name": "MEDICAL_RECORD_NUMBER",
        "pattern": r"\b(?:MRN|medical record (?:number|no\.?|#))[\s:#]*([A-Z0-9-]{6,12})\b",
        "ignore_case": True,
        "group": 1,
        "prefilter": ["mrn", "medical record"],
        "severity": "high", "confidence": 0.85, "category": "Health",
        "description": "Medical record number",
    },
    {
        "name": "ICD10_DIAGNOSIS",
        "pattern": r"[A-TV-Z](?<!\w[A-TV-Z])\d{2}(?:\.\d{1,4})?\b",
        "keywords": ["diagnosis", "icd", "icd-10", "dx", "condition"],
        "require_keyword": True,
        "severity": "high", "confidence": 0.75, "category": "Health",
        "description": "ICD-10 diagnosis code (keyword required)",
    },
    # ---------------------------------------------------------------- Credentials
    {
        "name": "PRIVATE_KEY",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "prefilter": ["-----BEGIN"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "Private key",
    },
    {
        "name": "AWS_ACCESS_KEY",
        "pattern": r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        "prefilter": ["AKIA", "ASIA", "ABIA", "ACCA"],
        "severity": "critical", "confidence": 0.98, "category": "Credentials",
        "description": "AWS access key ID",
    },
    {
        "name": "AWS_SECRET_KEY",
        "pattern": r"aws.{0,20}(?:secret|private).{0,20}[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "ignore_case": True,
        "group": 1,
        "prefilter": ["aws", "AWS", "Aws"],
        "severity": "critical", "confidence": 0.95, "category": "Credentials",
        "description": "AWS secret access key",
    },
    {
        "name": "GCP_SERVICE_ACCOUNT",
        "pattern": r"\"type\"\s*:\s*\"service_account\"",
        "prefilter": ["service_account"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "Google Cloud service account key file",
    },
    {
        "name": "GOOGLE_API_KEY",
        "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "prefilter": ["AIza"],
        "severity": "high", "confidence": 0.95, "category": "Credentials",
        "description": "Google API key",
    },
    {
        "name": "AZURE_STORAGE_KEY",
        "pattern": r"AccountKey=([A-Za-z0-9+/]{86}==)",
        "group": 1,
        "prefilter": ["AccountKey="],
        "severity": "critical", "confidence": 0.98, "category": "Credentials",
        "description": "Azure storage account key",
    },
    {
        "name": "GITHUB_TOKEN",
        "pattern": r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        "prefilter": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "GitHub token",
    },
    {
        "name": "GITLAB_TOKEN",
        "pattern": r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        "prefilter": ["glpat-"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "GitLab personal access token",
    },
    {
        "name": "SLACK_TOKEN",
        "pattern": r"\bxox[abposr]-[A-Za-z0-9-]{10,250}\b",
        "prefilter": ["xox"],
        "severity": "critical", "confidence": 0.97, "category": "Credentials",
        "description": "Slack token",
    },
    {
        "name": "SLACK_WEBHOOK",
        "pattern": r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{20,}",
        "prefilter": ["hooks.slack.com"],
        "severity": "high", "confidence": 0.98, "category": "Credentials",
        "description": "Slack incoming webhook URL",
    },
    {
        "name": "DISCORD_WEBHOOK",
        "pattern": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,}",
        "prefilter": ["discord"],
        "severity": "high", "confidence": 0.98, "category": "Credentials",
        "description": "Discord webhook URL",
    },
    {
        "name": "STRIPE_KEY",
        "pattern": r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,99}\b",
        "prefilter": ["_live_"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "Stripe live secret key",
    },
    {
        "name": "OPENAI_API_KEY",
        "pattern": r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
        "prefilter": ["T3BlbkFJ"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "OpenAI API key",
    },
    {
        "name": "ANTHROPIC_API_KEY",
        "pattern": r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b",
        "prefilter": ["sk-ant-"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "Anthropic API key",
    },
    {
        "name": "TELEGRAM_BOT_TOKEN",
        "pattern": r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
        "prefilter": [":AA"],
        "severity": "critical", "confidence": 0.97, "category": "Credentials",
        "description": "Telegram bot token",
    },
    {
        "name": "SENDGRID_API_KEY",
        "pattern": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        "prefilter": ["SG."],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "SendGrid API key",
    },
    {
        "name": "TWILIO_API_KEY",
        "pattern": r"\bSK[0-9a-f]{32}\b",
        "keywords": ["twilio"],
        "prefilter": ["SK"],
        "severity": "high", "confidence": 0.80, "category": "Credentials",
        "description": "Twilio API key SID",
    },
    {
        "name": "NPM_TOKEN",
        "pattern": r"\bnpm_[A-Za-z0-9]{36}\b",
        "prefilter": ["npm_"],
        "severity": "critical", "confidence": 0.99, "category": "Credentials",
        "description": "npm access token",
    },
    {
        "name": "JWT_TOKEN",
        "pattern": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        "validator": "jwt",
        "prefilter": ["eyJ"],
        "severity": "high", "confidence": 0.95, "category": "Credentials",
        "description": "JSON Web Token (header validated)",
    },
    {
        "name": "CONNECTION_STRING",
        "pattern": r"\b(?:mongodb(?:\+srv)?|mysql|mariadb|postgres(?:ql)?|redis|rediss|amqps?|mssql|sqlserver|oracle|ftp|sftp|ldaps?|smtp)://[^\s:/@'\"]+:[^\s@'\"]+@[^\s'\"<>]+",
        "ignore_case": True,
        "validator": "url_credentials",
        "prefilter": ["://"],
        "severity": "critical", "confidence": 0.95, "category": "Credentials",
        "description": "Connection string with embedded credentials",
    },
    {
        "name": "URL_WITH_CREDENTIALS",
        "pattern": r"\bhttps?://[^\s:/@'\"]+:[^\s@/'\"]+@[^\s'\"<>]+",
        "validator": "url_credentials",
        "prefilter": ["://"],
        "generic": True,
        "severity": "high", "confidence": 0.90, "category": "Credentials",
        "description": "URL with embedded username and password",
    },
    {
        "name": "PASSWORD_ASSIGNMENT",
        "pattern": r"(?:password|passwd|pwd|passphrase)[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,128})[\"']",
        "ignore_case": True,
        "group": 1,
        "validator": "not_placeholder",
        "prefilter": ["pass", "PASS", "Pass", "pwd", "PWD"],
        "severity": "critical", "confidence": 0.85, "category": "Credentials",
        "description": "Hard-coded password",
    },
    {
        "name": "GENERIC_SECRET",
        "pattern": r"(?:api[_-]?key|apikey|secret|token|access[_-]?key|client[_-]?secret|auth[_-]?key)[A-Za-z0-9_-]{0,20}[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{16,256})",
        "ignore_case": True,
        "group": 1,
        "validator": "high_entropy_secret",
        "prefilter": ["key", "secret", "token", "auth"],
        "generic": True,
        "severity": "high", "confidence": 0.80, "category": "Credentials",
        "description": "High-entropy secret assigned to a key/secret/token variable",
    },
    # ---------------------------------------------------------------- Classification / IP
    {
        "name": "CLASSIFICATION_LABEL",
        "pattern": r"\b(?:strictly confidential|company confidential|confidential - internal|internal use only|attorney[- ]client privileged|privileged (?:and|&) confidential|trade secret|do not distribute|not for distribution|restricted - internal)\b",
        "ignore_case": True,
        "prefilter": ["confidential", "internal use", "privileged", "trade secret", "distribut", "restricted"],
        "severity": "medium", "confidence": 0.70, "category": "Classification",
        "description": "Document classification marking",
    },
    {
        "name": "SQL_STATEMENT",
        "pattern": r"\b(?:SELECT\s+[\w*.,\s]{1,200}?\s+FROM\s+\w+|INSERT\s+INTO\s+\w+|DELETE\s+FROM\s+\w+|DROP\s+TABLE\s+\w+|ALTER\s+TABLE\s+\w+)",
        "prefilter": ["SELECT", "INSERT", "DELETE", "DROP", "ALTER"],
        "severity": "low", "confidence": 0.60, "category": "Source Code",
        "description": "SQL statement",
    },
]

# Old detector names -> current names. Findings/policies stored under old names keep working.
LEGACY_ALIASES = {
    "SSN": "US_SSN",
    "SSN_PATTERN": "US_SSN",
    "AADHAAR": "IN_AADHAAR",
    "PAN_INDIA": "IN_PAN",
    "CREDIT_CARD_FORMATTED": "CREDIT_CARD",
    "CREDIT_CARD_LUHN": "CREDIT_CARD",
    "PHONE_NUMBER": "PHONE_US",
    "PASSWORD_INLINE": "PASSWORD_ASSIGNMENT",
    "GENERIC_API_KEY": "GENERIC_SECRET",
    "ENV_VARIABLE": "GENERIC_SECRET",
    "SQL_QUERY": "SQL_STATEMENT",
}
