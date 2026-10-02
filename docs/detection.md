# Detection engine

This document describes how Tron decides that content is sensitive, how fast it does it, and where it still falls short of commercial DLP.

## Pipeline

```
upload / paste / file / event
        │
        ▼
 true file type (magic bytes) ──► extraction ──► normalization ──► detectors ──► validators ──► keyword context ──► overlap resolution ──► EDM ──► policy / severity
 pdf, docx, xlsx, pptx, odt,      text layer,     NFKC, strip        53 data        Luhn, IIN,    proximity window      one finding per        exact        bulk threshold,
 rtf, eml, zip/tar/gz, images     OCR, archives   zero-width chars   identifiers    Verhoeff,     (64 chars): boost      span, strongest        record       encrypted =
                                  (recursive)     base64 decode                     mod-97, ...   or required            wins                   match        explicit finding
```

| Stage | Module | What it does |
|---|---|---|
| True type | `src/extraction.py` `sniff_type` | Magic bytes decide the parser. A PDF renamed to `.txt` is parsed as PDF and reported as `type_mismatch`. |
| Extraction | `src/extraction.py` | PDF text layer via PDFium (`pypdfium2`); pages without text are rendered and OCR'd in parallel. OOXML and OpenDocument parsed with the standard library, including headers, footers, comments, footnotes, speaker notes, embedded files and numeric spreadsheet cells. Zip, tar, gzip and email attachments are expanded recursively (depth 3, 500 members, 200 MB, compression-ratio guard). Legacy binary Office files fall back to string extraction. |
| Encryption | `src/extraction.py` | Password-protected zip, PDF and Office files are detected and surface as an `ENCRYPTED_CONTENT` finding instead of passing as clean. |
| Normalization | `src/detection/engine.py` | NFKC normalization (full-width digits become ASCII) and removal of zero-width / bidi control characters, which attackers insert to break pattern matching. Base64 blobs are decoded and scanned. |
| Detectors | `src/detection/library.py` | 53 data identifiers. Each has a literal prefilter so its regex only runs when an anchor is present. |
| Validators | `src/detection/validators.py` | Checksums and structure checks that turn "looks like" into "is": Luhn + issuer prefix and length for cards, Verhoeff for Aadhaar, mod-97 + country length for IBAN, SSA area/group/serial rules for SSN, ABA checksum, GSTIN checksum, JWT header decoding, entropy and placeholder rejection for secrets. |
| Context | `src/detection/engine.py` | Keyword proximity within 64 characters. Ambiguous formats (a bare 9-digit number) only fire when a keyword such as "routing" or "ssn" is nearby; others get a confidence boost. |
| Overlaps | `src/detection/engine.py` | One finding per span: validated beats unvalidated, specific beats generic (`GITHUB_TOKEN` over `GENERIC_SECRET`), then severity and confidence. Console policy findings are never suppressed, because they carry the block/warn action. |
| EDM | `src/detection/edm.py` | Exact Data Match against protected records (see below). |
| Severity | `src/file_scanner.py` | Highest finding severity; escalated to critical when 10+ identity/financial/health findings occur in one file (`TRON_BULK_THRESHOLD`). |

The browser extension runs the same detectors: `browser-extension/detectors.js` is generated from the Python library (`scripts/build_extension_detectors.py`) and the validators are ported one-to-one. CI fails if the generated file is stale, and a parity test checks that both engines return identical results on the whole corpus.

## Detectors

| Detector | Category | Severity | Validation | Context |
|---|---|---|---|---|
| `CREDIT_CARD` | Financial | critical | payment_card | boost: card, credit, debit, visa |
| `IBAN` | Financial | high | iban | boost: iban, bank, account, swift |
| `US_BANK_ROUTING` | Financial | medium | aba_routing | required: routing, aba, rtn, transit |
| `BANK_ACCOUNT` | Financial | high | format only | required: account number, account no, acct, a/c |
| `US_SSN` | PII | critical | us_ssn | boost: ssn, social security, social sec, tax id |
| `US_SSN_UNFORMATTED` | PII | critical | us_ssn | required: ssn, social security, social sec |
| `US_ITIN` | PII | critical | format only | required: itin, taxpayer, tax id |
| `CA_SIN` | PII | critical | ca_sin | required: sin, social insurance |
| `UK_NINO` | PII | high | format only | boost: national insurance, nino, ni number |
| `PASSPORT` | PII | high | format only | required: passport |
| `DATE_OF_BIRTH` | PII | medium | format only | required: dob, date of birth, birth date, birthdate |
| `IN_AADHAAR` | PII | critical | aadhaar | boost: aadhaar, aadhar, uidai, uid |
| `IN_PAN` | PII | high | format only | boost: pan, permanent account, income tax |
| `IN_GSTIN` | PII | medium | gstin | boost: gst, gstin |
| `IN_UPI_ID` | Financial | medium | format only | - |
| `IN_VOTER_ID` | PII | high | format only | required: voter, epic, election |
| `UK_NHS_NUMBER` | Health | high | uk_nhs | required: nhs, national health, patient |
| `BR_CPF` | PII | critical | br_cpf | boost: cpf, cadastro |
| `ES_DNI` | PII | high | es_dni | boost: dni, nie, nif, documento |
| `AU_TFN` | PII | critical | au_tfn | required: tfn, tax file |
| `CN_RESIDENT_ID` | PII | critical | iso7064_mod11_2 | boost: id card, resident, 身份证 |
| `IMEI` | PII | medium | luhn_any | required: imei, device id |
| `EMAIL_ADDRESS` | PII | low | format only | - |
| `PHONE_US` | PII | low | format only | boost: phone, tel, mobile, cell |
| `PHONE_INDIA` | PII | low | format only | boost: phone, mobile, cell, contact |
| `PHONE_INDIA_BARE` | PII | low | format only | required: phone, mobile, cell, contact |
| `MEDICAL_RECORD_NUMBER` | Health | high | format only | - |
| `ICD10_DIAGNOSIS` | Health | high | format only | required: diagnosis, icd, icd-10, dx |
| `PRIVATE_KEY` | Credentials | critical | format only | - |
| `AWS_ACCESS_KEY` | Credentials | critical | format only | - |
| `AWS_SECRET_KEY` | Credentials | critical | format only | - |
| `GCP_SERVICE_ACCOUNT` | Credentials | critical | format only | - |
| `GOOGLE_API_KEY` | Credentials | high | format only | - |
| `AZURE_STORAGE_KEY` | Credentials | critical | format only | - |
| `GITHUB_TOKEN` | Credentials | critical | format only | - |
| `GITLAB_TOKEN` | Credentials | critical | format only | - |
| `SLACK_TOKEN` | Credentials | critical | format only | - |
| `SLACK_WEBHOOK` | Credentials | high | format only | - |
| `DISCORD_WEBHOOK` | Credentials | high | format only | - |
| `STRIPE_KEY` | Credentials | critical | format only | - |
| `OPENAI_API_KEY` | Credentials | critical | format only | - |
| `ANTHROPIC_API_KEY` | Credentials | critical | format only | - |
| `TELEGRAM_BOT_TOKEN` | Credentials | critical | format only | - |
| `SENDGRID_API_KEY` | Credentials | critical | format only | - |
| `TWILIO_API_KEY` | Credentials | high | format only | boost: twilio |
| `NPM_TOKEN` | Credentials | critical | format only | - |
| `JWT_TOKEN` | Credentials | high | jwt | - |
| `CONNECTION_STRING` | Credentials | critical | url_credentials | - |
| `URL_WITH_CREDENTIALS` | Credentials | high | url_credentials | - |
| `PASSWORD_ASSIGNMENT` | Credentials | critical | not_placeholder | - |
| `GENERIC_SECRET` | Credentials | high | high_entropy_secret | - |
| `CLASSIFICATION_LABEL` | Classification | medium | format only | - |
| `SQL_STATEMENT` | Source Code | low | format only | - |

### Validators

| Validator | What it checks |
|---|---|
| `luhn` | Luhn mod-10 checksum, 12-19 digits |
| `luhn_any` | Luhn mod-10 checksum, any length (IMEI, loyalty and custom account numbers) |
| `payment_card` | Luhn + issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro, RuPay) |
| `verhoeff` | Verhoeff checksum (dihedral group D5) |
| `aadhaar` | Verhoeff + Aadhaar structure (12 digits, first digit 2-9) |
| `iso7064_mod97` | ISO 7064 MOD 97-10 over alphanumerics (remainder 1) |
| `iban` | IBAN: country-specific length + ISO 7064 MOD 97-10 |
| `iso7064_mod11_2` | ISO 7064 MOD 11-2 (check character 0-9 or X) |
| `us_ssn` | US SSN area/group/serial rules (no 000/666/9xx areas, no 00 group, no 0000 serial) |
| `aba_routing` | US ABA routing number weighted checksum (3-7-1) |
| `ca_sin` | Canadian SIN Luhn checksum (9 digits) |
| `uk_nhs` | UK NHS number weighted mod 11 |
| `br_cpf` | Brazilian CPF two mod-11 check digits |
| `es_dni` | Spanish DNI/NIE mod-23 control letter |
| `au_tfn` | Australian Tax File Number weighted mod 11 |
| `gstin` | Indian GSTIN base-36 checksum character |
| `jwt` | JWT header decodes to JSON with an alg field |
| `not_placeholder` | Rejects placeholders (changeme, your-..., <...>, ${VAR}) and values under 6 chars |
| `high_entropy_secret` | Secret-like: >= 16 chars, mixed charset, Shannon entropy >= 3.5, not a placeholder or identifier |
| `url_credentials` | URL with user:password@ where the password is not a placeholder |

## Editing the library (console)

The **Detectors** page lists every detector with its validator, keywords and the policies that use it.

- **Built-in detectors** can be enabled or disabled and their severity, confidence, keywords, keyword requirement, pattern, validator and case sensitivity changed. Changes are stored as overrides (`detector_overrides` table) and can be reset to the shipped defaults at any time.
- **Custom detectors** combine a pattern, an optional capture group, any validator above, and keyword context (`custom_detectors` table).
- Every edit is validated before it is stored: the pattern must compile, must not match the empty string, and may only use regex syntax shared by Python and JavaScript, because the same definition runs in the browser extension.
- Changes reach the API scanner, agent event matching (rules engine), the endpoint agents and the browser extension (delivered with policy sync). Disabling a detector stops alerting on it but **never** weakens LLM redaction, which always runs every built-in detector.
- All changes are written to the audit log.

## Detection Lab

- **Rule builder**: describe what to protect in plain language. With a Gemini key the LLM drafts a rule; without one, an offline builder maps known identifiers to validated built-ins ("alert on Aadhaar numbers") and builds custom detectors from example values ("employee IDs like EMP-482913 with a Luhn check digit" becomes `\bEMP-\d{6}\b` + `luhn_any`). Drafts are validated server-side and can be saved as a detector and policy in one step.
- **Explainable testing**: every regex candidate is shown with its checksum result, the keyword found nearby and the final decision with the reason ("failed luhn_any check", "no keyword within 64 characters").
- **Checksum tools**: which validators a value passes, and a generator of random values with correct check digits (cards per brand, IBAN per country, Aadhaar, SSN, NHS, CPF, DNI, TFN, Chinese ID, IMEI, GSTIN, ...) for testing policies end to end.
- **Library scan**: run any text through the live library and see highlighted findings with their evidence.

API: `GET/POST /api/detectors`, `PATCH/DELETE /api/detectors/<name>`, `POST /api/detectors/test` (trace), `POST /api/detectors/check`, `POST /api/detectors/generate`.

Console policies can reference any detector by name instead of a raw regex (`rule_data: {"detector": "CREDIT_CARD"}`, or `"detector": "CREDIT_CARD"` in `POST /api/policies`). The catalogue is served at `GET /api/detectors`. The default policies use these references; untouched default policies in existing databases are upgraded automatically, edited ones are left alone.

## Exact Data Match (EDM)

Pattern detectors answer "does this look like an SSN?". EDM answers "is this one of *our customers'* records?".

```bash
# Build an index from the protected dataset (only keyed hashes are written)
python -m src.detection.edm build customers.csv --columns name,email,ssn,card --min-fields 2
# -> data/edm/customers.edm, key in data/edm/.key (or set TRON_EDM_KEY)

# Try it
python -m src.detection.edm test data/edm/customers.edm some_document.txt
```

- Values are normalized (case, whitespace, separators in numbers) and stored as 96-bit keyed BLAKE2b digests with their row numbers. The index contains no plaintext, and without the key it cannot be brute-forced offline.
- A match requires `--min-fields` distinct columns **of the same row** within 300 characters (for example name + SSN). A common first name or a lone SSN never matches by itself.
- Indexes in `TRON_EDM_DIR` (default `data/edm/`) are loaded by the API and agents at startup and produce `EDM_MATCH` findings (critical).
- 100,000 rows build in about 1 second (10 MB index); scanning runs at about 4 MB/s.

## Benchmarks

Measured on a 4-core cloud VM, Python 3.11, Node 22, Tesseract 5.3.4. Reproduce with `python scripts/benchmark_detection.py`.

### Detection quality

| Engine | Corpus (149 labeled cases) precision / recall | Unseen text (2.1 MB of `node_modules` docs): findings other than emails |
|---|---|---|
| Previous regex set (server) | 0.50 / 0.77 | 2,078 |
| Previous regex set (extension) | 0.63 / 0.77 | n/a |
| **Current engine (server and extension)** | **1.00 / 1.00** | **3** (phone numbers in a JSON test fixture) |

The corpus (`tests/detection_corpus.py`) was written alongside the engine, so its score is optimistic by construction; it is a regression suite, not an independent evaluation. The `node_modules` soak is independent: the old rules produced 1,857 `GENERIC_SECRET` hits on ordinary `key = value` text and 119 SQL hits on English words like "update"; the new engine produces three.

### Text scanning latency

| Document | Previous | Current |
|---|---|---|
| 100 KB | 48 ms | 16 ms |
| 1 MB | 528 ms | 177 ms (73 findings vs 239, most of the 239 false positives) |
| 10 MB | 4.4 s | 1.6 s |
| Browser extension, 1 MB | 34 ms (20 unvalidated patterns) | 73 ms (47 detectors at the time of measurement, validators, decode pass); a typical paste of a few KB takes under 1 ms |

### Extraction: replacing Docling

| File | Previous pipeline (PyPDF2 / pdf2image / 12-pass OCR) | Docling 2.132 | Current (pypdfium2 + 1-pass Tesseract) |
|---|---|---|---|
| 10-page text PDF | 149 ms | 8.05 s warm, 37.9 s first call | **12 ms** |
| Scanned 1-page PDF | 253 ms | 4.47 s | **~180 ms** |
| Scanned 8-page PDF | n/a | n/a | **458 ms** (pages OCR'd in parallel) |
| PNG screenshot | 1,963 ms | 3.19 s | **140 ms** |
| XLSX with a card number in a numeric cell | missed | n/a | found |
| Import / init | n/a | 3.5 s, 677 MB RSS | 0.06 s |
| Peak memory | n/a | 2.4 GB | 44 MB |
| Install size | n/a | 6.3 GB (torch, models) | 83 MB (entire requirements.txt) |

Docling also ran on every `FileContentScanner()` construction (each agent, the API, every Telegram `/scan`), so the old code paid its startup cost repeatedly.

Other latency fixes:
- Results are cached by SHA-256 of the content, so a re-uploaded or unchanged file costs a hash.
- The browser deep scan used to extract each file twice (once for detectors, again for policies); it now extracts once, in memory, without a temp file.
- Console policies were re-read from SQLite and recompiled on every agent event; they are now compiled once and refreshed every 5 seconds or on change.
- Tesseract's OpenMP threading roughly doubled latency on page-sized images; it now runs single-threaded per page with pages in parallel.

## Gap analysis vs commercial DLP (Symantec DLP, Zscaler DLP)

What Tron now has that the earlier version did not:

| Capability | Before | Now |
|---|---|---|
| Validated data identifiers (checksums, issuer ranges) | Luhn on one card pass only | Cards, Aadhaar, IBAN, SSN, ABA, SIN, GSTIN, JWT |
| Keyword proximity / context | none | per-detector keywords, required or boosting |
| Secrets coverage | 6 generic patterns | 20 credential detectors incl. GitHub, GitLab, Slack, Stripe, Google, Azure, OpenAI, Anthropic, Telegram, SendGrid, npm, private keys, credentialed URLs, entropy-checked generic secrets |
| Evasion handling | none | Unicode normalization, zero-width stripping, base64 decoding |
| True file type | extension only | magic bytes, mismatch flagged |
| Archives / email | none | zip, tar, gzip, eml with attachments, nested, bomb limits |
| Encrypted files | silently "clean" | explicit finding |
| Office coverage | DOCX body, XLSX shared strings | headers, footers, comments, notes, numeric cells, PPTX, ODF, RTF, embedded objects |
| Exact Data Match | none | hashed record index, multi-field record matching |
| Policies on agent events | broken (never loaded) | working, can reference validated detectors |
| Server/extension consistency | two hand-maintained regex lists | one generated library, parity-tested |

What the commercial products still do that Tron does not:

| Capability | Status in Tron |
|---|---|
| Indexed Document Matching (fingerprints of specific documents, partial-copy detection) | Not implemented. Next candidate: shingled MinHash fingerprints of protected documents. |
| ML classifiers for unstructured categories (source code, financial statements, resumes, legal) | Not implemented; only the optional LLM triage. |
| Inline network enforcement (TLS-inspecting proxy, CASB API connectors for SaaS) | Not implemented; enforcement happens in the browser extension and endpoint agents. |
| Kernel-level endpoint enforcement (block USB copy, print, screen capture) | Agents detect and report; they do not block at the OS level. |
| Microsoft Purview / sensitivity label integration | Classification markings are detected as text only. |
| High-throughput matching (Hyperscan, multi-tenant scale) | Python `re` at ~6 MB/s per core; adequate for endpoint and per-upload scanning, not for gateway-scale traffic. |
| Incident workflow at scale (case management, reviewer queues, retention) | Basic incidents, audit log and Telegram actions. |
