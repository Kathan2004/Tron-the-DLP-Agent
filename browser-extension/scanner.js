/**
 * TRON THE DLP AGENT — Client-Side File Scanner
 * Mirrors the backend Python scanner patterns for browser-level scanning.
 * Runs entirely in the browser — no data leaves the machine during scanning.
 */

let SENSITIVE_PATTERNS = {
    // ── PII — Identity Numbers ──────────────────────────────────
    SSN: {
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        severity: "critical",
        confidence: 0.95,
        description: "US Social Security Number",
        category: "PII"
    },
    AADHAAR: {
        pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
        severity: "critical",
        confidence: 0.88,
        description: "Indian Aadhaar Number",
        category: "PII"
    },
    PAN_INDIA: {
        pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
        severity: "high",
        confidence: 0.92,
        description: "Indian PAN Card Number",
        category: "PII"
    },
    PASSPORT: {
        pattern: /\b[A-Z]{1}[0-9]{7}\b/g,
        severity: "high",
        confidence: 0.70,
        description: "Passport Number",
        category: "PII"
    },

    // ── Financial ───────────────────────────────────────────────
    // Removed the unformatted CREDIT_CARD regex to prevent false positives on random 16-digit IDs
    // since we don't have a Luhn algorithm check in the browser regex.
    CREDIT_CARD_FORMATTED: {
        pattern: /\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b/g,
        severity: "critical",
        confidence: 0.92,
        description: "Formatted Credit Card Number",
        category: "Financial"
    },
    IBAN: {
        pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g,
        severity: "high",
        confidence: 0.85,
        description: "IBAN Number",
        category: "Financial"
    },
    BANK_ACCOUNT: {
        pattern: /(?:account|acct|a\/c)[\s#:.\-]*\d{8,18}/gi,
        severity: "high",
        confidence: 0.75,
        description: "Bank Account Number",
        category: "Financial"
    },

    // ── Credentials & Secrets ───────────────────────────────────
    AWS_ACCESS_KEY: {
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: "critical",
        confidence: 0.99,
        description: "AWS Access Key ID",
        category: "Credentials"
    },
    AWS_SECRET_KEY: {
        pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        severity: "critical",
        confidence: 0.95,
        description: "AWS Secret Access Key",
        category: "Credentials"
    },
    GENERIC_API_KEY: {
        pattern: /(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?/gi,
        severity: "critical",
        confidence: 0.80,
        description: "API Key / Secret",
        category: "Credentials"
    },
    PRIVATE_KEY: {
        pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
        severity: "critical",
        confidence: 0.99,
        description: "Private Key File",
        category: "Credentials"
    },
    PASSWORD_INLINE: {
        pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
        severity: "critical",
        confidence: 0.85,
        description: "Hardcoded Password",
        category: "Credentials"
    },
    CONNECTION_STRING: {
        pattern: /(?:mongodb|mysql|postgres|redis|amqp):\/\/[^\s'"]+/gi,
        severity: "critical",
        confidence: 0.90,
        description: "Database Connection String",
        category: "Credentials"
    },
    JWT_TOKEN: {
        pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
        severity: "high",
        confidence: 0.95,
        description: "JWT Token",
        category: "Credentials"
    },
    GCP_SERVICE_ACCOUNT: {
        pattern: /"type"\s*:\s*"service_account"/g,
        severity: "critical",
        confidence: 0.99,
        description: "GCP Service Account Key",
        category: "Credentials"
    },

    // ── PII — Contact Information ───────────────────────────────
    EMAIL_ADDRESS: {
        pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
        severity: "low",
        confidence: 0.98,
        description: "Email Address",
        category: "PII"
    },
    PHONE_NUMBER: {
        pattern: /\b(?:\+?1[-.\s])?\(?[2-9]\d{2}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
        severity: "low",
        confidence: 0.65,
        description: "Phone Number (US-formatted)",
        category: "PII"
    },
    PHONE_INDIA: {
        pattern: /\b(?:\+91[\s-])[6-9]\d{4}[\s-]?\d{5}\b/g,
        severity: "low",
        confidence: 0.70,
        description: "Indian Phone Number (Formatted)",
        category: "PII"
    },

    // ── Source Code & IP ────────────────────────────────────────
    SQL_QUERY: {
        pattern: /\b(?:SELECT\s+.+\s+FROM\s+|INSERT\s+INTO\s+.+\s+VALUES|UPDATE\s+.+\s+SET\s+|DELETE\s+FROM\s+.+\s+WHERE\s+)/gi,
        severity: "low",
        confidence: 0.60,
        description: "SQL Data Exfiltration",
        category: "Source Code"
    },
    ENV_VARIABLE: {
        pattern: /\b(?:[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|CREDS|API)[A-Z0-9_]*)\s*=\s*['"]?[A-Za-z0-9\-_/+]{10,}['"]?/g,
        severity: "medium",
        confidence: 0.85,
        description: "Sensitive Environment Variable",
        category: "Credentials"
    },
};

// File types we can scan as text
const SCANNABLE_EXTENSIONS = new Set([
    'txt', 'csv', 'tsv', 'json', 'yaml', 'yml', 'xml',
    'py', 'js', 'ts', 'jsx', 'tsx', 'java', 'go', 'rb', 'php',
    'c', 'cpp', 'h', 'rs', 'swift', 'kt',
    'html', 'htm', 'css', 'scss', 'less',
    'md', 'rst', 'log', 'conf', 'cfg', 'ini', 'toml',
    'env', 'sh', 'bash', 'zsh', 'bat', 'ps1',
    'sql', 'pgsql', 'mysql',
    'dockerfile', 'tf', 'hcl',
    'properties', 'gradle', 'pom',
    'doc', 'docx', 'xls', 'xlsx', 'pdf',
]);

// Max file size to scan (10MB)
const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * Return exact matched text (no masking).
 */
function redactMatch(text, patternName) {
    return String(text || "");
}

function isValidLuhn(cardDigits) {
    const digits = String(cardDigits || '').replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = parseInt(digits[i], 10);
        if (shouldDouble) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
}

/**
 * Scan text content for all sensitive patterns.
 * Returns array of findings.
 */
function scanText(text, source = "unknown") {
    const findings = [];
    const lines = text.split("\n");

    for (const [name, config] of Object.entries(SENSITIVE_PATTERNS)) {
        // Skip non-regex rules (extension, file_size) or broken entries
        if (config.rule_type && config.rule_type !== 'regex') continue;
        if (!config.pattern || !config.pattern.source) continue;

        // Reset regex lastIndex
        const regex = new RegExp(config.pattern.source, config.pattern.flags);

        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];
            let match;

            while ((match = regex.exec(line)) !== null) {
                const matched = match[0];
                const redacted = redactMatch(matched, name);

                // Context: surrounding text
                const start = Math.max(0, match.index - 20);
                const end = Math.min(line.length, match.index + matched.length + 20);
                let context = line.substring(start, end);
                if (context.length > 100) context = context.substring(0, 100);

                findings.push({
                    pattern_name: name,
                    description: config.description,
                    category: config.category,
                    matched_text: redacted,
                    raw_length: matched.length,
                    line_number: lineNum + 1,
                    severity: config.severity,
                    confidence: config.confidence,
                    context,
                    policy_action: config.__dynamic ? String(config.action || 'monitor').toLowerCase() : undefined,
                    policy_threshold: config.__dynamic ? (parseInt(config.threshold, 10) || 1) : undefined,
                    policy_window_mins: config.__dynamic ? (parseInt(config.window, 10) || 60) : undefined,
                });
            }
        }
    }

    // Extra pass: generic Luhn-valid credit card detection (handles plain 16-digit cards).
    const cardLike = /\b(?:\d[ -]?){13,19}\b/g;
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        let m;
        while ((m = cardLike.exec(line)) !== null) {
            const raw = m[0];
            const digits = raw.replace(/\D/g, '');
            if (!isValidLuhn(digits)) continue;

            const start = Math.max(0, m.index - 20);
            const end = Math.min(line.length, m.index + raw.length + 20);
            let context = line.substring(start, end);
            if (context.length > 100) context = context.substring(0, 100);

            findings.push({
                pattern_name: "CREDIT_CARD_LUHN",
                description: "Credit Card Number (Luhn Valid)",
                category: "Financial",
                matched_text: redactMatch(raw, "CREDIT_CARD"),
                raw_length: digits.length,
                line_number: lineNum + 1,
                severity: "critical",
                confidence: 0.96,
                context,
            });
        }
    }

    return findings;
}

/**
 * Read file as text and scan it.
 * Returns a promise that resolves to scan results.
 */
function scanFile(file) {
    return new Promise((resolve, reject) => {
        // Check file size
        if (file.size > MAX_FILE_SIZE) {
            resolve({
                file_name: file.name,
                file_size: file.size,
                file_type: file.type,
                skipped: true,
                reason: "File too large (> 10MB)",
                findings: [],
                severity: "none",
            });
            return;
        }

        if (file.size === 0) {
            resolve({
                file_name: file.name,
                file_size: 0,
                file_type: file.type,
                skipped: true,
                reason: "Empty file",
                findings: [],
                severity: "none",
            });
            return;
        }

        // Get extension (including dot)
        const nameParts = file.name.split(".");
        const ext = nameParts.length > 1 ? "." + nameParts.pop().toLowerCase() : "";

        const reader = new FileReader();

        reader.onload = function (e) {
            const text = e.target.result;
            let findings = scanText(text, file.name);

            // ─── Policy Evaluations (Non-Regex) ─────────────────────
            for (const [name, config] of Object.entries(SENSITIVE_PATTERNS)) {
                if (config.rule_type === 'file_size') {
                    const maxSizeBytes = (config.max_size_mb || 0) * 1024 * 1024;
                    if (maxSizeBytes > 0 && file.size > maxSizeBytes) {
                        findings.push({
                            pattern_name: name,
                            description: config.description,
                            category: "Policy Violation",
                            matched_text: `File size: ${(file.size / (1024 * 1024)).toFixed(2)}MB`,
                            raw_length: 0,
                            line_number: 0,
                            severity: config.severity,
                            confidence: 1.0,
                            context: `File exceeds maximum size limit of ${config.max_size_mb}MB`,
                        });
                    }
                } else if (config.rule_type === 'extension') {
                    const blocked = (config.blocked_extensions || []).map(e => e.startsWith(".") ? e.toLowerCase() : "." + e.toLowerCase());
                    if (blocked.includes(ext)) {
                        findings.push({
                            pattern_name: name,
                            description: config.description,
                            category: "Policy Violation",
                            matched_text: `Blocked Type: ${ext}`,
                            raw_length: 0,
                            line_number: 0,
                            severity: config.severity,
                            confidence: 1.0,
                            context: `Files with ${ext} extension are prohibited by policy.`,
                        });
                    }
                }
            }

            // Calculate overall severity
            let severity = "none";
            if (findings.length > 0) {
                const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
                const maxSeverity = findings.reduce((max, f) => {
                    return severityOrder[f.severity] > severityOrder[max.severity] ? f : max;
                });
                severity = maxSeverity.severity;
            }

            // Group findings by category
            const categorySummary = {};
            for (const f of findings) {
                if (!categorySummary[f.category]) {
                    categorySummary[f.category] = { count: 0, patterns: new Set() };
                }
                categorySummary[f.category].count++;
                categorySummary[f.category].patterns.add(f.description);
            }

            // Convert Set to Array for serialization
            for (const cat in categorySummary) {
                categorySummary[cat].patterns = [...categorySummary[cat].patterns];
            }

            resolve({
                file_name: file.name,
                file_size: file.size,
                file_type: file.type || ext,
                scan_time: new Date().toISOString(),
                findings: findings,
                finding_count: findings.length,
                severity: severity,
                category_summary: categorySummary,
                skipped: false,
            });
        };

        reader.onerror = function () {
            reject(new Error(`Failed to read file: ${file.name}`));
        };

        // Read as text
        reader.readAsText(file);
    });
}

/**
 * Scan multiple files.
 */
async function scanFiles(fileList) {
    const results = [];
    for (const file of fileList) {
        try {
            const result = await scanFile(file);
            results.push(result);
        } catch (err) {
            results.push({
                file_name: file.name,
                file_size: file.size,
                error: err.message,
                findings: [],
                severity: "none",
                skipped: true,
            });
        }
    }
    return results;
}

/**
 * Dynamically update SENSITIVE_PATTERNS from SIEM policies.
 */
function updatePatterns(dynamicPatterns) {
    if (!Array.isArray(dynamicPatterns)) return;

    // Remove only previously injected dynamic rules, keep built-in baseline rules.
    for (const [k, v] of Object.entries(SENSITIVE_PATTERNS)) {
        if (v && v.__dynamic === true) {
            delete SENSITIVE_PATTERNS[k];
        }
    }

    let added = 0;
    const newPatterns = {};

    for (const p of dynamicPatterns) {
        if (!p.name) continue;

        try {
            const ruleType = p.rule_type || 'regex';
            const ruleData = p.rule_data || {};
            const severity = (p.severity || "medium").toLowerCase();
            const exceptionSets = Array.isArray(ruleData.exception_sets)
                ? ruleData.exception_sets
                    .filter(x => x && typeof x === 'object')
                    .map(x => ({
                        id: x.id ? String(x.id) : '',
                        scope_type: x.scope_type ? String(x.scope_type).toLowerCase() : 'global',
                        policy_id: x.policy_id ? String(x.policy_id) : null,
                        mode: x.mode ? String(x.mode).toLowerCase() : 'allow_and_log',
                        users: Array.isArray(x.users) ? x.users.map(v => String(v || '').trim()).filter(Boolean) : [],
                        senders: Array.isArray(x.senders) ? x.senders.map(v => String(v || '').trim()).filter(Boolean) : [],
                        recipients: Array.isArray(x.recipients) ? x.recipients.map(v => String(v || '').trim()).filter(Boolean) : [],
                        domains: Array.isArray(x.domains) ? x.domains.map(v => String(v || '').trim()).filter(Boolean) : [],
                        expires_at: x.expires_at ? String(x.expires_at) : null,
                        reason: x.reason ? String(x.reason) : '',
                        ticket_id: x.ticket_id ? String(x.ticket_id) : '',
                        name: x.name ? String(x.name) : '',
                    }))
                : [];
            const rawExceptions = (ruleData && typeof ruleData === 'object' && ruleData.exceptions && typeof ruleData.exceptions === 'object')
                ? ruleData.exceptions
                : {};
            const exceptions = {
                users: Array.isArray(rawExceptions.users) ? rawExceptions.users.map(v => String(v || '').trim()).filter(Boolean) : [],
                senders: Array.isArray(rawExceptions.senders) ? rawExceptions.senders.map(v => String(v || '').trim()).filter(Boolean) : [],
                recipients: Array.isArray(rawExceptions.recipients) ? rawExceptions.recipients.map(v => String(v || '').trim()).filter(Boolean) : [],
                domains: Array.isArray(rawExceptions.domains) ? rawExceptions.domains.map(v => String(v || '').trim()).filter(Boolean) : [],
                expires_at: rawExceptions.expires_at ? String(rawExceptions.expires_at) : null,
                mode: rawExceptions.mode ? String(rawExceptions.mode) : 'allow_and_log',
                reason: rawExceptions.reason ? String(rawExceptions.reason) : '',
                ticket_id: rawExceptions.ticket_id ? String(rawExceptions.ticket_id) : '',
            };

            if (ruleType === 'regex') {
                let flags = "gi";
                let regexStr = p.regex || ruleData.pattern;
                if (!regexStr) continue;

                if (regexStr.startsWith("(?i)")) {
                    regexStr = regexStr.replace("(?i)", "");
                }

                new RegExp(regexStr);

                newPatterns[p.name] = {
                    pattern: new RegExp(regexStr, flags),
                    severity: severity,
                    confidence: 0.85,
                    description: p.name,
                    category: "SIEM Policy",
                    rule_type: 'regex',
                    action: (p.action || 'monitor').toLowerCase(),
                    threshold: (parseInt(p.threshold, 10) || 1),
                    window: (parseInt(p.window, 10) || 60),
                    exceptions,
                    exception_sets: exceptionSets,
                    __dynamic: true,
                };
            } else if (ruleType === 'file_size') {
                newPatterns[p.name] = {
                    rule_type: 'file_size',
                    max_size_mb: ruleData.max_size_mb,
                    severity: severity,
                    description: p.description || p.name,
                    category: "SIEM Policy",
                    action: (p.action || 'monitor').toLowerCase(),
                    threshold: (parseInt(p.threshold, 10) || 1),
                    window: (parseInt(p.window, 10) || 60),
                    exceptions,
                    exception_sets: exceptionSets,
                    __dynamic: true,
                };
            } else if (ruleType === 'extension') {
                // Support legacy patterns where the UI stored a single pattern
                // string like "EXT: .php, .php3" in rule_data.pattern.
                let blocked = ruleData.blocked_extensions;
                if (!Array.isArray(blocked) && typeof (ruleData.pattern || p.regex) === 'string') {
                    const raw = (ruleData.pattern || p.regex || '').toString();
                    if (raw.toUpperCase().startsWith('EXT:')) {
                        blocked = raw.slice(4).split(',').map(s => s.trim()).filter(Boolean)
                            .map(e => (e.startsWith('.') ? e.toLowerCase() : '.' + e.toLowerCase()));
                    }
                }

                newPatterns[p.name] = {
                    rule_type: 'extension',
                    blocked_extensions: blocked,
                    severity: severity,
                    description: p.description || p.name,
                    category: "SIEM Policy",
                    action: (p.action || 'monitor').toLowerCase(),
                    threshold: (parseInt(p.threshold, 10) || 1),
                    window: (parseInt(p.window, 10) || 60),
                    exceptions,
                    exception_sets: exceptionSets,
                    __dynamic: true,
                };
            } else if (ruleType === 'network') {
                let blockedDomains = ruleData.blocked_domains;
                if (!Array.isArray(blockedDomains)) {
                    const raw = (ruleData.pattern || p.regex || '').toString();
                    blockedDomains = raw
                        .split(',')
                        .map(s => s.trim().toLowerCase())
                        .filter(Boolean)
                        .map(v => v.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/$/, ''));
                }

                newPatterns[p.name] = {
                    rule_type: 'network',
                    blocked_domains: (blockedDomains || []).map(v => String(v || '')
                        .trim()
                        .toLowerCase()
                        .replace(/^https?:\/\//, '')
                        .replace(/^www\./, '')
                        .replace(/\/$/, '')),
                    severity: severity,
                    description: p.description || p.name,
                    category: "SIEM Policy",
                    action: (p.action || 'monitor').toLowerCase(),
                    threshold: (parseInt(p.threshold, 10) || 1),
                    window: (parseInt(p.window, 10) || 60),
                    exceptions,
                    exception_sets: exceptionSets,
                    __dynamic: true,
                };
            }
            added++;
        } catch (err) {
            console.warn(`TRON THE DLP AGENT: Invalid dynamic rule for ${p.name}:`, err);
        }
    }

    // Assign new properties to the existing object reference
    Object.assign(SENSITIVE_PATTERNS, newPatterns);

    if (added > 0) {
        console.log(`Scanner updated with ${added} LIVE dynamic rules from SIEM`);
    }
}

// Export for use in content script and background
if (typeof globalThis !== "undefined") {
    globalThis.TronScanner = {
        scanText,
        scanFile,
        scanFiles,
        redactMatch,
        updatePatterns,
        SENSITIVE_PATTERNS,
        SCANNABLE_EXTENSIONS,
    };
}
