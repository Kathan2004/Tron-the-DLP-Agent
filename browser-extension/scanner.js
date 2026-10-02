/**
 * TRON THE DLP AGENT — Client-Side Scanner
 * Same detector library as the server (browser-extension/detectors.js is generated from
 * src/detection/library.py). Runs entirely in the browser — no data leaves the machine
 * during scanning.
 *
 * Pipeline: normalize (NFKC, strip zero-width chars) -> literal prefilter -> regex ->
 * checksum validator -> keyword proximity -> overlap resolution -> base64 decode pass.
 */

const TRON_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const TRON_INVISIBLE = /[­᠎​-‏‪-‮⁠-⁤﻿]/g;
const TRON_B64_RUN = /[A-Za-z0-9+/_-](?<![A-Za-z0-9+/=_-].)[A-Za-z0-9+/_-]{39,}={0,2}(?![A-Za-z0-9+/=_-])/g;
const TRON_MAX_SCAN_CHARS = 20000000;
const TRON_MAX_CANDIDATES = 20000;

// ─── Validators (mirror src/detection/validators.py) ─────────────
function tronDigits(v) { return String(v || "").replace(/\D/g, ""); }

function isValidLuhn(value) {
    const d = tronDigits(value);
    if (d.length < 12 || d.length > 19) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
        let n = d.charCodeAt(d.length - 1 - i) - 48;
        if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
    }
    return sum % 10 === 0;
}

function validPaymentCard(value) {
    const d = tronDigits(value);
    if (new Set(d).size === 1 || !isValidLuhn(d)) return false;
    const n = d.length;
    const p2 = +d.slice(0, 2), p3 = +d.slice(0, 3), p4 = +d.slice(0, 4), p6 = +d.slice(0, 6);
    if (d[0] === "4") return n === 13 || n === 16 || n === 19;
    if ((p2 >= 51 && p2 <= 55) || (p6 >= 222100 && p6 <= 272099)) return n === 16;
    if (p2 === 34 || p2 === 37) return n === 15;
    if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || (p6 >= 622126 && p6 <= 622925)) return n >= 16 && n <= 19;
    if (p4 >= 3528 && p4 <= 3589) return n >= 16 && n <= 19;
    if ((p3 >= 300 && p3 <= 305) || p2 === 36 || p2 === 38 || p2 === 39 || p4 === 3095) return n >= 14 && n <= 19;
    if (p2 === 62 || p2 === 81) return n >= 16 && n <= 19;
    if ([5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763].includes(p4)) return n >= 12 && n <= 19;
    if (["60", "65", "81", "82"].includes(d.slice(0, 2)) || ["508", "353", "356"].includes(d.slice(0, 3))) return n === 16;
    return false;
}

const TRON_VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const TRON_VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

function validAadhaar(value) {
    const d = tronDigits(value);
    if (d.length !== 12 || d[0] === "0" || d[0] === "1" || new Set(d).size <= 2) return false;
    let c = 0;
    for (let i = 0; i < d.length; i++) c = TRON_VD[c][TRON_VP[i % 8][d.charCodeAt(d.length - 1 - i) - 48]];
    return c === 0;
}

const TRON_IBAN_LEN = {AD:24,AE:23,AL:28,AT:20,AZ:28,BA:20,BE:16,BG:22,BH:22,BR:29,BY:28,CH:21,CR:22,CY:28,CZ:24,DE:22,DK:18,DO:28,EE:20,EG:29,ES:24,FI:18,FO:18,FR:27,GB:22,GE:22,GI:23,GL:18,GR:27,GT:28,HR:21,HU:28,IE:22,IL:23,IQ:23,IS:26,IT:27,JO:30,KW:30,KZ:20,LB:28,LC:32,LI:21,LT:20,LU:20,LV:21,MC:27,MD:24,ME:22,MK:19,MR:27,MT:31,MU:30,NL:18,NO:15,PK:24,PL:28,PS:29,PT:25,QA:29,RO:24,RS:22,SA:24,SC:31,SE:24,SI:19,SK:24,SM:27,ST:25,SV:28,TL:23,TN:24,TR:26,UA:29,VA:22,VG:24,XK:20};

function validIban(value) {
    const s = String(value || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
    if (TRON_IBAN_LEN[s.slice(0, 2)] !== s.length) return false;
    const r = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of r) {
        const v = parseInt(ch, 36);
        rem = v > 9 ? (rem * 100 + v) % 97 : (rem * 10 + v) % 97;
    }
    return rem === 1;
}

function validUsSsn(value) {
    const d = tronDigits(value);
    if (d.length !== 9) return false;
    const area = d.slice(0, 3), group = d.slice(3, 5), serial = d.slice(5);
    if (area === "000" || area === "666" || area[0] === "9" || group === "00" || serial === "0000") return false;
    return d !== "078051120" && d !== "219099999";
}

function validAbaRouting(value) {
    const d = tronDigits(value);
    if (d.length !== 9 || d === "000000000") return false;
    const w = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum = 0;
    for (let i = 0; i < 9; i++) sum += (d.charCodeAt(i) - 48) * w[i];
    return sum % 10 === 0;
}

function validCaSin(value) {
    const d = tronDigits(value);
    if (d.length !== 9) return false;
    let sum = 0;
    for (let i = 0; i < 9; i++) {
        let n = d.charCodeAt(8 - i) - 48;
        if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
    }
    return sum % 10 === 0;
}

const TRON_GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
function validGstin(value) {
    const s = String(value || "").toUpperCase();
    if (s.length !== 15) return false;
    let total = 0;
    for (let i = 0; i < 14; i++) {
        const idx = TRON_GSTIN_CHARS.indexOf(s[i]);
        if (idx < 0) return false;
        const v = idx * (i % 2 ? 2 : 1);
        total += Math.floor(v / 36) + (v % 36);
    }
    return TRON_GSTIN_CHARS[(36 - (total % 36)) % 36] === s[14];
}

function validJwt(value) {
    try {
        let head = String(value).split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
        head += "=".repeat((4 - (head.length % 4)) % 4);
        return "alg" in JSON.parse(atob(head));
    } catch (_) { return false; }
}

function tronEntropy(v) {
    if (!v) return 0;
    const counts = {};
    for (const ch of v) counts[ch] = (counts[ch] || 0) + 1;
    let h = 0;
    for (const c of Object.values(counts)) { const p = c / v.length; h -= p * Math.log2(p); }
    return h;
}

const TRON_PLACEHOLDER = /^(?:x+|\*+|\.+|-+|_+|0+|changeme|change[-_]?me|password|passwd|secret|example|sample|test|dummy|redacted|null|none|undefined|true|false|todo|tbd|placeholder)$|^(?:your|my|insert|enter|replace)[-_ ]|^<.*>$|^\$\{.*\}$|^\{\{.*\}\}$|^%\(.*\)s$|^\$[A-Z_]+$/i;

function validNotPlaceholder(value) {
    const v = String(value || "").trim().replace(/^['"]|['"]$/g, "");
    return v.length >= 6 && !TRON_PLACEHOLDER.test(v);
}

const TRON_DOTTED_IDENTIFIER = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;
const TRON_URL_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:([^@\s]+)@/i;
const TRON_PLACEHOLDER_PASSWORDS = new Set(["pass", "pwd", "password", "passwd", "secret", "changeme", "xxx", "xxxx",
    "****", "user", "username", "example", "test", "dummy"]);

function validUrlCredentials(value) {
    const m = TRON_URL_PASSWORD.exec(String(value || ""));
    if (!m) return false;
    return !TRON_PLACEHOLDER_PASSWORDS.has(m[1].toLowerCase()) && !TRON_PLACEHOLDER.test(m[1]);
}

function validHighEntropySecret(value) {
    const v = String(value || "").trim().replace(/^['"]|['"]$/g, "");
    if (!validNotPlaceholder(v) || v.length < 16 || TRON_DOTTED_IDENTIFIER.test(v)) return false;
    if (/^[A-Za-z]+$/.test(v) && v.length < 32) return false;  // identifiers, not secrets
    const classes = [/[a-z]/, /[A-Z]/, /\d/].filter(rx => rx.test(v)).length;
    return classes >= 2 && tronEntropy(v) >= 3.5;
}

const TRON_VALIDATORS = {
    luhn: isValidLuhn, payment_card: validPaymentCard, aadhaar: validAadhaar, iban: validIban,
    us_ssn: validUsSsn, aba_routing: validAbaRouting, ca_sin: validCaSin, gstin: validGstin,
    jwt: validJwt, not_placeholder: validNotPlaceholder, high_entropy_secret: validHighEntropySecret,
    url_credentials: validUrlCredentials,
};

// ─── Built-in detectors ──────────────────────────────────────────
function tronEscapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); }

function tronCompileDetector(d) {
    const keywords = (d.keywords || []).map(k => k.toLowerCase());
    const prefilter = d.prefilter || null;
    return {
        // "d" (match indices) is only needed to locate a capture group; it slows V8 down otherwise.
        pattern: new RegExp(d.pattern, (d.group ? "gd" : "g") + (d.ignore_case ? "i" : "")),
        severity: d.severity,
        confidence: d.confidence,
        description: d.description,
        category: d.category,
        group: d.group || 0,
        validator: d.validator ? TRON_VALIDATORS[d.validator] : null,
        keywords,
        keywordRe: keywords.length
            ? new RegExp("(?:" + [...keywords].sort((a, b) => b.length - a.length).map(tronEscapeRegex).join("|") + ")(?![a-z0-9])", "g")
            : null,
        require_keyword: !!d.require_keyword,
        prefilter: prefilter ? (d.ignore_case ? prefilter.map(p => p.toLowerCase()) : prefilter) : null,
        prefilterLower: !!d.ignore_case,
        generic: !!d.generic,
        rule_type: "regex",
        __builtin: true,
    };
}

const TRON_BUILTINS = {};
for (const d of TRON_DETECTORS) TRON_BUILTINS[d.name] = tronCompileDetector(d);

// Built-in detectors + dynamic SIEM policies (see updatePatterns).
let SENSITIVE_PATTERNS = Object.assign({}, TRON_BUILTINS);

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

function tronNormalize(text) {
    // eslint-disable-next-line no-control-regex
    if (/^[\x00-\x7f]*$/.test(text)) return text;
    return text.normalize("NFKC").replace(TRON_INVISIBLE, "");
}

const TRON_ALNUM = /[\p{L}\p{N}]/u;

function tronFindKeyword(keywordRe, lower, lo, hi) {
    // Search only inside [lo, hi): an unbounded exec() would scan to the end of the text
    // for every candidate without a nearby keyword.
    const windowText = lower.slice(lo, Math.min(hi, lower.length));
    keywordRe.lastIndex = 0;
    let km;
    while ((km = keywordRe.exec(windowText)) !== null) {
        const abs = lo + km.index;
        const prev = abs > 0 ? lower[abs - 1] : "";
        if (!prev || !TRON_ALNUM.test(prev)) return km[0];
    }
    return null;
}

function tronRunDetector(name, det, text, ctx, out, extra) {
    if (det.prefilter) {
        const hay = det.prefilterLower ? ctx.lower() : text;
        if (!det.prefilter.some(p => hay.includes(p))) return;
    }
    if (det.require_keyword && !ctx.ignoreKeyword) {
        const lower = ctx.lower();
        if (!det.keywords.some(k => lower.includes(k)) || !tronFindKeyword(det.keywordRe, lower, 0, lower.length)) return;
    }
    const regex = new RegExp(det.pattern.source, det.pattern.flags);
    let m, n = 0;
    while ((m = regex.exec(text)) !== null) {
        if (m[0].length === 0) { regex.lastIndex++; continue; }
        let value = m[0], start = m.index, end = m.index + m[0].length;
        if (det.group && m[det.group] !== undefined && m.indices && m.indices[det.group]) {
            value = m[det.group];
            [start, end] = m.indices[det.group];
        }
        if (!value || !value.trim()) continue;
        let validated = false;
        if (det.validator) {
            if (!det.validator(value)) continue;
            validated = true;
        }
        let keyword = null;
        if (det.keywordRe) {
            const lower = ctx.lower();
            keyword = tronFindKeyword(det.keywordRe, lower, Math.max(0, m.index - TRON_KEYWORD_WINDOW), m.index + m[0].length + TRON_KEYWORD_WINDOW);
        }
        if (det.require_keyword && !keyword && !ctx.ignoreKeyword) continue;
        out.push(Object.assign({
            pattern_name: name,
            description: det.description,
            category: det.category,
            matched_text: redactMatch(value, name),
            raw_length: value.length,
            start, end,
            severity: det.severity,
            confidence: Math.round(Math.min((det.confidence || 0.85) + (keyword ? TRON_KEYWORD_BOOST : 0), 0.99) * 100) / 100,
            validated,
            generic: det.generic,
            keyword,
        }, extra || {}));
        if (++n >= TRON_MAX_CANDIDATES) break;
    }
}

function tronCandidates(text, ignoreKeyword, encoding) {
    let lowerCache = null;
    const ctx = { ignoreKeyword, lower: () => (lowerCache === null ? (lowerCache = text.toLowerCase()) : lowerCache) };
    const out = [];
    for (const [name, config] of Object.entries(SENSITIVE_PATTERNS)) {
        if (!config) continue;
        if (config.__builtin) {
            tronRunDetector(name, config, text, ctx, out, encoding ? { encoding } : null);
        } else if (config.rule_type === 'detector') {
            const base = TRON_BUILTINS[config.detector];
            if (!base) continue;
            // Policy that references a built-in detector: validated matching, policy metadata.
            tronRunDetector(name, base, text, ctx, out, Object.assign({
                description: config.description || name,
                category: "SIEM Policy",
                severity: config.severity,
                policy_action: config.action,
                policy_threshold: config.threshold,
                policy_window_mins: config.window,
            }, encoding ? { encoding } : {}));
        } else if (config.rule_type === 'regex' && config.pattern && config.pattern.source) {
            const regex = new RegExp(config.pattern.source, config.pattern.flags);
            let m, n = 0;
            while ((m = regex.exec(text)) !== null) {
                if (m[0].length === 0) { regex.lastIndex++; continue; }
                out.push({
                    pattern_name: name,
                    description: config.description,
                    category: config.category,
                    matched_text: redactMatch(m[0], name),
                    raw_length: m[0].length,
                    start: m.index, end: m.index + m[0].length,
                    severity: config.severity,
                    confidence: config.confidence,
                    validated: false,
                    generic: false,
                    policy_action: config.__dynamic ? String(config.action || 'monitor').toLowerCase() : undefined,
                    policy_threshold: config.__dynamic ? (parseInt(config.threshold, 10) || 1) : undefined,
                    policy_window_mins: config.__dynamic ? (parseInt(config.window, 10) || 60) : undefined,
                    encoding: encoding || undefined,
                });
                if (++n >= TRON_MAX_CANDIDATES) break;
            }
        }
    }
    return out;
}

function tronDecodedCandidates(text, ignoreKeyword) {
    const out = [];
    let budget = 2000000, i = 0;
    TRON_B64_RUN.lastIndex = 0;
    let m;
    while ((m = TRON_B64_RUN.exec(text)) !== null) {
        if (i++ >= 64 || budget <= 0) break;
        const blob = m[0];
        if (blob.startsWith("eyJ") && blob.split(".").length >= 3) continue;
        let decoded;
        try {
            const b = blob.replace(/-/g, "+").replace(/_/g, "/");
            const bin = atob(b + "=".repeat((4 - (b.length % 4)) % 4));
            budget -= bin.length;
            decoded = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
        } catch (_) { continue; }
        if (!decoded) continue;
        let printable = 0;
        for (const ch of decoded) if (ch === "\n" || ch === "\r" || ch === "\t" || ch >= " ") printable++;
        if (printable / decoded.length < 0.95) continue;
        for (const c of tronCandidates(decoded, ignoreKeyword, "base64")) {
            c.start = m.index; c.end = m.index + blob.length;
            out.push(c);
        }
    }
    return out;
}

function tronPriority(f) {
    return [f.generic ? 0 : 1, f.validated ? 1 : 0, TRON_SEVERITY_RANK[f.severity] || 0, f.confidence || 0, f.end - f.start];
}

function tronResolveOverlaps(cands) {
    const sorted = cands.slice().sort((a, b) => {
        const pa = tronPriority(a), pb = tronPriority(b);
        for (let i = 0; i < pa.length; i++) if (pa[i] !== pb[i]) return pb[i] - pa[i];
        return 0;
    });
    const accepted = [], spans = [];
    for (const c of sorted) {
        // Policy findings carry enforcement metadata: never suppressed by a built-in overlap.
        if (c.encoding || c.category === "SIEM Policy" || c.policy_action !== undefined) { accepted.push(c); continue; }
        if (spans.some(([s, e]) => c.start < e && s < c.end)) continue;
        spans.push([c.start, c.end]);
        accepted.push(c);
    }
    const seen = new Set();
    return accepted.sort((a, b) => a.start - b.start || a.end - b.end).filter(f => {
        const k = f.pattern_name + "\u0000" + f.matched_text + "\u0000" + f.start;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
}

/**
 * Scan text content for all sensitive patterns.
 * Returns array of findings.
 */
function scanText(text, source = "unknown") {
    if (!text) return [];
    let input = String(text);
    if (input.length > TRON_MAX_SCAN_CHARS) input = input.slice(0, TRON_MAX_SCAN_CHARS);
    const norm = tronNormalize(input);
    const ignoreKeyword = source === "llm-redaction";
    const findings = tronResolveOverlaps([...tronCandidates(norm, ignoreKeyword), ...tronDecodedCandidates(norm, ignoreKeyword)]);

    // Line numbers + context
    const newlines = [];
    for (let i = norm.indexOf("\n"); i !== -1; i = norm.indexOf("\n", i + 1)) newlines.push(i);
    for (const f of findings) {
        let lo = 0, hi = newlines.length;
        while (lo < hi) { const mid = (lo + hi) >> 1; if (newlines[mid] < f.start) lo = mid + 1; else hi = mid; }
        f.line_number = lo + 1;
        f.context = norm.slice(Math.max(0, f.start - 30), Math.min(norm.length, f.end + 30)).replace(/\n/g, " ").slice(0, 120);
        delete f.start; delete f.end; delete f.generic;
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
    // A policy may share a name with a built-in detector (e.g. CREDIT_CARD); restore built-ins.
    for (const [k, v] of Object.entries(TRON_BUILTINS)) {
        if (!SENSITIVE_PATTERNS[k]) SENSITIVE_PATTERNS[k] = v;
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

            const detectorRef = String(ruleData.detector || '').toUpperCase();
            const detectorName = TRON_LEGACY_ALIASES[detectorRef] || detectorRef;
            if (ruleType === 'regex' && detectorName && TRON_BUILTINS[detectorName]) {
                // Policy referencing a validated built-in detector (checksums, keyword context).
                newPatterns[p.name] = {
                    rule_type: 'detector',
                    detector: detectorName,
                    pattern: TRON_BUILTINS[detectorName].pattern,
                    severity: severity,
                    confidence: TRON_BUILTINS[detectorName].confidence,
                    description: p.description || p.name,
                    category: "SIEM Policy",
                    action: (p.action || 'monitor').toLowerCase(),
                    threshold: (parseInt(p.threshold, 10) || 1),
                    window: (parseInt(p.window, 10) || 60),
                    exceptions,
                    exception_sets: exceptionSets,
                    __dynamic: true,
                };
            } else if (ruleType === 'regex') {
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
