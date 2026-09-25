/**
 * TRON THE DLP AGENT — Background Service Worker
 * Handles communication between content script and DLP API.
 * Manages scan results, settings, and notifications.
 */

importScripts("scanner.js");
importScripts("ai_analyzer.js");

// ─── Default Settings ────────────────────────────────────────
const DEFAULT_SETTINGS = {
    enabled: true,
    apiUrl: "http://localhost:5001",
    blockMode: "block",       // "warn" | "block" | "monitor"
    notifyOnDetection: true,
    reportToApi: true,
    scanThreshold: "medium",  // minimum severity to trigger: "low" | "medium" | "high" | "critical"
    allowedDomains: [],       // whitelisted domains
    blockedDomains: [],       // always block uploads to these
    maxFileSize: 10 * 1024 * 1024,
    // AI Settings
    aiEnabled: true,
    geminiApiKey: "",         // User sets this in popup settings
    aiScanMode: "smart",     // "always" | "smart" | "never"
    // smart = AI runs only for image OCR or context-only risky uploads
    deepScanEnabled: true,     // keep deep scan enabled in strict mode for binary formats (pdf/image)
    deepScanTimeoutMs: 12000,
    strictInspection: true,    // fail-closed when content cannot be confidently inspected
    settingsLocked: true,      // admin-managed; end users cannot change policy/API from popup
    hardBlockAllUploads: false,
    silentMode: false,
    highRiskDomains: [
        "pastebin", "paste.", "hastebin", "ghostbin",
        "file.io", "transfer.sh", "wetransfer",
        "mega.nz", "anonfiles", "catbox",
        "discord", "telegram", "slack",
        "reddit", "4chan",
        "github.com", "gitlab.com", "gist.github",
    ],
};

let settings = { ...DEFAULT_SETTINGS };
let scanHistory = [];
const reportedDownloadIds = new Set();
let cachedGeoMeta = null;
let lastGeoMetaFetch = 0;
let latestPreciseLocation = null;
const runtimeSessionId = `sess-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
let cachedAgentIdentity = null;
let agentIdentityPromise = null;
let cachedUserIdentity = null;
let lastUserIdentityFetch = 0;
let pendingArtifactQueue = [];
let artifactFlushInProgress = false;
const recentFileScanCache = new Map();
const FILE_SCAN_DEDUP_WINDOW_MS = 12000;
const policyHitTracker = new Map();
const POLICY_HIT_TRACKER_STORAGE_KEY = 'policyHitTrackerV1';
let dynamicNetworkPolicyDomains = [];
let stats = {
    totalScans: 0,
    totalBlocked: 0,
    totalWarned: 0,
    totalAllowed: 0,
    findingsByCategory: {},
    startedAt: new Date().toISOString(),
};

function hydratePolicyHitTracker(raw) {
    policyHitTracker.clear();
    if (!raw || typeof raw !== 'object') return;
    const now = Date.now();
    const maxRetentionMs = 24 * 60 * 60 * 1000;
    for (const [k, arr] of Object.entries(raw)) {
        if (!k || !Array.isArray(arr)) continue;
        const cleaned = arr
            .map(v => Number(v))
            .filter(v => Number.isFinite(v) && (now - v) <= maxRetentionMs)
            .sort((a, b) => a - b);
        if (cleaned.length > 0) {
            policyHitTracker.set(k, cleaned);
        }
    }
}

function persistPolicyHitTracker() {
    try {
        const asObj = {};
        for (const [k, arr] of policyHitTracker.entries()) {
            if (!Array.isArray(arr) || arr.length === 0) continue;
            asObj[k] = arr.slice(-1000);
        }
        chrome.storage.local.set({ [POLICY_HIT_TRACKER_STORAGE_KEY]: asObj });
    } catch (_) {
        // best effort persistence only
    }
}

// ─── Initialize ──────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get(["settings", "scanHistory", "stats"], (data) => {
        if (data.settings) settings = { ...DEFAULT_SETTINGS, ...data.settings };
        if (data.scanHistory) scanHistory = data.scanHistory;
        if (data.stats) stats = { ...stats, ...data.stats };
    });
    console.log("TRON THE DLP AGENT Extension installed");
    // Report extension installed/loaded to server
    if (settings.reportToApi && settings.apiUrl) {
        try {
            getAgentIdentity().then(({ agentId }) => {
                fetch(`${settings.apiUrl}/api/fleet/agents/${encodeURIComponent(agentId)}/operational`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                    body: JSON.stringify({ event_type: 'extension_installed', message: 'Extension installed/loaded', details: { version: chrome.runtime.getManifest().version } })
                }).catch(() => {});
            }).catch(() => {});
        } catch (e) {}
    }
});

// Load settings on startup
chrome.storage.local.get(["settings", "scanHistory", "stats", "dynamicPatterns", "pendingArtifactQueue", POLICY_HIT_TRACKER_STORAGE_KEY], (data) => {
    if (data.settings) settings = { ...DEFAULT_SETTINGS, ...data.settings };
    if (data.scanHistory) scanHistory = data.scanHistory || [];
    if (data.stats) stats = { ...stats, ...data.stats };
    if (Array.isArray(data.pendingArtifactQueue)) pendingArtifactQueue = data.pendingArtifactQueue;
    hydratePolicyHitTracker(data[POLICY_HIT_TRACKER_STORAGE_KEY]);
    if (data.dynamicPatterns && globalThis.TronScanner) {
        globalThis.TronScanner.updatePatterns(data.dynamicPatterns);
    }

    // Start syncing policies
    syncPolicies();
    setInterval(syncPolicies, 5 * 60 * 1000); // Every 5 minutes

    // Fleet check-in
    fleetCheckin();
    setInterval(fleetCheckin, 60 * 1000); // Every 60 seconds

    // Retry pending artifact uploads (best-effort reliability)
    flushPendingArtifactQueue();
    setInterval(flushPendingArtifactQueue, 30 * 1000);
    // Report that extension is active (operational)
    if (settings.reportToApi && settings.apiUrl) {
        getAgentIdentity().then(({ agentId }) => {
            fetch(`${settings.apiUrl}/api/fleet/agents/${encodeURIComponent(agentId)}/operational`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                body: JSON.stringify({ event_type: 'extension_started', message: 'Extension started and policies synced', details: { version: chrome.runtime.getManifest().version } })
            }).catch(() => {});
        }).catch(() => {});
    }
});

// ─── Fleet Check-in ──────────────────────────────────────────
async function fleetCheckin() {
    if (!settings.apiUrl) return;
    try {
        const aid = await getAgentIdentity();
        const meta = await buildAgentMeta();
        const userIdentity = await getBestEffortUserIdentity();
        await fetch(`${settings.apiUrl}/api/fleet/checkin`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
            body: JSON.stringify({
                agent_id: aid.agentId,
                agent_type: "browser_extension",
                hostname: aid.hostname,
                os: navigator.userAgentData?.platform || navigator.platform || "unknown",
                version: chrome.runtime.getManifest().version,
                user: userIdentity,
                scans_reported: stats.totalScans,
                incidents_reported: stats.totalBlocked + stats.totalWarned,
                meta: {
                    ...meta,
                    dlp_enabled: settings.enabled !== false,
                    extension_runtime_id: chrome.runtime.id,
                    extension_instance_id: aid.instanceId,
                },
            })
        });
    } catch (err) {
        // Silent fail
    }
}

function storageGet(keys) {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.get(keys, (data) => resolve(data || {}));
        } catch (_) {
            resolve({});
        }
    });
}

function storageSet(data) {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.set(data, () => resolve(true));
        } catch (_) {
            resolve(false);
        }
    });
}

async function getAgentIdentity() {
    if (cachedAgentIdentity) return cachedAgentIdentity;
    if (agentIdentityPromise) return agentIdentityPromise;

    agentIdentityPromise = (async () => {
        const existing = await storageGet(["extensionInstanceId"]);
        let instanceId = existing.extensionInstanceId;
        if (!instanceId) {
            instanceId = `inst-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
            await storageSet({ extensionInstanceId: instanceId });
        }

        const suffix = String(instanceId).slice(-6);
        cachedAgentIdentity = {
            instanceId,
            agentId: `browser-ext-${chrome.runtime.id}-${instanceId}`,
            hostname: `Chrome-${suffix}`,
        };
        return cachedAgentIdentity;
    })();

    try {
        return await agentIdentityPromise;
    } finally {
        agentIdentityPromise = null;
    }
}

function getPlatformInfo() {
    return new Promise((resolve) => {
        try {
            chrome.runtime.getPlatformInfo((info) => resolve(info || {}));
        } catch (_) {
            resolve({});
        }
    });
}

async function getBestEffortUserIdentity() {
    const now = Date.now();
    if (cachedUserIdentity && (now - lastUserIdentityFetch) < 10 * 60 * 1000) {
        return cachedUserIdentity;
    }

    let identity = 'browser_user';
    try {
        if (chrome.identity && typeof chrome.identity.getProfileUserInfo === 'function') {
            const profile = await new Promise((resolve) => {
                try {
                    chrome.identity.getProfileUserInfo((info) => resolve(info || {}));
                } catch (_) {
                    resolve({});
                }
            });
            if (profile && profile.email) {
                identity = profile.email;
            }
        }
    } catch (_) {
        // fallback stays browser_user
    }

    if (identity === 'browser_user') {
        const aid = await getAgentIdentity();
        identity = `browser_user_${String(aid.instanceId).slice(-6)}`;
    }

    cachedUserIdentity = identity;
    lastUserIdentityFetch = now;
    return identity;
}

async function fetchGeoMeta() {
    const now = Date.now();
    // Cache geo lookup for 6 hours to avoid noisy external calls.
    if (cachedGeoMeta && (now - lastGeoMetaFetch) < 6 * 60 * 60 * 1000) {
        return cachedGeoMeta;
    }

    try {
        const res = await fetch('https://ipapi.co/json/', { headers: { 'ngrok-skip-browser-warning': 'true' } });
        if (res.ok) {
            const geo = await res.json();
            cachedGeoMeta = {
                location: [geo.city, geo.region, geo.country_name].filter(Boolean).join(', ') || 'Remote',
                geo,
            };
            lastGeoMetaFetch = now;
            return cachedGeoMeta;
        }
    } catch (_) {
        // Ignore and fallback
    }

    return {
        location: 'Remote',
        geo: {},
    };
}

async function reverseGeocode(lat, lon) {
    try {
        const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}`;
        const res = await fetch(url, {
            headers: {
                'Accept': 'application/json',
                'User-Agent': 'TronDLP/1.0 (fleet geolocation)'
            }
        });
        if (!res.ok) return null;
        const data = await res.json();
        const addr = data.address || {};
        return {
            location: [addr.city || addr.town || addr.village, addr.state, addr.country].filter(Boolean).join(', ') || data.display_name || null,
            city: addr.city || addr.town || addr.village || null,
            region: addr.state || null,
            country_name: addr.country || null,
            display_name: data.display_name || null,
        };
    } catch (_) {
        return null;
    }
}

async function buildAgentMeta() {
    const platformInfo = await getPlatformInfo();
    const geoMeta = await fetchGeoMeta();

    let preciseMeta = {};
    if (latestPreciseLocation && Number.isFinite(latestPreciseLocation.latitude) && Number.isFinite(latestPreciseLocation.longitude)) {
        const rg = await reverseGeocode(latestPreciseLocation.latitude, latestPreciseLocation.longitude);
        preciseMeta = {
            location: rg?.location || geoMeta.location,
            geo: {
                ...(geoMeta.geo || {}),
                latitude: latestPreciseLocation.latitude,
                longitude: latestPreciseLocation.longitude,
                accuracy_m: latestPreciseLocation.accuracy_m,
                source: latestPreciseLocation.source || 'browser_geolocation',
                captured_at: latestPreciseLocation.timestamp,
                ...(rg || {}),
            }
        };
    }

    return {
        ...geoMeta,
        ...preciseMeta,
        platform: [platformInfo.os, platformInfo.arch].filter(Boolean).join('/') || (navigator.userAgentData?.platform || navigator.platform || 'unknown'),
        arch: platformInfo.arch || 'unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
        language: navigator.language || 'unknown',
        user_agent: navigator.userAgent || 'unknown',
        session_id: runtimeSessionId,
    };
}

// ─── Screenshot Capture ──────────────────────────────────────
async function captureScreenshot(domain, severity, findings) {
    try {
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: "jpeg", quality: 60 });
        await fetch(`${settings.apiUrl}/api/screenshots`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
            body: JSON.stringify({
                image_data: dataUrl,
                domain: domain,
                severity: severity,
                url: "",
                findings_summary: findings.slice(0, 3).map(f => `[${f.pattern_name}] ${f.matched_text}`).join(", "),
            })
        });
        console.log("Screenshot captured and sent to SIEM");
    } catch (err) {
        console.warn("Screenshot capture failed:", err.message);
    }
}

// ─── Sync Remote Policies ────────────────────────────────────
async function syncPolicies() {
    if (!settings.apiUrl) return;

    try {
        const aid = await getAgentIdentity();
        const syncUrl = `${settings.apiUrl}/api/policies/sync?agent_id=${encodeURIComponent(aid.agentId)}`;
        const response = await fetch(syncUrl, {
            headers: { "ngrok-skip-browser-warning": "true" }
        });
        if (response.ok) {
            const data = await response.json();
            const patterns = Array.isArray(data.patterns) ? data.patterns : [];

            const networkPolicyDomains = patterns
                .filter(p => {
                    const isNetworkBlock = String(p?.rule_type || '').toLowerCase() === 'network'
                        && String(p?.action || '').toLowerCase() === 'block';
                    return isNetworkBlock;
                })
                .flatMap(p => {
                    const rd = (p && typeof p.rule_data === 'object' && p.rule_data) ? p.rule_data : {};
                    const arr = Array.isArray(rd.blocked_domains) ? rd.blocked_domains : [];
                    return arr;
                })
                .map(v => normalizeHost(v))
                .filter(Boolean);

            dynamicNetworkPolicyDomains = Array.from(new Set(networkPolicyDomains));

            if (data.managed_settings && typeof data.managed_settings === 'object') {
                settings = { ...settings, ...data.managed_settings, settingsLocked: true };
                const managedBlocked = Array.isArray(data.managed_settings.blockedDomains)
                    ? data.managed_settings.blockedDomains
                    : [];
                // Keep hard blocked domains strictly from managed settings only.
                // Network policies (with threshold/window) are evaluated in policy engine path.
                settings.blockedDomains = Array.from(new Set(
                    managedBlocked.map(v => normalizeHost(v)).filter(Boolean)
                ));
                chrome.storage.local.set({ settings });

                // Broadcast to content scripts so they refresh quickly.
                chrome.tabs.query({}, (tabs) => {
                    for (const tab of tabs) {
                        chrome.tabs.sendMessage(tab.id, { type: "SETTINGS_UPDATED", settings }).catch(() => { });
                    }
                });
            } else {
                // If managed settings are absent, proactively drop stale domains that were
                // previously merged from network policies to avoid bypassing threshold logic.
                const currentBlocked = Array.isArray(settings.blockedDomains) ? settings.blockedDomains : [];
                const pruned = currentBlocked
                    .map(v => normalizeHost(v))
                    .filter(Boolean)
                    .filter(v => !networkPolicyDomains.includes(v));
                settings.blockedDomains = Array.from(new Set(pruned));
                chrome.storage.local.set({ settings });
            }
            if (patterns.length > 0) {
                console.log(`Synced ${patterns.length} dynamic policies from SIEM`);
                chrome.storage.local.set({ dynamicPatterns: patterns });
                if (globalThis.TronScanner) {
                    globalThis.TronScanner.updatePatterns(patterns);
                }
            }
        }
    } catch (err) {
        console.warn("TRON THE DLP AGENT: Failed to sync rules:", err.message);
    }
}

// ─── Message Handler ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_FILE") {
        handleFileScan(message, sender)
            .then(sendResponse)
            .catch((err) => {
                console.error("TRON THE DLP AGENT: SCAN_FILE failure:", err);
                sendResponse({
                    action: "block",
                    reason: "background_exception_fail_closed",
                    severity: "high",
                    findings: [],
                    findingCount: 0,
                    fileName: message?.fileName || "unknown_file",
                });
            });
        return true; // async response
    }

    if (message.type === "GET_UPLOAD_CONTEXT") {
        Promise.all([getBestEffortUserIdentity(), getAgentIdentity()]).then(([userIdentity, aid]) => {
            sendResponse({
                apiUrl: settings.apiUrl,
                agentId: aid.agentId,
                hostname: aid.hostname,
                user: userIdentity,
            });
        }).catch(() => {
            sendResponse({ apiUrl: settings.apiUrl, agentId: '', hostname: '', user: 'browser_user' });
        });
        return true;
    }

    if (message.type === "UPLOAD_ARTIFACT_RAW") {
        postRawArtifactMultipart(message).then((res) => sendResponse(res)).catch(() => sendResponse({ ok: false }));
        return true;
    }

    if (message.type === "GET_SETTINGS") {
        sendResponse({ settings });
        return false;
    }

    if (message.type === "UPDATE_SETTINGS") {
        if (settings.settingsLocked) {
            sendResponse({ success: false, error: "settings_locked", message: "Settings are managed by administrator" });
            return false;
        }
        settings = { ...settings, ...message.settings };
        chrome.storage.local.set({ settings });
        // Broadcast to all content scripts
        chrome.tabs.query({}, (tabs) => {
            for (const tab of tabs) {
                chrome.tabs.sendMessage(tab.id, { type: "SETTINGS_UPDATED", settings }).catch(() => { });
            }
        });
        sendResponse({ success: true });
        // Send operational log about settings change
        if (settings.reportToApi && settings.apiUrl) {
            getAgentIdentity().then(({ agentId }) => {
                fetch(`${settings.apiUrl}/api/fleet/agents/${encodeURIComponent(agentId)}/operational`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                    body: JSON.stringify({ event_type: 'settings_updated', message: 'Extension settings updated', details: message.settings })
                }).catch(() => {});
            }).catch(() => {});
        }
        return false;
    }

    if (message.type === "GET_STATS") {
        sendResponse({ stats, historyCount: scanHistory.length });
        return false;
    }

    if (message.type === "GET_HISTORY") {
        const limit = message.limit || 50;
        sendResponse({ history: scanHistory.slice(-limit).reverse() });
        return false;
    }

    if (message.type === "CLEAR_HISTORY") {
        scanHistory = [];
        stats = {
            totalScans: 0, totalBlocked: 0, totalWarned: 0, totalAllowed: 0,
            findingsByCategory: {}, startedAt: new Date().toISOString(),
        };
        chrome.storage.local.set({ scanHistory, stats });
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "FILE_UPLOAD_DECISION") {
        // User made a decision on a blocked upload
        const { decision, scanId } = message;
        const entry = scanHistory.find(h => h.id === scanId);
        if (entry) {
            entry.userDecision = decision;
            entry.decisionTime = new Date().toISOString();
        }
        if (decision === "allow") stats.totalAllowed++;
        if (decision === "block") stats.totalBlocked++;
        chrome.storage.local.set({ scanHistory, stats });
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "SCAN_TEXT") {
        handleTextScan(message, sender)
            .then(sendResponse)
            .catch((err) => {
                console.error("TRON THE DLP AGENT: SCAN_TEXT failure:", err);
                sendResponse({
                    action: "allow",
                    reason: "text_scan_exception",
                    severity: "none",
                    findings: [],
                    domain: extractDomain(message?.url || sender?.tab?.url || ""),
                });
            });
        return true;
    }

    if (message.type === "PRECISE_LOCATION_UPDATE") {
        const loc = message.location || {};
        if (Number.isFinite(loc.latitude) && Number.isFinite(loc.longitude)) {
            latestPreciseLocation = {
                latitude: loc.latitude,
                longitude: loc.longitude,
                accuracy_m: loc.accuracy_m,
                altitude: loc.altitude,
                heading: loc.heading,
                speed: loc.speed,
                timestamp: loc.timestamp || new Date().toISOString(),
                source: loc.source || 'browser_geolocation',
            };
        }
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "PRECISE_LOCATION_STATUS") {
        const status = message.status || 'unknown';
        const trigger = message.trigger || 'unknown';
        if (settings.reportToApi && settings.apiUrl) {
            getAgentIdentity().then(({ agentId }) => {
                fetch(`${settings.apiUrl}/api/fleet/agents/${encodeURIComponent(agentId)}/operational`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                    body: JSON.stringify({
                        event_type: 'location_permission_status',
                        message: `Precise location ${status}`,
                        details: { status, trigger }
                    })
                }).catch(() => {});
            }).catch(() => {});
        }
        sendResponse({ success: true });
        return false;
    }
});

// ─── Download scanning ───────────────────────────────────────
chrome.downloads.onCreated.addListener((downloadItem) => {
    if (!settings.enabled) return;

    // Quick heuristic for malware simulation
    const riskyExts = ['.exe', '.bat', '.sh', '.vbs', '.msi', '.scr', '.dll'];
    const filename = (downloadItem.filename || downloadItem.url).split('?')[0].toLowerCase();
    const isRisky = riskyExts.some(ext => filename.endsWith(ext));

    if (isRisky) {
        chrome.downloads.pause(downloadItem.id, () => {
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: "Download Blocked",
                message: `TRON THE DLP AGENT blocked the download of a potentially malicious file: ${downloadItem.filename}`,
                priority: 2
            });
            chrome.downloads.cancel(downloadItem.id);
            // Optionally report to API
            if (settings.reportToApi) {
                reportToApi(downloadItem.filename, 0, extractDomain(downloadItem.url), [], "critical", "block", null);
                // Report blocked risky download immediately
                try {
                    if (!reportedDownloadIds.has(downloadItem.id)) {
                        reportedDownloadIds.add(downloadItem.id);
                        Promise.all([getBestEffortUserIdentity(), getAgentIdentity()]).then(([userIdentity, aid]) => {
                            fetch(`${settings.apiUrl}/api/scan/report`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                                body: JSON.stringify({
                                    agent_id: aid.agentId,
                                    scan_type: 'web_download',
                                    source: downloadItem.url,
                                    findings: [],
                                    severity: 'critical',
                                    file_path: downloadItem.filename || downloadItem.url,
                                    file_size: downloadItem.fileSize || 0,
                                    user: userIdentity,
                                    host: aid.hostname
                                })
                            }).catch(() => {});
                        }).catch(() => {});
                    }
                } catch (e) {}
            }
        });
    }
});

// Report completed (non-blocked) downloads with final metadata.
chrome.downloads.onChanged.addListener((delta) => {
    if (!settings.enabled || !settings.reportToApi || !settings.apiUrl) return;
    if (!delta || !delta.id || !delta.state) return;
    if (delta.state.current !== 'complete') return;
    if (reportedDownloadIds.has(delta.id)) return;

    chrome.downloads.search({ id: delta.id }, (results) => {
        try {
            const item = (results && results[0]) || null;
            if (!item) return;

            reportedDownloadIds.add(delta.id);
            Promise.all([getBestEffortUserIdentity(), getAgentIdentity()]).then(([userIdentity, aid]) => {
                fetch(`${settings.apiUrl}/api/scan/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
                    body: JSON.stringify({
                        agent_id: aid.agentId,
                        scan_type: 'web_download',
                        source: item.url || '',
                        findings: [],
                        severity: 'none',
                        file_path: item.filename || item.finalUrl || item.url || `download-${item.id}`,
                        file_size: item.fileSize || item.bytesReceived || item.totalBytes || 0,
                        user: userIdentity,
                        host: aid.hostname
                    })
                }).catch(() => {});
            }).catch(() => {});
        } catch (e) {
            // ignore
        }
    });
});

// ─── File Scan Handler ───────────────────────────────────────
async function handleFileScan(message, sender) {
    const { fileContent, fileContentBase64, fileContentTruncated, isImage, fileName, fileSize, fileType, uploadUrl, clientArtifactUpload, uploadBatchId } = message;

    if (!settings.enabled) {
        return { action: "allow", reason: "DLP disabled" };
    }

    // Check allowed domains
    const domain = extractDomain(uploadUrl || sender.tab?.url || "");
    const userIdentity = await getBestEffortUserIdentity();
    const exceptionCtx = buildExceptionContext({
        user: userIdentity,
        domain,
        text: (typeof fileContent === 'string' ? fileContent.slice(0, 5000) : ''),
    });
    if ((settings.allowedDomains || []).some(d => domainMatchesPolicy(domain, d))) {
        return { action: "allow", reason: "Whitelisted domain" };
    }

    // Check blocked domains
    if ((settings.blockedDomains || []).some(d => domainMatchesPolicy(domain, d))) {
        recordScan(fileName, fileSize, domain, [], "block", "Blocked domain");
        return { action: "block", reason: "Domain is on the blocklist" };
    }

    // De-duplicate near-simultaneous scans of the same file payload.
    // Some sites trigger multiple handlers (change + submit) for one upload.
    const fpSample = fileContentBase64
        ? String(fileContentBase64).slice(0, 512)
        : String(fileContent || '').slice(0, 512);
    const fingerprint = `${domain}|${fileName}|${fileSize}|${fpSample.length}|${fpSample.slice(0, 120)}`;
    const nowMs = Date.now();
    const cached = recentFileScanCache.get(fingerprint);
    if (cached && (nowMs - cached.ts) <= FILE_SCAN_DEDUP_WINDOW_MS) {
        return {
            ...cached.result,
            deduped: true,
            dedup_reason: 'same_file_recently_scanned',
        };
    }

    // Periodic cleanup to avoid unbounded growth.
    if (recentFileScanCache.size > 100) {
        for (const [k, v] of recentFileScanCache.entries()) {
            if ((nowMs - v.ts) > (FILE_SCAN_DEDUP_WINDOW_MS * 3)) {
                recentFileScanCache.delete(k);
            }
        }
    }

    stats.totalScans++;

    // If extension/type was spoofed (e.g., image renamed to .txt), detect real mime from bytes.
    // This allows OCR-capable AI path to still run on image payloads.
    let effectiveIsImage = !!isImage;
    let effectiveMime = '';
    let aiInputContent = typeof fileContent === 'string' ? fileContent : '';
    if (fileContentBase64) {
        effectiveMime = inferMimeFromBase64(fileContentBase64);
        if (!effectiveIsImage && effectiveMime.startsWith('image/')) {
            effectiveIsImage = true;
            aiInputContent = `data:${effectiveMime};base64,${fileContentBase64}`;
        }
    }
    const effectiveFileType = normalizeMimeType(fileType, fileName, effectiveMime || inferMimeFromBase64(fileContentBase64 || ''));
    const isPdf = (effectiveFileType === 'application/pdf') || String(fileName || '').toLowerCase().endsWith('.pdf');

    // ── PHASE 0: Policy Checks (Extension/Size) ─────────────────
    const policyFindings = [];
    const exceptionFindings = [];
    const nameParts = fileName.split(".");
    const ext = nameParts.length > 1 ? "." + nameParts.pop().toLowerCase() : "";
    const rules = globalThis.TronScanner.SENSITIVE_PATTERNS || {};
    const matchedGlobalExceptionSet = findMatchingGlobalExceptionSet(rules, exceptionCtx);

    for (const [name, config] of Object.entries(rules)) {
        if (config.rule_type === 'extension') {
            // Normalize blocked extensions; accept either an array or a legacy pattern string
            let blockedList = config.blocked_extensions;
            if (!Array.isArray(blockedList) && typeof config.pattern === 'string' && config.pattern.toUpperCase().startsWith('EXT:')) {
                blockedList = config.pattern.slice(4).split(',').map(s => s.trim()).filter(Boolean);
            }
            const blocked = (blockedList || []).map(e => e.startsWith(".") ? e.toLowerCase() : "." + e.toLowerCase());
            if (blocked.includes(ext)) {
                if (isPolicyException(config.exceptions, exceptionCtx)) {
                    exceptionFindings.push({
                        pattern_name: `${name}_EXCEPTION`,
                        description: `Policy exception matched for ${name}`,
                        category: "Policy Exception",
                        matched_text: `Bypass extension block: ${ext}`,
                        raw_length: 0,
                        line_number: 0,
                        severity: 'low',
                        confidence: 1.0,
                        context: buildExceptionNote(config.exceptions, exceptionCtx),
                        policy_action: 'monitor',
                        source: 'policy_exception',
                    });
                    continue;
                }
                console.log(`TRON AGENT: Matching Extension Policy FOUND: ${name} (blocking ${ext})`);
                policyFindings.push({
                    pattern_name: name,
                    description: config.description,
                    category: "Policy Violation",
                    matched_text: `Blocked Type: ${ext}`,
                    raw_length: 0,
                    line_number: 0,
                    severity: config.severity,
                    confidence: 1.0,
                    context: `Files with ${ext} extension are prohibited by policy.`,
                    policy_action: String(config.action || 'monitor').toLowerCase(),
                    policy_threshold: (parseInt(config.threshold, 10) || 1),
                    policy_window_mins: (parseInt(config.window, 10) || 60),
                });
            }
        } else if (config.rule_type === 'file_size') {
            const maxSizeBytes = (parseInt(config.max_size_mb) || 0) * 1024 * 1024;
            if (maxSizeBytes > 0 && fileSize > maxSizeBytes) {
                if (isPolicyException(config.exceptions, exceptionCtx)) {
                    exceptionFindings.push({
                        pattern_name: `${name}_EXCEPTION`,
                        description: `Policy exception matched for ${name}`,
                        category: "Policy Exception",
                        matched_text: `Bypass file-size block: ${(fileSize / (1024 * 1024)).toFixed(2)}MB`,
                        raw_length: 0,
                        line_number: 0,
                        severity: 'low',
                        confidence: 1.0,
                        context: buildExceptionNote(config.exceptions, exceptionCtx),
                        policy_action: 'monitor',
                        source: 'policy_exception',
                    });
                    continue;
                }
                policyFindings.push({
                    pattern_name: name,
                    description: config.description,
                    category: "Policy Violation",
                    matched_text: `File size: ${(fileSize / (1024 * 1024)).toFixed(2)}MB`,
                    raw_length: 0,
                    line_number: 0,
                    severity: config.severity,
                    confidence: 1.0,
                    context: `File exceeds maximum size limit of ${config.max_size_mb}MB`,
                    policy_action: String(config.action || 'monitor').toLowerCase(),
                    policy_threshold: (parseInt(config.threshold, 10) || 1),
                    policy_window_mins: (parseInt(config.window, 10) || 60),
                });
            }
        } else if (config.rule_type === 'network') {
            const blocked = Array.isArray(config.blocked_domains) ? config.blocked_domains : [];
            const matchedBlockedDomain = blocked.find(bd => domainMatchesPolicy(domain, bd));
            if (matchedBlockedDomain) {
                if (isPolicyException(config.exceptions, exceptionCtx)) {
                    exceptionFindings.push({
                        pattern_name: `${name}_EXCEPTION`,
                        description: `Policy exception matched for ${name}`,
                        category: "Policy Exception",
                        matched_text: `Bypass domain block: ${matchedBlockedDomain}`,
                        raw_length: 0,
                        line_number: 0,
                        severity: 'low',
                        confidence: 1.0,
                        context: buildExceptionNote(config.exceptions, exceptionCtx),
                        policy_action: 'monitor',
                        source: 'policy_exception',
                    });
                    continue;
                }
                policyFindings.push({
                    pattern_name: name,
                    description: config.description || 'Blocked destination domain policy',
                    category: "Policy Violation",
                    matched_text: `Blocked Domain: ${matchedBlockedDomain}`,
                    raw_length: 0,
                    line_number: 0,
                    severity: config.severity,
                    confidence: 1.0,
                    context: `Destination ${domain} matched blocked domain policy ${matchedBlockedDomain}`,
                    policy_action: String(config.action || 'block').toLowerCase(),
                    policy_threshold: (parseInt(config.threshold, 10) || 1),
                    policy_window_mins: (parseInt(config.window, 10) || 60),
                });
            }
        }
    }

    // ── PHASE 1: Regex Scan (fast, free) ────────────────────────
    const regexInput = (effectiveIsImage || isPdf) ? '' : (typeof fileContent === 'string' ? fileContent : '');
    const rawRegexFindings = globalThis.TronScanner.scanText(regexInput, fileName);
    const regexFindings = rawRegexFindings.filter((f) => {
        const cfg = rules[String(f?.pattern_name || '')];
        return !isPolicyException(cfg?.exceptions, exceptionCtx);
    });

    // Regex-first fast path (Symantec-style):
    // If deterministic policy/regex already found enforceable matches,
    // do not spend extra time on deep parse/AI.
    const quickFindingsRaw = dedupeFindings([...policyFindings, ...regexFindings, ...exceptionFindings]);
    const quickEnforceableFindings = quickFindingsRaw.filter(isEnforceableFinding);

    // ── PHASE 1B: Server Deep File Parse (conditional fallback) ─
    // Deep parse runs only when initial deterministic scan is clean.
    // This preserves high recall while keeping regex-path latency very low.
    let serverDeepFindings = [];
    let deepScanStatus = { attempted: false, ok: false, findings: [] };
    const requiresDeepInspection = !!(effectiveIsImage || isPdf);
    const shouldRunDeepScan = !!(
        settings.apiUrl &&
        fileContentBase64 &&
        quickEnforceableFindings.length === 0 &&
        (settings.deepScanEnabled === true || requiresDeepInspection)
    );
    if (shouldRunDeepScan) {
        deepScanStatus = await fetchServerDeepScan({
            fileName,
            fileSize,
            domain,
            fileType: effectiveFileType,
            isImage: effectiveIsImage,
            fileContentBase64,
        });
        serverDeepFindings = deepScanStatus.findings || [];
    }

    let allFindings = dedupeFindings([...quickFindingsRaw, ...serverDeepFindings]);
    allFindings = applyPolicyThresholdGates(allFindings, domain);
    const enforceableFindings = allFindings.filter(isEnforceableFinding);

    // Determine regex severity
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    const thresholdLevel = severityOrder[settings.scanThreshold] || 2;
    let overallSeverity = "none";
    if (enforceableFindings.length > 0) {
        const maxFinding = enforceableFindings.reduce((max, f) =>
            severityOrder[f.severity] > severityOrder[max.severity] ? f : max
        );
        overallSeverity = maxFinding.severity;
    }

    const hasCriticalFinding = enforceableFindings.some(f => (f.severity || '').toLowerCase() === 'critical');
    const hasHighOrCriticalFinding = enforceableFindings.some(f => {
        const sev = (f.severity || '').toLowerCase();
        return sev === 'high' || sev === 'critical';
    });
    const hasAadhaar = enforceableFindings.some(f => String(f.pattern_name || '').toUpperCase().includes('AADHAAR'));
    const hasCreditCard = enforceableFindings.some(f => String(f.pattern_name || '').toUpperCase().includes('CREDIT_CARD'));
    const hasPolicyBlock = enforceableFindings.some(f => String(f.policy_action || '').toLowerCase() === 'block');
    const hasPolicyWarn = enforceableFindings.some(f => String(f.policy_action || '').toLowerCase() === 'warn');
    const hasAnyFinding = enforceableFindings.length > 0;

    // Confidence gate: do not allow if inspection coverage is weak.
    const inspectedByRegex = !!regexInput && regexInput.length > 0;
    const inspectedByDeep = deepScanStatus.attempted && deepScanStatus.ok;
    // AI alone is not considered deterministic enough for strict-inspection anti-evasion.
    const inspectionConfident = inspectedByRegex || inspectedByDeep;

    if (!hasAnyFinding && settings.strictInspection && !inspectionConfident) {
        allFindings.push({
            pattern_name: 'UNSCANNABLE_CONTENT',
            description: 'File could not be confidently inspected (strict mode)',
            category: 'Policy Violation',
            matched_text: fileName,
            raw_length: 0,
            line_number: 0,
            severity: 'high',
            confidence: 1.0,
            context: `strictInspection=true, regex=${inspectedByRegex}, deep=${inspectedByDeep}, image_ai=${effectiveIsImage && settings.aiEnabled && !!settings.geminiApiKey}`,
            source: 'inspection_guard',
        });
        overallSeverity = 'high';
    }

    // Determine initial action from regex/deep scan
    let action;
    if (allFindings.length === 0) {
        action = "allow";
    } else if (hasPolicyBlock) {
        action = "block";
    } else if (hasAadhaar || hasCreditCard || (settings.strictInspection && hasHighOrCriticalFinding)) {
        action = "block";
    } else if (hasCriticalFinding) {
        // Never allow critical leaks through.
        action = "block";
    } else if (hasPolicyWarn) {
        action = "warn";
    } else if (severityOrder[overallSeverity] < thresholdLevel) {
        action = "allow";
    } else if (settings.blockMode === "block") {
        action = "block";
    } else if (settings.blockMode === "warn") {
        action = "warn";
    } else {
        action = "monitor";
    }

    // Group by category
    const categories = {};
    for (const f of allFindings) {
        if (!categories[f.category]) categories[f.category] = [];
        categories[f.category].push(f);
    }

    // Build initial result
    let result = {
        action,
        findings: allFindings,
        severity: overallSeverity,
        categories,
        findingCount: allFindings.length,
        fileName,
        ai_analysis: { enabled: false },
    };

    if (matchedGlobalExceptionSet) {
        result.findings = dedupeFindings([
            ...(result.findings || []),
            {
                pattern_name: `GLOBAL_EXCEPTION_${matchedGlobalExceptionSet.id || 'MATCHED'}`,
                description: `Global exception matched: ${matchedGlobalExceptionSet.name || 'unnamed'}`,
                category: 'Policy Exception',
                matched_text: `Bypass due to global exception at ${domain || 'unknown'}`,
                raw_length: 0,
                line_number: 0,
                severity: 'low',
                confidence: 1.0,
                context: buildExceptionNote(matchedGlobalExceptionSet, exceptionCtx),
                policy_action: 'monitor',
                source: 'global_exception',
            }
        ]);
        result.findingCount = result.findings.length;
        result.action = 'allow';
        result.severity = 'none';
        result.reason = `global_exception:${matchedGlobalExceptionSet.id || 'matched'}`;
    }

    if (isPdf) {
        // Deterministic PDF mode: disable AI-based narrative output.
        result.ai_analysis = { enabled: false, skipped_reason: 'pdf_deterministic_mode' };
    }

    // ── PHASE 2: AI Scan (smart, contextual) ────────────────────
    // Bandwidth optimization:
    // - If deterministic engine already found data (policy/regex/deep), skip AI in smart mode.
    // - Run AI only when we still need extra context/OCR (mostly no-findings cases).
    const hasAnyRuleDetection = allFindings.some(f => String(f?.pattern_name || '').toUpperCase() !== 'UNSCANNABLE_CONTENT');
    const hasGeminiConfigured = !!(settings.aiEnabled && settings.geminiApiKey);
    const shouldRunAI = hasGeminiConfigured && !isPdf && (
        !hasAnyFinding && (
        settings.aiScanMode === "always" ||
        (settings.aiScanMode === "smart" && (
            effectiveIsImage ||                 // OCR/image checks when deterministic path found nothing
            isHighRiskDomain(domain)
        ))
        )
    );

    if (!shouldRunAI && hasGeminiConfigured) {
        if (settings.aiScanMode === 'smart' && hasAnyRuleDetection) {
            result.ai_analysis = { enabled: false, skipped_reason: 'deterministic_detection_present' };
        }
    }

    if (shouldRunAI) {
        try {
            // If strict-inspection inserted only the UNSCANNABLE_CONTENT guard,
            // remove it before AI merge so successful AI evidence can drive final action.
            result.findings = (result.findings || []).filter(
                (f) => String(f?.pattern_name || '').toUpperCase() !== 'UNSCANNABLE_CONTENT'
            );
            result.findingCount = result.findings.length;
            if (result.findingCount === 0) {
                result.severity = 'none';
                if (result.action === 'block') result.action = 'allow';
            }

            console.log(`Running AI analysis on ${fileName}... (isImage: ${effectiveIsImage})`);
            const aiResult = await globalThis.TronAI.analyzeWithAI(
                aiInputContent, fileName, domain, allFindings, settings.geminiApiKey, effectiveIsImage
            );

            // Merge AI results with regex results
            result = globalThis.TronAI.mergeAnalysis(result, aiResult);

            // If AI extracted text that matches a dynamic regex policy,
            // enforce policy intent (especially block rules like custom keyword blocks).
            const policyFromAI = deriveDynamicPolicyFindingsFromAIEvidence(result.findings);
            if (policyFromAI.length > 0) {
                result.findings = dedupeFindings([...(result.findings || []), ...policyFromAI]);
                result.findingCount = result.findings.length;

                const hasPolicyBlock = policyFromAI.some(f => String(f.policy_action || '').toLowerCase() === 'block');
                if (hasPolicyBlock) {
                    result.action = 'block';
                }
            }

            // Re-apply block mode to merged action
            if (result.action !== "allow" && settings.blockMode === "monitor") {
                result.action = "monitor";
            }
            if (hasCriticalFinding || hasAadhaar || hasCreditCard || (settings.strictInspection && hasHighOrCriticalFinding)) {
                result.action = "block";
            }

            if (matchedGlobalExceptionSet) {
                result.action = 'allow';
                result.severity = 'none';
                result.reason = `global_exception:${matchedGlobalExceptionSet.id || 'matched'}`;
            }

            console.log(`AI verdict: ${aiResult.recommendation || "N/A"} | Risk: ${aiResult.risk_score || "N/A"}/100`);
        } catch (aiErr) {
            console.warn("AI analysis failed, using regex-only results:", aiErr);
            result.ai_analysis = { enabled: true, error: aiErr.message };
        }
    }

    if (matchedGlobalExceptionSet) {
        result.action = 'allow';
        result.severity = 'none';
        result.reason = `global_exception:${matchedGlobalExceptionSet.id || 'matched'}`;
    }

    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    result.scanId = scanId;

    // Record
    recordScan(fileName, fileSize, domain, result.findings, result.action,
        `${result.findingCount} items found${shouldRunAI ? " (AI+Policy)" : " (Policy/Regex)"}`,
        scanId, result.ai_analysis);

    // Report to DLP API (non-blocking): never delay upload verdict for telemetry/artifact work.
    if (settings.reportToApi) {
        void (async () => {
            try {
                let uploadedArtifactId = null;

                // For blocked files, if content script is handling raw upload, skip base64 upload here
                // to avoid storing truncated artifacts and mismatched evidence links.
                if (result.action === "block" && !clientArtifactUpload) {
                    const up = await uploadFlaggedArtifact({
                        fileName,
                        fileContent,
                        fileContentBase64,
                        fileContentTruncated,
                        fileSize,
                        fileType: effectiveFileType,
                        scanId,
                        domain,
                        action: result.action,
                        severity: result.severity,
                        findings: result.findings,
                    });
                    if (up && up.ok && up.artifactId) uploadedArtifactId = up.artifactId;
                }

                const contentSha256 = fileContentBase64
                    ? await sha256Base64(fileContentBase64)
                    : await sha256Text((typeof fileContent === 'string' ? fileContent : ''), 200000);
                const shouldReportIncident = (result.action !== "allow") || (Array.isArray(result.findings) && result.findings.length > 0);
                if (shouldReportIncident) {
                    reportToApi(fileName, fileSize, domain, result.findings, result.severity, result.action, result.ai_analysis, {
                        event_kind: 'file_upload_scan',
                        upload_url: uploadUrl,
                        upload_batch_id: String(uploadBatchId || '').trim(),
                        file_type: effectiveFileType,
                        file_ext: ext,
                        is_image: !!isImage,
                        scan_id: scanId,
                        finding_names: [...new Set(result.findings.map(f => f.pattern_name).filter(Boolean))],
                        finding_categories: [...new Set(result.findings.map(f => f.category).filter(Boolean))],
                        content_sha256: contentSha256,
                        artifact_id: uploadedArtifactId,
                        source_page: sender?.tab?.url || uploadUrl || '',
                        exception_applied: !!matchedGlobalExceptionSet,
                        exception_mode: matchedGlobalExceptionSet ? String(matchedGlobalExceptionSet.mode || 'allow_and_log') : '',
                        exception_id: matchedGlobalExceptionSet ? String(matchedGlobalExceptionSet.id || '') : '',
                        reason: result.reason || '',
                    });
                }

                if (!clientArtifactUpload && result.action !== "block" && (result.findings.length > 0 || result.action !== "allow")) {
                    await uploadFlaggedArtifact({
                        fileName,
                        fileContent,
                        fileContentBase64,
                        fileContentTruncated,
                        fileSize,
                        fileType: effectiveFileType,
                        scanId,
                        domain,
                        action: result.action,
                        severity: result.severity,
                        findings: result.findings,
                    });
                }
            } catch (err) {
                console.warn('Post-scan reporting failed (non-blocking):', err?.message || err);
            }
        })();
    }

    // Capture screenshot on violation
    if (result.action !== "allow") {
        captureScreenshot(domain, result.severity, result.findings);
    }

    // Show notification
    if (settings.notifyOnDetection && result.action !== "allow") {
        const aiTag = shouldRunAI ? " [AI]" : "";
        showNotification(fileName, result.findingCount, result.severity, result.action, aiTag);
    }

    // Limit findings sent back to content script
    result.findings = result.findings.slice(0, 25);

    // Cache latest result for short-window de-dup.
    recentFileScanCache.set(fingerprint, {
        ts: nowMs,
        result: {
            action: result.action,
            findings: result.findings,
            severity: result.severity,
            categories: result.categories,
            findingCount: result.findingCount,
            fileName: result.fileName,
            ai_analysis: result.ai_analysis,
            scanId: result.scanId,
            reason: result.reason,
        },
    });

    return result;
}

function inferMimeFromBase64(base64) {
    const head = String(base64 || '').slice(0, 32);
    if (head.startsWith('iVBORw0KGgo')) return 'image/png';
    if (head.startsWith('/9j/')) return 'image/jpeg';
    if (head.startsWith('UklGR')) return 'image/webp';
    if (head.startsWith('R0lGOD')) return 'image/gif';
    if (head.startsWith('JVBERi0')) return 'application/pdf';
    return '';
}

function normalizeMimeType(fileType, fileName, inferredMime) {
    const ft = String(fileType || '').trim().toLowerCase();
    if (ft.includes('/')) return ft;
    if (inferredMime) return inferredMime;
    const name = String(fileName || '').toLowerCase();
    if (name.endsWith('.pdf')) return 'application/pdf';
    if (name.endsWith('.docx')) return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    if (name.endsWith('.xlsx')) return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    if (name.endsWith('.txt') || name.endsWith('.log') || name.endsWith('.csv') || name.endsWith('.json') || name.endsWith('.xml') || name.endsWith('.md')) return 'text/plain';
    return 'application/octet-stream';
}

function dedupeFindings(findings) {
    const seen = new Set();
    const out = [];
    for (const f of findings || []) {
        const key = [f?.pattern_name || '', f?.matched_text || '', f?.line_number || 0, f?.severity || ''].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(f);
    }
    return out;
}

function deriveDynamicPolicyFindingsFromAIEvidence(findings) {
    const out = [];
    const all = Array.isArray(findings) ? findings : [];
    const aiOnly = all.filter(f => String(f?.source || '').toLowerCase() === 'ai');
    if (!aiOnly.length) return out;

    const patterns = (globalThis.TronScanner && globalThis.TronScanner.SENSITIVE_PATTERNS)
        ? globalThis.TronScanner.SENSITIVE_PATTERNS
        : null;
    if (!patterns || typeof patterns !== 'object') return out;

    for (const [name, cfg] of Object.entries(patterns)) {
        if (!cfg || cfg.__dynamic !== true || cfg.rule_type !== 'regex' || !(cfg.pattern instanceof RegExp)) {
            continue;
        }

        const rx = new RegExp(cfg.pattern.source, cfg.pattern.flags);
        for (const af of aiOnly) {
            const hay = [af?.matched_text, af?.description, af?.context].filter(Boolean).join(' \n ');
            if (!hay) continue;

            let m;
            while ((m = rx.exec(hay)) !== null) {
                const matched = String(m[0] || '').trim();
                if (!matched) continue;
                out.push({
                    pattern_name: name,
                    description: cfg.description || name,
                    category: cfg.category || 'SIEM Policy',
                    matched_text: matched,
                    raw_length: matched.length,
                    line_number: 0,
                    severity: cfg.severity || 'high',
                    confidence: 0.95,
                    context: 'Policy matched against AI-extracted evidence text',
                    source: 'policy_from_ai',
                    policy_action: String(cfg.action || 'monitor').toLowerCase(),
                });
                if (m.index === rx.lastIndex) rx.lastIndex++;
            }
        }
    }

    return out;
}

async function fetchServerDeepScan({ fileName, fileSize, domain, fileType, isImage, fileContentBase64 }) {
    try {
        const [userIdentity] = await Promise.all([getBestEffortUserIdentity()]);
        const controller = new AbortController();
        const isPdfLike = String(fileType || '').toLowerCase() === 'application/pdf' || String(fileName || '').toLowerCase().endsWith('.pdf');
        const configuredTimeout = Number(settings.deepScanTimeoutMs);
        const defaultTimeout = (isImage || isPdfLike) ? 30000 : 12000;
        const timeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout > 0
            ? Math.min(Math.max(configuredTimeout, 2000), 45000)
            : defaultTimeout;
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(`${settings.apiUrl}/api/scan/browser-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
            signal: controller.signal,
            body: JSON.stringify({
                file_name: fileName,
                file_size: fileSize,
                domain,
                user: userIdentity,
                file_content_base64: fileContentBase64,
            }),
        });
        clearTimeout(timeout);
        if (!res.ok) {
            return { attempted: true, ok: false, findings: [] };
        }
        const body = await res.json();
        const inspected = body?.inspected !== false;
        const list = Array.isArray(body?.findings) ? body.findings : [];
        const findings = list.map((f) => ({
            pattern_name: f.pattern_name || 'SERVER_DEEP_SCAN',
            description: f.pattern_name || 'Server deep scan finding',
            category: 'Server Deep Scan',
            matched_text: f.matched_text || '',
            raw_length: 0,
            line_number: f.line_number || 0,
            severity: f.severity || 'low',
            confidence: typeof f.confidence === 'number' ? f.confidence : 0.7,
            context: f.context || '',
            source: 'server_deep_scan',
        }));
        return { attempted: true, ok: inspected, findings };
    } catch (_) {
        return { attempted: true, ok: false, findings: [] };
    }
}

/**
 * Check if a domain is considered high-risk for data uploads.
 */
function isHighRiskDomain(domain) {
    const base = Array.isArray(settings?.highRiskDomains) ? settings.highRiskDomains : [];
    const dynamic = Array.isArray(dynamicNetworkPolicyDomains) ? dynamicNetworkPolicyDomains : [];
    const merged = Array.from(new Set([
        ...base.map(v => String(v || '').trim().toLowerCase()).filter(Boolean),
        ...dynamic.map(v => String(v || '').trim().toLowerCase()).filter(Boolean),
    ]));

    return merged.some(pattern => domainMatchesPolicy(domain, pattern) || String(domain || '').toLowerCase().includes(pattern));
}

// ─── Helpers ─────────────────────────────────────────────────

function extractDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return "unknown";
    }
}

function normalizeHost(value) {
    return String(value || '')
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .replace(/:\d+$/, '')
        .replace(/\/$/, '');
}

function domainMatchesPolicy(domain, blockedDomain) {
    const d = normalizeHost(domain);
    const b = normalizeHost(blockedDomain);
    if (!d || !b || d === 'unknown') return false;
    return d === b || d.endsWith(`.${b}`);
}

function normalizeEmail(value) {
    const s = String(value || '').trim().toLowerCase();
    if (!s) return '';
    const m = s.match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i);
    return m ? String(m[0]).toLowerCase() : '';
}

function extractLabeledEmail(text, labels) {
    const body = String(text || '');
    if (!body) return '';
    const alt = labels.map(l => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    const rx = new RegExp(`(?:^|[\\r\\n])\\s*(?:${alt})\\s*[:=]\\s*([^\\r\\n]+)`, 'i');
    const m = body.match(rx);
    if (!m) return '';
    return normalizeEmail(m[1]);
}

function buildExceptionContext({ user = '', domain = '', text = '' } = {}) {
    const normalizedUser = String(user || '').trim().toLowerCase();
    const sender = extractLabeledEmail(text, ['sender', 'from']) || normalizedUser;
    const recipient = extractLabeledEmail(text, ['recipient', 'to']);
    return {
        user: normalizedUser,
        sender,
        recipient,
        domain: normalizeHost(domain),
    };
}

function emailDomain(value) {
    const em = normalizeEmail(value);
    if (!em || !em.includes('@')) return '';
    return normalizeHost(em.split('@')[1]);
}

function hasListMatch(value, list) {
    if (!value || !Array.isArray(list) || list.length === 0) return false;
    const v = String(value || '').trim().toLowerCase();
    return list.some(item => {
        const x = String(item || '').trim().toLowerCase();
        if (!x) return false;
        return v === x;
    });
}

function isPolicyException(exceptions, ctx) {
    if (!exceptions || typeof exceptions !== 'object') return false;
    const expiresAt = String(exceptions.expires_at || '').trim();
    if (expiresAt) {
        const expTs = Date.parse(expiresAt);
        if (Number.isFinite(expTs) && Date.now() > expTs) {
            return false;
        }
    }

    const users = Array.isArray(exceptions.users) ? exceptions.users : [];
    const senders = Array.isArray(exceptions.senders) ? exceptions.senders : [];
    const recipients = Array.isArray(exceptions.recipients) ? exceptions.recipients : [];
    const domains = Array.isArray(exceptions.domains) ? exceptions.domains : [];

    // Criteria semantics:
    // - blank criterion list => wildcard (does not restrict)
    // - non-blank criterion list => must match
    // - all criteria blank => global wildcard exception
    const userCriterion = users.length === 0 || hasListMatch(ctx?.user, users) || hasListMatch(ctx?.sender, users);
    const senderCriterion = senders.length === 0 || hasListMatch(ctx?.sender, senders) || hasListMatch(ctx?.user, senders);
    const recipientCriterion = recipients.length === 0
        || hasListMatch(ctx?.recipient, recipients)
        || hasListMatch(emailDomain(ctx?.recipient), recipients);
    const domainCriterion = domains.length === 0
        || domains.some(d => domainMatchesPolicy(ctx?.domain || '', d))
        || domains.some(d => domainMatchesPolicy(emailDomain(ctx?.recipient), d));

    return userCriterion && senderCriterion && recipientCriterion && domainCriterion;
}

function buildExceptionNote(exceptions, ctx) {
    const parts = [];
    if ((exceptions?.users || []).length > 0 && (hasListMatch(ctx?.user, exceptions?.users || []) || hasListMatch(ctx?.sender, exceptions?.users || []))) {
        parts.push(`user=${ctx.user || ctx.sender}`);
    }
    if ((exceptions?.senders || []).length > 0 && (hasListMatch(ctx?.sender, exceptions?.senders || []) || hasListMatch(ctx?.user, exceptions?.senders || []))) {
        parts.push(`sender=${ctx.sender || ctx.user}`);
    }
    if ((exceptions?.recipients || []).length > 0 && (hasListMatch(ctx?.recipient, exceptions?.recipients || []) || hasListMatch(emailDomain(ctx?.recipient), exceptions?.recipients || []))) {
        parts.push(`recipient=${ctx.recipient}`);
    }
    if ((exceptions?.domains || []).length > 0 && (
        (exceptions?.domains || []).some(d => domainMatchesPolicy(ctx?.domain || '', d))
        || (exceptions?.domains || []).some(d => domainMatchesPolicy(emailDomain(ctx?.recipient), d))
    )) {
        parts.push(`domain=${ctx.domain}`);
    }
    const reason = String(exceptions?.reason || '').trim();
    const ticket = String(exceptions?.ticket_id || '').trim();
    if (reason) parts.push(`reason=${reason}`);
    if (ticket) parts.push(`ticket=${ticket}`);
    return parts.join('; ');
}

function collectExceptionSetsFromRules(rules) {
    const sets = [];
    const seen = new Set();
    const allRules = (rules && typeof rules === 'object') ? Object.values(rules) : [];

    for (const cfg of allRules) {
        if (!cfg || typeof cfg !== 'object') continue;
        const arr = Array.isArray(cfg.exception_sets) ? cfg.exception_sets : [];
        for (const s of arr) {
            if (!s || typeof s !== 'object') continue;
            const key = String(s.id || JSON.stringify(s));
            if (seen.has(key)) continue;
            seen.add(key);
            sets.push(s);
        }
    }

    return sets;
}

function findMatchingGlobalExceptionSet(rules, ctx) {
    // Enterprise behavior:
    // Any matched allow-style exception set (global or policy-scoped)
    // can override blocking for the current transfer context.
    const sets = collectExceptionSetsFromRules(rules);

    for (const s of sets) {
        if (isPolicyException(s, ctx)) {
            const mode = String(s.mode || 'allow_and_log').toLowerCase();
            if (mode === 'allow' || mode === 'allow_and_log') return s;
        }
    }
    return null;
}

function registerPolicyHitAndCheckThreshold(ruleName, domain, action, threshold, windowMins) {
    const thresholdValue = Math.max(1, parseInt(threshold, 10) || 1);
    const windowValue = Math.max(1, parseInt(windowMins, 10) || 60);
    const actionValue = String(action || 'monitor').toLowerCase();
    const key = `${String(ruleName || 'UNKNOWN')}|${normalizeHost(domain) || 'unknown'}|${actionValue}|${thresholdValue}|${windowValue}`;
    const now = Date.now();
    const cutoff = now - (windowValue * 60 * 1000);
    const kept = (policyHitTracker.get(key) || []).filter(ts => Number(ts) >= cutoff);
    kept.push(now);
    policyHitTracker.set(key, kept);
    persistPolicyHitTracker();
    return {
        hits: kept.length,
        threshold: thresholdValue,
        windowMins: windowValue,
        thresholdMet: kept.length >= thresholdValue,
    };
}

function applyPolicyThresholdGates(findings, domain) {
    if (!Array.isArray(findings) || findings.length === 0) return findings || [];

    const perRuleStatus = new Map();
    for (const f of findings) {
        const action = String(f?.policy_action || '').toLowerCase();
        if (!action || action === 'monitor' || action === 'allow') continue;

        const threshold = Math.max(1, parseInt(f?.policy_threshold, 10) || 1);
        const windowMins = Math.max(1, parseInt(f?.policy_window_mins, 10) || 60);
        const rule = String(f?.pattern_name || 'UNKNOWN');
        const mapKey = `${rule}|${action}|${threshold}|${windowMins}`;

        if (!perRuleStatus.has(mapKey)) {
            perRuleStatus.set(mapKey, registerPolicyHitAndCheckThreshold(rule, domain, action, threshold, windowMins));
        }
    }

    return findings.map((f) => {
        const action = String(f?.policy_action || '').toLowerCase();
        if (!action || action === 'monitor' || action === 'allow') return f;

        const threshold = Math.max(1, parseInt(f?.policy_threshold, 10) || 1);
        const windowMins = Math.max(1, parseInt(f?.policy_window_mins, 10) || 60);
        const rule = String(f?.pattern_name || 'UNKNOWN');
        const mapKey = `${rule}|${action}|${threshold}|${windowMins}`;
        const status = perRuleStatus.get(mapKey) || {
            hits: 1,
            threshold,
            windowMins,
            thresholdMet: threshold <= 1,
        };

        return {
            ...f,
            policy_hits: status.hits,
            policy_threshold: status.threshold,
            policy_window_mins: status.windowMins,
            policy_threshold_met: status.thresholdMet,
        };
    });
}

function isEnforceableFinding(finding) {
    const action = String(finding?.policy_action || '').toLowerCase();
    if (!action) return true;
    return finding?.policy_threshold_met !== false;
}

function recordScan(fileName, fileSize, domain, findings, action, reason, scanId = null, aiAnalysis = null) {
    const entry = {
        id: scanId || `scan_${Date.now()}`,
        timestamp: new Date().toISOString(),
        fileName,
        fileSize,
        domain,
        findingCount: findings.length,
        severity: findings.length > 0
            ? findings.reduce((max, f) => {
                const order = { critical: 4, high: 3, medium: 2, low: 1 };
                return order[f.severity] > order[max.severity] ? f : max;
            }).severity
            : "none",
        action,
        reason,
        findings: findings.slice(0, 10),
        aiUsed: !!(aiAnalysis && aiAnalysis.enabled && !aiAnalysis.error),
        aiRiskScore: aiAnalysis?.risk_score || null,
        aiReasoning: aiAnalysis?.reasoning || null,
    };

    scanHistory.push(entry);

    if (scanHistory.length > 500) {
        scanHistory = scanHistory.slice(-500);
    }

    for (const f of findings) {
        stats.findingsByCategory[f.category] = (stats.findingsByCategory[f.category] || 0) + 1;
    }

    if (action === "block") stats.totalBlocked++;
    if (action === "warn") stats.totalWarned++;

    chrome.storage.local.set({ scanHistory, stats });
}

async function reportToApi(fileName, fileSize, domain, findings, severity, action, aiAnalysis = null, context = {}) {
    try {
        const [userIdentity, aid] = await Promise.all([getBestEffortUserIdentity(), getAgentIdentity()]);
        const patternNames = [...new Set(findings.map(f => f.pattern_name))];
        const sample = findings.slice(0, 5)
            .map(f => `[${f.pattern_name}] ${f.matched_text}`)
            .join("\n");

        const isPdfCtx = String(context.file_type || '').toLowerCase() === 'application/pdf' || String(context.file_ext || '').toLowerCase() === '.pdf';
        const aiEnabledForEvent = !!(aiAnalysis?.enabled && !aiAnalysis?.error) && !isPdfCtx;

        const aiSummary = aiEnabledForEvent
            ? `\nAI Risk: ${aiAnalysis.risk_score}/100 | Recommendation: ${aiAnalysis.recommendation}\nAI Reasoning: ${aiAnalysis.reasoning || "N/A"}`
            : "";

        const payload = {
            agent_id: aid.agentId,
            hostname: aid.hostname,
            user: userIdentity,
            source_host: domain,
            channel: "browser_upload",
            payload: `File: ${fileName}\nDomain: ${domain}\nAction: ${action}\nPatterns: ${patternNames.join(", ")}\n${sample}${aiSummary}`,
            agent_type: "browser_extension",
            geo: {
                agent_id: aid.agentId,
                agent_host: aid.hostname,
                file_size: fileSize,
                finding_count: findings.length,
                severity: severity,
                action: action,
                domain: domain,
                findings: findings.slice(0, 50).map(f => ({
                    pattern_name: f.pattern_name,
                    matched_text: f.matched_text,
                    category: f.category,
                    severity: f.severity,
                    description: f.description,
                })),
                ai_used: aiEnabledForEvent,
                ai_risk_score: aiAnalysis?.risk_score || null,
                ai_recommendation: aiAnalysis?.recommendation || null,
                ...context,
            }
        };

        await fetch(`${settings.apiUrl}/api/browser/incident`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
            body: JSON.stringify(payload),
        });
    } catch (err) {
        console.warn("TRON THE DLP AGENT: Cannot reach API:", err.message);
    }
}

function bytesToBase64(bytes) {
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        const sub = bytes.subarray(i, i + chunk);
        bin += String.fromCharCode(...sub);
    }
    return btoa(bin);
}

async function uploadFlaggedArtifact({ fileName, fileContent, fileContentBase64, fileContentTruncated, fileSize, fileType, scanId, domain, action, severity, findings }) {
    try {
        if (!settings.enabled || !settings.reportToApi || !settings.apiUrl) return;
        let contentBase64 = null;
        let truncated = !!fileContentTruncated;
        let payloadBytesLength = 0;

        if (typeof fileContentBase64 === 'string' && fileContentBase64.length) {
            contentBase64 = fileContentBase64;
            try {
                payloadBytesLength = Math.floor((fileContentBase64.length * 3) / 4);
            } catch (_) {
                payloadBytesLength = 0;
            }
        } else if (typeof fileContent === 'string' && fileContent.length) {
            const maxBytes = 20 * 1024 * 1024;
            const encoder = new TextEncoder();
            let bytes = encoder.encode(fileContent);
            if (bytes.length > maxBytes) {
                bytes = bytes.slice(0, maxBytes);
                truncated = true;
            }
            payloadBytesLength = bytes.length;
            contentBase64 = bytesToBase64(bytes);
        }

        if (!contentBase64) return;
        const [userIdentity, aid] = await Promise.all([getBestEffortUserIdentity(), getAgentIdentity()]);

        const payload = {
            agent_id: aid.agentId,
            hostname: aid.hostname,
            user: userIdentity,
            source_host: domain,
            file_name: fileName || 'upload.bin',
            file_type: fileType || 'application/octet-stream',
            file_size: Number.isFinite(fileSize) ? fileSize : payloadBytesLength,
            scan_id: scanId || '',
            action,
            severity,
            findings,
            truncated,
            content_base64: contentBase64,
        };

        const postRes = await postArtifactPayload(payload);
        if (!postRes.ok) {
            pendingArtifactQueue.push(payload);
            chrome.storage.local.set({ pendingArtifactQueue });
            return { ok: false, artifactId: null };
        }
        return { ok: true, artifactId: postRes.artifactId || null };
    } catch (_) {
        // Queue on error for retry
        try {
            pendingArtifactQueue.push({
                file_name: fileName || 'upload.bin',
                file_type: fileType || 'application/octet-stream',
                file_size: Number.isFinite(fileSize) ? fileSize : 0,
                scan_id: scanId || '',
                source_host: domain,
                action,
                severity,
                findings,
                content_base64: fileContentBase64 || null,
            });
            chrome.storage.local.set({ pendingArtifactQueue });
        } catch (_) {}
        return { ok: false, artifactId: null };
    }
}

async function postArtifactPayload(payload) {
    try {
        const res = await fetch(`${settings.apiUrl}/api/browser/artifact`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) return { ok: false, artifactId: null };
        const body = await res.json().catch(() => ({}));
        return { ok: true, artifactId: body?.artifact_id || null };
    } catch (_) {
        return { ok: false, artifactId: null };
    }
}

async function postRawArtifactMultipart(message) {
    try {
        const apiUrl = String(message.apiUrl || settings.apiUrl || '').trim();
        if (!apiUrl) return { ok: false };

        const fileBuffer = message.fileBuffer;
        if (!fileBuffer) return { ok: false };

        const blob = new Blob([fileBuffer], { type: message.fileType || 'application/octet-stream' });
        const fd = new FormData();
        fd.append('file', blob, message.fileName || 'upload.bin');
        fd.append('agent_id', message.agentId || '');
        fd.append('hostname', message.hostname || '');
        fd.append('user', message.user || 'browser_user');
        fd.append('source_host', message.sourceHost || 'unknown');
        fd.append('file_name', message.fileName || 'upload.bin');
        fd.append('file_type', message.fileType || 'application/octet-stream');
        fd.append('file_size', String(message.fileSize || 0));
        fd.append('scan_id', message.scanId || '');
        fd.append('action', message.action || 'block');
        fd.append('severity', message.severity || 'high');
        fd.append('findings', JSON.stringify(message.findings || []));

        const res = await fetch(`${apiUrl}/api/browser/artifact/raw`, {
            method: 'POST',
            headers: { 'ngrok-skip-browser-warning': 'true' },
            body: fd,
        });
        if (!res.ok) return { ok: false };
        const body = await res.json().catch(() => ({}));
        return { ok: true, artifact_id: body?.artifact_id || null };
    } catch (_) {
        return { ok: false };
    }
}

async function flushPendingArtifactQueue() {
    if (artifactFlushInProgress) return;
    if (!pendingArtifactQueue.length) return;
    if (!settings.enabled || !settings.reportToApi || !settings.apiUrl) return;

    artifactFlushInProgress = true;
    try {
        const next = [];
        for (const p of pendingArtifactQueue) {
            const postRes = await postArtifactPayload(p);
            if (!postRes.ok) next.push(p);
        }
        pendingArtifactQueue = next;
        chrome.storage.local.set({ pendingArtifactQueue });
    } finally {
        artifactFlushInProgress = false;
    }
}

async function sha256Text(text, maxLen = 200000) {
    try {
        if (!text || typeof text !== 'string') return null;
        const input = text.length > maxLen ? text.slice(0, maxLen) : text;
        const enc = new TextEncoder().encode(input);
        const digest = await crypto.subtle.digest('SHA-256', enc);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) {
        return null;
    }
}

async function sha256Base64(base64) {
    try {
        if (!base64 || typeof base64 !== 'string') return null;
        const bin = atob(base64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const digest = await crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) {
        return null;
    }
}

function showNotification(fileName, findingCount, severity, action, aiTag = "") {
    const severityEmoji = {
        critical: "CRIT",
        high: "HIGH",
        medium: "MED",
        low: "LOW",
    };

    const actionText = action === "block" ? "BLOCKED" : "WARNING";

    chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `TRON THE DLP AGENT — ${actionText}${aiTag}`,
        message: `${severityEmoji[severity] || "⚪"} ${findingCount} sensitive item(s) found in "${fileName}"\nSeverity: ${severity.toUpperCase()}`,
        priority: severity === "critical" ? 2 : 1,
    });
}

// ─── Text Scan Handler (Clipboard/Paste DLP) ──────────────────────
async function handleTextScan(message, sender) {
    const { text, url } = message;
    if (!settings.enabled) return { action: "allow" };

    const domain = extractDomain(url || sender.tab?.url || "");
    const userIdentity = await getBestEffortUserIdentity();
    const exceptionCtx = buildExceptionContext({ user: userIdentity, domain, text });

    if ((settings.allowedDomains || []).some(d => domainMatchesPolicy(domain, d))) {
        return { action: "allow", findings: [], severity: "none", domain, reason: "Whitelisted domain" };
    }

    if ((settings.blockedDomains || []).some(d => domainMatchesPolicy(domain, d))) {
        const blockedFindings = [{
            pattern_name: 'BLOCKED_DOMAIN',
            description: 'Destination domain is blocked by policy',
            category: 'Policy Violation',
            matched_text: domain,
            raw_length: 0,
            line_number: 0,
            severity: 'high',
            confidence: 1.0,
            context: `Domain ${domain} is on managed blocked list`,
            policy_action: 'block',
        }];
        recordScan("Pasted Text", text.length, domain, blockedFindings, "block", "Blocked domain policy (paste)");
        if (settings.reportToApi) {
            reportToApi("Pasted_Text", text.length, domain, blockedFindings, "high", "block", null, {
                event_kind: 'clipboard_paste_scan',
                source_page: url || sender?.tab?.url || '',
                finding_names: ['BLOCKED_DOMAIN'],
                finding_categories: ['Policy Violation'],
                content_sha256: await sha256Text(text, 50000),
                reason: 'domain_blocklist_policy',
            });
        }
        return { action: "block", findings: blockedFindings, severity: "high", domain, reason: "Domain is on the blocklist" };
    }

    if (!globalThis.TronScanner || typeof globalThis.TronScanner.scanText !== 'function') {
        return { action: "allow", findings: [], severity: "none", domain, reason: "scanner_unavailable" };
    }

    const rawFindings = globalThis.TronScanner.scanText(text, "clipboard");

    const rules = globalThis.TronScanner.SENSITIVE_PATTERNS || {};
    const matchedGlobalExceptionSet = findMatchingGlobalExceptionSet(rules, exceptionCtx);
    const findings = rawFindings.filter((f) => {
        const cfg = rules[String(f?.pattern_name || '')];
        return !isPolicyException(cfg?.exceptions, exceptionCtx);
    });
    const policyFindings = [];
    const exceptionFindings = [];
    for (const [name, config] of Object.entries(rules)) {
        if (config.rule_type !== 'network') continue;
        const blocked = Array.isArray(config.blocked_domains) ? config.blocked_domains : [];
        const matchedBlockedDomain = blocked.find(bd => domainMatchesPolicy(domain, bd));
        if (!matchedBlockedDomain) continue;
        if (isPolicyException(config.exceptions, exceptionCtx)) {
            exceptionFindings.push({
                pattern_name: `${name}_EXCEPTION`,
                description: `Policy exception matched for ${name}`,
                category: 'Policy Exception',
                matched_text: `Bypass domain block: ${matchedBlockedDomain}`,
                raw_length: 0,
                line_number: 0,
                severity: 'low',
                confidence: 1.0,
                context: buildExceptionNote(config.exceptions, exceptionCtx),
                policy_action: 'monitor',
                source: 'policy_exception',
            });
            continue;
        }

        policyFindings.push({
            pattern_name: name,
            description: config.description || 'Blocked destination domain policy',
            category: 'Policy Violation',
            matched_text: `Blocked Domain: ${matchedBlockedDomain}`,
            raw_length: 0,
            line_number: 0,
            severity: config.severity || 'high',
            confidence: 1.0,
            context: `Destination ${domain} matched blocked domain policy ${matchedBlockedDomain}`,
            policy_action: String(config.action || 'block').toLowerCase(),
            policy_threshold: (parseInt(config.threshold, 10) || 1),
            policy_window_mins: (parseInt(config.window, 10) || 60),
        });
    }

    let mergedFindings = dedupeFindings([...(findings || []), ...policyFindings, ...exceptionFindings]);
    mergedFindings = applyPolicyThresholdGates(mergedFindings, domain);
    if (mergedFindings.length === 0) return { action: "allow", findings: [], severity: "none", domain };
    const enforceableFindings = mergedFindings.filter(isEnforceableFinding);
    if (enforceableFindings.length === 0) {
        recordScan("Pasted Text", text.length, domain, mergedFindings, "allow", "Policy threshold pending");
        if (settings.reportToApi) {
            reportToApi("Pasted_Text", text.length, domain, mergedFindings, "none", "allow", null, {
                event_kind: 'clipboard_paste_scan',
                source_page: url || sender?.tab?.url || '',
                finding_names: [...new Set(mergedFindings.map(f => f.pattern_name).filter(Boolean))],
                finding_categories: [...new Set(mergedFindings.map(f => f.category).filter(Boolean))],
                content_sha256: await sha256Text(text, 50000),
                reason: 'policy_threshold_pending',
            });
        }
        return { action: "allow", findings: mergedFindings, severity: "none", domain, reason: "policy_threshold_pending" };
    }

    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    const thresholdLevel = severityOrder[settings.scanThreshold] || 2;
    const overallSeverity = enforceableFindings.reduce((max, f) => severityOrder[f.severity] > severityOrder[max.severity] ? f : max).severity;
    const hasPolicyBlock = enforceableFindings.some(f => String(f.policy_action || '').toLowerCase() === 'block');
    const hasPolicyWarn = enforceableFindings.some(f => String(f.policy_action || '').toLowerCase() === 'warn');

    let action = "allow";
    if (hasPolicyBlock) {
        action = "block";
    } else if (hasPolicyWarn) {
        action = "warn";
    } else if (severityOrder[overallSeverity] >= thresholdLevel) {
        action = settings.blockMode === "block" ? "block" : "warn";
    }

    if (matchedGlobalExceptionSet) {
        mergedFindings = dedupeFindings([
            ...mergedFindings,
            {
                pattern_name: `GLOBAL_EXCEPTION_${matchedGlobalExceptionSet.id || 'MATCHED'}`,
                description: `Global exception matched: ${matchedGlobalExceptionSet.name || 'unnamed'}`,
                category: 'Policy Exception',
                matched_text: `Bypass due to global exception at ${domain || 'unknown'}`,
                raw_length: 0,
                line_number: 0,
                severity: 'low',
                confidence: 1.0,
                context: buildExceptionNote(matchedGlobalExceptionSet, exceptionCtx),
                policy_action: 'monitor',
                source: 'global_exception',
            }
        ]);
        action = 'allow';
    }

    // Quick notification
    if (action !== "allow" && settings.notifyOnDetection) {
        showNotification("Pasted Text", mergedFindings.length, overallSeverity, action, " [Text]");
    }

    // Report
    recordScan(
        "Pasted Text",
        text.length,
        domain,
        mergedFindings,
        action,
        matchedGlobalExceptionSet ? `global_exception:${matchedGlobalExceptionSet.id || 'matched'}` : "Clipboard DLP caught sensitive text"
    );
    const shouldReportPaste = settings.reportToApi || mergedFindings.some(f => String(f?.policy_action || '').toLowerCase() !== '');
    if (shouldReportPaste) {
        reportToApi("Pasted_Text", text.length, domain, mergedFindings, action === 'allow' ? 'none' : overallSeverity, action, null, {
            event_kind: 'clipboard_paste_scan',
            source_page: url || sender?.tab?.url || '',
            finding_names: [...new Set(mergedFindings.map(f => f.pattern_name).filter(Boolean))],
            finding_categories: [...new Set(mergedFindings.map(f => f.category).filter(Boolean))],
            content_sha256: await sha256Text(text, 50000),
            exception_applied: !!matchedGlobalExceptionSet,
            exception_mode: matchedGlobalExceptionSet ? String(matchedGlobalExceptionSet.mode || 'allow_and_log') : '',
            exception_id: matchedGlobalExceptionSet ? String(matchedGlobalExceptionSet.id || '') : '',
            reason: matchedGlobalExceptionSet ? `global_exception:${matchedGlobalExceptionSet.id || 'matched'}` : '',
        });
    }

    return {
        action,
        findings: mergedFindings,
        severity: action === 'allow' ? 'none' : overallSeverity,
        domain,
        reason: matchedGlobalExceptionSet ? `global_exception:${matchedGlobalExceptionSet.id || 'matched'}` : undefined,
    };
}
