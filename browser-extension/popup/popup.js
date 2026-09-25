/**
 * TRON THE DLP AGENT — Popup Script
 * Controls the extension popup UI: stats, activity, settings.
 */

document.addEventListener("DOMContentLoaded", () => {
    let settingsLocked = false;
    const elements = {
        enableToggle: document.getElementById("enableToggle"),
        statScans: document.getElementById("statScans"),
        statBlocked: document.getElementById("statBlocked"),
        statWarned: document.getElementById("statWarned"),
        statAllowed: document.getElementById("statAllowed"),
        activityList: document.getElementById("activityList"),
        saveSettings: document.getElementById("saveSettings"),
        clearHistory: document.getElementById("clearHistory"),
        scanThreshold: document.getElementById("scanThreshold"),
        apiUrl: document.getElementById("apiUrl"),
        reportToApi: document.getElementById("reportToApi"),
        notifyOnDetection: document.getElementById("notifyOnDetection"),
        connectionStatus: document.getElementById("connectionStatus"),
        // AI elements
        aiEnabled: document.getElementById("aiEnabled"),
        geminiApiKey: document.getElementById("geminiApiKey"),
        aiScanMode: document.getElementById("aiScanMode"),
        settingsManagedNotice: document.getElementById("settingsManagedNotice"),
    };

    // ─── Load Data ───────────────────────────────────────────────

    loadStats();
    loadSettings();
    loadActivity();
    checkApiConnection();

    // ─── Tab Switching ───────────────────────────────────────────

    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
        });
    });

    // ─── Enable Toggle ──────────────────────────────────────────

    elements.enableToggle.addEventListener("change", () => {
        if (settingsLocked) {
            loadSettings();
            return;
        }
        chrome.runtime.sendMessage({
            type: "UPDATE_SETTINGS",
            settings: { enabled: elements.enableToggle.checked }
        });
    });

    // ─── Save Settings ──────────────────────────────────────────

    elements.saveSettings.addEventListener("click", () => {
        if (settingsLocked) return;
        const blockMode = document.querySelector('input[name="blockMode"]:checked')?.value || "warn";

        chrome.runtime.sendMessage({
            type: "UPDATE_SETTINGS",
            settings: {
                blockMode,
                scanThreshold: elements.scanThreshold.value,
                apiUrl: elements.apiUrl.value,
                reportToApi: elements.reportToApi.checked,
                notifyOnDetection: elements.notifyOnDetection.checked,
                // AI settings
                aiEnabled: elements.aiEnabled.checked,
                geminiApiKey: elements.geminiApiKey.value.trim(),
                aiScanMode: elements.aiScanMode.value,
            }
        }, () => {
            // Flash button to confirm save
            elements.saveSettings.textContent = "✓ Saved!";
            elements.saveSettings.style.background = "linear-gradient(135deg, #10b981, #059669)";
            setTimeout(() => {
                elements.saveSettings.textContent = "Save Settings";
                elements.saveSettings.style.background = "";
            }, 1500);
        });
    });

    // ─── Clear History ──────────────────────────────────────────

    elements.clearHistory.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
            loadStats();
            loadActivity();
            elements.clearHistory.textContent = "✓ Cleared!";
            setTimeout(() => {
                elements.clearHistory.textContent = "Clear History";
            }, 1500);
        });
    });

    // ─── Helpers ────────────────────────────────────────────────

    function loadStats() {
        chrome.runtime.sendMessage({ type: "GET_STATS" }, (response) => {
            if (!response) return;
            const { stats } = response;
            elements.statScans.textContent = stats.totalScans || 0;
            elements.statBlocked.textContent = stats.totalBlocked || 0;
            elements.statWarned.textContent = stats.totalWarned || 0;
            elements.statAllowed.textContent = stats.totalAllowed || 0;
        });
    }

    function loadSettings() {
        chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
            if (!response?.settings) return;
            const s = response.settings;
            settingsLocked = s.settingsLocked !== false;
            setSettingsLockUI(settingsLocked);

            elements.enableToggle.checked = s.enabled !== false;
            elements.scanThreshold.value = s.scanThreshold || "medium";
            elements.apiUrl.value = s.apiUrl || "http://localhost:5001";
            elements.reportToApi.checked = s.reportToApi !== false;
            elements.notifyOnDetection.checked = s.notifyOnDetection !== false;

            // AI settings
            elements.aiEnabled.checked = s.aiEnabled !== false;
            elements.geminiApiKey.value = s.geminiApiKey || "";
            elements.aiScanMode.value = s.aiScanMode || "smart";

            // Block mode radio
            const radio = document.querySelector(`input[name="blockMode"][value="${s.blockMode || 'warn'}"]`);
            if (radio) radio.checked = true;
        });
    }

    function loadActivity() {
        chrome.runtime.sendMessage({ type: "GET_HISTORY", limit: 30 }, (response) => {
            if (!response?.history || response.history.length === 0) {
                elements.activityList.innerHTML = `
          <div class="empty-state">
            <div class="empty-icon">--</div>
            <p>No scans yet</p>
            <p class="empty-sub">Upload a file on any website to see activity here</p>
          </div>
        `;
                return;
            }

            elements.activityList.innerHTML = response.history.map(item => {
                const icon = getActionIcon(item.action);
                const badge = getActionBadge(item.action);
                const time = formatTime(item.timestamp);
                const findings = item.findingCount || 0;
                const aiTag = item.aiUsed
                    ? `<span class="activity-ai-tag" title="AI Risk: ${item.aiRiskScore || '?'}/100">AI</span>`
                    : "";

                return `
          <div class="activity-item">
            <span class="activity-icon">${icon}</span>
            <div class="activity-details">
              <div class="activity-file" title="${escapeHtml(item.fileName)}">${escapeHtml(item.fileName)} ${aiTag}</div>
              <div class="activity-meta">
                <span>${time}</span>
                <span>${escapeHtml(item.domain)}</span>
                ${findings > 0 ? `<span>${findings} finding${findings > 1 ? "s" : ""}</span>` : ""}
                ${item.aiRiskScore ? `<span>AI: ${item.aiRiskScore}/100</span>` : ""}
              </div>
            </div>
            <span class="activity-badge ${badge.class}">${badge.text}</span>
          </div>
        `;
            }).join("");
        });
    }

    function checkApiConnection() {
        chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
            const apiUrl = response?.settings?.apiUrl || "http://localhost:5001";

            fetch(`${apiUrl}/api/health`, { method: "GET", signal: AbortSignal.timeout(3000) })
                .then(r => {
                    if (r.ok) {
                        elements.connectionStatus.innerHTML = `<span class="connection-dot online"></span> API Connected`;
                    } else {
                        elements.connectionStatus.innerHTML = `<span class="connection-dot offline"></span> API Error`;
                    }
                })
                .catch(() => {
                    elements.connectionStatus.innerHTML = `<span class="connection-dot offline"></span> API Offline`;
                });
        });
    }

    function setSettingsLockUI(locked) {
        if (elements.settingsManagedNotice) {
            elements.settingsManagedNotice.style.display = locked ? "block" : "none";
        }

        const toDisable = [
            elements.enableToggle,
            elements.scanThreshold,
            elements.apiUrl,
            elements.reportToApi,
            elements.notifyOnDetection,
            elements.aiEnabled,
            elements.geminiApiKey,
            elements.aiScanMode,
        ];
        toDisable.forEach((el) => {
            if (el) el.disabled = !!locked;
        });
        document.querySelectorAll('input[name="blockMode"]').forEach((el) => {
            el.disabled = !!locked;
        });

        if (elements.saveSettings) {
            elements.saveSettings.style.display = locked ? "none" : "inline-block";
        }
    }

    function getActionIcon(action) {
        return { block: "BLOCK", warn: "WARN", allow: "ALLOW", monitor: "MON" }[action] || "FILE";
    }

    function getActionBadge(action) {
        const badges = {
            block: { text: "BLOCKED", class: "badge-block" },
            warn: { text: "WARNED", class: "badge-warn" },
            allow: { text: "CLEAN", class: "badge-allow" },
            monitor: { text: "LOGGED", class: "badge-monitor" },
        };
        return badges[action] || { text: action.toUpperCase(), class: "badge-allow" };
    }

    function formatTime(timestamp) {
        try {
            const d = new Date(timestamp);
            const now = new Date();
            const diff = now - d;

            if (diff < 60000) return "Just now";
            if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
            if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
            return d.toLocaleDateString();
        } catch {
            return "";
        }
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text || "";
        return div.innerHTML;
    }
});
