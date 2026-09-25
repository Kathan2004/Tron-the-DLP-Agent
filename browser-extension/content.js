/**
 * TRON THE DLP AGENT — Content Script
 * Intercepts file uploads in web pages (input[type=file], drag-and-drop, form submissions).
 * Scans files before they leave the machine and shows warning/block UI.
 */

(function () {
  "use strict";

  // Prevent double injection
  if (window.__tronDLPInjected) return;
  window.__tronDLPInjected = true;

  let settings = {
    enabled: true,
    blockMode: "warn",
    scanThreshold: "medium",
    hardBlockAllUploads: false,
    silentMode: false,
  };

  // Load settings from background
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
    if (response?.settings) settings = response.settings;
  });

  // Listen for settings updates
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SETTINGS_UPDATED") {
      settings = message.settings;
    }
  });

  let skipEvents = false;
  let lastPreciseLocationSentAt = 0;

  const GEO_STATE_KEYS = {
    state: "geo_permission_state",      // granted | denied | unknown
    lastPromptAt: "geo_last_prompt_at", // epoch ms
    lastSentAt: "geo_last_sent_at",     // epoch ms
  };

  function storageGet(keys) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(keys, (data) => resolve(data || {}));
      } catch (_) {
        resolve({});
      }
    });
  }

  function storageSet(obj) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set(obj, () => resolve());
      } catch (_) {
        resolve();
      }
    });
  }

  function sendPreciseLocationToBackground(position) {
    try {
      const coords = position?.coords || {};
      chrome.runtime.sendMessage({
        type: "PRECISE_LOCATION_UPDATE",
        location: {
          latitude: coords.latitude,
          longitude: coords.longitude,
          accuracy_m: coords.accuracy,
          altitude: coords.altitude,
          heading: coords.heading,
          speed: coords.speed,
          timestamp: new Date(position.timestamp || Date.now()).toISOString(),
          source: "browser_geolocation",
        },
      }, () => {
        // ignore response
      });
      lastPreciseLocationSentAt = Date.now();
    } catch (_) {
      // ignore
    }
  }

  async function tryPreciseLocationReport(trigger = "auto") {
    if (!settings.enabled) return;
    if (!navigator.geolocation) return;
    // Do not prompt from iframes (prevents repeated per-site/per-frame prompts).
    if (window.top !== window.self) return;

    // Some sites explicitly block geolocation via Permissions-Policy.
    // In those cases, avoid calling getCurrentPosition() to prevent noisy violations.
    try {
      const pp = document.permissionsPolicy || document.featurePolicy;
      if (pp && typeof pp.allowsFeature === "function") {
        const allowed = pp.allowsFeature("geolocation");
        if (!allowed) {
          chrome.runtime.sendMessage({
            type: "PRECISE_LOCATION_STATUS",
            status: "blocked_by_permissions_policy",
            trigger,
          }, () => {});
          return;
        }
      }
    } catch (_) {
      // If policy check fails, continue and let geolocation API decide.
    }

    const now = Date.now();
    const geoState = await storageGet([GEO_STATE_KEYS.state, GEO_STATE_KEYS.lastPromptAt, GEO_STATE_KEYS.lastSentAt]);
    const permissionState = geoState[GEO_STATE_KEYS.state] || "unknown";
    const lastPromptAt = Number(geoState[GEO_STATE_KEYS.lastPromptAt] || 0);
    const lastSentAt = Number(geoState[GEO_STATE_KEYS.lastSentAt] || 0);

    // If previously denied, back off prompts for 24h (no nagging across sites).
    if (permissionState === "denied" && (now - lastPromptAt) < 24 * 60 * 60 * 1000) {
      return;
    }

    // If granted and we recently sent, skip.
    if (permissionState === "granted" && (now - Math.max(lastSentAt, lastPreciseLocationSentAt)) < 15 * 60 * 1000) {
      return;
    }

    await storageSet({ [GEO_STATE_KEYS.lastPromptAt]: now });

    navigator.geolocation.getCurrentPosition(
      async (position) => {
        sendPreciseLocationToBackground(position);
        await storageSet({
          [GEO_STATE_KEYS.state]: "granted",
          [GEO_STATE_KEYS.lastSentAt]: Date.now(),
        });
      },
      async (err) => {
        // Permission denied or unavailable; fallback to IP geo in backend.
        const denied = err && err.code === 1;
        if (denied) {
          await storageSet({ [GEO_STATE_KEYS.state]: "denied" });
          chrome.runtime.sendMessage({
            type: "PRECISE_LOCATION_STATUS",
            status: "denied",
            trigger,
          }, () => {});
        } else {
          // err.code === 1 can also happen due policy blocks on some pages;
          // if browser surfaces a message, forward it for observability.
          const msg = (err && err.message ? String(err.message) : "").toLowerCase();
          const policyBlocked = msg.includes("permissions policy") || msg.includes("permission policy");
          chrome.runtime.sendMessage({
            type: "PRECISE_LOCATION_STATUS",
            status: policyBlocked ? "blocked_by_permissions_policy" : "unavailable",
            trigger,
          }, () => {});
        }
      },
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 5 * 60 * 1000,
      }
    );
  }

  function insertTextSafely(target, text) {
    if (!target) return false;
    try {
      if (target.tagName === "TEXTAREA" || (target.tagName === "INPUT" && /^(text|search|url|tel|email|password)$/i.test(target.type || "text"))) {
        const start = typeof target.selectionStart === "number" ? target.selectionStart : target.value.length;
        const end = typeof target.selectionEnd === "number" ? target.selectionEnd : target.value.length;
        target.setRangeText(text, start, end, "end");
        target.dispatchEvent(new Event("input", { bubbles: true }));
        return true;
      }

      if (target.isContentEditable || target.closest?.("[contenteditable='true']")) {
        const editable = target.isContentEditable ? target : target.closest("[contenteditable='true']");
        editable.focus();
        const ok = document.execCommand("insertText", false, text);
        if (ok) return true;

        const sel = window.getSelection();
        if (sel && sel.rangeCount > 0) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          range.insertNode(document.createTextNode(text));
          range.collapse(false);
          sel.removeAllRanges();
          sel.addRange(range);
          return true;
        }
      }
    } catch (_) {
      // fallthrough
    }
    return false;
  }

  // ─── Intercept <input type="file"> ──────────────────────────

  document.addEventListener("change", async (e) => {
    if (!settings.enabled || skipEvents) return;

    const input = e.target;
    if (input.tagName !== "INPUT" || input.type !== "file") return;
    if (!input.files || input.files.length === 0) return;

    if (settings.hardBlockAllUploads) {
      e.preventDefault();
      e.stopImmediatePropagation();
      input.value = "";
      showToast("Uploads blocked by organization policy", "blocked");
      return;
    }

    e.preventDefault();
    e.stopImmediatePropagation();

    const files = Array.from(input.files);
    const allowed = await handleFileUpload(files, input, e);

    if (allowed) {
      // Re-fire event so the website's JS can process the file
      skipEvents = true;
      input.dispatchEvent(new Event("change", { bubbles: true }));
      input.dispatchEvent(new Event("input", { bubbles: true }));
      setTimeout(() => { skipEvents = false; }, 100);
    } else {
      // Clear the file input if blocked
      input.value = "";
    }
  }, true);

  // Try precise location collection shortly after script loads.
  setTimeout(() => {
    tryPreciseLocationReport("startup");
  }, 1500);

  // Retry when tab becomes active/visible again.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      tryPreciseLocationReport("visibility");
    }
  });

  // ─── Intercept Drag & Drop ──────────────────────────────────

  document.addEventListener("drop", async (e) => {
    if (!settings.enabled || skipEvents) return;
    if (!e.dataTransfer?.files?.length) return;

    if (settings.hardBlockAllUploads) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showToast("File drop blocked by organization policy", "blocked");
      return;
    }

    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;

    // For drop events, we can't perfectly re-dispatch DataTransfer objects
    // So we just check. If it's bad, we stop it. 
    // Since we need to wait for async, we must stop it now.
    e.preventDefault();
    e.stopImmediatePropagation();

    const allowed = await handleFileUpload(files, e.target, e);
    if (allowed) {
      showToast("Drop event allowed, but you may need to drop it again or use the file picker (browser limitation).", "info");
    }
  }, true);

  // ─── Intercept Form Submissions ─────────────────────────────

  document.addEventListener("submit", async (e) => {
    if (!settings.enabled || skipEvents) return;

    const form = e.target;
    const fileInputs = form.querySelectorAll('input[type="file"]');

    let hasFiles = false;
    for (const input of fileInputs) {
      if (input.files && input.files.length > 0) hasFiles = true;
    }

    if (!hasFiles) return;

    if (settings.hardBlockAllUploads) {
      e.preventDefault();
      e.stopImmediatePropagation();
      for (const input of fileInputs) {
        if (input && input.type === "file") input.value = "";
      }
      showToast("Upload blocked by organization policy", "blocked");
      return;
    }

    e.preventDefault();
    e.stopImmediatePropagation();

    let allAllowed = true;
    for (const input of fileInputs) {
      if (input.files && input.files.length > 0) {
        const files = Array.from(input.files);
        const allowed = await checkFiles(files);
        if (!allowed) {
          allAllowed = false;
          input.value = ""; // Clear bad input
        }
      }
    }

    if (allAllowed) {
      skipEvents = true;
      try {
        form.submit();
      } catch (err) {
        // Some JS frameworks override submit
        form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      }
      setTimeout(() => { skipEvents = false; }, 100);
    }
  }, true);

  // ─── Intercept Clipboard Paste (Clipboard DLP) ────────────────
  document.addEventListener("paste", async (e) => {
    if (!settings.enabled || skipEvents) return;

    const text = e.clipboardData?.getData("text/plain");
    if (!text || text.length < 3) return; // Ignore tiny texts or pure images

    if (settings.hardBlockAllUploads) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showToast("Paste blocked by organization policy", "blocked");
      return;
    }

    const target = e.target;
    const editable = target && (
      target.isContentEditable ||
      target.tagName === "TEXTAREA" ||
      (target.tagName === "INPUT" && /^(text|search|url|tel|email|password)$/i.test(target.type || "text")) ||
      target.closest?.("[contenteditable='true']")
    );
    if (!editable) return; // don't break non-editable page shortcuts

    e.preventDefault();
    e.stopImmediatePropagation();

    showToast("Scanning pasted text...", "info");

    const result = await new Promise((resolve) => {
      let finished = false;
      const done = (payload) => {
        if (finished) return;
        finished = true;
        resolve(payload);
      };

      const timeout = setTimeout(() => done({ action: "allow", reason: "scan_timeout_fail_open" }), 5000);
      try {
        chrome.runtime.sendMessage({
          type: "SCAN_TEXT",
          text: text,
          url: window.location.href,
        }, (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            done({ action: "allow", reason: "runtime_error_fail_open" });
            return;
          }
          done(response || { action: "allow", reason: "empty_response_fail_open" });
        });
      } catch (err) {
        clearTimeout(timeout);
        done({ action: "allow", reason: "send_failed_fail_open" });
      }
    });

    if (result.action === "block") {
      showToast("Paste Blocked: Sensitive Data Detected", "blocked");
    } else if (result.action === "warn") {
      if (confirm("Tron: This pasted text contains sensitive data. Paste anyway?")) {
        skipEvents = true;
        insertTextSafely(target, text);
        setTimeout(() => { skipEvents = false; }, 100);
      }
    } else {
      // Allow it
      skipEvents = true;
      const inserted = insertTextSafely(target, text);
      if (!inserted) {
        showToast("Paste allowed but browser blocked scripted insert.", "warning");
      }
      setTimeout(() => { skipEvents = false; }, 100);
    }
  }, true);

  // ─── Print & Screen Capture Prevention ──────────────────────────

  // Apply strict CSS to prevent printing on suspected internal databases
  // In a real enterprise setup, this would check against a list of managed domains.
  const isProtected = window.location.hostname.includes("internal") ||
    window.location.hostname.includes("dashboard") ||
    window.location.hostname === "localhost" ||
    window.location.hostname.includes("dlptest");

  if (isProtected) {
    const style = document.createElement("style");
    style.textContent = `
        @media print {
            html, body { display: none !important; }
            html::after {
                content: "Printing is strictly disabled on this page by TRON THE DLP AGENT.";
                display: block !important;
                font-family: sans-serif;
                padding: 50px;
                color: red;
                font-size: 20px;
                text-align: center;
            }
        }
      `;
    if (document.head || document.documentElement) {
      (document.head || document.documentElement).appendChild(style);
    } else {
      document.addEventListener("DOMContentLoaded", () => {
        (document.head || document.documentElement).appendChild(style);
      });
    }

    document.addEventListener("keydown", (e) => {
      // Stop CTRL+P / CMD+P
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "p") {
        e.preventDefault();
        showToast("Printing is restricted here.", "warning");
      }
    }, true);
  }

  // ─── Core Handler ──────────────────────────────────────────

  async function handleFileUpload(files, targetElement, originalEvent) {
    // Show scanning indicator
    const scanOverlay = showScanningOverlay(files);
    const uploadBatchId = `upl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

    try {
      const results = [];

      for (const file of files) {
        const contentContext = await readFileAsContext(file);
        if (contentContext === null) {
          // Fail-closed: if we cannot even read the file payload, do not allow silent bypass.
          results.push({ action: "block", fileName: file.name, findings: [], severity: "high", reason: "unreadable_file_context" });
          continue;
        }

        // Send to background for scanning
        const result = await new Promise((resolve) => {
          let done = false;
          const finish = (r) => {
            if (done) return;
            done = true;
            resolve(r);
          };
          const timeout = setTimeout(() => finish({ action: "block", reason: "scan_timeout_fail_closed" }), 45000);
          chrome.runtime.sendMessage({
            type: "SCAN_FILE",
            fileContent: contentContext.content,
            fileContentBase64: contentContext.contentBase64,
            fileContentTruncated: contentContext.contentTruncated,
            isImage: contentContext.isImage,
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type || contentContext.ext,
            clientArtifactUpload: true,
            uploadBatchId,
            uploadUrl: window.location.href,
          }, (response) => {
            clearTimeout(timeout);
            if (chrome.runtime.lastError) {
              finish({ action: "block", reason: "runtime_error_fail_closed" });
              return;
            }
            finish(response || { action: "block", reason: "empty_response_fail_closed" });
          });
        });

        if (result?.action === "block" && !result?.deduped) {
          await uploadBlockedArtifactDirect(file, result);
          if (isFailClosedReason(result?.reason)) {
            await reportFailClosedBlockToSiem(file, result, uploadBatchId);
          }
        }

        results.push(result);
      }

      // Remove scanning overlay
      scanOverlay.remove();

      // Check if any file was blocked/warned
      const blocked = results.filter(r => r.action === "block");
      const warned = results.filter(r => r.action === "warn");
      const clean = results.filter(r => r.action === "allow" || r.action === "monitor");

      if (blocked.length > 0) {
        showBlockedModal(blocked, files, targetElement);
        return false;
      } else if (warned.length > 0) {
        const userChoice = await showWarningModal(warned, files);
        if (userChoice === "allow") {
          showToast("Upload allowed by user", "info");
          return true;
        } else {
          showToast("Upload blocked by user", "blocked");
          return false;
        }
      } else {
        // All clean — show quick confirmation
        showToast(`${files.length} file(s) scanned — clean ✓`, "clean");
        return true;
      }

    } catch (err) {
      scanOverlay.remove();
      console.error("TRON THE DLP AGENT scan error:", err);
      showToast("Scan error — upload blocked (fail-closed)", "blocked");
      return false;
    }
  }

  async function uploadBlockedArtifactDirect(file, scanResult) {
    try {
      const ctx = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "GET_UPLOAD_CONTEXT" }, (resp) => resolve(resp || {}));
      });
      const apiUrl = (ctx.apiUrl || "").trim();
      let uploaded = false;

      // Primary path: direct multipart upload from content context.
      if (apiUrl) {
        try {
          const fd = new FormData();
          fd.append("file", file, file.name || "upload.bin");
          fd.append("agent_id", ctx.agentId || "");
          fd.append("hostname", ctx.hostname || "");
          fd.append("user", ctx.user || "browser_user");
          fd.append("source_host", window.location.hostname || "unknown");
          fd.append("file_name", file.name || "upload.bin");
          fd.append("file_type", file.type || "application/octet-stream");
          fd.append("file_size", String(file.size || 0));
          fd.append("scan_id", scanResult?.scanId || "");
          fd.append("action", scanResult?.action || "block");
          fd.append("severity", scanResult?.severity || "high");
          fd.append("findings", JSON.stringify(scanResult?.findings || []));

          const res = await fetch(`${apiUrl}/api/browser/artifact/raw`, {
            method: "POST",
            headers: { "ngrok-skip-browser-warning": "true" },
            body: fd,
          });
          uploaded = !!res.ok;
        } catch (_) {
          uploaded = false;
        }
      }

      // Fallback path: background worker uploads multipart.
      if (!uploaded) {
        const fileBuffer = await file.arrayBuffer();
        await new Promise((resolve) => {
          chrome.runtime.sendMessage({
            type: "UPLOAD_ARTIFACT_RAW",
            apiUrl,
            agentId: ctx.agentId || "",
            hostname: ctx.hostname || "",
            user: ctx.user || "browser_user",
            sourceHost: window.location.hostname || "unknown",
            fileName: file.name || "upload.bin",
            fileType: file.type || "application/octet-stream",
            fileSize: file.size || 0,
            scanId: scanResult?.scanId || "",
            action: scanResult?.action || "block",
            severity: scanResult?.severity || "high",
            findings: scanResult?.findings || [],
            fileBuffer,
          }, (resp) => {
            const ok = !!resp?.ok && !chrome.runtime.lastError;
            resolve(ok);
          });
        });
      }
    } catch (_) {
      // best effort; background queue remains fallback path if needed
    }
  }

  function isFailClosedReason(reason) {
    const r = String(reason || "").toLowerCase();
    return [
      "scan_timeout_fail_closed",
      "runtime_error_fail_closed",
      "empty_response_fail_closed",
      "unreadable_file_context",
    ].includes(r);
  }

  async function reportFailClosedBlockToSiem(file, scanResult, uploadBatchId = "") {
    try {
      const ctx = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "GET_UPLOAD_CONTEXT" }, (resp) => resolve(resp || {}));
      });

      const apiUrl = String(ctx.apiUrl || "").trim();
      if (!apiUrl) return;

      const reason = String(scanResult?.reason || "scan_fail_closed");
      const payload = {
        agent_type: "browser_extension",
        source_host: window.location.hostname || "unknown",
        user: ctx.user || "browser_user",
        payload: `File: ${file?.name || "unknown"}\nDomain: ${window.location.hostname || "unknown"}\nAction: block\nReason: ${reason}\nPatterns: FAIL_CLOSED`,
        geo: {
          file_name: file?.name || "unknown",
          file_size: file?.size || 0,
          file_type: file?.type || "application/octet-stream",
          action: "block",
          severity: scanResult?.severity || "high",
          reason,
          finding_count: 0,
          findings: [],
          upload_url: window.location.href,
          upload_batch_id: uploadBatchId || '',
          fail_closed: true,
        }
      };

      await fetch(`${apiUrl}/api/browser/incident`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
        body: JSON.stringify(payload),
      });
    } catch (_) {
      // best effort; keep block behavior unchanged
    }
  }

  async function checkFiles(files) {
    for (const file of files) {
      const contentContext = await readFileAsContext(file);
      if (contentContext === null) return false;

      const result = await new Promise((resolve) => {
        let done = false;
        const finish = (r) => {
          if (done) return;
          done = true;
          resolve(r);
        };
        const timeout = setTimeout(() => finish({ action: "block", reason: "scan_timeout_fail_closed" }), 45000);
        chrome.runtime.sendMessage({
          type: "SCAN_FILE",
          fileContent: contentContext.content,
          fileContentBase64: contentContext.contentBase64,
          fileContentTruncated: contentContext.contentTruncated,
          isImage: contentContext.isImage,
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type || contentContext.ext,
          uploadUrl: window.location.href,
        }, (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            finish({ action: "block", reason: "runtime_error_fail_closed" });
            return;
          }
          finish(response || { action: "block", reason: "empty_response_fail_closed" });
        });
      });

      if (result.action === "block") return false; // Changed to false as per typical blocking logic
    }
    return true; // Changed to true if all files are allowed
  }

  // ─── File Reader ───────────────────────────────────────────

  function readFileAsContext(file) {
    return new Promise((resolve) => {
      const ext = file.name.includes(".") ? file.name.split(".").pop().toLowerCase() : "";

      // Handle Images for OCR
      const imageExts = ["png", "jpg", "jpeg", "webp"];
      if (imageExts.includes(ext) || file.type.startsWith("image/")) {
        const reader = new FileReader();
        reader.onload = async () => {
          const bytes = await readFileBytesAsBase64(file, 20 * 1024 * 1024);
          resolve({
            content: reader.result,
            isImage: true,
            ext,
            contentBase64: bytes?.base64 || null,
            contentTruncated: !!bytes?.truncated,
          });
        };
        reader.onerror = () => resolve(null);
        reader.readAsDataURL(file); // Needs DataURL for Gemini Vision
        return;
      }

      // Skip heavy binary formats
      const binaryTypes = [
        "video/", "audio/", "application/zip",
        "application/x-rar", "application/x-7z", "application/gzip",
        "application/octet-stream", "application/wasm",
      ];

      if (binaryTypes.some(t => file.type.startsWith(t))) {
        resolve(null);
        return;
      }

      // Check extension
      const textExts = ["txt", "csv", "json", "xml", "html", "htm", "js", "css", "md", "log", "ini", "cfg", "conf", "yaml", "yml", "sh", "bat", "ps1", "py", "java", "c", "cpp", "h", "hpp", "go", "rb", "php", "asp", "aspx", "jsp", "ts", "tsx", "jsx", "vue", "svelte", "sql", "rtf", "tex"];

      // PDFs are binary containers; do not read them as plain text in browser.
      // Send raw bytes for backend deep parsing + OCR fallback.
      if (ext === "pdf" || file.type === "application/pdf") {
        readFileBytesAsBase64(file, 20 * 1024 * 1024).then((bytes) => {
          resolve({
            content: "",
            isImage: false,
            ext,
            contentBase64: bytes?.base64 || null,
            contentTruncated: !!bytes?.truncated,
          });
        }).catch(() => resolve(null));
        return;
      }

      // If it's a known text-based extension or a generic text type
      if (textExts.includes(ext) || file.type.startsWith("text/")) {
        const reader = new FileReader();
        reader.onload = async () => {
          const bytes = await readFileBytesAsBase64(file, 20 * 1024 * 1024);
          resolve({
            content: reader.result,
            isImage: false,
            ext,
            contentBase64: bytes?.base64 || null,
            contentTruncated: !!bytes?.truncated,
          });
        };
        reader.onerror = () => resolve(null);

        // Only read first 5MB for scanning
        const slice = file.slice(0, 5 * 1024 * 1024);
        reader.readAsText(slice);
        return;
      }

      // Unknown/binary types: still send raw bytes for server deep parsing.
      readFileBytesAsBase64(file, 20 * 1024 * 1024).then((bytes) => {
        resolve({
          content: "",
          isImage: false,
          ext,
          contentBase64: bytes?.base64 || null,
          contentTruncated: !!bytes?.truncated,
        });
      }).catch(() => resolve(null));
    });
  }

  function readFileBytesAsBase64(file, maxBytes) {
    return new Promise((resolve) => {
      try {
        const truncated = file.size > maxBytes;
        const blob = truncated ? file.slice(0, maxBytes) : file;
        const reader = new FileReader();
        reader.onload = () => {
          const arr = new Uint8Array(reader.result || new ArrayBuffer(0));
          let bin = "";
          const chunk = 0x8000;
          for (let i = 0; i < arr.length; i += chunk) {
            bin += String.fromCharCode(...arr.subarray(i, i + chunk));
          }
          resolve({ base64: btoa(bin), truncated });
        };
        reader.onerror = () => resolve(null);
        reader.readAsArrayBuffer(blob);
      } catch (_) {
        resolve(null);
      }
    });
  }

  // ─── UI Components ─────────────────────────────────────────

  function showScanningOverlay(files) {
    const overlay = document.createElement("div");
    overlay.className = "tron-scanning-overlay";
    overlay.innerHTML = `
      <div class="tron-scanning-card">
        <div class="tron-scanning-spinner"></div>
        <div class="tron-scanning-text">
          <div class="tron-scanning-title">TRON THE DLP AGENT</div>
          <div class="tron-scanning-subtitle">Scanning ${files.length} file(s) with AI + Pattern Analysis...</div>
          <div class="tron-scanning-files">${files.map(f => f.name).join(", ")}</div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    return overlay;
  }

  function showToast(message, type = "info") {
    if (settings.silentMode) return;
    const toast = document.createElement("div");
    toast.className = `tron-toast tron-toast-${type}`;

    const icons = {
      clean: "✅",
      blocked: "X",
      info: "ℹ️",
      warning: "⚠️",
    };

    toast.innerHTML = `
      <span class="tron-toast-icon">${icons[type] || "!"}</span>
      <span class="tron-toast-msg">${message}</span>
    `;

    document.body.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => toast.classList.add("tron-toast-visible"));

    // Auto remove after 4s
    setTimeout(() => {
      toast.classList.remove("tron-toast-visible");
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  }

  function showBlockedModal(blockedResults, files, targetElement) {
    const result = blockedResults[0];
    const findings = result.findings || [];
    const reason = String(result.reason || "");
    const severity = String(result.severity || "high").toLowerCase();
    const severityLabel = severity.toUpperCase();
    const fileName = result.fileName || (files && files[0] && files[0].name) || "unknown_file";

    const modal = document.createElement("div");
    modal.className = "tron-modal-overlay";
    modal.innerHTML = `
      <div class="tron-modal tron-modal-blocked">
        <div class="tron-modal-header tron-header-blocked">
          <div class="tron-modal-icon">X</div>
          <h2>Upload Blocked</h2>
          <p>Sensitive data detected — this file cannot be uploaded</p>
        </div>
        <div class="tron-modal-body">
          <div class="tron-file-info">
            <div class="tron-file-name">FILE: ${escapeHtml(fileName)}</div>
            <div class="tron-severity tron-severity-${severity}">
              ${severityLabel} SEVERITY
            </div>
          </div>
          <div class="tron-findings-summary">
            <span class="tron-finding-count">${result.findingCount || findings.length}</span> sensitive item(s) detected
          </div>
          ${((result.findingCount || findings.length) === 0 && reason)
            ? `<div class="tron-domain-info">Reason: <strong>${escapeHtml(reason.replaceAll('_', ' '))}</strong></div>`
            : ""}
          ${renderAIContext(result)}
          <div class="tron-findings-list">
            ${findings.slice(0, 8).map(f => `
              <div class="tron-finding-item">
                <span class="tron-finding-severity tron-sev-${f.severity}">●</span>
                <span class="tron-finding-name">${escapeHtml(f.description || f.pattern_name)}</span>
                <span class="tron-finding-text">${escapeHtml(f.matched_text)}</span>
              </div>
            `).join("")}
            ${findings.length > 8 ? `<div class="tron-finding-more">...and ${findings.length - 8} more</div>` : ""}
          </div>
          <div class="tron-domain-info">
            Target: <strong>${escapeHtml(window.location.hostname)}</strong>
          </div>
        </div>
        <div class="tron-modal-footer">
          <button class="tron-btn tron-btn-secondary" id="tron-close-blocked">Understood</button>
        </div>
        <div class="tron-modal-brand">Protected by TRON THE DLP AGENT${result.ai_analysis?.enabled ? ' + AI' : ''}</div>
      </div>
    `;

    document.body.appendChild(modal);
    requestAnimationFrame(() => modal.classList.add("tron-modal-visible"));

    modal.querySelector("#tron-close-blocked").addEventListener("click", () => {
      modal.classList.remove("tron-modal-visible");
      setTimeout(() => modal.remove(), 300);

      chrome.runtime.sendMessage({
        type: "FILE_UPLOAD_DECISION",
        decision: "block",
        scanId: result.scanId,
      });
    });
  }

  function showWarningModal(warnedResults, files) {
    return new Promise((resolve) => {
      const result = warnedResults[0];
      const findings = result.findings || [];
      const severity = String(result.severity || "medium").toLowerCase();
      const severityLabel = severity.toUpperCase();
      const fileName = result.fileName || (files && files[0] && files[0].name) || "unknown_file";

      const modal = document.createElement("div");
      modal.className = "tron-modal-overlay";
      modal.innerHTML = `
        <div class="tron-modal tron-modal-warning">
          <div class="tron-modal-header tron-header-warning">
            <div class="tron-modal-icon">⚠️</div>
            <h2>Sensitive Data Warning</h2>
            <p>The file you're uploading contains sensitive information</p>
          </div>
          <div class="tron-modal-body">
            <div class="tron-file-info">
              <div class="tron-file-name">FILE: ${escapeHtml(fileName)}</div>
              <div class="tron-severity tron-severity-${severity}">
                ${severityLabel} SEVERITY
              </div>
            </div>
            <div class="tron-findings-summary">
              <span class="tron-finding-count">${result.findingCount || findings.length}</span> sensitive item(s) detected
            </div>
            ${renderAIContext(result)}
            <div class="tron-findings-list">
              ${findings.slice(0, 8).map(f => `
                <div class="tron-finding-item">
                  <span class="tron-finding-severity tron-sev-${f.severity}">●</span>
                  <span class="tron-finding-name">${escapeHtml(f.description || f.pattern_name)}</span>
                  <span class="tron-finding-text">${escapeHtml(f.matched_text)}</span>
                </div>
              `).join("")}
              ${findings.length > 8 ? `<div class="tron-finding-more">...and ${findings.length - 8} more</div>` : ""}
            </div>
            <div class="tron-domain-info">
              Uploading to: <strong>${escapeHtml(window.location.hostname)}</strong>
            </div>
            <div class="tron-warn-message">
              ⚠️ Proceeding will upload this file <strong>with sensitive data</strong> to the target website. This action will be logged.
            </div>
          </div>
          <div class="tron-modal-footer">
            <button class="tron-btn tron-btn-danger" id="tron-block-upload">
              Block Upload
            </button>
            <button class="tron-btn tron-btn-warning" id="tron-allow-upload">
              ⚡ Upload Anyway
            </button>
          </div>
          <div class="tron-modal-brand">Protected by TRON THE DLP AGENT${result.ai_analysis?.enabled ? ' + AI' : ''}</div>
        </div>
      `;

      document.body.appendChild(modal);
      requestAnimationFrame(() => modal.classList.add("tron-modal-visible"));

      modal.querySelector("#tron-block-upload").addEventListener("click", () => {
        modal.classList.remove("tron-modal-visible");
        setTimeout(() => modal.remove(), 300);
        chrome.runtime.sendMessage({
          type: "FILE_UPLOAD_DECISION",
          decision: "block",
          scanId: result.scanId,
        });
        resolve("block");
      });

      modal.querySelector("#tron-allow-upload").addEventListener("click", () => {
        modal.classList.remove("tron-modal-visible");
        setTimeout(() => modal.remove(), 300);
        chrome.runtime.sendMessage({
          type: "FILE_UPLOAD_DECISION",
          decision: "allow",
          scanId: result.scanId,
        });
        resolve("allow");
      });
    });
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text || "";
    return div.innerHTML;
  }

  /**
   * Render AI analysis context panel for modals.
   */
  function renderAIContext(result) {
    const ai = result.ai_analysis;
    if (!ai || !ai.enabled || ai.error) return "";

    const riskColor = ai.risk_score >= 70 ? "#ef4444" : ai.risk_score >= 40 ? "#f59e0b" : "#10b981";

    return `
          <div class="tron-ai-panel">
            <div class="tron-ai-header">
              <span>AI Analysis</span>
              <span class="tron-ai-risk" style="color: ${riskColor}">
                Risk: ${ai.risk_score}/100
              </span>
            </div>
            ${ai.reasoning ? `<div class="tron-ai-reasoning">${escapeHtml(ai.reasoning)}</div>` : ""}
            ${ai.context_analysis ? `<div class="tron-ai-context">${escapeHtml(ai.context_analysis)}</div>` : ""}
            ${ai.categories && ai.categories.length > 0 ? `
              <div class="tron-ai-categories">
                ${ai.categories.map(c => `<span class="tron-ai-cat">${escapeHtml(c)}</span>`).join("")}
              </div>
            ` : ""}
          </div>
        `;
  }

})();
