const MESSAGE_TYPES = {
  GET_POPUP_SUMMARY: "DILI_GET_POPUP_SUMMARY",
  GET_PROVIDER_HEALTH: "DILI_GET_PROVIDER_HEALTH",
  GET_ANALYSIS_RECORDS: "DILI_GET_ANALYSIS_RECORDS",
  CLEAR_ANALYSIS_RECORDS: "DILI_CLEAR_ANALYSIS_RECORDS",
  RESCAN_CURRENT_TAB: "DILI_RESCAN_CURRENT_TAB"
};

const statusList = document.getElementById("status-list");
const activityList = document.getElementById("activity-list");
const messageBox = document.getElementById("message");
const exportButton = document.getElementById("export-btn");
const clearButton = document.getElementById("clear-btn");
const rescanButton = document.getElementById("rescan-btn");

init().catch((error) => {
  setMessage(`Failed to initialize popup: ${error.message || "unknown error"}`);
});

async function init() {
  bindActions();
  await refreshPopupData();
}

function bindActions() {
  exportButton.addEventListener("click", async () => {
    try {
      const response = await sendMessage({ type: MESSAGE_TYPES.GET_ANALYSIS_RECORDS });
      const records = response?.records || [];
      if (records.length === 0) {
        setMessage("No analysis records available to export.");
        return;
      }

      const csv = convertRecordsToCsv(records);
      downloadCsv(csv);
      setMessage(`CSV export completed with ${records.length} record(s).`);
      console.debug("[DILI] CSV export completed.");
    } catch (error) {
      console.warn("[DILI] CSV export failed", error);
      setMessage(`CSV export failed: ${error.message || "unknown error"}`);
    }
  });

  clearButton.addEventListener("click", async () => {
    try {
      await sendMessage({ type: MESSAGE_TYPES.CLEAR_ANALYSIS_RECORDS });
      setMessage("Analysis logs cleared.");
      console.debug("[DILI] Popup requested log clear.");
      await refreshPopupData();
    } catch (error) {
      setMessage(`Failed to clear logs: ${error.message || "unknown error"}`);
    }
  });

  rescanButton.addEventListener("click", async () => {
    try {
      const response = await sendMessage({ type: MESSAGE_TYPES.RESCAN_CURRENT_TAB });
      setMessage(response?.result?.message || "Re-scan command sent.");
      await refreshPopupData();
    } catch (error) {
      setMessage(`Re-scan failed: ${error.message || "unknown error"}`);
    }
  });
}

async function refreshPopupData() {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabUrl = activeTab?.url || "";
  const [summaryResponse, providerHealthResponse] = await Promise.all([
    sendMessage({
      type: MESSAGE_TYPES.GET_POPUP_SUMMARY,
      tabUrl
    }),
    sendMessage({
      type: MESSAGE_TYPES.GET_PROVIDER_HEALTH
    })
  ]);

  const summary = summaryResponse?.summary || {};
  const providerHealth = providerHealthResponse?.providerHealth || {};

  renderStatus(summary, providerHealth);
  renderActivity(summary.recentActivity || []);
}

function renderStatus(summary, providerHealth) {
  const gsb = providerHealth.gsb || {};
  const urlhaus = providerHealth.urlhaus || {};
  const items = [
    `Current tab supported: ${summary.tabSupported ? "Yes" : "No"}`,
    `Analyzed posts (session): ${summary.analyzedPostsInSession || 0}`,
    `Flagged posts (session): ${summary.flaggedPostsInSession || 0}`,
    `Stored analyses: ${summary.totalStoredAnalyses || 0}`,
    `Config loaded: ${providerHealth.configLoaded ? "Yes" : "No"}`,
    `Config source: ${providerHealth.configSource || "unknown"}`,
    `Config error: ${formatText(providerHealth.configError, "none")}`,
    `GSB key loaded: ${gsb.configured ? "Yes" : "No"}`,
    `GSB last check: ${formatProviderStatus(gsb.lastStatus)}`,
    `GSB last HTTP status: ${formatText(gsb.lastHttpStatus, "n/a")}`,
    `GSB last error: ${formatText(gsb.lastError, "none")}`,
    `GSB last checked at: ${formatTimestampOrFallback(gsb.lastCheckedAt)}`,
    `URLhaus mode: ${urlhaus.mode || "public"}`,
    `URLhaus last check: ${formatProviderStatus(urlhaus.lastStatus)}`,
    `URLhaus last HTTP status: ${formatText(urlhaus.lastHttpStatus, "n/a")}`,
    `URLhaus last error: ${formatText(urlhaus.lastError, "none")}`,
    `URLhaus last checked at: ${formatTimestampOrFallback(urlhaus.lastCheckedAt)}`
  ];

  statusList.innerHTML = items.map((text) => `<li>${escapeHtml(text)}</li>`).join("");
}

function renderActivity(activity) {
  if (!activity.length) {
    activityList.innerHTML = "<li>No analysis events yet.</li>";
    return;
  }

  activityList.innerHTML = activity
    .map((entry) => {
      const time = formatTimestamp(entry.timestamp);
      const domain = entry.domain || "unknown-domain";
      const score = Number.isFinite(entry.safetyScore) ? entry.safetyScore : "--";
      return `<li>${escapeHtml(`${time} | ${entry.classification || "Unknown"} (${score}) | ${domain}`)}</li>`;
    })
    .join("");
}

function convertRecordsToCsv(records) {
  const headers = [
    "timestamp",
    "postId",
    "url",
    "domain",
    "urlHash",
    "safetyScore",
    "classification",
    "gsbConfigured",
    "gsbFlagged",
    "urlhausConfigured",
    "urlhausFlagged",
    "redirectCount",
    "usedShortener",
    "suspiciousTld",
    "obfuscationDetected",
    "displayedDomainMismatch",
    "integrityMismatch",
    "state"
  ];

  const rows = records.map((record) => {
    const gsb = findProviderResult(record.providerResults, "gsb");
    const urlhaus = findProviderResult(record.providerResults, "urlhaus");
    const features = record.features || {};
    return [
      formatTimestamp(record.timestamp),
      record.postId || "",
      record.url || "",
      record.domain || "",
      record.urlHash || "",
      record.safetyScore ?? "",
      record.classification || "",
      gsb?.configured ?? "",
      gsb?.flagged ?? "",
      urlhaus?.configured ?? "",
      urlhaus?.flagged ?? "",
      features.redirectCount ?? "",
      features.shortenedUrl ?? "",
      features.suspiciousTld ?? "",
      features.obfuscatedUrl ?? "",
      features.textMismatch ?? "",
      features.integrityHashMismatch ?? "",
      record.state || ""
    ];
  });

  return [headers, ...rows]
    .map((row) => row.map(csvEscape).join(","))
    .join("\n");
}

function downloadCsv(csvText) {
  const blob = new Blob([csvText], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `dili-analysis-export-${timestampForFilename(new Date())}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function csvEscape(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function setMessage(text) {
  messageBox.textContent = text;
}

function findProviderResult(results, providerName) {
  if (!Array.isArray(results)) {
    return null;
  }

  return results.find((item) => item.provider === providerName) || null;
}

function formatProviderStatus(status) {
  return formatText(status, "not-yet-run");
}

function formatTimestamp(timestamp) {
  const date = new Date(Number(timestamp || Date.now()));
  return Number.isNaN(date.getTime()) ? "invalid-date" : date.toISOString();
}

function formatTimestampOrFallback(timestamp) {
  if (!timestamp) {
    return "not-yet-run";
  }

  return formatTimestamp(timestamp);
}

function formatText(value, fallback) {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  return String(value);
}

function timestampForFilename(date) {
  const parts = [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0"),
    String(date.getHours()).padStart(2, "0"),
    String(date.getMinutes()).padStart(2, "0"),
    String(date.getSeconds()).padStart(2, "0")
  ];

  return `${parts[0]}-${parts[1]}-${parts[2]}-${parts[3]}-${parts[4]}-${parts[5]}`;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function sendMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) {
    throw new Error(response?.error || "Background request failed.");
  }

  return response;
}
