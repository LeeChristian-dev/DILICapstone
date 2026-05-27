const MESSAGE_TYPES = {
  GET_POPUP_SUMMARY: "DILI_GET_POPUP_SUMMARY",
  GET_SCAN_STATE: "DILI_GET_SCAN_STATE",
  SET_SCAN_STATE: "DILI_SET_SCAN_STATE",
  GET_ANALYSIS_RECORDS: "DILI_GET_ANALYSIS_RECORDS",
  CLEAR_ANALYSIS_RECORDS: "DILI_CLEAR_ANALYSIS_RECORDS",
  RESET_SESSION: "DILI_RESET_SESSION",
  RESCAN_CURRENT_TAB: "DILI_RESCAN_CURRENT_TAB",
  GET_SCAN_STATUS: "DILI_GET_SCAN_STATUS"
};

const popupState = {
  activeTab: null,
  summary: {},
  scanEnabled: true,
  bootstrapWarningVisible: false,
  refreshIntervalId: null
};

const LIVE_REFRESH_INTERVAL_MS = 3000;

const dashboardShell = document.querySelector(".dashboard-shell");
const menuToggleButton = document.getElementById("menu-toggle");
const settingsMenu = document.getElementById("settings-menu");
const howToggleButton = document.getElementById("how-toggle");
const howPanel = document.getElementById("how-panel");
const powerToggleButton = document.getElementById("power-toggle");
const powerStatus = document.getElementById("power-status");
const exportButton = document.getElementById("export-btn");
const restartButton = document.getElementById("restart-btn");
const clearButton = document.getElementById("clear-btn");
const messageBox = document.getElementById("message");
const refreshButton = document.getElementById("refresh-btn");
const tabContext = document.getElementById("tab-context");
const tabContextText = document.getElementById("tab-context-text");
const statScannedPosts = document.getElementById("stat-scanned-posts");
const statAnalyzedPosts = document.getElementById("stat-analyzed-posts");
const statFlaggedPosts = document.getElementById("stat-flagged-posts");
const statTotalStored = document.getElementById("stat-total-stored");
const sessionSinceEl = document.getElementById("session-since");
const providerChipsEl = document.getElementById("provider-chips");
const recentActivityList = document.getElementById("recent-activity-list");
const recentEmptyEl = document.getElementById("recent-empty");

init().catch((error) => {
  renderPopupBootstrapWarning(null, error);
});

async function init() {
  bindActions();
  await refreshPopupData();
  startLiveRefresh();
}

function startLiveRefresh() {
  if (popupState.refreshIntervalId !== null) {
    return;
  }

  popupState.refreshIntervalId = setInterval(() => {
    refreshPopupData().catch(() => {});
  }, LIVE_REFRESH_INTERVAL_MS);
}

function stopLiveRefresh() {
  if (popupState.refreshIntervalId !== null) {
    clearInterval(popupState.refreshIntervalId);
    popupState.refreshIntervalId = null;
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopLiveRefresh();
  } else {
    refreshPopupData().catch(() => {});
    startLiveRefresh();
  }
});

function bindActions() {
  refreshButton.addEventListener("click", async () => {
    refreshButton.classList.add("spinning");
    await refreshPopupData().catch(() => {});
    setTimeout(() => refreshButton.classList.remove("spinning"), 500);
  });

  menuToggleButton.addEventListener("click", (event) => {
    event.stopPropagation();
    toggleSettingsMenu();
  });

  howToggleButton.addEventListener("click", (event) => {
    event.stopPropagation();
    toggleHowPanel();
  });

  document.addEventListener("click", (event) => {
    if (settingsMenu.hidden) {
      return;
    }

    if (settingsMenu.contains(event.target) || menuToggleButton.contains(event.target)) {
      return;
    }

    closeSettingsMenu();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSettingsMenu();
    }
  });

  powerToggleButton.addEventListener("click", async () => {
    closeSettingsMenu();

    try {
      const nextEnabled = !popupState.scanEnabled;
      const response = await sendMessage({
        type: MESSAGE_TYPES.SET_SCAN_STATE,
        enabled: nextEnabled
      });

      popupState.scanEnabled = response?.scanEnabled !== false;
      renderProtectionState();

      setMessage(
        popupState.scanEnabled
          ? "Protection turned on. Current page scan started."
          : "Protection turned off. DILI panels were removed."
      );

      await refreshPopupData();
    } catch (error) {
      setMessage(`Failed to update protection state: ${error.message || "unknown error"}`);
    }
  });

  exportButton.addEventListener("click", async () => {
    closeSettingsMenu();

    try {
      const response = await sendMessage({ type: MESSAGE_TYPES.GET_ANALYSIS_RECORDS });
      const records = response?.records || [];
      if (records.length === 0) {
        setMessage("No retained session records are available to export.");
        return;
      }

      const csv = convertRecordsToCsv(records);
      downloadCsv(csv);
      setMessage(`CSV export completed with ${records.length} record(s).`);
    } catch (error) {
      console.warn("[DILI] CSV export failed", error);
      setMessage(`CSV export failed: ${error.message || "unknown error"}`);
    }
  });

  restartButton.addEventListener("click", async () => {
    closeSettingsMenu();

    try {
      await sendMessage({ type: MESSAGE_TYPES.RESET_SESSION });

      let message = "Session restarted.";
      if (popupState.scanEnabled && popupState.summary?.tabSupported) {
        const response = await sendMessage({ type: MESSAGE_TYPES.RESCAN_CURRENT_TAB });
        message = response?.result?.message || "Session restarted and page scan triggered.";
      }

      setMessage(message);
      await refreshPopupData();
    } catch (error) {
      setMessage(`Failed to restart session: ${error.message || "unknown error"}`);
    }
  });

  clearButton.addEventListener("click", async () => {
    closeSettingsMenu();

    try {
      await sendMessage({ type: MESSAGE_TYPES.CLEAR_ANALYSIS_RECORDS });
      setMessage("Session logs cleared.");
      await refreshPopupData();
    } catch (error) {
      setMessage(`Failed to clear logs: ${error.message || "unknown error"}`);
    }
  });
}

async function refreshPopupData() {
  let activeTab = null;
  let summaryResponse = null;
  let scanStateResponse = null;
  let bootstrapError = null;

  try {
    [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (error) {
    bootstrapError = error;
  }

  const tabUrl = activeTab?.url || "";

  if (!bootstrapError) {
    try {
      summaryResponse = await sendMessage({
        type: MESSAGE_TYPES.GET_POPUP_SUMMARY,
        tabUrl
      });
    } catch (error) {
      bootstrapError = bootstrapError || error;
    }

    try {
      scanStateResponse = await sendMessage({
        type: MESSAGE_TYPES.GET_SCAN_STATE
      });
    } catch (error) {
      bootstrapError = bootstrapError || error;
    }
  }

  popupState.activeTab = activeTab || null;
  popupState.summary = summaryResponse?.summary || buildPopupFallbackSummary(activeTab);
  popupState.summary.scanStatus = await getContentScanStatus(activeTab, popupState.summary);

  if (scanStateResponse?.scanEnabled !== undefined) {
    popupState.scanEnabled = scanStateResponse.scanEnabled !== false;
  }

  renderProtectionState();
  renderTabContext(popupState.activeTab, popupState.summary);
  renderStats(popupState.summary);
  renderSessionSince(popupState.summary);
  renderProviderChips(popupState.summary.providerSummary);
  renderRecentActivity(popupState.summary.recentActivity);

  if (bootstrapError) {
    renderPopupBootstrapWarning(activeTab, bootstrapError);
  } else if (popupState.bootstrapWarningVisible) {
    popupState.bootstrapWarningVisible = false;
    setMessage("");
  }
}

function renderProtectionState() {
  powerToggleButton.classList.toggle("power-toggle-on", popupState.scanEnabled);
  powerToggleButton.classList.toggle("power-toggle-off", !popupState.scanEnabled);
  powerToggleButton.setAttribute("aria-pressed", String(popupState.scanEnabled));
  powerStatus.textContent = popupState.scanEnabled ? "Protection On" : "Protection Off";
  dashboardShell.classList.toggle("protection-off", !popupState.scanEnabled);
}

async function getContentScanStatus(activeTab, summary) {
  if (!summary?.tabSupported || !activeTab?.id) {
    return null;
  }

  try {
    const response = await chrome.tabs.sendMessage(activeTab.id, {
      type: MESSAGE_TYPES.GET_SCAN_STATUS
    });
    return response?.status || null;
  } catch {
    return null;
  }
}
function renderStats(summary) {
  const status = summary.scanStatus || {};

  const visibleCandidates =
    Number(status.candidatePostsFound || 0) > 0
      ? status.candidatePostsFound
      : summary.postsScannedInSession ?? summary.scannedPostsInSession ?? 0;

  const pageAnalyses =
    Number(status.analyzedPosts || 0) > 0
      ? status.analyzedPosts
      : summary.postsAnalyzedInSession ?? summary.analyzedLinksInSession ?? 0;

  const visiblePanels =
    Number(status.visiblePanels || 0) > 0
      ? status.visiblePanels
      : summary.flaggedPostsInSession ?? 0;

  statScannedPosts.textContent = String(visibleCandidates);
  statAnalyzedPosts.textContent = String(pageAnalyses);
  statFlaggedPosts.textContent = String(visiblePanels);
  statTotalStored.textContent = String(summary.totalStoredAnalyses ?? 0);
}
function renderTabContext(activeTab, summary) {
  const url = String(activeTab?.url || "").trim();
  const tabSupported = summary.tabSupported === true;

  tabContext.classList.remove("context-ok", "context-warn", "context-bad");

  const isRestricted =
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("devtools://");

  if (isRestricted) {
    tabContextText.textContent =
      "Open a normal Facebook tab (facebook.com) to scan posts. Extension pages and browser settings URLs cannot be scanned.";
    tabContext.classList.add("context-warn");
    return;
  }

  if (tabSupported) {
    tabContextText.textContent = "Facebook tab — DILI can scan posts on this page.";
    tabContext.classList.add("context-ok");
    return;
  }

  tabContextText.textContent = "Not a Facebook URL — DILI only runs on *.facebook.com.";
  tabContext.classList.add("context-warn");
}

function buildPopupFallbackSummary(activeTab) {
  const url = String(activeTab?.url || "").trim();
  const tabSupported = Boolean(url && url.includes("facebook.com") && !url.startsWith("chrome://") && !url.startsWith("edge://") && !url.startsWith("about:") && !url.startsWith("chrome-extension://") && !url.startsWith("devtools://"));

  return {
    tabSupported,
    postsScannedInSession: 0,
    scannedPostsInSession: 0,
    postsAnalyzedInSession: 0,
    analyzedPostsInSession: 0,
    analyzedLinksInSession: 0,
    flaggedPostsInSession: 0,
    totalStoredAnalyses: 0,
    sessionStartedAt: 0,
    providerSummary: null,
    recentActivity: [],
    scanStatus: null
  };
}

function renderPopupBootstrapWarning(activeTab, error) {
  const isFacebookTab = String(activeTab?.url || "").includes("facebook.com");
  tabContext.classList.remove("context-ok", "context-warn", "context-bad");
  tabContext.classList.add("context-warn");
  popupState.bootstrapWarningVisible = true;
  tabContextText.textContent = isFacebookTab
    ? "Facebook tab detected, but DILI background service worker did not respond. Reload the extension and check the service worker console."
    : "DILI background service worker did not respond. Reload the extension and check the service worker console.";
  setMessage("DILI background service worker did not respond. Reload the extension and check the service worker console.");
  console.warn("[DILI] Popup bootstrap failed", error);
}

function renderSessionSince(summary) {
  const started = Number(summary.sessionStartedAt || 0);
  if (!Number.isFinite(started) || started <= 0) {
    sessionSinceEl.hidden = true;
    sessionSinceEl.textContent = "";
    return;
  }

  const label = formatTimestamp(started);
  sessionSinceEl.textContent = `Session started: ${label}`;
  sessionSinceEl.hidden = false;
}

function renderProviderChips(providerSummary) {
  providerChipsEl.textContent = "";

  if (!providerSummary || typeof providerSummary !== "object") {
    const fallback = document.createElement("span");
    fallback.className = "recent-meta";
    fallback.style.padding = "4px 2px";
    fallback.textContent = "Provider status unavailable.";
    providerChipsEl.appendChild(fallback);
    return;
  }

  const order = ["config", "gsb", "urlhaus", "virustotal"];
  for (const key of order) {
    const entry = providerSummary[key];
    if (!entry || typeof entry !== "object") {
      continue;
    }

    const chip = document.createElement("span");
    const state = String(entry.state || "off");
    chip.className = `provider-chip provider-chip--${sanitizeProviderStateClass(state)}`;

    const labelSpan = document.createElement("span");
    labelSpan.className = "prov-label";
    labelSpan.textContent = `${key === "virustotal" ? "VT Config" : (entry.label || key)}:`;

    const textSpan = document.createElement("span");
    textSpan.textContent = String(entry.text || "—");

    if (key === "virustotal") {
      chip.title = "Provider is configured or available. Individual URL scans may still be pending.";
    }

    chip.appendChild(labelSpan);
    chip.appendChild(textSpan);
    providerChipsEl.appendChild(chip);
  }
}

function sanitizeProviderStateClass(state) {
  if (state === "ready" || state === "public" || state === "off" || state === "error" || state === "pending" || state === "rate-limited") {
    return state;
  }

  return "off";
}

function renderRecentActivity(recentActivity) {
  recentActivityList.textContent = "";

  if (!Array.isArray(recentActivity) || recentActivity.length === 0) {
    recentEmptyEl.hidden = false;
    return;
  }

  recentEmptyEl.hidden = true;

  for (const item of recentActivity) {
    const li = document.createElement("li");
    const title = document.createElement("span");
const domain = item.domain || "—";
const classification = String(item.classification || "").trim();
const state = String(item.state || "").toLowerCase();
const providerOverride = item.providerOverride === true;
const scanFinalized = providerOverride || item.scanFinalized === true;

const pending = !providerOverride && (
  !scanFinalized ||
  state === "pending-provider" ||
  classification.toLowerCase() === "scan pending"
);

const terminalIncomplete = !providerOverride && (
  state === "verification-incomplete" ||
  state === "completed-limited" ||
  classification.toLowerCase() === "verification incomplete" ||
  classification.toLowerCase() === "unverified"
);

const scoreValue = toFinitePopupScoreOrNull(item.safetyScore);
const hasScore = (providerOverride || (scanFinalized && !pending && !terminalIncomplete)) &&
  scoreValue !== null &&
  Number.isFinite(scoreValue);

const scoreText = pending
  ? "not final"
  : terminalIncomplete
    ? "no score"
    : hasScore
      ? `score ${scoreValue}`
      : "no score";

const statusLabel = providerOverride
  ? "High Risk"
  : pending
    ? "Scan Pending"
    : terminalIncomplete
      ? "Verification Incomplete"
      : classification || "Unverified";

title.textContent = `${domain} · ${statusLabel} · ${scoreText}`;

    const meta = document.createElement("span");
    meta.className = "recent-meta";
    meta.textContent = `${formatTimestamp(item.timestamp)} · ${String(item.postId || "").slice(0, 24)}${
      String(item.postId || "").length > 24 ? "…" : ""
    } · ${item.state || "—"}`;

    li.appendChild(title);
    li.appendChild(meta);
    recentActivityList.appendChild(li);
  }
}

function toggleSettingsMenu() {
  if (settingsMenu.hidden) {
    openSettingsMenu();
    return;
  }

  closeSettingsMenu();
}

function openSettingsMenu() {
  settingsMenu.hidden = false;
  menuToggleButton.setAttribute("aria-expanded", "true");
}

function closeSettingsMenu() {
  settingsMenu.hidden = true;
  howPanel.hidden = true;
  menuToggleButton.setAttribute("aria-expanded", "false");
  howToggleButton.setAttribute("aria-expanded", "false");
}

function toggleHowPanel() {
  const nextHiddenState = !howPanel.hidden;
  howPanel.hidden = nextHiddenState;
  howToggleButton.setAttribute("aria-expanded", String(!nextHiddenState));
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
    "analyzedLinkCount",
    "lowestScoringLinkDomain",
    "lowestScoringLinkUrl",
    "gsbStatus",
    "urlhausStatus",
    "gsbConfigured",
    "gsbFlagged",
    "gsbCheckedUrl",
    "gsbCheckedAt",
    "gsbDurationMs",
    "gsbResultSummary",
    "urlhausConfigured",
    "urlhausFlagged",
    "urlhausCheckedUrl",
    "urlhausCheckedAt",
    "urlhausDurationMs",
    "urlhausResultSummary",
    "vtStatus",
    "vtConfigured",
    "vtFlagged",
    "vtCheckedUrl",
    "vtCheckedAt",
    "vtResultSummary",
    "vtMaliciousCount",
    "vtSuspiciousCount",
    "vtAnalysisId",
    "redirectCount",
    "usedShortener",
    "suspiciousTld",
    "obfuscationDetected",
    "displayedDomainMismatch",
    "integrityMismatch",
    "state",
    "verificationState",
    "interceptionRecommended",
    "manualVerdict",
    "expectedClassification",
    "isCorrect",
    "accuracyNotes"
  ];

  const rows = records.map((record) => {
    const gsb = findProviderResult(record.providerResults, "gsb");
    const urlhaus = findProviderResult(record.providerResults, "urlhaus");
    const vt = findProviderResult(record.providerResults, "virustotal");
    const features = record.features || {};
    const analyzedLinkCount =
      record.analyzedLinkCount ??
      (Array.isArray(record.linkScoreSummary) ? record.linkScoreSummary.length : "");
    return [
      formatTimestamp(record.timestamp),
      record.postId || "",
      record.url || record.analysisUrl || record.normalizedUrl || "",
      record.domain || "",
      record.urlHash || "",
      record.safetyScore ?? "",
      record.classification || "",
      analyzedLinkCount,
      record.lowestScoringLinkDomain || "",
      record.lowestScoringLinkUrl || "",
      gsb?.details?.status ?? "",
      urlhaus?.details?.status ?? "",
      gsb?.configured ?? "",
      gsb?.flagged ?? "",
      gsb?.checkedUrl ?? "",
      gsb?.checkedAt ?? "",
      gsb?.durationMs ?? "",
      gsb?.resultSummary || getProviderOutcomeSummary(gsb),
      urlhaus?.details?.authKeyConfigured ?? urlhaus?.details?.authConfigured ?? urlhaus?.configured ?? "",
      urlhaus?.flagged ?? "",
      urlhaus?.checkedUrl ?? "",
      urlhaus?.checkedAt ?? "",
      urlhaus?.durationMs ?? "",
      urlhaus?.resultSummary || getProviderOutcomeSummary(urlhaus),
      vt?.details?.status ?? "",
      vt?.configured ?? "",
      vt?.flagged ?? "",
      vt?.checkedUrl ?? "",
      vt?.checkedAt ?? "",
      vt?.resultSummary || getProviderOutcomeSummary(vt),
      vt?.details?.maliciousCount ?? "",
      vt?.details?.suspiciousCount ?? "",
      vt?.details?.analysisId ?? "",
      features.redirectCount ?? "",
      features.shortenedUrl ?? "",
      features.suspiciousTld ?? "",
      features.obfuscatedUrl ?? "",
      features.textMismatch ?? "",
      features.integrityHashMismatch ?? "",
      record.state || "",
      record.verificationState || "",
      inferInterceptionRecommended(record),
      "",
      "",
      "",
      ""
    ];
  });

  return [headers, ...rows]
    .map((row) => row.map(csvEscape).join(","))
    .join("\n");
}

function inferInterceptionRecommended(record = {}) {
  const score = toFinitePopupScoreOrNull(record.safetyScore);
  const classification = String(record.classification || "").toLowerCase();
  const gsb = findProviderResult(record.providerResults, "gsb");
  const urlhaus = findProviderResult(record.providerResults, "urlhaus");
  const vt = findProviderResult(record.providerResults, "virustotal");
  const providerFlagged = Array.isArray(record.providerResults) && record.providerResults.some((item) => item?.flagged === true);

  return Boolean(
    record.interceptionRecommended === true ||
    record.providerOverride === true ||
    classification === "high risk" ||
    classification === "suspicious" ||
    (score !== null && Number.isFinite(score) && score < 60) ||
    providerFlagged ||
    gsb?.flagged === true ||
    urlhaus?.flagged === true ||
    vt?.flagged === true
  );
}

function toFinitePopupScoreOrNull(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
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

function getProviderOutcomeSummary(provider = {}) {
  if (!provider || typeof provider !== "object") {
    return "";
  }

  const providerName = String(provider.provider || "").toLowerCase();
  const status = String(provider.details?.status || "").toLowerCase();

  if (providerName === "virustotal") {
    if (!provider.configured || status === "not-configured") {
      return "VirusTotal not configured.";
    }
    if (status === "pending") {
      return "VirusTotal scan submitted; result pending.";
    }
    if (status === "rate-limited") {
      return "VirusTotal rate limit reached.";
    }
    if (status === "timeout") {
      return "VirusTotal verification timed out.";
    }
    if (status === "error" || status === "parse-error") {
      return "VirusTotal request failed.";
    }
    return provider.flagged
      ? "VirusTotal reported malicious/suspicious detections."
      : "VirusTotal reported no malicious detections.";
  }

  if (providerName === "urlhaus" && status === "error") {
    return "Lookup unavailable after retry.";
  }

  if (providerName !== "urlhaus" && (!provider.configured || status === "not-configured")) {
    return "Provider not configured.";
  }

  if (status === "timeout") {
    return "Verification timed out.";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return "Request failed.";
  }

  if (!provider.checked || status === "skipped" || status === "not-configured") {
    return "Provider not configured.";
  }

  if (providerName === "gsb") {
    return provider.flagged ? "Unsafe URL reported." : "No unsafe matches reported.";
  }

  if (providerName === "urlhaus") {
    return provider.flagged ? "Known malware record found." : "No known malware record found.";
  }

  return provider.flagged ? "Provider reported a match." : "No provider match reported.";
}

function setMessage(text) {
  const value = String(text || "").trim();
  messageBox.textContent = value;
  messageBox.hidden = !value;
}

function findProviderResult(results, providerName) {
  if (!Array.isArray(results)) {
    return null;
  }

  return results.find((item) => item.provider === providerName) || null;
}

function formatTimestamp(timestamp) {
  const date = new Date(Number(timestamp || Date.now()));
  return Number.isNaN(date.getTime()) ? "invalid-date" : date.toLocaleString();
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

async function sendMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) {
    throw new Error(response?.error || "Background request failed.");
  }

  return response;
}
