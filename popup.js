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
const diagNoUrl = document.getElementById("diag-no-url");
const diagHidden = document.getElementById("diag-hidden");
const diagActionArea = document.getElementById("diag-action-area");
const diagNoOwner = document.getElementById("diag-no-owner");
const diagInternalFacebook = document.getElementById("diag-internal-facebook");
const diagImageSource = document.getElementById("diag-image-source");
const diagGenericDomain = document.getElementById("diag-generic-domain");
const diagHeaderDomain = document.getElementById("diag-header-domain");
const diagNestedShared = document.getElementById("diag-nested-shared");
const diagDirectCandidates = document.getElementById("diag-direct-candidates");
const diagEmbeddedCandidates = document.getElementById("diag-embedded-candidates");
const diagFallbackCandidates = document.getElementById("diag-fallback-candidates");
const diagVisibleDomain = document.getElementById("diag-visible-domain");
const diagPanelFallback = document.getElementById("diag-panel-fallback");
const diagPanelRelocated = document.getElementById("diag-panel-relocated");
const diagAnalysisRequests = document.getElementById("diag-analysis-requests");
const diagAnalysisResponses = document.getElementById("diag-analysis-responses");
const diagAnalysisMissing = document.getElementById("diag-analysis-missing");
const diagAnalysisRendered = document.getElementById("diag-analysis-rendered");
const diagStaleSignature = document.getElementById("diag-stale-signature");
const diagStaleFingerprint = document.getElementById("diag-stale-fingerprint");
const diagStaleText = document.getElementById("diag-stale-text");
const diagStaleRescan = document.getElementById("diag-stale-rescan");
const diagPanelRemoved = document.getElementById("diag-panel-removed");
const diagPanelPreserved = document.getElementById("diag-panel-preserved");
const diagHiddenDomain = document.getElementById("diag-hidden-domain");
const diagMalformedCandidate = document.getElementById("diag-malformed-candidate");
const diagPipeline = document.getElementById("diag-pipeline");
const diagBreakdown = document.getElementById("diag-breakdown");
const providerChipsEl = document.getElementById("provider-chips");
const recentActivityList = document.getElementById("recent-activity-list");
const recentEmptyEl = document.getElementById("recent-empty");

init().catch((error) => {
  setMessage(`Failed to initialize popup: ${error.message || "unknown error"}`);
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
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabUrl = activeTab?.url || "";
  const [summaryResponse, scanStateResponse] = await Promise.all([
    sendMessage({
      type: MESSAGE_TYPES.GET_POPUP_SUMMARY,
      tabUrl
    }),
    sendMessage({
      type: MESSAGE_TYPES.GET_SCAN_STATE
    })
  ]);

  popupState.activeTab = activeTab || null;
  popupState.summary = summaryResponse?.summary || {};
  popupState.summary.scanStatus = await getContentScanStatus(activeTab, popupState.summary);
  popupState.scanEnabled = scanStateResponse?.scanEnabled !== false;

renderProtectionState();
renderTabContext(popupState.activeTab, popupState.summary);
renderStats(popupState.summary);
renderDiagnostics(popupState.summary);
renderSessionSince(popupState.summary);
renderProviderChips(popupState.summary.providerSummary);
renderRecentActivity(popupState.summary.recentActivity);
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
function renderDiagnostics(summary) {
  const status = summary.scanStatus || {};

  setDiagnosticValue(diagNoUrl, status.skippedNoUrl);
  setDiagnosticValue(diagHidden, status.skippedHidden);
  setDiagnosticValue(diagActionArea, status.skippedActionArea);
  setDiagnosticValue(diagNoOwner, status.skippedNoOwningPost);
  setDiagnosticValue(diagInternalFacebook, status.skippedInternalFacebook);
  setDiagnosticValue(diagImageSource, status.skippedImageSource);
  setDiagnosticValue(diagGenericDomain, status.skippedGenericDomain);
  setDiagnosticValue(diagHeaderDomain, status.skippedHeaderDomain);
  setDiagnosticValue(diagNestedShared, status.skippedNestedSharedStory);

  setDiagnosticValue(diagAnalysisRequests, status.analysisRequestsSent);
  setDiagnosticValue(diagAnalysisResponses, status.analysisResponsesReceived);
  setDiagnosticValue(diagAnalysisMissing, status.analysisResponsesMissing);
  setDiagnosticValue(diagAnalysisRendered, status.analysisRenderedPanels);

  setDiagnosticValue(
    diagStaleSignature,
    Number(status.analysisStaleDiscardedBySignature || 0) +
      Number(status.analysisStaleDiscardedByRequestId || 0) +
      Number(status.analysisStaleDiscardedByMissingRequest || 0)
  );

  setDiagnosticValue(diagStaleFingerprint, status.analysisStaleDiscardedByFingerprint);
  setDiagnosticValue(diagStaleText, status.analysisStaleDiscardedByTextHash);
  setDiagnosticValue(diagStaleRescan, status.analysisStaleDiscardedByCurrentRescan);

  setDiagnosticValue(
    diagPanelRemoved,
    Number(status.panelRemovedNoLinkState || 0) +
      Number(status.panelRemovedCollapsedDeferred || 0)
  );

  setDiagnosticValue(
    diagPanelPreserved,
    Number(status.panelPreservedNoLinkRescan || 0) +
      Number(status.panelPreservedCollapsedRescan || 0)
  );

  setDiagnosticValue(diagHiddenDomain, status.hiddenDomainFallbackSkipped);

  setDiagnosticValue(diagMalformedCandidate, status.skippedMalformedCandidate);

  setDiagnosticValue(diagDirectCandidates, status.directCandidatesFound);
  setDiagnosticValue(diagEmbeddedCandidates, status.embeddedCandidatesFound);
  setDiagnosticValue(diagFallbackCandidates, status.fallbackCandidatesFound);
  setDiagnosticValue(diagVisibleDomain, status.visibleDomainCandidatesFound);

  setDiagnosticValue(diagPanelFallback, status.panelMountFallbackUsed);
  setDiagnosticValue(diagPanelRelocated, status.panelUnsafeRelocated);

  const breakdown = status.lastCandidateBreakdown;
  if (diagBreakdown) {
    if (breakdown && typeof breakdown === "object") {
      diagBreakdown.textContent =
        `Last candidates: direct ${Number(breakdown.direct || 0)}, ` +
        `embedded ${Number(breakdown.embedded || 0)}, ` +
        `sponsored ${Number(breakdown.sponsoredFallback || 0)}, ` +
        `visible-domain ${Number(breakdown.visibleDomainFallback || 0)}, ` +
        `total ${Number(breakdown.total || 0)}.`;
    } else {
      diagBreakdown.textContent = "No candidate breakdown yet.";
    }
  }

  const pipeline = status.lastAnalysisPipelineState;
  if (diagPipeline) {
    if (pipeline && typeof pipeline === "object") {
      const stage = String(pipeline.stage || "unknown");
      const reason = pipeline.reason ? ` · ${pipeline.reason}` : "";
      const postId = pipeline.postId ? ` · ${String(pipeline.postId).slice(0, 24)}${String(pipeline.postId).length > 24 ? "…" : ""}` : "";
      diagPipeline.textContent = `Pipeline: ${stage}${reason}${postId}`;
    } else {
      diagPipeline.textContent = "No pipeline state yet.";
    }
  }
}

function setDiagnosticValue(element, value) {
  if (!element) {
    return;
  }

  const number = Number(value || 0);
  element.textContent = String(Number.isFinite(number) ? number : 0);
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

  const order = ["config", "gsb", "urlhaus"];
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
    labelSpan.textContent = `${entry.label || key}:`;

    const textSpan = document.createElement("span");
    textSpan.textContent = String(entry.text || "—");

    chip.appendChild(labelSpan);
    chip.appendChild(textSpan);
    providerChipsEl.appendChild(chip);
  }
}

function sanitizeProviderStateClass(state) {
  if (state === "ready" || state === "public" || state === "off" || state === "error") {
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
    const classification = item.classification || "—";
    const score =
      item.safetyScore === null || item.safetyScore === undefined || item.safetyScore === ""
        ? "—"
        : String(item.safetyScore);
    title.textContent = `${domain} · ${classification} · score ${score}`;

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
      record.state || "",
      record.verificationState || "",
      record.interceptionRecommended ?? inferInterceptionRecommended(record),
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
  const features = record.features || {};
  const score = Number(record.safetyScore);
  const classification = String(record.classification || "").toLowerCase();
  const gsb = findProviderResult(record.providerResults, "gsb");
  const urlhaus = findProviderResult(record.providerResults, "urlhaus");

  if (gsb?.flagged || urlhaus?.flagged) {
    return true;
  }

  if (classification.includes("high risk") || classification.includes("suspicious")) {
    return true;
  }

  if (Number.isFinite(score) && score < 60) {
    return true;
  }

  if (features.integrityHashMismatch && Number.isFinite(score) && score < 75) {
    return true;
  }

  return false;
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
