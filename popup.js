const MESSAGE_TYPES = {
  GET_POPUP_SUMMARY: "DILI_GET_POPUP_SUMMARY",
  GET_SCAN_STATE: "DILI_GET_SCAN_STATE",
  SET_SCAN_STATE: "DILI_SET_SCAN_STATE",
  GET_ANALYSIS_RECORDS: "DILI_GET_ANALYSIS_RECORDS",
  CLEAR_ANALYSIS_RECORDS: "DILI_CLEAR_ANALYSIS_RECORDS",
  RESET_SESSION: "DILI_RESET_SESSION",
  RESCAN_CURRENT_TAB: "DILI_RESCAN_CURRENT_TAB"
};

const popupState = {
  activeTab: null,
  summary: {},
  scanEnabled: true
};

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
const statScannedPosts = document.getElementById("stat-scanned-posts");
const statAnalyzedPosts = document.getElementById("stat-analyzed-posts");

init().catch((error) => {
  setMessage(`Failed to initialize popup: ${error.message || "unknown error"}`);
});

async function init() {
  bindActions();
  await refreshPopupData();
}

function bindActions() {
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

      if (popupState.summary?.tabSupported && popupState.activeTab?.id) {
        await chrome.tabs.reload(popupState.activeTab.id);
      }

      setMessage(
        popupState.scanEnabled
          ? "Protection turned on. Current page refreshed."
          : "Protection turned off. Current page refreshed."
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
  popupState.scanEnabled = scanStateResponse?.scanEnabled !== false;

  renderProtectionState();
  renderStats(popupState.summary);
}

function renderProtectionState() {
  powerToggleButton.classList.toggle("power-toggle-on", popupState.scanEnabled);
  powerToggleButton.classList.toggle("power-toggle-off", !popupState.scanEnabled);
  powerToggleButton.setAttribute("aria-pressed", String(popupState.scanEnabled));
  powerStatus.textContent = popupState.scanEnabled ? "Protection On" : "Protection Off";
  dashboardShell.classList.toggle("protection-off", !popupState.scanEnabled);
}

function renderStats(summary) {
  statScannedPosts.textContent = String(summary.postsScannedInSession ?? summary.scannedPostsInSession ?? 0);
  statAnalyzedPosts.textContent = String(summary.postsAnalyzedInSession ?? summary.analyzedLinksInSession ?? 0);
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
