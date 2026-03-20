import { calculateSafetyScore, classifySafetyScore } from "./riskEngine.js";
import { sha256Hex } from "./utils/hash.js";
import { analyzeRedirects } from "./utils/redirectAnalyzer.js";
import { analyzeUrlFeatures, normalizeUrl } from "./utils/urlAnalyzer.js";
import {
  appendAnalysisRecord,
  checkDomainPreviouslyFlagged,
  clearAnalysisRecords,
  getAllAnalysisRecords,
  getBaseline,
  markDomainFlagged,
  setBaseline,
  updatePostAnalysis
} from "./utils/storage.js";

const MESSAGE_TYPES = {
  ANALYZE_LINK: "DILI_ANALYZE_LINK",
  REANALYZE_LINK: "DILI_REANALYZE_LINK",
  GET_POST_STATE: "DILI_GET_POST_STATE",
  SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
  GET_POPUP_SUMMARY: "DILI_GET_POPUP_SUMMARY",
  GET_ANALYSIS_RECORDS: "DILI_GET_ANALYSIS_RECORDS",
  CLEAR_ANALYSIS_RECORDS: "DILI_CLEAR_ANALYSIS_RECORDS",
  RESCAN_CURRENT_TAB: "DILI_RESCAN_CURRENT_TAB",
  RESCAN_NOW: "DILI_RESCAN_NOW",
  POST_ANALYSIS_UPDATE: "DILI_POST_ANALYSIS_UPDATE"
};

const URL_FINAL_CACHE_TTL_MS = 10 * 60 * 1000;
const EXTERNAL_INFLIGHT_TTL_MS = 90 * 1000;

const sessionInfo = {
  startedAt: Date.now()
};

let cachedConfigPromise = null;
const finalAnalysisCache = new Map();
const inFlightExternalChecks = new Map();

chrome.runtime.onInstalled.addListener(() => {
  logDebug("Background service worker installed.");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse({ ok: true, ...result }))
    .catch((error) => {
      console.warn("[DILI] Background message error", error);
      sendResponse({
        ok: false,
        error: "Background request failed."
      });
    });

  return true;
});

async function handleMessage(message, sender) {
  switch (message?.type) {
    case MESSAGE_TYPES.GET_POST_STATE:
      return {
        type: MESSAGE_TYPES.GET_POST_STATE,
        baseline: await getBaseline(message.postId)
      };

    case MESSAGE_TYPES.SET_NO_LINK_STATE:
      return {
        type: MESSAGE_TYPES.SET_NO_LINK_STATE,
        baseline: await setNoLinkState(message)
      };

    case MESSAGE_TYPES.ANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.ANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          displayedText: message.displayedText,
          isReanalysis: false,
          tabId: sender?.tab?.id
        })
      };

    case MESSAGE_TYPES.REANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.REANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          displayedText: message.displayedText,
          isReanalysis: true,
          tabId: sender?.tab?.id
        })
      };

    case MESSAGE_TYPES.GET_POPUP_SUMMARY:
      return {
        type: MESSAGE_TYPES.GET_POPUP_SUMMARY,
        summary: await buildPopupSummary(message?.tabUrl || "")
      };

    case MESSAGE_TYPES.GET_ANALYSIS_RECORDS:
      return {
        type: MESSAGE_TYPES.GET_ANALYSIS_RECORDS,
        records: await getAllAnalysisRecords()
      };

    case MESSAGE_TYPES.CLEAR_ANALYSIS_RECORDS:
      await clearAnalysisRecords();
      logDebug("Analysis records cleared from storage.");
      return {
        type: MESSAGE_TYPES.CLEAR_ANALYSIS_RECORDS,
        cleared: true
      };

    case MESSAGE_TYPES.RESCAN_CURRENT_TAB:
      return {
        type: MESSAGE_TYPES.RESCAN_CURRENT_TAB,
        result: await triggerRescanForActiveTab()
      };

    default:
      throw new Error(`Unsupported message type: ${message?.type || "unknown"}`);
  }
}

async function setNoLinkState(message) {
  const baseline = await getBaseline(message.postId);

  return updatePostAnalysis(message.postId, {
    state: "no_link",
    classification: baseline?.classification || null,
    safetyScore: baseline?.safetyScore ?? null,
    features: baseline?.features || null,
    lastChecked: Date.now(),
    pendingExternal: false,
    reasons: baseline?.reasons || [],
    postId: message.postId
  });
}

async function performLinkAnalysis({ postId, rawUrl, displayedText, isReanalysis, tabId }) {
  let normalizedUrl;

  try {
    normalizedUrl = normalizeUrl(rawUrl);
  } catch {
    const failed = await updatePostAnalysis(postId, {
      postId,
      normalizedUrl: "",
      urlHash: "",
      classification: "Unknown",
      safetyScore: null,
      features: null,
      deductions: [],
      providerResults: [],
      redirectAnalysis: {
        redirectCount: 0,
        notes: ["Some checks could not be completed."],
        chain: [],
        resolvedUrl: "",
        resolutionMethod: "heuristic-only",
        fetchAttempted: false,
        fetchAllowed: false
      },
      urlFeatureAnalysis: null,
      reasons: ["This link could not be fully checked."],
      lastChecked: Date.now(),
      state: "analysis_failed",
      pendingExternal: false
    });

    return {
      ...failed,
      analysisMode: "failed-parse",
      reusedClassification: false
    };
  }

  const currentHash = await sha256Hex(normalizedUrl);
  const existingBaseline = await getBaseline(postId);

  if (
    isReanalysis &&
    existingBaseline?.urlHash &&
    existingBaseline.urlHash === currentHash &&
    existingBaseline.classification &&
    existingBaseline.pendingExternal !== true
  ) {
    const unchangedRecord = await updatePostAnalysis(postId, {
      state: existingBaseline.state || resolveStateFromClassification(existingBaseline.classification),
      lastChecked: Date.now()
    });

    logDebug(`Edit detection for ${postId}: hash unchanged, baseline reused.`);

    return {
      ...unchangedRecord,
      normalizedUrl,
      urlHash: currentHash,
      analysisMode: "reused-baseline",
      reusedClassification: true
    };
  }

  const domain = safeHostname(normalizedUrl);
  const domainPreviouslyFlagged = await checkDomainPreviouslyFlagged(domain);
  const urlFeatures = analyzeUrlFeatures({
    rawUrl: normalizedUrl,
    displayedText
  });
  const passiveRedirect = await analyzeRedirects(normalizedUrl, { allowNetworkProbe: false });

  const localFeatures = {
    googleSafeBrowsingFlagged: false,
    urlhausFlagged: false,
    domainPreviouslyFlagged,
    redirectCount: passiveRedirect.redirectCount,
    shortenedUrl: urlFeatures.shortenedUrl,
    obfuscatedUrl: urlFeatures.obfuscatedUrl,
    suspiciousTld: urlFeatures.suspiciousTld,
    textMismatch: urlFeatures.textMismatch,
    integrityHashMismatch: Boolean(isReanalysis && existingBaseline?.urlHash && existingBaseline.urlHash !== currentHash)
  };

  const localScoring = calculateSafetyScore(localFeatures);
  const localClassification = classifySafetyScore(localScoring.score);
  const localReasons = buildHumanReasons({
    deductions: localScoring.deductions,
    redirectAnalysis: passiveRedirect,
    includeExternalNote: true
  });

  const preliminaryRecord = {
    postId,
    normalizedUrl,
    urlHash: currentHash,
    classification: localClassification,
    safetyScore: localScoring.score,
    features: localFeatures,
    deductions: localScoring.deductions,
    providerResults: [createDefaultProviderResult("gsb"), createDefaultProviderResult("urlhaus")],
    redirectAnalysis: passiveRedirect,
    urlFeatureAnalysis: urlFeatures,
    reasons: localReasons,
    lastChecked: Date.now(),
    state: "analysis_partial",
    pendingExternal: true
  };

  const storedPreliminary = existingBaseline
    ? await updatePostAnalysis(postId, preliminaryRecord)
    : await setBaseline(postId, preliminaryRecord);

  const cachedFinal = readCachedFinal(normalizedUrl);
  if (cachedFinal) {
    const finalizedFromCache = await finalizeRecord({
      postId,
      currentHash,
      normalizedUrl,
      existingBaseline,
      urlFeatures,
      domain,
      isReanalysis,
      tabId,
      passiveRedirect,
      externalBundle: cachedFinal,
      sourceMode: "cache-final"
    });

    return finalizedFromCache;
  }

  void queueExternalFinalization({
    postId,
    currentHash,
    normalizedUrl,
    existingBaseline,
    urlFeatures,
    domain,
    isReanalysis,
    tabId,
    passiveRedirect
  });

  return {
    ...storedPreliminary,
    analysisMode: isReanalysis ? "reanalyzed-preliminary" : "baseline-preliminary",
    reusedClassification: false
  };
}

async function queueExternalFinalization(context) {
  try {
    const externalBundle = await getOrRunExternalChecks(context.normalizedUrl);
    await finalizeRecord({
      ...context,
      externalBundle,
      sourceMode: "finalized-external"
    });
  } catch (error) {
    console.debug("[DILI] External finalization failed", error);

    const fallback = {
      providerResults: [createDefaultProviderResult("gsb"), createDefaultProviderResult("urlhaus")],
      redirectAnalysis: {
        ...context.passiveRedirect,
        notes: mergeNotes(context.passiveRedirect.notes || [], ["Some external checks were unavailable."])
      }
    };

    await finalizeRecord({
      ...context,
      externalBundle: fallback,
      sourceMode: "finalized-fallback"
    });
  }
}

async function finalizeRecord({
  postId,
  currentHash,
  normalizedUrl,
  existingBaseline,
  urlFeatures,
  domain,
  isReanalysis,
  tabId,
  passiveRedirect,
  externalBundle,
  sourceMode
}) {
  const providerResults = externalBundle.providerResults || [createDefaultProviderResult("gsb"), createDefaultProviderResult("urlhaus")];
  const gsbResult = providerResults.find((item) => item.provider === "gsb") || createDefaultProviderResult("gsb");
  const urlhausResult = providerResults.find((item) => item.provider === "urlhaus") || createDefaultProviderResult("urlhaus");
  const redirectAnalysis = externalBundle.redirectAnalysis || passiveRedirect;

  const redirectCount = Math.max(Number(passiveRedirect?.redirectCount || 0), Number(redirectAnalysis?.redirectCount || 0));
  const features = {
    googleSafeBrowsingFlagged: gsbResult.flagged,
    urlhausFlagged: urlhausResult.flagged,
    domainPreviouslyFlagged: await checkDomainPreviouslyFlagged(domain),
    redirectCount,
    shortenedUrl: urlFeatures.shortenedUrl,
    obfuscatedUrl: urlFeatures.obfuscatedUrl,
    suspiciousTld: urlFeatures.suspiciousTld,
    textMismatch: urlFeatures.textMismatch,
    integrityHashMismatch: Boolean(isReanalysis && existingBaseline?.urlHash && existingBaseline.urlHash !== currentHash)
  };

  const scoring = calculateSafetyScore(features);
  const classification = classifySafetyScore(scoring.score);
  const providerDegraded = providerResults.some((item) => item.details?.status === "error");
  const reasons = buildHumanReasons({
    deductions: scoring.deductions,
    providerResults,
    redirectAnalysis,
    includeExternalNote: providerDegraded
  });

  const nextState = providerDegraded && classification === "Safe"
    ? "analysis_partial"
    : resolveStateFromClassification(classification);

  const record = {
    postId,
    normalizedUrl,
    urlHash: currentHash,
    classification,
    safetyScore: scoring.score,
    features,
    deductions: scoring.deductions,
    providerResults,
    redirectAnalysis,
    urlFeatureAnalysis: urlFeatures,
    reasons,
    lastChecked: Date.now(),
    state: nextState,
    pendingExternal: false
  };

  const storedRecord = existingBaseline
    ? await updatePostAnalysis(postId, record)
    : await setBaseline(postId, record);

  if (classification === "High Risk" || gsbResult.flagged || urlhausResult.flagged) {
    await markDomainFlagged(domain);
  }

  await appendAnalysisRecord({
    timestamp: Date.now(),
    postId,
    url: normalizedUrl,
    domain,
    urlHash: currentHash,
    safetyScore: scoring.score,
    classification,
    features,
    providerResults,
    state: nextState
  });

  writeCachedFinal(normalizedUrl, {
    providerResults,
    redirectAnalysis,
    cachedAt: Date.now()
  });

  if (tabId) {
    notifyContentUpdate(tabId, {
      type: MESSAGE_TYPES.POST_ANALYSIS_UPDATE,
      postId,
      analysis: {
        ...storedRecord,
        analysisMode: sourceMode,
        reusedClassification: false
      }
    });
  }

  logDebug(`Provider checks: gsb=${gsbResult.flagged} urlhaus=${urlhausResult.flagged}`);
  logDebug(`Scoring result for ${postId}: safety=${scoring.score} classification=${classification}`);

  return {
    ...storedRecord,
    analysisMode: sourceMode,
    reusedClassification: false
  };
}

function resolveStateFromClassification(classification) {
  if (classification === "High Risk") {
    return "high_risk";
  }

  if (classification === "Suspicious") {
    return "suspicious";
  }

  return "safe";
}

function buildHumanReasons({ deductions = [], providerResults = [], redirectAnalysis = null, includeExternalNote = false }) {
  const reasons = [];

  for (const item of deductions) {
    if (!item.triggered) {
      continue;
    }

    if (item.id === "shortenedUrl") {
      reasons.push("This link uses a URL shortener.");
    } else if (item.id === "suspiciousTld") {
      reasons.push("This link uses a top-level domain often abused in scams.");
    } else if (item.id === "integrityHashMismatch") {
      reasons.push("This link appears to have changed after earlier analysis.");
    } else if (item.id === "textMismatch") {
      reasons.push("The displayed text and destination domain do not match.");
    } else if (item.id === "googleSafeBrowsingFlagged") {
      reasons.push("Google Safe Browsing flagged this destination.");
    } else if (item.id === "urlhausFlagged") {
      reasons.push("URLhaus identified suspicious behavior for this link.");
    } else if (item.id === "redirectCount") {
      reasons.push("This link may redirect through multiple destinations.");
    } else if (item.id === "obfuscatedUrl") {
      reasons.push("This link contains obfuscation indicators.");
    }
  }

  const providerDegraded = providerResults.some((item) => item.details?.status === "error");
  if (includeExternalNote || providerDegraded) {
    reasons.push("Some checks could not be completed in the browser environment.");
  }

  if (Array.isArray(redirectAnalysis?.notes)) {
    for (const note of redirectAnalysis.notes) {
      if (/limited|unavailable/i.test(note)) {
        reasons.push("Redirect analysis was limited in the browser environment.");
        break;
      }
    }
  }

  if (reasons.length === 0) {
    reasons.push("No strong risk indicators were found for this link.");
  }

  return [...new Set(reasons)].slice(0, 4);
}

function mergeNotes(first, second) {
  return [...new Set([...(first || []), ...(second || [])])];
}

async function getOrRunExternalChecks(normalizedUrl) {
  const cached = readCachedFinal(normalizedUrl);
  if (cached) {
    return cached;
  }

  const inFlight = inFlightExternalChecks.get(normalizedUrl);
  if (inFlight && inFlight.expiresAt > Date.now()) {
    return inFlight.promise;
  }

  const promise = (async () => {
    const [providerResults, redirectAnalysis] = await Promise.all([
      runThreatIntelligenceChecks(normalizedUrl),
      analyzeRedirects(normalizedUrl, { allowNetworkProbe: true })
    ]);

    return {
      providerResults,
      redirectAnalysis
    };
  })();

  inFlightExternalChecks.set(normalizedUrl, {
    promise,
    expiresAt: Date.now() + EXTERNAL_INFLIGHT_TTL_MS
  });

  try {
    const result = await promise;
    writeCachedFinal(normalizedUrl, result);
    return result;
  } finally {
    inFlightExternalChecks.delete(normalizedUrl);
  }
}

function readCachedFinal(normalizedUrl) {
  const cached = finalAnalysisCache.get(normalizedUrl);
  if (!cached) {
    return null;
  }

  if (cached.expiresAt <= Date.now()) {
    finalAnalysisCache.delete(normalizedUrl);
    return null;
  }

  return cached.value;
}

function writeCachedFinal(normalizedUrl, value) {
  finalAnalysisCache.set(normalizedUrl, {
    value,
    expiresAt: Date.now() + URL_FINAL_CACHE_TTL_MS
  });
}

async function runThreatIntelligenceChecks(normalizedUrl) {
  const [gsb, urlhaus] = await Promise.all([
    lookupGoogleSafeBrowsing(normalizedUrl),
    lookupUrlhaus(normalizedUrl)
  ]);

  return [gsb, urlhaus];
}

async function lookupGoogleSafeBrowsing(normalizedUrl) {
  const config = await getRuntimeConfig();
  const key = String(config.GSB_API_KEY || "").trim();

  if (!key) {
    return {
      provider: "gsb",
      configured: false,
      checked: false,
      flagged: false,
      category: null,
      details: {
        status: "not-configured",
        message: "Safe Browsing key not configured."
      }
    };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`;
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "dili-extension",
          clientVersion: "1.1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: normalizedUrl }]
        }
      })
    });

    if (!response.ok) {
      return {
        provider: "gsb",
        configured: true,
        checked: true,
        flagged: false,
        category: null,
        details: {
          status: "error",
          httpStatus: response.status,
          message: "Some external checks were unavailable."
        }
      };
    }

    const payload = await response.json();
    const matches = Array.isArray(payload.matches) ? payload.matches : [];
    const category = matches[0]?.threatType || null;

    return {
      provider: "gsb",
      configured: true,
      checked: true,
      flagged: matches.length > 0,
      category,
      details: {
        status: "checked",
        matchesCount: matches.length
      }
    };
  } catch {
    return {
      provider: "gsb",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        message: "Some external checks were unavailable."
      }
    };
  }
}

async function lookupUrlhaus(normalizedUrl) {
  const config = await getRuntimeConfig();
  const authKey = String(config.URLHAUS_AUTH_KEY || "").trim();

  if (!authKey) {
    return {
      provider: "urlhaus",
      configured: false,
      checked: false,
      flagged: false,
      category: null,
      details: {
        status: "not-configured",
        message: "URLhaus auth key not configured.",
        authConfigured: false
      }
    };
  }

  return performUrlhausLookup(normalizedUrl, authKey);
}

async function performUrlhausLookup(normalizedUrl, authKey) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Auth-Key": authKey
  };

  try {
    const body = new URLSearchParams({ url: normalizedUrl });

    const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers,
      body: body.toString()
    });

    if (!response.ok) {
      return {
        provider: "urlhaus",
        configured: true,
        checked: true,
        flagged: false,
        category: null,
        details: {
          status: "error",
          httpStatus: response.status,
          message: "Some external checks were unavailable.",
          authConfigured: true
        }
      };
    }

    const payload = await parseJsonSafe(response);
    if (!payload) {
      return {
        provider: "urlhaus",
        configured: true,
        checked: true,
        flagged: false,
        category: null,
        details: {
          status: "error",
          message: "Some external checks were unavailable.",
          authConfigured: true,
          parseError: "invalid-json"
        }
      };
    }

    const status = String(payload.query_status || "").toLowerCase();
    const flagged = status === "ok" || status === "online";
    const category = payload.threat || payload.tags?.[0] || "malware-oriented";

    return {
      provider: "urlhaus",
      configured: true,
      checked: true,
      flagged,
      category: flagged ? String(category) : null,
      details: {
        status: "checked",
        queryStatus: payload.query_status || null,
        authConfigured: true
      }
    };
  } catch {
    return {
      provider: "urlhaus",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        message: "Some external checks were unavailable.",
        authConfigured: true
      }
    };
  }
}

async function buildPopupSummary(tabUrl) {
  const [records, config] = await Promise.all([getAllAnalysisRecords(), getRuntimeConfig()]);
  const providerStatus = computeProviderStatus(config);
  const isSupportedTab = isSupportedFacebookUrl(tabUrl);
  const sessionRecords = records.filter((record) => Number(record.timestamp || 0) >= sessionInfo.startedAt);
  const analyzedPostsInSession = new Set(sessionRecords.map((record) => record.postId).filter(Boolean)).size;
  const flaggedPostsInSession = new Set(
    sessionRecords
      .filter((record) => record.classification === "Suspicious" || record.classification === "High Risk")
      .map((record) => record.postId)
      .filter(Boolean)
  ).size;

  return {
    tabSupported: isSupportedTab,
    analyzedPostsInSession,
    flaggedPostsInSession,
    totalStoredAnalyses: records.length,
    providerStatus,
    recentActivity: records
      .slice(-10)
      .reverse()
      .map((record) => ({
        timestamp: record.timestamp,
        postId: record.postId,
        domain: record.domain,
        safetyScore: record.safetyScore,
        classification: record.classification,
        state: record.state
      }))
  };
}

async function triggerRescanForActiveTab() {
  const [activeTab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!activeTab?.id) {
    return {
      success: false,
      message: "No active tab available for re-scan."
    };
  }

  if (!isSupportedFacebookUrl(activeTab.url || "")) {
    return {
      success: false,
      message: "Active tab is not a supported Facebook page."
    };
  }

  try {
    await chrome.tabs.sendMessage(activeTab.id, {
      type: MESSAGE_TYPES.RESCAN_NOW
    });

    return {
      success: true,
      message: "Re-scan command sent to the active Facebook tab."
    };
  } catch {
    return {
      success: false,
      message: "Failed to send re-scan message to content script."
    };
  }
}

function notifyContentUpdate(tabId, payload) {
  chrome.tabs.sendMessage(tabId, payload).catch(() => {
    // Tab may no longer have an active content script.
  });
}

async function getRuntimeConfig() {
  if (cachedConfigPromise) {
    return cachedConfigPromise;
  }

  cachedConfigPromise = (async () => {
    const fallback = {
      GSB_API_KEY: "",
      URLHAUS_AUTH_KEY: ""
    };

    try {
      const module = await import(chrome.runtime.getURL("config.local.js"));
      const config = {
        ...fallback,
        GSB_API_KEY: String(module.GSB_API_KEY || ""),
        URLHAUS_AUTH_KEY: String(module.URLHAUS_AUTH_KEY || "")
      };

      logProviderKeyPresence(config);
      return config;
    } catch {
      logProviderKeyPresence(fallback);
      return fallback;
    }
  })();

  return cachedConfigPromise;
}

function createDefaultProviderResult(provider) {
  return {
    provider,
    configured: false,
    checked: false,
    flagged: false,
    category: null,
    details: {
      status: "not-configured",
      message: "Provider lookup pending or unavailable."
    }
  };
}

function computeProviderStatus(config) {
  const gsbConfigured = Boolean(String(config.GSB_API_KEY || "").trim());
  const urlhausConfigured = Boolean(String(config.URLHAUS_AUTH_KEY || "").trim());

  return {
    gsbConfigured,
    urlhausConfigured,
    urlhausAuthConfigured: urlhausConfigured
  };
}

function logProviderKeyPresence(config) {
  const hasGsbKey = Boolean(String(config.GSB_API_KEY || "").trim());
  const hasUrlhausKey = Boolean(String(config.URLHAUS_AUTH_KEY || "").trim());

  logDebug(`Config detected: GSB_API_KEY=${hasGsbKey ? "present" : "missing"}`);
  logDebug(`Config detected: URLHAUS_AUTH_KEY=${hasUrlhausKey ? "present" : "missing"}`);
}

async function parseJsonSafe(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function isSupportedFacebookUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol.startsWith("http") && parsed.hostname.includes("facebook.com");
  } catch {
    return false;
  }
}

function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function logDebug(message) {
  console.debug(`[DILI] ${message}`);
}
