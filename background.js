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
  RESCAN_NOW: "DILI_RESCAN_NOW"
};

const sessionInfo = {
  startedAt: Date.now()
};

let cachedConfigPromise = null;

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
        error: error.message || "Unknown background error."
      });
    });

  return true;
});

async function handleMessage(message) {
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
          isReanalysis: false
        })
      };

    case MESSAGE_TYPES.REANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.REANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          displayedText: message.displayedText,
          isReanalysis: true
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
  const state = baseline?.urlHash ? "monitored" : "no_link";

  return updatePostAnalysis(message.postId, {
    state,
    classification: baseline?.classification || null,
    safetyScore: baseline?.safetyScore ?? null,
    features: baseline?.features || null,
    lastChecked: Date.now(),
    postId: message.postId
  });
}

async function performLinkAnalysis({ postId, rawUrl, displayedText, isReanalysis }) {
  const normalizedUrl = normalizeUrl(rawUrl);
  const currentHash = await sha256Hex(normalizedUrl);
  const existingBaseline = await getBaseline(postId);

  if (
    isReanalysis &&
    existingBaseline?.urlHash &&
    existingBaseline.urlHash === currentHash &&
    existingBaseline.classification
  ) {
    const unchangedRecord = await updatePostAnalysis(postId, {
      state: "monitored",
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

  const urlFeatures = analyzeUrlFeatures({
    rawUrl: normalizedUrl,
    displayedText
  });
  const redirectAnalysis = await analyzeRedirects(normalizedUrl);
  const domain = safeHostname(normalizedUrl);
  const domainPreviouslyFlagged = await checkDomainPreviouslyFlagged(domain);
  const providerResults = await runThreatIntelligenceChecks(normalizedUrl);
  const gsbResult = providerResults.find((item) => item.provider === "gsb") || createDefaultProviderResult("gsb");
  const urlhausResult = providerResults.find((item) => item.provider === "urlhaus") || createDefaultProviderResult("urlhaus");

  const features = {
    googleSafeBrowsingFlagged: gsbResult.flagged,
    urlhausFlagged: urlhausResult.flagged,
    domainPreviouslyFlagged,
    redirectCount: redirectAnalysis.redirectCount,
    shortenedUrl: urlFeatures.shortenedUrl,
    obfuscatedUrl: urlFeatures.obfuscatedUrl,
    suspiciousTld: urlFeatures.suspiciousTld,
    textMismatch: urlFeatures.textMismatch,
    integrityHashMismatch: Boolean(isReanalysis && existingBaseline?.urlHash && existingBaseline.urlHash !== currentHash)
  };

  const scoring = calculateSafetyScore(features);
  const classification = classifySafetyScore(scoring.score);
  const nextState = features.integrityHashMismatch ? "changed" : "monitored";
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
    lastChecked: Date.now(),
    state: nextState
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

  if (features.integrityHashMismatch) {
    logDebug(`Edit detection for ${postId}: integrity hash changed.`);
  }

  logDebug(`Provider checks: gsb=${gsbResult.flagged} urlhaus=${urlhausResult.flagged}`);
  logDebug(`Scoring result for ${postId}: safety=${scoring.score} classification=${classification}`);

  return {
    ...storedRecord,
    analysisMode: isReanalysis ? "reanalyzed" : "baseline-created",
    reusedClassification: false
  };
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
        message: "GSB_API_KEY is missing in config.local.js."
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
          message: "Safe Browsing lookup returned non-OK status."
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
        matchesCount: matches.length,
        matches
      }
    };
  } catch (error) {
    return {
      provider: "gsb",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        message: error.message || "Unknown Safe Browsing error."
      }
    };
  }
}

async function lookupUrlhaus(normalizedUrl) {
  const config = await getRuntimeConfig();
  const optionalAuth = String(config.URLHAUS_AUTH_TOKEN || config.URLHAUS_API_KEY || "").trim();
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  if (optionalAuth) {
    headers.Authorization = `Bearer ${optionalAuth}`;
  }

  try {
    const body = new URLSearchParams({
      url: normalizedUrl
    });

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
          message: "URLhaus lookup returned non-OK status.",
          authConfigured: Boolean(optionalAuth)
        }
      };
    }

    const payload = await response.json();
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
        source: payload.urlhaus_reference || payload.reporter || null,
        authConfigured: Boolean(optionalAuth),
        payload
      }
    };
  } catch (error) {
    return {
      provider: "urlhaus",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        message: error.message || "Unknown URLhaus lookup error.",
        authConfigured: Boolean(optionalAuth)
      }
    };
  }
}

async function buildPopupSummary(tabUrl) {
  const [records, config] = await Promise.all([
    getAllAnalysisRecords(),
    getRuntimeConfig()
  ]);
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
    providerStatus: {
      gsbConfigured: Boolean(String(config.GSB_API_KEY || "").trim()),
      urlhausConfigured: true,
      urlhausAuthConfigured: Boolean(String(config.URLHAUS_AUTH_TOKEN || config.URLHAUS_API_KEY || "").trim())
    },
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
  } catch (error) {
    return {
      success: false,
      message: error.message || "Failed to send re-scan message to content script."
    };
  }
}

async function getRuntimeConfig() {
  if (cachedConfigPromise) {
    return cachedConfigPromise;
  }

  cachedConfigPromise = (async () => {
    const fallback = {
      GSB_API_KEY: "",
      URLHAUS_API_KEY: "",
      URLHAUS_AUTH_TOKEN: ""
    };

    try {
      const module = await import(chrome.runtime.getURL("config.local.js"));
      return {
        ...fallback,
        GSB_API_KEY: String(module.GSB_API_KEY || ""),
        URLHAUS_API_KEY: String(module.URLHAUS_API_KEY || ""),
        URLHAUS_AUTH_TOKEN: String(module.URLHAUS_AUTH_TOKEN || "")
      };
    } catch {
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
      message: "Provider fallback result."
    }
  };
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
