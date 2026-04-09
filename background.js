import { GSB_API_KEY, URLHAUS_AUTH_KEY } from "./config.local.js";
import { calculateSafetyScore, classifySafetyScore } from "./riskEngine.js";
import { sha256Hex } from "./utils/hash.js";
import { analyzeRedirects } from "./utils/redirectAnalyzer.js";
import { analyzeUrlFeatures, detectDomainMismatch, getRegistrableDomain, normalizeUrl } from "./utils/urlAnalyzer.js";
import {
  appendAnalysisRecord,
  checkDomainPreviouslyFlagged,
  clearAnalysisRecords,
  getAllAnalysisRecords,
  getBaseline,
  getScanEnabledState,
  markDomainFlagged,
  setScanEnabledState,
  setBaseline,
  updatePostAnalysis
} from "./utils/storage.js";

const CONFIG_FILE_NAME = "config.local.js";

const MESSAGE_TYPES = {
  ANALYZE_LINK: "DILI_ANALYZE_LINK",
  REANALYZE_LINK: "DILI_REANALYZE_LINK",
  GET_POST_STATE: "DILI_GET_POST_STATE",
  SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
  GET_SCAN_STATE: "DILI_GET_SCAN_STATE",
  SET_SCAN_STATE: "DILI_SET_SCAN_STATE",
  GET_POPUP_SUMMARY: "DILI_GET_POPUP_SUMMARY",
  GET_PROVIDER_HEALTH: "DILI_GET_PROVIDER_HEALTH",
  GET_ANALYSIS_RECORDS: "DILI_GET_ANALYSIS_RECORDS",
  CLEAR_ANALYSIS_RECORDS: "DILI_CLEAR_ANALYSIS_RECORDS",
  RESET_SESSION: "DILI_RESET_SESSION",
  RESCAN_CURRENT_TAB: "DILI_RESCAN_CURRENT_TAB",
  RESCAN_NOW: "DILI_RESCAN_NOW"
};

const providerHealth = createInitialProviderHealth();
const runtimeConfig = createRuntimeConfig();
const CURRENT_ANALYSIS_SCHEMA_VERSION = 3;
const SESSION_TTL_MS = 60 * 60 * 1000;
const URL_ANALYSIS_CACHE_TTL_MS = 10 * 60 * 1000;
const urlAnalysisCache = new Map();
const sessionInfo = createSessionState();

applyConfigDiagnostics(runtimeConfig);
bindSessionLifecycleObservers();

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

    case MESSAGE_TYPES.GET_SCAN_STATE:
      return {
        type: MESSAGE_TYPES.GET_SCAN_STATE,
        scanEnabled: await getScanEnabledState()
      };

    case MESSAGE_TYPES.SET_SCAN_STATE:
      return {
        type: MESSAGE_TYPES.SET_SCAN_STATE,
        scanEnabled: await setScanEnabledState(message?.enabled !== false)
      };

    case MESSAGE_TYPES.ANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.ANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          displayedText: message.displayedText,
          candidateContext: message.candidateContext,
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
          candidateContext: message.candidateContext,
          isReanalysis: true
        })
      };

    case MESSAGE_TYPES.GET_POPUP_SUMMARY:
      return {
        type: MESSAGE_TYPES.GET_POPUP_SUMMARY,
        summary: await buildPopupSummary(message?.tabUrl || "")
      };

    case MESSAGE_TYPES.GET_PROVIDER_HEALTH:
      await getRuntimeConfig();
      return {
        type: MESSAGE_TYPES.GET_PROVIDER_HEALTH,
        providerHealth: getProviderHealthSnapshot()
      };

    case MESSAGE_TYPES.GET_ANALYSIS_RECORDS:
      await ensureActiveSession("popup-records");
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

    case MESSAGE_TYPES.RESET_SESSION:
      return {
        type: MESSAGE_TYPES.RESET_SESSION,
        result: await restartSession()
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

async function performLinkAnalysis({ postId, rawUrl, displayedText, candidateContext, isReanalysis }) {
  if (!(await getScanEnabledState())) {
    throw new Error("Scanning is currently disabled.");
  }

  await ensureActiveSession("analysis");

  const urlFeatures = analyzeUrlFeatures({
    rawUrl
  });
  const normalizedUrl = urlFeatures.normalizedUrl;
  const existingBaseline = await getBaseline(postId);
  const compatibleBaseline = getCompatibleBaseline(existingBaseline);

  if (existingBaseline && !compatibleBaseline) {
    logDebug(`Legacy baseline detected for ${postId}; integrity comparison skipped for this scan.`);
  }

  const reusableUrlAnalysis = await getReusableUrlAnalysis(rawUrl, urlFeatures);
  const analysisUrl = reusableUrlAnalysis.analysisUrl;
  const redirectAnalysis = reusableUrlAnalysis.redirectAnalysis;
  const providerResults = reusableUrlAnalysis.providerResults;
  const domain = reusableUrlAnalysis.domain || safeHostname(analysisUrl || normalizedUrl);
  const normalizedCandidateContext = buildCandidateContext(candidateContext, {
    analysisUrl,
    normalizedUrl,
    domain
  });
  const currentHash = await sha256Hex(buildStableUrlHashInput({
    analysisUrl,
    normalizedUrl
  }));
  const textComparison = detectDomainMismatch(displayedText || "", analysisUrl);
  const domainPreviouslyFlagged = await checkDomainPreviouslyFlagged(domain);
  const gsbResult = providerResults.find((item) => item.provider === "gsb") || createDefaultProviderResult("gsb");
  const urlhausResult = providerResults.find((item) => item.provider === "urlhaus") || createDefaultProviderResult("urlhaus");
  const postContextFeatures = {
    domainPreviouslyFlagged,
    textMismatch: textComparison.mismatch,
    integrityHashMismatch: Boolean(isReanalysis && hasCompatibleIntegrityMismatch(compatibleBaseline, {
      currentHash,
      analysisUrl,
      normalizedUrl,
      candidateContext: normalizedCandidateContext
    }))
  };
  const enrichedUrlFeatures = {
    ...reusableUrlAnalysis.urlFeatureAnalysis,
    finalAnalysisUrl: analysisUrl,
    finalDomain: domain,
    displayDomain: textComparison.displayDomain,
    actualDomain: textComparison.actualDomain,
    displayTextLooksLikeDomain: textComparison.displayTextLooksLikeDomain,
    genericDisplayText: textComparison.genericText,
    textMismatch: postContextFeatures.textMismatch,
    wrapperToExternalDestination: Boolean(reusableUrlAnalysis.urlFeatureAnalysis.wrapperToExternalDestination || redirectAnalysis.wrapperToExternalDestination)
  };
  const urlLevelFeaturesBase = {
    ...reusableUrlAnalysis.urlLevelFeatures,
    wrapperToExternalDestination: enrichedUrlFeatures.wrapperToExternalDestination
  };
  const urlLevelFeatures = {
    ...urlLevelFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(urlLevelFeaturesBase)
  };
  const combinedFeaturesBase = {
    ...urlLevelFeatures,
    ...postContextFeatures
  };
  const features = {
    ...combinedFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(combinedFeaturesBase)
  };
  const urlLevelScoring = calculateSafetyScore(urlLevelFeatures);
  const urlLevelClassification = classifySafetyScore(urlLevelScoring.score);
  const scoring = calculateSafetyScore(features);
  const classification = classifySafetyScore(scoring.score);
  const nextState = features.integrityHashMismatch ? "changed" : "monitored";
  const record = {
    postId,
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    normalizedUrl,
    analysisUrl,
    rawUrl,
    urlHash: currentHash,
    candidateMode: normalizedCandidateContext.candidateMode,
    dominantDomain: normalizedCandidateContext.dominantDomain,
    candidateDomainCount: normalizedCandidateContext.candidateDomainCount,
    selectedNormalizedTarget: normalizedCandidateContext.selectedNormalizedTarget,
    candidateContext: normalizedCandidateContext,
    classification,
    safetyScore: scoring.score,
    features,
    deductions: scoring.deductions,
    providerResults,
    redirectAnalysis,
    urlFeatureAnalysis: enrichedUrlFeatures,
    lastChecked: Date.now(),
    state: nextState
  };

  const storedRecord = existingBaseline
    ? await updatePostAnalysis(postId, record)
    : await setBaseline(postId, record);

  if (urlLevelClassification === "High Risk" || gsbResult.flagged || urlhausResult.flagged) {
    await markDomainFlagged(domain);
  }

  await appendAnalysisRecord({
    timestamp: Date.now(),
    postId,
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    url: analysisUrl,
    originalUrl: normalizedUrl,
    domain,
    urlHash: currentHash,
    safetyScore: scoring.score,
    classification,
    features,
    providerResults,
    state: nextState
  });

  sessionInfo.lastActivityAt = Date.now();

  if (features.integrityHashMismatch) {
    logDebug(`Edit detection for ${postId}: integrity hash changed.`);
  }

  logDebug(`URL analysis reused=${reusableUrlAnalysis.cacheHit} analysisUrl=${analysisUrl}`);
  logDebug(`Provider checks: gsb=${gsbResult.flagged} urlhaus=${urlhausResult.flagged}`);
  logDebug(`Scoring result for ${postId}: safety=${scoring.score} classification=${classification}`);

  return {
    ...storedRecord,
    analysisMode: isReanalysis ? (compatibleBaseline ? "reanalyzed" : "legacy-baseline-refresh") : "baseline-created",
    reusedClassification: false
  };
}

function resolveAnalysisUrl(urlFeatures, redirectAnalysis) {
  const candidates = [
    redirectAnalysis?.resolvedUrl,
    urlFeatures?.unwrappedUrl,
    urlFeatures?.normalizedUrl
  ];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    try {
      return normalizeUrl(candidate);
    } catch {
      continue;
    }
  }

  throw new Error("Unable to resolve a stable analysis URL.");
}

function getCompatibleBaseline(existingBaseline) {
  if (!existingBaseline || Number(existingBaseline.analysisSchemaVersion || 0) !== CURRENT_ANALYSIS_SCHEMA_VERSION) {
    return null;
  }

  return existingBaseline;
}

function hasCompatibleIntegrityMismatch(existingBaseline, currentAnalysis) {
  if (!existingBaseline?.urlHash) {
    return false;
  }

  const baselineCandidateContext = buildCandidateContext(existingBaseline.candidateContext || existingBaseline, existingBaseline);
  const currentCandidateContext = buildCandidateContext(currentAnalysis.candidateContext, currentAnalysis);

  if (!isStableSingleTargetCandidateMode(baselineCandidateContext) || !isStableSingleTargetCandidateMode(currentCandidateContext)) {
    return hasMeaningfulCandidateDestinationChange(baselineCandidateContext, currentCandidateContext);
  }

  if (
    baselineCandidateContext.selectedNormalizedTarget &&
    currentCandidateContext.selectedNormalizedTarget &&
    baselineCandidateContext.selectedNormalizedTarget === currentCandidateContext.selectedNormalizedTarget
  ) {
    return false;
  }

  const baselineTarget = buildStableUrlHashInput({
    analysisUrl: existingBaseline.analysisUrl,
    normalizedUrl: existingBaseline.normalizedUrl
  });
  const currentTarget = buildStableUrlHashInput(currentAnalysis);

  if (baselineTarget && currentTarget && baselineTarget === currentTarget) {
    return false;
  }

  return existingBaseline.urlHash !== currentAnalysis.currentHash;
}

function buildCandidateContext(candidateContext = {}, fallback = {}) {
  const selectedNormalizedTarget = normalizeComparableCandidateTarget(
    candidateContext.selectedNormalizedTarget ||
    fallback.selectedNormalizedTarget ||
    fallback.analysisUrl ||
    fallback.normalizedUrl
  );
  const dominantDomain = normalizeCandidateDomain(
    candidateContext.dominantDomain ||
    fallback.dominantDomain ||
    getRegistrableDomain(fallback.domain || safeHostname(selectedNormalizedTarget || fallback.analysisUrl || fallback.normalizedUrl))
  );
  const candidateDomainCount = Math.max(1, Number(candidateContext.candidateDomainCount || fallback.candidateDomainCount || (dominantDomain ? 1 : 0)));
  const candidateMode = normalizeCandidateMode(
    candidateContext.candidateMode ||
    fallback.candidateMode,
    candidateDomainCount
  );

  return {
    candidateMode,
    dominantDomain,
    candidateDomainCount,
    selectedNormalizedTarget
  };
}

function normalizeComparableCandidateTarget(candidate) {
  if (!candidate) {
    return "";
  }

  try {
    return normalizeUrl(candidate);
  } catch {
    return String(candidate || "").trim();
  }
}

function normalizeCandidateDomain(domain) {
  return String(domain || "").toLowerCase().trim();
}

function normalizeCandidateMode(mode, candidateDomainCount = 1) {
  const normalizedMode = String(mode || "").toLowerCase().trim();
  if (["single", "multi-same-domain", "multi-mixed"].includes(normalizedMode)) {
    return normalizedMode;
  }

  return Number(candidateDomainCount || 0) > 1 ? "multi-mixed" : "single";
}

function isStableSingleTargetCandidateMode(candidateContext) {
  return candidateContext?.candidateMode === "single";
}

function hasMeaningfulCandidateDestinationChange(baselineCandidateContext, currentCandidateContext) {
  if (!baselineCandidateContext || !currentCandidateContext) {
    return false;
  }

  if (
    baselineCandidateContext.dominantDomain &&
    currentCandidateContext.dominantDomain &&
    baselineCandidateContext.dominantDomain === currentCandidateContext.dominantDomain
  ) {
    return false;
  }

  if (
    baselineCandidateContext.selectedNormalizedTarget &&
    currentCandidateContext.selectedNormalizedTarget &&
    baselineCandidateContext.selectedNormalizedTarget === currentCandidateContext.selectedNormalizedTarget
  ) {
    return false;
  }

  return Boolean(
    baselineCandidateContext.dominantDomain &&
    currentCandidateContext.dominantDomain &&
    baselineCandidateContext.dominantDomain !== currentCandidateContext.dominantDomain
  );
}

function buildStableUrlHashInput({ analysisUrl, normalizedUrl }) {
  const candidates = [analysisUrl, normalizedUrl];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    try {
      return normalizeUrl(candidate);
    } catch {
      continue;
    }
  }

  return String(analysisUrl || normalizedUrl || "").trim();
}

async function getReusableUrlAnalysis(rawUrl, urlFeatures) {
  pruneUrlAnalysisCache();

  const initialCacheKeys = buildUrlAnalysisCacheKeys(urlFeatures);
  for (const cacheKey of initialCacheKeys) {
    const cachedEntry = getUrlAnalysisCacheEntry(cacheKey);
    if (!cachedEntry) {
      continue;
    }

    logDebug(`URL analysis cache hit: ${cacheKey}`);
    logDebug(`Reused cached redirect/provider analysis for ${cachedEntry.analysisUrl}`);

    const aliasKeys = buildUrlAnalysisCacheKeys(urlFeatures, cachedEntry.analysisUrl);
    setUrlAnalysisCacheEntry(aliasKeys, stripUrlAnalysisCacheMetadata(cachedEntry), cachedEntry.cachedAt);

    return {
      ...cachedEntry,
      cacheHit: true,
      cacheKey
    };
  }

  const cacheMissKey = initialCacheKeys[0] || normalizeCacheKey(rawUrl) || "unknown-url";
  logDebug(`URL analysis cache miss: ${cacheMissKey}`);

  const redirectAnalysis = await analyzeRedirects(rawUrl);
  const analysisUrl = resolveAnalysisUrl(urlFeatures, redirectAnalysis);
  const domain = safeHostname(analysisUrl || urlFeatures.normalizedUrl);
  const analysisUrlFeatures = analyzeUrlFeatures({
    rawUrl: analysisUrl
  });
  const providerResults = await runThreatIntelligenceChecks(analysisUrl);
  const stableUrlFeatureAnalysis = {
    ...analysisUrlFeatures,
    sourceNormalizedUrl: urlFeatures.normalizedUrl,
    sourceUnwrappedUrl: urlFeatures.unwrappedUrl,
    sourceRawComparableUrl: urlFeatures.rawComparableUrl,
    finalAnalysisUrl: analysisUrl,
    finalDomain: domain,
    shortenedUrl: Boolean(urlFeatures.shortenedUrl || analysisUrlFeatures.shortenedUrl),
    usesKnownWrapper: Boolean(urlFeatures.usesKnownWrapper),
    wrapperChain: urlFeatures.wrapperChain,
    wrapperHosts: urlFeatures.wrapperHosts,
    wrapperToExternalDestination: Boolean(urlFeatures.wrapperToExternalDestination || redirectAnalysis.wrapperToExternalDestination)
  };
  const urlLevelFeatures = buildUrlLevelFeatures({
    redirectAnalysis,
    providerResults,
    urlFeatureAnalysis: stableUrlFeatureAnalysis
  });
  const cacheEntry = {
    analysisUrl,
    domain,
    redirectAnalysis,
    providerResults,
    urlFeatureAnalysis: stableUrlFeatureAnalysis,
    urlLevelFeatures
  };

  setUrlAnalysisCacheEntry(buildUrlAnalysisCacheKeys(urlFeatures, analysisUrl), cacheEntry);

  return {
    ...getUrlAnalysisCacheEntry(analysisUrl),
    cacheHit: false,
    cacheKey: analysisUrl
  };
}

function buildUrlLevelFeatures({ redirectAnalysis, providerResults, urlFeatureAnalysis }) {
  const gsbResult = providerResults.find((item) => item.provider === "gsb") || createDefaultProviderResult("gsb");
  const urlhausResult = providerResults.find((item) => item.provider === "urlhaus") || createDefaultProviderResult("urlhaus");

  const baseFeatures = {
    googleSafeBrowsingFlagged: gsbResult.flagged,
    urlhausFlagged: urlhausResult.flagged,
    domainPreviouslyFlagged: false,
    redirectCount: redirectAnalysis.redirectCount,
    multipleRedirects: redirectAnalysis.multipleRedirects,
    crossDomainRedirectChain: redirectAnalysis.crossDomainRedirectChain,
    redirectChainToDifferentRegistrantLikeTarget: redirectAnalysis.redirectChainToDifferentRegistrantLikeTarget,
    wrapperToExternalDestination: Boolean(urlFeatureAnalysis.wrapperToExternalDestination),
    suspiciousRedirectPattern: redirectAnalysis.suspiciousPattern,
    trackingHopToUnrelatedDomain: redirectAnalysis.trackingHopToUnrelatedDomain,
    shortenerToUnrelatedDomain: redirectAnalysis.shortenerToUnrelatedDomain,
    shortenedUrl: urlFeatureAnalysis.shortenedUrl,
    obfuscatedUrl: urlFeatureAnalysis.obfuscatedUrl,
    suspiciousTld: urlFeatureAnalysis.suspiciousTld,
    textMismatch: false,
    excessiveQueryComplexity: urlFeatureAnalysis.excessiveQueryComplexity,
    suspiciousPath: urlFeatureAnalysis.suspiciousPath,
    excessiveSubdomainDepth: urlFeatureAnalysis.excessiveSubdomainDepth,
    usernamePasswordTrick: urlFeatureAnalysis.usernamePasswordTrick,
    trustedEndpoint: Boolean(urlFeatureAnalysis.trustedEndpoint),
    httpsEndpoint: Boolean(urlFeatureAnalysis.httpsEndpoint),
    trustedEndpointMitigationEligible: false,
    integrityHashMismatch: false
  };

  return {
    ...baseFeatures,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(baseFeatures)
  };
}

function isTrustedEndpointMitigationEligible(features = {}) {
  const redirectCount = Number(features.redirectCount || 0);

  if (!features.trustedEndpoint || !features.httpsEndpoint) {
    return false;
  }

  if (features.googleSafeBrowsingFlagged || features.urlhausFlagged) {
    return false;
  }

  if (features.textMismatch || features.integrityHashMismatch) {
    return false;
  }

  if (features.suspiciousTld || features.suspiciousPath || features.obfuscatedUrl || features.usernamePasswordTrick) {
    return false;
  }

  if (features.suspiciousRedirectPattern || features.shortenerToUnrelatedDomain || features.trackingHopToUnrelatedDomain) {
    return false;
  }

  if (redirectCount > 3) {
    return false;
  }

  return true;
}

function buildUrlAnalysisCacheKeys(urlFeatures = {}, analysisUrl = "") {
  const keys = [];
  const candidates = [
    analysisUrl,
    urlFeatures.normalizedUrl,
    urlFeatures.unwrappedUrl,
    urlFeatures.rawComparableUrl
  ];

  for (const candidate of candidates) {
    const cacheKey = normalizeCacheKey(candidate);
    if (cacheKey && !keys.includes(cacheKey)) {
      keys.push(cacheKey);
    }
  }

  return keys;
}

function normalizeCacheKey(candidate) {
  if (!candidate) {
    return "";
  }

  try {
    return normalizeUrl(candidate);
  } catch {
    return String(candidate || "").trim();
  }
}

function getUrlAnalysisCacheEntry(cacheKey) {
  if (!cacheKey) {
    return null;
  }

  const entry = urlAnalysisCache.get(cacheKey);
  if (!entry) {
    return null;
  }

  if (entry.expiresAt <= Date.now()) {
    urlAnalysisCache.delete(cacheKey);
    return null;
  }

  return {
    cachedAt: entry.cachedAt,
    expiresAt: entry.expiresAt,
    ...cloneValue(entry.payload)
  };
}

function setUrlAnalysisCacheEntry(cacheKeys, payload, cachedAt = Date.now()) {
  const normalizedKeys = [...new Set((cacheKeys || []).filter(Boolean))];
  if (normalizedKeys.length === 0) {
    return;
  }

  const entry = {
    cachedAt,
    expiresAt: cachedAt + URL_ANALYSIS_CACHE_TTL_MS,
    payload: cloneValue(payload)
  };

  for (const cacheKey of normalizedKeys) {
    urlAnalysisCache.set(cacheKey, entry);
  }

  pruneUrlAnalysisCache();
}

function pruneUrlAnalysisCache() {
  const now = Date.now();

  for (const [cacheKey, entry] of urlAnalysisCache.entries()) {
    if (entry.expiresAt <= now) {
      urlAnalysisCache.delete(cacheKey);
    }
  }
}

function cloneValue(value) {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }

  return JSON.parse(JSON.stringify(value));
}

function stripUrlAnalysisCacheMetadata(entry) {
  if (!entry) {
    return entry;
  }

  const { cachedAt, expiresAt, ...payload } = entry;
  return payload;
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
  const checkedAt = Date.now();
  const key = String(config.GSB_API_KEY || "").trim();

  if (!key) {
    const missingKeyMessage = config.configLoaded
      ? `GSB_API_KEY is missing in ${CONFIG_FILE_NAME}.`
      : config.configError || `Failed to load ${CONFIG_FILE_NAME}.`;

    updateGsbHealth({
      configured: false,
      available: false,
      lastStatus: "not-configured",
      lastHttpStatus: null,
      lastError: missingKeyMessage,
      lastCheckedAt: checkedAt
    });

    return {
      provider: "gsb",
      configured: false,
      checked: false,
      flagged: false,
      category: null,
      details: {
        status: "not-configured",
        message: missingKeyMessage
      }
    };
  }

  let response = null;

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`;
    response = await fetch(endpoint, {
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
      const errorMessage = `Safe Browsing lookup returned HTTP ${response.status}.`;

      updateGsbHealth({
        configured: true,
        available: false,
        lastStatus: "error",
        lastHttpStatus: response.status,
        lastError: errorMessage,
        lastCheckedAt: checkedAt
      });

      return {
        provider: "gsb",
        configured: true,
        checked: true,
        flagged: false,
        category: null,
        details: {
          status: "error",
          httpStatus: response.status,
          message: errorMessage
        }
      };
    }

    const payload = await response.json();
    const matches = Array.isArray(payload.matches) ? payload.matches : [];
    const category = matches[0]?.threatType || null;

    updateGsbHealth({
      configured: true,
      available: true,
      lastStatus: "ok",
      lastHttpStatus: response.status,
      lastError: null,
      lastCheckedAt: checkedAt
    });

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
    updateGsbHealth({
      configured: true,
      available: false,
      lastStatus: "error",
      lastHttpStatus: response?.status ?? null,
      lastError: safeErrorMessage(error, "Unknown Safe Browsing error."),
      lastCheckedAt: checkedAt
    });

    return {
      provider: "gsb",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        httpStatus: response?.status ?? null,
        message: safeErrorMessage(error, "Unknown Safe Browsing error.")
      }
    };
  }
}

async function lookupUrlhaus(normalizedUrl) {
  const config = getRuntimeConfig();
  const checkedAt = Date.now();
  const authKey = String(config.URLHAUS_AUTH_KEY || "").trim();
  const mode = "public";
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  let response = null;

  try {
    const body = new URLSearchParams({
      url: normalizedUrl
    });

    response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers,
      body: body.toString()
    });

    if (!response.ok) {
      const errorMessage = `URLhaus lookup returned HTTP ${response.status}.`;

      updateUrlhausHealth({
        mode,
        available: false,
        lastStatus: "error",
        lastHttpStatus: response.status,
        lastError: errorMessage,
        lastCheckedAt: checkedAt
      });

      return {
        provider: "urlhaus",
        configured: true,
        checked: true,
        flagged: false,
        category: null,
        details: {
          status: "error",
          httpStatus: response.status,
          message: errorMessage,
          mode,
          authConfigured: Boolean(authKey),
          authKeyConfigured: Boolean(authKey)
        }
      };
    }

    const payload = await response.json();
    const status = String(payload.query_status || "").toLowerCase();
    const flagged = status === "ok" || status === "online";
    const category = payload.threat || payload.tags?.[0] || "malware-oriented";

    updateUrlhausHealth({
      mode,
      available: true,
      lastStatus: "ok",
      lastHttpStatus: response.status,
      lastError: null,
      lastCheckedAt: checkedAt
    });

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
        mode,
        authConfigured: Boolean(authKey),
        authKeyConfigured: Boolean(authKey),
        payload
      }
    };
  } catch (error) {
    updateUrlhausHealth({
      mode,
      available: false,
      lastStatus: "error",
      lastHttpStatus: response?.status ?? null,
      lastError: safeErrorMessage(error, "Unknown URLhaus lookup error."),
      lastCheckedAt: checkedAt
    });

    return {
      provider: "urlhaus",
      configured: true,
      checked: true,
      flagged: false,
      category: null,
      details: {
        status: "error",
        httpStatus: response?.status ?? null,
        message: safeErrorMessage(error, "Unknown URLhaus lookup error."),
        mode,
        authConfigured: Boolean(authKey),
        authKeyConfigured: Boolean(authKey)
      }
    };
  }
}

async function buildPopupSummary(tabUrl) {
  await ensureActiveSession("popup-summary");

  const records = await getAllAnalysisRecords();
  const scanEnabled = await getScanEnabledState();
  const isSupportedTab = isSupportedFacebookUrl(tabUrl);
  const sessionRecords = records.filter((record) => Number(record.timestamp || 0) >= sessionInfo.startedAt);
  const scannedPostsInSession = new Set(sessionRecords.map((record) => record.postId).filter(Boolean)).size;
  const analyzedLinksInSession = sessionRecords.length;
  const flaggedPostsInSession = new Set(
    sessionRecords
      .filter((record) => record.classification === "Suspicious" || record.classification === "High Risk")
      .map((record) => record.postId)
      .filter(Boolean)
  ).size;

  return {
    scanEnabled,
    tabSupported: isSupportedTab,
    postsScannedInSession: scannedPostsInSession,
    scannedPostsInSession,
    postsAnalyzedInSession: analyzedLinksInSession,
    analyzedPostsInSession: scannedPostsInSession,
    analyzedLinksInSession,
    flaggedPostsInSession,
    totalStoredAnalyses: records.length,
    sessionStartedAt: sessionInfo.startedAt,
    providerSummary: buildCompactProviderSummary(),
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
  if (!(await getScanEnabledState())) {
    return {
      success: false,
      message: "Protection is off. Turn DILI on before scanning."
    };
  }

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

async function restartSession() {
  await resetSession("manual");

  return {
    success: true,
    message: "Session restarted."
  };
}

async function ensureActiveSession(reason) {
  if (Date.now() - sessionInfo.startedAt < SESSION_TTL_MS) {
    return false;
  }

  await resetSession(`${reason}-expired`);
  return true;
}

async function resetSession(reason) {
  await clearAnalysisRecords();

  const now = Date.now();
  sessionInfo.id = createSessionId(now);
  sessionInfo.startedAt = now;
  sessionInfo.lastActivityAt = now;
  sessionInfo.lastResetAt = now;
  sessionInfo.lastResetReason = reason || "manual";

  logDebug(`Session reset: ${sessionInfo.lastResetReason}`);
}

function createSessionState(now = Date.now()) {
  return {
    id: createSessionId(now),
    startedAt: now,
    lastActivityAt: now,
    lastResetAt: now,
    lastResetReason: "startup",
    trackedFacebookTabs: new Map()
  };
}

function createSessionId(timestamp = Date.now()) {
  return `session-${timestamp}`;
}

function bindSessionLifecycleObservers() {
  if (chrome.webNavigation?.onCommitted) {
    chrome.webNavigation.onCommitted.addListener((details) => {
      handleSupportedTopLevelNavigation(details).catch((error) => {
        console.warn("[DILI] Session navigation handling failed", error);
      });
    });
  }
}

async function handleSupportedTopLevelNavigation(details) {
  if (!details || details.frameId !== 0 || !isSupportedFacebookUrl(details.url || "")) {
    return;
  }

  const normalizedUrl = normalizeSupportedTabUrl(details.url);
  const previousUrl = sessionInfo.trackedFacebookTabs.get(details.tabId) || "";
  const isReload = details.transitionType === "reload";
  const isNavigationChange = Boolean(previousUrl && previousUrl !== normalizedUrl);
  const isFirstSupportedLoad = !previousUrl;

  sessionInfo.trackedFacebookTabs.set(details.tabId, normalizedUrl);

  if (!isReload && !isNavigationChange && !isFirstSupportedLoad) {
    return;
  }

  const reason = isReload
    ? "page-refresh"
    : isNavigationChange
      ? "page-navigation"
      : "page-load";

  await resetSession(reason);
}

function normalizeSupportedTabUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    url.hash = "";
    return url.toString();
  } catch {
    return String(rawUrl || "").trim();
  }
}

function getRuntimeConfig() {
  return runtimeConfig;
}

function createRuntimeConfig() {
  return {
    GSB_API_KEY: String(GSB_API_KEY || "").trim(),
    URLHAUS_AUTH_KEY: String(URLHAUS_AUTH_KEY || "").trim(),
    configLoaded: true,
    configSource: CONFIG_FILE_NAME,
    configError: null
  };
}

function createInitialProviderHealth() {
  return {
    configLoaded: false,
    configSource: "not-yet-loaded",
    configError: null,
    gsb: {
      configured: false,
      available: false,
      lastStatus: "not-yet-run",
      lastHttpStatus: null,
      lastError: null,
      lastCheckedAt: null
    },
    urlhaus: {
      mode: "public",
      authKeyConfigured: false,
      available: true,
      lastStatus: "not-yet-run",
      lastHttpStatus: null,
      lastError: null,
      lastCheckedAt: null
    }
  };
}

function applyConfigDiagnostics(config) {
  const gsbKeyLoaded = Boolean(String(config.GSB_API_KEY || "").trim());
  const urlhausAuthKeyLoaded = Boolean(String(config.URLHAUS_AUTH_KEY || "").trim());
  const configError = config.configLoaded ? null : config.configError || `Unable to load ${CONFIG_FILE_NAME}.`;

  providerHealth.configLoaded = Boolean(config.configLoaded);
  providerHealth.configSource = config.configSource || (config.configLoaded ? CONFIG_FILE_NAME : "fallback");
  providerHealth.configError = configError;

  providerHealth.gsb.configured = gsbKeyLoaded;

  if (!gsbKeyLoaded) {
    providerHealth.gsb.available = false;
    providerHealth.gsb.lastStatus = "not-configured";
    providerHealth.gsb.lastHttpStatus = null;
    providerHealth.gsb.lastError = config.configLoaded
      ? `GSB_API_KEY is missing in ${CONFIG_FILE_NAME}.`
      : configError;
  } else {
    if (providerHealth.gsb.lastStatus === "not-configured") {
      providerHealth.gsb.lastStatus = "not-yet-run";
      providerHealth.gsb.lastHttpStatus = null;
      providerHealth.gsb.lastError = null;
    }

    providerHealth.gsb.available = providerHealth.gsb.lastStatus !== "error";
  }

  providerHealth.urlhaus.mode = "public";
  providerHealth.urlhaus.authKeyConfigured = urlhausAuthKeyLoaded;
  providerHealth.urlhaus.available = providerHealth.urlhaus.lastStatus !== "error";

  if (providerHealth.urlhaus.lastStatus === "not-yet-run") {
    providerHealth.urlhaus.lastError = null;
  }
}

function updateGsbHealth(patch) {
  Object.assign(providerHealth.gsb, patch);
}

function updateUrlhausHealth(patch) {
  Object.assign(providerHealth.urlhaus, patch);
}

function getProviderHealthSnapshot() {
  return {
    configLoaded: providerHealth.configLoaded,
    configSource: providerHealth.configSource,
    configError: providerHealth.configError,
    gsb: {
      configured: providerHealth.gsb.configured,
      available: providerHealth.gsb.available,
      lastStatus: providerHealth.gsb.lastStatus,
      lastHttpStatus: providerHealth.gsb.lastHttpStatus,
      lastError: providerHealth.gsb.lastError,
      lastCheckedAt: providerHealth.gsb.lastCheckedAt
    },
    urlhaus: {
      mode: providerHealth.urlhaus.mode,
      authKeyConfigured: providerHealth.urlhaus.authKeyConfigured,
      available: providerHealth.urlhaus.available,
      lastStatus: providerHealth.urlhaus.lastStatus,
      lastHttpStatus: providerHealth.urlhaus.lastHttpStatus,
      lastError: providerHealth.urlhaus.lastError,
      lastCheckedAt: providerHealth.urlhaus.lastCheckedAt
    }
  };
}

function buildCompactProviderSummary() {
  const snapshot = getProviderHealthSnapshot();

  return {
    config: {
      label: "Config",
      state: snapshot.configLoaded && !snapshot.configError ? "ready" : "error",
      text: snapshot.configLoaded && !snapshot.configError ? "Ready" : "Error"
    },
    gsb: {
      label: "GSB",
      state: getGsbProviderState(snapshot.gsb || {}),
      text: formatCompactProviderText(getGsbProviderState(snapshot.gsb || {}))
    },
    urlhaus: {
      label: "URLhaus",
      state: getUrlhausProviderState(snapshot.urlhaus || {}),
      text: formatCompactProviderText(getUrlhausProviderState(snapshot.urlhaus || {}))
    }
  };
}

function getGsbProviderState(gsb = {}) {
  if (!gsb.configured) {
    return "off";
  }

  if (gsb.lastStatus === "error" || gsb.available === false) {
    return "error";
  }

  return "ready";
}

function getUrlhausProviderState(urlhaus = {}) {
  if (urlhaus.lastStatus === "error" || urlhaus.available === false) {
    return "error";
  }

  if (urlhaus.mode === "public") {
    return "public";
  }

  return "ready";
}

function formatCompactProviderText(state) {
  switch (state) {
    case "ready":
      return "Ready";
    case "public":
      return "Public";
    case "off":
      return "Off";
    default:
      return "Error";
  }
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

function safeErrorMessage(error, fallbackMessage) {
  if (error && typeof error.message === "string" && error.message.trim()) {
    return error.message.trim();
  }

  if (typeof error === "string" && error.trim()) {
    return error.trim();
  }

  return fallbackMessage;
}

function logDebug(message) {
  console.debug(`[DILI] ${message}`);
}
