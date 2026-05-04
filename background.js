import { GSB_API_KEY, URLHAUS_API_KEY, URLHAUS_AUTH_KEY } from "./config.local.js";
import { calculateSafetyScore, classifySafetyScore } from "./riskEngine.js";
import { sha256Hex } from "./utils/hash.js";
import { resolveEndpoint } from "./utils/endpointResolver.js";
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
const CURRENT_ANALYSIS_SCHEMA_VERSION = 4;
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
      {
        const scanEnabled = await setScanEnabledState(message?.enabled !== false);
        await notifyActiveFacebookTabScanState(scanEnabled);
        return {
          type: MESSAGE_TYPES.SET_SCAN_STATE,
          scanEnabled
        };
      }

    case MESSAGE_TYPES.ANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.ANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          links: message.links,
          displayedText: message.displayedText,
          candidateContext: message.candidateContext,
          postTextHash: message.postTextHash,
          normalizedVisiblePostText: message.normalizedVisiblePostText,
          isReanalysis: false
        })
      };

    case MESSAGE_TYPES.REANALYZE_LINK:
      return {
        type: MESSAGE_TYPES.REANALYZE_LINK,
        analysis: await performLinkAnalysis({
          postId: message.postId,
          rawUrl: message.url,
          links: message.links,
          displayedText: message.displayedText,
          candidateContext: message.candidateContext,
          postTextHash: message.postTextHash,
          normalizedVisiblePostText: message.normalizedVisiblePostText,
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
  const now = Date.now();
  const firstSeenAt = Number(baseline?.firstSeenAt || baseline?.baselineFirstSeenAt || now);
  const postTextHash = String(message.postTextHash || baseline?.postTextHash || "");
  const normalizedVisiblePostText = String(message.normalizedVisiblePostText || baseline?.normalizedVisiblePostText || "");

  return updatePostAnalysis(message.postId, {
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    baselineState: "no_link",
    hadLinkAtBaseline: false,
    firstSeenAt,
    baselineFirstSeenAt: firstSeenAt,
    lastSeenAt: now,
    lastChecked: now,
    state: "no_link",
    classification: "No Link",
    safetyScore: null,
    urlHash: "",
    normalizedUrl: "",
    analysisUrl: "",
    rawUrl: "",
    providerResults: [],
    deductions: [],
    technicalDetails: [],
    redirectAnalysis: {
      redirectCount: 0,
      redirectChain: [],
      notes: []
    },
    candidateContext: null,
    endpointConfidence: "",
    providerOverride: false,
    features: {
      noLinkBaseline: true,
      linkInsertedAfterBaseline: false,
      integrityHashMismatch: false
    },
    postTextHash,
    normalizedVisiblePostText,
    postId: message.postId
  });
}

async function performLinkAnalysis({ postId, rawUrl, links, displayedText, candidateContext, postTextHash, normalizedVisiblePostText, isReanalysis }) {
  const linkInputs = Array.isArray(links) && links.length > 0
    ? links.slice(0, 8)
    : [{
      url: rawUrl,
      displayText: displayedText,
      candidateContext
    }];
  const analyses = [];
  const limitations = [];

  for (let index = 0; index < linkInputs.length; index += 1) {
    const link = linkInputs[index] || {};
    try {
      const analysis = await performSingleLinkAnalysis({
        postId,
        rawUrl: link.url || rawUrl,
        displayedText: link.displayText || displayedText,
        candidateContext: link.candidateContext || candidateContext,
        postTextHash,
        normalizedVisiblePostText,
        isReanalysis,
        persist: false
      });
      analyses.push(analysis);
    } catch (error) {
      limitations.push(`Link ${index + 1} analysis failed: ${safeErrorMessage(error, "Unknown link analysis error.")}`);
    }
  }

  if (analyses.length === 0) {
    throw new Error(limitations[0] || "No links could be analyzed.");
  }

  const worst = analyses
    .slice()
    .sort((left, right) => {
      const leftScore = Number.isFinite(left.safetyScore) ? left.safetyScore : 101;
      const rightScore = Number.isFinite(right.safetyScore) ? right.safetyScore : 101;
      return leftScore - rightScore;
    })[0];
  const persistedWorst = await persistPostLevelAnalysis(postId, worst);

  return {
    ...persistedWorst,
    linkAnalyses: analyses.map(compactLiveLinkAnalysis),
    analyzedLinkCount: analyses.length,
    failedLinkLimitations: limitations,
    limitations: [...(worst.limitations || []), ...limitations].slice(0, 8)
  };
}

async function performSingleLinkAnalysis({ postId, rawUrl, displayedText, candidateContext, postTextHash, normalizedVisiblePostText, isReanalysis, persist = true }) {
  if (!(await getScanEnabledState())) {
    throw new Error("Scanning is currently disabled.");
  }

  await ensureActiveSession("analysis");

  const endpointResult = await resolveEndpoint(rawUrl);
  if (endpointResult.isInternalFacebook) {
    return {
      postId,
      rawUrl,
      normalizedUrl: endpointResult.normalizedRawUrl,
      analysisUrl: endpointResult.effectiveEndpoint,
      classification: "Unverified",
      safetyScore: null,
      endpointResult,
      endpointConfidence: endpointResult.endpointConfidence,
      limitations: ["Internal Facebook link ignored."],
      features: {
        internalFacebook: true
      },
      deductions: [],
      providerResults: [createDefaultProviderResult("gsb"), createDefaultProviderResult("urlhaus")],
      redirectAnalysis: {
        redirectCount: 0,
        redirectChain: endpointResult.resolutionChain,
        notes: endpointResult.warnings
      },
      state: "internal-facebook",
      analysisMode: "internal-facebook-ignored",
      reusedClassification: false
    };
  }

  const urlFeatures = analyzeUrlFeatures({
    rawUrl
  });
  const normalizedUrl = urlFeatures.normalizedUrl;
  const existingBaseline = await getBaseline(postId);
  const compatibleBaseline = getCompatibleBaseline(existingBaseline);

  if (existingBaseline && !compatibleBaseline) {
    logDebug(`Legacy baseline detected for ${postId}; integrity comparison skipped for this scan.`);
  }

  const reusableUrlAnalysis = normalizeReusableUrlAnalysis(await getReusableUrlAnalysis(rawUrl, urlFeatures, endpointResult, endpointResult?.redirectAnalysis));
  const analysisUrl = reusableUrlAnalysis.analysisUrl;
  const redirectAnalysis = reusableUrlAnalysis.redirectAnalysis;
  const providerResults = normalizeProviderResults(reusableUrlAnalysis.providerResults);
  const domain = reusableUrlAnalysis.domain || safeHostname(analysisUrl || normalizedUrl);
  const normalizedCandidateContext = buildCandidateContext(candidateContext, {
    analysisUrl,
    endpointResult,
    normalizedUrl,
    domain
  });
  const currentHash = await sha256Hex(buildStableUrlHashInput({
    analysisUrl,
    normalizedUrl
  }));
  const textComparison = detectDomainMismatch(displayedText || "", analysisUrl);
  const domainPreviouslyFlagged = await checkDomainPreviouslyFlagged(domain);
  const gsbResult = getNormalizedProviderResult(providerResults, "gsb");
  const urlhausResult = getNormalizedProviderResult(providerResults, "urlhaus");
  const detectedAt = Date.now();
  const baselineFirstSeenAt = Number(existingBaseline?.baselineFirstSeenAt || existingBaseline?.firstSeenAt || detectedAt);
  const currentPostTextHash = String(postTextHash || "");
  const normalizedCurrentPostText = String(normalizedVisiblePostText || "").replace(/\s+/g, " ").trim();
  const hadNoLinkBaseline = Boolean(
    (compatibleBaseline?.baselineState || existingBaseline?.baselineState) === "no_link" ||
    existingBaseline?.hadLinkAtBaseline === false
  );
  const linkInsertedAfterBaseline = Boolean(isReanalysis && hadNoLinkBaseline);
  const previousPostTextHash = String(existingBaseline?.postTextHash || existingBaseline?.currentPostTextHash || "");
  const postContextFeatures = {
    domainPreviouslyFlagged,
    textMismatch: textComparison.mismatch,
    integrityHashMismatch: Boolean(linkInsertedAfterBaseline || (isReanalysis && compatibleBaseline?.postIdentityStable === true && normalizedCandidateContext.candidateMode === "single" && hasCompatibleIntegrityMismatch(compatibleBaseline, {
      currentHash,
      analysisUrl,
      normalizedUrl,
      candidateContext: normalizedCandidateContext
    })))
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
    wrapperToExternalDestination: shouldApplyWrapperRisk({
      endpointResult,
      redirectAnalysis,
      urlFeatureAnalysis: reusableUrlAnalysis.urlFeatureAnalysis,
      providerResults,
      textMismatch: postContextFeatures.textMismatch
    }),
    facebookWrapperUnwrapped: Boolean(endpointResult.isFacebookWrapper && !endpointResult.isInternalFacebook)
  };
  const urlLevelFeaturesBase = {
    ...reusableUrlAnalysis.urlLevelFeatures,
    wrapperToExternalDestination: enrichedUrlFeatures.wrapperToExternalDestination
  };
  const urlLevelFeatures = applyMainstreamResolvedShortlinkMitigation({
    ...urlLevelFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(urlLevelFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  const combinedFeaturesBase = {
    ...urlLevelFeatures,
    ...postContextFeatures
  };
  const features = applyMainstreamResolvedShortlinkMitigation({
    ...combinedFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(combinedFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  const urlLevelScoring = calculateSafetyScore(urlLevelFeatures);
  const providerOverride = Boolean(gsbResult.flagged || urlhausResult.flagged);
  const urlLevelClassification = providerOverride ? "High Risk" : classifySafetyScore(urlLevelScoring.score);
  const scoring = calculateSafetyScore(features);
  const endpointResolutionFailed = Boolean(
    !endpointResult?.effectiveEndpoint ||
    endpointResult?.resolutionMethod === "missing-url" ||
    endpointResult?.resolutionMethod === "invalid-url" ||
    (endpointResult?.endpointConfidence === "low" && !endpointResult?.redirectAnalysis?.resolvedUrl && !endpointResult?.resolvedUrl)
  );
  let finalScore = providerOverride ? Math.min(scoring.score, 20) : scoring.score;
  if (!providerOverride) {
    if (endpointResolutionFailed) {
      finalScore = Math.min(finalScore, 74);
    } else if (endpointResult?.endpointConfidence === "low") {
      finalScore = Math.min(finalScore, 79);
    }
  }
  const classification = providerOverride ? "High Risk" : classifySafetyScore(finalScore);
  const nextState = features.integrityHashMismatch ? "changed" : "monitored";
  const record = {
    postId,
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    normalizedUrl,
    analysisUrl,
    rawUrl,
    urlHash: currentHash,
    postTextHash: currentPostTextHash,
    normalizedVisiblePostText: normalizedCurrentPostText,
    previousPostTextHash,
    currentPostTextHash,
    baselineFirstSeenAt,
    detectedAt,
    hadLinkAtBaseline: Boolean(existingBaseline?.hadLinkAtBaseline === true || existingBaseline?.baselineState === "link"),
    linkInsertedAfterBaseline,
    postIntegrityEvent: linkInsertedAfterBaseline ? "link_inserted_after_no_link_baseline" : "",
    baselineState: compatibleBaseline?.baselineState || existingBaseline?.baselineState || "",
    candidateMode: normalizedCandidateContext.candidateMode,
    dominantDomain: normalizedCandidateContext.dominantDomain,
    candidateDomainCount: normalizedCandidateContext.candidateDomainCount,
    selectedNormalizedTarget: normalizedCandidateContext.selectedNormalizedTarget,
    candidateContext: normalizedCandidateContext,
    classification,
    safetyScore: finalScore,
    features,
    deductions: scoring.deductions,
    providerOverride,
    providerResults,
    technicalDetails: buildTechnicalDetails({
      endpointResult,
      redirectAnalysis,
      urlFeatureAnalysis: enrichedUrlFeatures,
      analysis: {
        postIntegrityEvent: linkInsertedAfterBaseline ? "link_inserted_after_no_link_baseline" : "",
        linkInsertedAfterBaseline,
        baselineFirstSeenAt,
        previousPostTextHash,
        currentPostTextHash
      }
    }),
    endpointConfidence: endpointResult.endpointConfidence,
    limitations: buildAnalysisLimitations({ endpointResult, providerResults }),
    postIdentityStable: normalizedCandidateContext.postIdentityStable === true,
    integrityComparisonStatus: normalizedCandidateContext.postIdentityStable === true ? "checked" : "skipped-unstable-post-identity",
    redirectAnalysis,
    urlFeatureAnalysis: enrichedUrlFeatures,
    lastChecked: Date.now(),
    state: nextState
  };

  if (!record.postIdentityStable) {
    record.limitations = [
      ...(record.limitations || []),
      "Post integrity comparison skipped because no stable Facebook post identity was available."
    ].slice(0, 8);
  }

  const storedRecord = persist
    ? existingBaseline
      ? await updatePostAnalysis(postId, record)
      : await setBaseline(postId, record)
    : record;

  if (urlLevelClassification === "High Risk" || gsbResult.flagged || urlhausResult.flagged) {
    await markDomainFlagged(domain);
  }

  if (persist) {
    await appendAnalysisRecord({
      timestamp: Date.now(),
      postId,
      analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
      url: analysisUrl,
      originalUrl: normalizedUrl,
      domain,
      urlHash: currentHash,
      safetyScore: finalScore,
      classification,
      features,
      providerResults,
      endpointResult,
      endpointConfidence: endpointResult.endpointConfidence,
      limitations: record.limitations,
      providerOverride,
      state: nextState
    });
  }

  sessionInfo.lastActivityAt = Date.now();

  if (features.integrityHashMismatch) {
    logDebug(`Edit detection for ${postId}: integrity hash changed.`);
  }

  logDebug(`URL analysis reused=${reusableUrlAnalysis.cacheHit} analysisUrl=${analysisUrl}`);
  logDebug(`Provider checks: gsb=${gsbResult.flagged} urlhaus=${urlhausResult.flagged}`);
  logDebug(`Scoring result for ${postId}: safety=${finalScore} classification=${classification}`);

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
    selectedNormalizedTarget,
    postIdentityStable: candidateContext.postIdentityStable === true || fallback.postIdentityStable === true
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

async function getReusableUrlAnalysis(rawUrl, urlFeatures, endpointResult = null, redirectAnalysis = null) {
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
      ...normalizeReusableUrlAnalysis(cachedEntry),
      cacheHit: true,
      cacheKey
    };
  }

  const cacheMissKey = initialCacheKeys[0] || normalizeCacheKey(rawUrl) || "unknown-url";
  logDebug(`URL analysis cache miss: ${cacheMissKey}`);

  const safeEndpointResult = endpointResult || {};
  const safeRedirectAnalysis = normalizeRedirectAnalysis(redirectAnalysis || endpointResult?.redirectAnalysis || await analyzeRedirects(rawUrl));
  const analysisUrl = endpointResult?.effectiveEndpoint || resolveAnalysisUrl(urlFeatures, safeRedirectAnalysis);
  const domain = safeHostname(analysisUrl || urlFeatures.normalizedUrl);
  const analysisUrlFeatures = analyzeUrlFeatures({
    rawUrl: analysisUrl
  });
  const providerResults = normalizeProviderResults(await runThreatIntelligenceChecks(analysisUrl));
  const stableUrlFeatureAnalysis = {
    ...analysisUrlFeatures,
    sourceNormalizedUrl: urlFeatures.normalizedUrl,
    sourceUnwrappedUrl: urlFeatures.unwrappedUrl,
    sourceRawComparableUrl: urlFeatures.rawComparableUrl,
    finalAnalysisUrl: analysisUrl,
    finalDomain: domain,
    endpointConfidence: endpointResult?.endpointConfidence || "",
    shortenedUrl: Boolean(urlFeatures.shortenedUrl || analysisUrlFeatures.shortenedUrl),
    usesKnownWrapper: Boolean(urlFeatures.usesKnownWrapper),
    wrapperChain: urlFeatures.wrapperChain,
    wrapperHosts: urlFeatures.wrapperHosts,
    wrapperToExternalDestination: shouldApplyWrapperRisk({
      endpointResult: safeEndpointResult,
      redirectAnalysis: safeRedirectAnalysis,
      urlFeatureAnalysis: {
        ...analysisUrlFeatures,
        shortenedUrl: Boolean(urlFeatures.shortenedUrl || analysisUrlFeatures.shortenedUrl)
      },
      providerResults,
      textMismatch: false
    }),
    facebookWrapperUnwrapped: Boolean(safeEndpointResult.isFacebookWrapper && !safeEndpointResult.isInternalFacebook)
  };
  const urlLevelFeatures = buildUrlLevelFeatures({
    redirectAnalysis: safeRedirectAnalysis,
    providerResults,
    urlFeatureAnalysis: stableUrlFeatureAnalysis
  });
  const cacheEntry = {
    analysisUrl,
    domain,
    redirectAnalysis: safeRedirectAnalysis,
    providerResults,
    endpointResult: safeEndpointResult,
    urlFeatureAnalysis: stableUrlFeatureAnalysis,
    urlLevelFeatures
  };

  setUrlAnalysisCacheEntry(buildUrlAnalysisCacheKeys(urlFeatures, analysisUrl), cacheEntry);

  return {
    ...cacheEntry,
    cacheHit: false,
    cacheKey: normalizeCacheKey(analysisUrl) || analysisUrl
  };
}

function buildUrlLevelFeatures({ redirectAnalysis, providerResults, urlFeatureAnalysis }) {
  const safeProviderResults = normalizeProviderResults(providerResults);
  const safeRedirectAnalysis = normalizeRedirectAnalysis(redirectAnalysis);
  const safeUrlFeatureAnalysis = urlFeatureAnalysis || {};
  const gsbResult = safeProviderResults.find((item) => item.provider === "gsb");
  const urlhausResult = safeProviderResults.find((item) => item.provider === "urlhaus");

  const baseFeatures = {
    googleSafeBrowsingFlagged: gsbResult.flagged,
    urlhausFlagged: urlhausResult.flagged,
    domainPreviouslyFlagged: false,
    redirectCount: safeRedirectAnalysis.redirectCount,
    multipleRedirects: safeRedirectAnalysis.multipleRedirects,
    crossDomainRedirectChain: safeRedirectAnalysis.crossDomainRedirectChain,
    redirectChainToDifferentRegistrantLikeTarget: safeRedirectAnalysis.redirectChainToDifferentRegistrantLikeTarget,
    wrapperToExternalDestination: Boolean(safeUrlFeatureAnalysis.wrapperToExternalDestination),
    suspiciousRedirectPattern: safeRedirectAnalysis.suspiciousPattern,
    trackingHopToUnrelatedDomain: safeRedirectAnalysis.trackingHopToUnrelatedDomain,
    shortenerToUnrelatedDomain: safeRedirectAnalysis.shortenerToUnrelatedDomain,
    shortenedUrl: safeUrlFeatureAnalysis.shortenedUrl,
    obfuscatedUrl: safeUrlFeatureAnalysis.obfuscatedUrl,
    suspiciousTld: safeUrlFeatureAnalysis.suspiciousTld,
    textMismatch: false,
    excessiveQueryComplexity: safeUrlFeatureAnalysis.excessiveQueryComplexity,
    suspiciousPath: safeUrlFeatureAnalysis.suspiciousPath,
    excessiveSubdomainDepth: safeUrlFeatureAnalysis.excessiveSubdomainDepth,
    usernamePasswordTrick: safeUrlFeatureAnalysis.usernamePasswordTrick,
    trustedEndpoint: Boolean(safeUrlFeatureAnalysis.trustedEndpoint),
    httpsEndpoint: Boolean(safeUrlFeatureAnalysis.httpsEndpoint),
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

function normalizeReusableUrlAnalysis(value = {}) {
  const safeValue = value && typeof value === "object" ? value : {};
  return {
    ...safeValue,
    providerResults: normalizeProviderResults(safeValue.providerResults),
    redirectAnalysis: normalizeRedirectAnalysis(safeValue.redirectAnalysis),
    urlFeatureAnalysis: safeValue.urlFeatureAnalysis && typeof safeValue.urlFeatureAnalysis === "object"
      ? safeValue.urlFeatureAnalysis
      : {},
    endpointResult: safeValue.endpointResult && typeof safeValue.endpointResult === "object"
      ? safeValue.endpointResult
      : {}
  };
}

function normalizeProviderResults(providerResults) {
  const values = Array.isArray(providerResults) ? providerResults : [];
  const gsb = values.find((item) => item?.provider === "gsb") || createDefaultProviderResult("gsb");
  const urlhaus = values.find((item) => item?.provider === "urlhaus") || createDefaultProviderResult("urlhaus");
  return [gsb, urlhaus];
}

function getNormalizedProviderResult(providerResults, providerName) {
  return normalizeProviderResults(providerResults).find((item) => item.provider === providerName) || createDefaultProviderResult(providerName);
}

function normalizeRedirectAnalysis(redirectAnalysis = {}) {
  const safe = redirectAnalysis && typeof redirectAnalysis === "object" ? redirectAnalysis : {};
  return {
    redirectCount: Number(safe.redirectCount || 0),
    redirectChain: Array.isArray(safe.redirectChain) ? safe.redirectChain : Array.isArray(safe.chain) ? safe.chain : [],
    chain: Array.isArray(safe.chain) ? safe.chain : Array.isArray(safe.redirectChain) ? safe.redirectChain : [],
    redirectDomains: Array.isArray(safe.redirectDomains) ? safe.redirectDomains : [],
    uniqueRegistrableDomains: Array.isArray(safe.uniqueRegistrableDomains) ? safe.uniqueRegistrableDomains : [],
    resolvedUrl: safe.resolvedUrl || "",
    resolutionMethod: safe.resolutionMethod || "unknown",
    notes: Array.isArray(safe.notes) ? safe.notes : [],
    fetchAttempted: Boolean(safe.fetchAttempted),
    fetchAllowed: Boolean(safe.fetchAllowed),
    fetchSucceeded: Boolean(safe.fetchSucceeded),
    suspiciousPattern: Boolean(safe.suspiciousPattern),
    multipleRedirects: Boolean(safe.multipleRedirects),
    crossDomainRedirectChain: Boolean(safe.crossDomainRedirectChain),
    redirectChainToDifferentRegistrantLikeTarget: Boolean(safe.redirectChainToDifferentRegistrantLikeTarget),
    wrapperToExternalDestination: Boolean(safe.wrapperToExternalDestination),
    shortenerToUnrelatedDomain: Boolean(safe.shortenerToUnrelatedDomain),
    trackingHopToUnrelatedDomain: Boolean(safe.trackingHopToUnrelatedDomain)
  };
}

function shouldApplyWrapperRisk({ endpointResult = {}, redirectAnalysis = {}, urlFeatureAnalysis = {}, providerResults = [], textMismatch = false } = {}) {
  const safeProviderResults = normalizeProviderResults(providerResults);
  const providerFlagged = safeProviderResults.some((item) => item.flagged);
  const safeRedirectAnalysis = normalizeRedirectAnalysis(redirectAnalysis);
  const safeFeatures = urlFeatureAnalysis || {};
  const usesFacebookWrapper = Boolean(endpointResult.isFacebookWrapper || safeFeatures.facebookWrapperUnwrapped);

  if (!usesFacebookWrapper || endpointResult.isInternalFacebook) {
    return false;
  }

  const normalResolvedExternalWrapper = Boolean(
    endpointResult.endpointConfidence !== "low" &&
    endpointResult.effectiveEndpoint &&
    endpointResult.effectiveDomain &&
    !endpointResult.isInternalFacebook &&
    safeFeatures.httpsEndpoint !== false
  );

  if (
    normalResolvedExternalWrapper &&
    !providerFlagged &&
    !textMismatch &&
    !safeRedirectAnalysis.suspiciousPattern &&
    !safeFeatures.suspiciousPath &&
    !safeFeatures.usernamePasswordTrick &&
    !safeFeatures.rawIpHost &&
    !safeFeatures.suspiciousFileExtension
  ) {
    return false;
  }

  return Boolean(
    endpointResult.endpointConfidence === "low" ||
    providerFlagged ||
    textMismatch ||
    safeRedirectAnalysis.suspiciousPattern ||
    safeFeatures.suspiciousPath ||
    safeFeatures.usernamePasswordTrick ||
    safeFeatures.rawIpHost ||
    safeFeatures.suspiciousFileExtension
  );
}

function applyMainstreamResolvedShortlinkMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const mainstreamDomains = new Set([
    "tiktok.com",
    "shopee.ph",
    "shopee.com",
    "lazada.com.ph",
    "lazada.com",
    "youtube.com",
    "youtu.be",
    "instagram.com",
    "facebook.com",
    "messenger.com"
  ]);
  const confidence = String(endpointResult?.endpointConfidence || "").toLowerCase();
  const isEligible = Boolean(
    features.shortenedUrl &&
    mainstreamDomains.has(finalDomain) &&
    ["high", "medium"].includes(confidence) &&
    features.httpsEndpoint &&
    !features.googleSafeBrowsingFlagged &&
    !features.urlhausFlagged &&
    !features.suspiciousPath &&
    !features.suspiciousTld &&
    !features.usernamePasswordTrick &&
    !features.textMismatch &&
    !features.integrityHashMismatch
  );

  if (!isEligible) {
    return features;
  }

  return {
    ...features,
    excessiveQueryComplexity: false,
    obfuscatedUrl: false,
    suspiciousRedirectPattern: false,
    shortenerToUnrelatedDomain: false,
    trackingHopToUnrelatedDomain: false,
    crossDomainRedirectChain: false,
    redirectChainToDifferentRegistrantLikeTarget: false,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: true,
    mainstreamResolvedShortlink: true
  };
}

function buildAnalysisLimitations({ endpointResult, providerResults }) {
  const limitations = [];
  const safeProviderResults = normalizeProviderResults(providerResults);
  const gsb = safeProviderResults.find((item) => item.provider === "gsb");
  const urlhaus = safeProviderResults.find((item) => item.provider === "urlhaus");

  if (!gsb.configured) {
    limitations.push("Google Safe Browsing is not configured.");
  } else if (gsb.details?.status === "error") {
    limitations.push("Google Safe Browsing lookup returned an error.");
  }

  if (urlhaus.details?.status === "error") {
    limitations.push("URLhaus public lookup was unavailable.");
  } else if (urlhaus.details?.authKeyConfigured === false || urlhaus.details?.authConfigured === false) {
    limitations.push("URLhaus was checked in public mode.");
  }

if (!endpointResult?.effectiveEndpoint) {
  limitations.push("DILI could not confidently resolve the final endpoint.");
}

  for (const warning of endpointResult?.warnings || []) {
    if (isNormalWrapperMessage(warning)) {
      continue;
    }
    limitations.push(warning);
  }

  return [...new Set(limitations)].slice(0, 8);
}

function isNormalWrapperMessage(message) {
  return /facebook wrapper concealed|wrapper concealed an external destination|facebook wrapper unwrapped/i.test(String(message || ""));
}

function buildTechnicalDetails({ endpointResult = {}, redirectAnalysis = {}, urlFeatureAnalysis = {}, analysis = {} } = {}) {
  const details = [];
  const effectiveDomain = endpointResult.effectiveDomain || urlFeatureAnalysis.finalDomain || "";
  const chainDomains = [...new Set((redirectAnalysis.redirectChain || endpointResult.resolutionChain || [])
    .map((url) => safeHostname(url))
    .filter(Boolean))];

  if (endpointResult.isFacebookWrapper && effectiveDomain) {
    details.push(`Facebook wrapper unwrapped to ${effectiveDomain}.`);
  }

  if (chainDomains.length > 1) {
    details.push(`Redirect chain: ${chainDomains.join(" -> ")}.`);
  }

  if (urlFeatureAnalysis.sourceNormalizedUrl && urlFeatureAnalysis.sourceRawComparableUrl && urlFeatureAnalysis.sourceNormalizedUrl !== urlFeatureAnalysis.sourceRawComparableUrl) {
    details.push("Tracking parameters were stripped for comparison.");
  }

  if (endpointResult.endpointConfidence) {
    details.push(`Endpoint confidence: ${endpointResult.endpointConfidence}.`);
  }

  if (analysis.postIntegrityEvent) {
    details.push(`Post integrity event: ${String(analysis.postIntegrityEvent).replace(/_/g, " ")}.`);
  }

  if (analysis.linkInsertedAfterBaseline) {
    details.push("A link was inserted after a stored no-link baseline.");
  }

  if (analysis.baselineFirstSeenAt) {
    details.push(`Baseline first seen: ${new Date(Number(analysis.baselineFirstSeenAt)).toISOString()}.`);
  }

  if (analysis.previousPostTextHash) {
    details.push(`Previous post text hash: ${analysis.previousPostTextHash}.`);
  }

  if (analysis.currentPostTextHash) {
    details.push(`Current post text hash: ${analysis.currentPostTextHash}.`);
  }

  return [...new Set(details)].slice(0, 6);
}

function compactLiveLinkAnalysis(analysis = {}) {
  return {
    analysisUrl: analysis.analysisUrl,
    normalizedUrl: analysis.normalizedUrl,
    domain: analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
    safetyScore: analysis.safetyScore,
    classification: analysis.classification,
    endpointConfidence: analysis.endpointConfidence,
    providerOverride: Boolean(analysis.providerOverride),
    limitations: (analysis.limitations || []).slice(0, 5)
  };
}

async function persistPostLevelAnalysis(postId, analysis) {
  if (!analysis || analysis.analysisMode === "internal-facebook-ignored") {
    return analysis;
  }

  try {
    const existingBaseline = await getBaseline(postId);
    const storedRecord = existingBaseline
      ? await updatePostAnalysis(postId, analysis)
      : await setBaseline(postId, analysis);

    await appendAnalysisRecord({
      timestamp: Date.now(),
      postId,
      analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
      url: analysis.analysisUrl,
      originalUrl: analysis.normalizedUrl,
      domain: analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
      urlHash: analysis.urlHash,
      postTextHash: analysis.postTextHash,
      previousPostTextHash: analysis.previousPostTextHash,
      currentPostTextHash: analysis.currentPostTextHash,
      baselineFirstSeenAt: analysis.baselineFirstSeenAt,
      detectedAt: analysis.detectedAt,
      hadLinkAtBaseline: analysis.hadLinkAtBaseline,
      linkInsertedAfterBaseline: analysis.linkInsertedAfterBaseline,
      postIntegrityEvent: analysis.postIntegrityEvent,
      baselineState: analysis.baselineState,
      normalizedVisiblePostText: analysis.normalizedVisiblePostText,
      safetyScore: analysis.safetyScore,
      classification: analysis.classification,
      features: analysis.features,
      providerResults: analysis.providerResults,
      endpointResult: analysis.endpointResult,
      endpointConfidence: analysis.endpointConfidence,
      limitations: analysis.limitations,
      providerOverride: Boolean(analysis.providerOverride),
      postIdentityStable: analysis.postIdentityStable === true,
      integrityComparisonStatus: analysis.integrityComparisonStatus,
      state: analysis.state
    });

    return {
      ...analysis,
      ...storedRecord
    };
  } catch (error) {
    return {
      ...analysis,
      limitations: [
        ...(analysis.limitations || []),
        `Storage warning: ${safeErrorMessage(error, "analysis persistence failed")}`
      ].slice(0, 8)
    };
  }
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
  const config = await getRuntimeConfig();
  const checkedAt = Date.now();
  const authKey = String(config.URLHAUS_AUTH_KEY || config.URLHAUS_API_KEY || "").trim();
  const mode = authKey ? "authenticated" : "public";
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded"
  };
  if (authKey) {
    headers["Auth-Key"] = authKey;
  }

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
  await getRuntimeConfig();

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
        finalSite: record.finalSite,
        domain: record.domain || record.finalSite,
        safetyScore: record.safetyScore ?? record.score,
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
    await injectContentScript(activeTab.id);
    return {
      success: true,
      message: "Content script was reconnected; scan will start shortly."
    };
  }
}

async function notifyActiveFacebookTabScanState(enabled) {
  const [activeTab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!activeTab?.id || !isSupportedFacebookUrl(activeTab.url || "")) {
    return;
  }

  try {
    await chrome.tabs.sendMessage(activeTab.id, {
      type: MESSAGE_TYPES.SET_SCAN_STATE,
      enabled
    });
  } catch {
    if (enabled) {
      await injectContentScript(activeTab.id);
    }
  }
}

async function injectContentScript(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        window.__DILI_FORCE_REINIT__ = true;
      }
    });
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"]
    });
  } catch (error) {
    logDebug(`Content script injection fallback failed: ${safeErrorMessage(error, "unknown error")}`);
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

async function getRuntimeConfig() {
  try {
    const stored = await chromeStorageGet([
      "dili:config:gsbApiKey",
      "dili:config:urlhausAuthKey",
      "dili:config:urlhausApiKey"
    ]);

    runtimeConfig.GSB_API_KEY = String(stored["dili:config:gsbApiKey"] || GSB_API_KEY || "").trim();
    runtimeConfig.URLHAUS_AUTH_KEY = String(stored["dili:config:urlhausAuthKey"] || URLHAUS_AUTH_KEY || URLHAUS_API_KEY || "").trim();
    runtimeConfig.URLHAUS_API_KEY = String(stored["dili:config:urlhausApiKey"] || URLHAUS_API_KEY || "").trim();
    runtimeConfig.configLoaded = true;
    runtimeConfig.configSource = hasStoredProviderConfig(stored) ? "chrome.storage.local" : CONFIG_FILE_NAME;
    runtimeConfig.configError = null;
  } catch (error) {
    runtimeConfig.configError = safeErrorMessage(error, "Unable to read runtime provider configuration.");
  }

  applyConfigDiagnostics(runtimeConfig);
  return runtimeConfig;
}

function createRuntimeConfig() {
  return {
    GSB_API_KEY: String(GSB_API_KEY || "").trim(),
    URLHAUS_AUTH_KEY: String(URLHAUS_AUTH_KEY || URLHAUS_API_KEY || "").trim(),
    URLHAUS_API_KEY: String(URLHAUS_API_KEY || "").trim(),
    configLoaded: true,
    configSource: CONFIG_FILE_NAME,
    configError: null
  };
}

function chromeStorageGet(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve(result || {});
    });
  });
}

function hasStoredProviderConfig(stored = {}) {
  return Boolean(
    stored["dili:config:gsbApiKey"] ||
    stored["dili:config:urlhausAuthKey"] ||
    stored["dili:config:urlhausApiKey"]
  );
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

  providerHealth.urlhaus.mode = urlhausAuthKeyLoaded ? "authenticated" : "public";
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
