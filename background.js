import {
  GSB_API_KEY,
  URLHAUS_API_KEY,
  URLHAUS_AUTH_KEY,
  VIRUSTOTAL_API_KEY
} from "./config.local.js";
import { calculateSafetyScore, classifySafetyScore } from "./riskEngine.js";
import { sha256Hex } from "./utils/hash.js";
import { resolveEndpoint } from "./utils/endpointResolver.js";
import { analyzeRedirects } from "./utils/redirectAnalyzer.js";
import { analyzeUrlFeatures, detectDomainMismatch, getRegistrableDomain, normalizeUrl } from "./utils/urlAnalyzer.js";
import {
  appendAnalysisRecord,
  checkDomainPreviouslyFlagged,
  clearAnalysisRecords,
  clearDomainFlagRecords,
  getAllAnalysisRecords,
  getBaseline,
  getScanEnabledState,
  markDomainFlagged,
  setScanEnabledState,
  setBaseline,
  updatePostAnalysis
} from "./utils/storage.js";
const CONFIG_FILE_NAME = "config.local.js";
const DEMO_SCORE_BIAS_STORAGE_KEY = "dili:debug:scoreBiasEnabled";
const DEMO_SCORE_BIAS_AMOUNT_STORAGE_KEY = "dili:debug:scoreBiasAmount";

const MESSAGE_TYPES = {
  ANALYZE_LINK: "DILI_ANALYZE_LINK",
  REANALYZE_LINK: "DILI_REANALYZE_LINK",
  REFRESH_VIRUSTOTAL_RESULT: "DILI_REFRESH_VIRUSTOTAL_RESULT",
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
const performanceStats = {
  lastTotalAnalysisMs: 0,
  lastEndpointMs: 0,
  lastReusableAnalysisMs: 0,
  lastProviderMs: 0,
  lastScoringMs: 0,
  lastStorageMs: 0,
  maxTotalAnalysisMs: 0,
  maxEndpointMs: 0,
  maxProviderMs: 0,
  maxStorageMs: 0,
  lastCacheHit: false,
  lastAnalyzedDomain: "",
  providerCacheHits: 0,
  providerCacheMisses: 0,
  providerInFlightJoins: 0,
  providerRequestsStarted: 0,
  providerRequestsCompleted: 0,
  providerRequestsFailed: 0,
  providerTimeouts: 0,
  providerErrorCacheHits: 0,
  lastProviderCacheStatus: ""
};
const providerHealth = createInitialProviderHealth();
const runtimeConfig = createRuntimeConfig();
const CURRENT_ANALYSIS_SCHEMA_VERSION = 4;
const SESSION_TTL_MS = 60 * 60 * 1000;
const URL_ANALYSIS_CACHE_TTL_MS = 10 * 60 * 1000;
const PROVIDER_RESULT_CACHE_TTL_MS = 10 * 60 * 1000;
const PROVIDER_ERROR_CACHE_TTL_MS = 60 * 1000;
const PROVIDER_PENDING_CACHE_TTL_MS = 15 * 1000;
const PROVIDER_CACHE_MAX_ENTRIES = 300;
const VIRUSTOTAL_MIN_REQUEST_INTERVAL_MS = 20 * 1000;
const VIRUSTOTAL_SOFT_DEADLINE_MS = 2800;
const VIRUSTOTAL_PENDING_FOLLOWUP_INTERVAL_MS = 20 * 1000;
const VIRUSTOTAL_PENDING_TTL_MS = 30 * 60 * 1000;
const urlAnalysisCache = new Map();
const providerResultCache = new Map();
const providerRequestInFlight = new Map();
const virusTotalPendingAnalysisCache = new Map();
let providerCacheGeneration = 0;
let lastVirusTotalRequestAt = 0;
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

if (chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") {
      return;
    }

    const providerConfigKeys = [
    "dili:config:gsbApiKey",
    "dili:config:urlhausAuthKey",
    "dili:config:urlhausApiKey",
    "dili:config:virustotalApiKey",
    DEMO_SCORE_BIAS_STORAGE_KEY,
    DEMO_SCORE_BIAS_AMOUNT_STORAGE_KEY
  ];

    if (!providerConfigKeys.some((key) => Object.prototype.hasOwnProperty.call(changes, key))) {
      return;
    }

    clearProviderCaches({ clearUrlAnalysis: true, clearPendingVirusTotal: true });
    getRuntimeConfig().catch((error) => {
      logDebug(`Provider config refresh after storage change failed: ${safeErrorMessage(error, "unknown error")}`);
    });
  });
}

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

    case MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT:
      return refreshVirusTotalResultForPost(message);

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
  {
    await clearAnalysisRecords();
    const clearedDomainFlags = await clearDomainFlagRecords();
    clearProviderCaches({ clearUrlAnalysis: true });

    logDebug(`Analysis records cleared from storage. Local domain flags cleared: ${clearedDomainFlags}.`);

    return {
      type: MESSAGE_TYPES.CLEAR_ANALYSIS_RECORDS,
      cleared: true,
      clearedDomainFlags
    };
  }

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
  const normalizedVisiblePostText = String(
    message.normalizedVisiblePostText || baseline?.normalizedVisiblePostText || ""
  );

  const baselineState =
    message.baselineState === "truncated_unexpanded"
      ? "truncated_unexpanded"
      : message.baselineState === "observed_no_link_unstable"
        ? "observed_no_link_unstable"
        : "no_link";

  const isConfirmedNoLink = baselineState === "no_link";

  return updatePostAnalysis(message.postId, {
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    baselineState,
    hadLinkAtBaseline: isConfirmedNoLink ? false : null,
    firstSeenAt,
    baselineFirstSeenAt: firstSeenAt,
    lastSeenAt: now,
    lastChecked: now,
    state: isConfirmedNoLink ? "no_link" : "truncated",
    classification: isConfirmedNoLink ? "No Link" : "Caption Collapsed",
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
      noLinkBaseline: isConfirmedNoLink,
      truncatedUnexpanded: !isConfirmedNoLink,
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

  // The post-level result intentionally follows the lowest-scoring successful link
  // so one risky link cannot be hidden by several safe links.
  const worst = analyses
    .slice()
    .sort((left, right) => {
      const leftScore = Number.isFinite(left.safetyScore) ? left.safetyScore : 101;
      const rightScore = Number.isFinite(right.safetyScore) ? right.safetyScore : 101;
      return leftScore - rightScore;
    })[0];
  const linkScoreSummary = analyses.map((item, index) => ({
    index: index + 1,
    url: item.analysisUrl || item.normalizedUrl || "",
    domain:
      item.endpointResult?.effectiveDomain ||
      item.urlFeatureAnalysis?.finalDomain ||
      item.domain ||
      "",
    safetyScore: item.safetyScore,
    classification: item.classification
  })).slice(0, 8);
  const enrichedWorst = {
    ...worst,
    analyzedLinkCount: analyses.length,
    failedLinkCount: limitations.length,
    multiLinkPost: analyses.length > 1,
    lowestScoringLinkUrl: worst.analysisUrl || worst.normalizedUrl || "",
    lowestScoringLinkDomain:
      worst.endpointResult?.effectiveDomain ||
      worst.urlFeatureAnalysis?.finalDomain ||
      worst.domain ||
      "",
    linkScoreSummary
  };
  const persistedWorst = await persistPostLevelAnalysis(postId, enrichedWorst);

  return {
    ...persistedWorst,
    linkAnalyses: analyses.map(compactLiveLinkAnalysis),
    analyzedLinkCount: analyses.length,
    failedLinkCount: limitations.length,
    multiLinkPost: analyses.length > 1,
    lowestScoringLinkUrl: enrichedWorst.lowestScoringLinkUrl,
    lowestScoringLinkDomain: enrichedWorst.lowestScoringLinkDomain,
    linkScoreSummary,
    failedLinkLimitations: limitations,
    limitations: [...(worst.limitations || []), ...limitations].slice(0, 8)
  };
}
async function performSingleLinkAnalysis({ postId, rawUrl, displayedText, candidateContext, postTextHash, normalizedVisiblePostText, isReanalysis, persist = true }) {
  const totalStartedAt = nowMs();

  if (!(await getScanEnabledState())) {
    throw new Error("Scanning is currently disabled.");
  }

  await ensureActiveSession("analysis");

const endpointStartedAt = nowMs();
const endpointResult = await resolveEndpoint(rawUrl);
const endpointMs = elapsedMs(endpointStartedAt);
performanceStats.lastEndpointMs = endpointMs;
recordMaxPerformanceStat("maxEndpointMs", endpointMs);
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
      providerResults: [createDefaultProviderResult("gsb"), createDefaultProviderResult("urlhaus"), createDefaultProviderResult("virustotal")],
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

const reusableStartedAt = nowMs();
const reusableUrlAnalysis = normalizeReusableUrlAnalysis(
  await getReusableUrlAnalysis(rawUrl, urlFeatures, endpointResult, endpointResult?.redirectAnalysis)
);
performanceStats.lastReusableAnalysisMs = elapsedMs(reusableStartedAt);
performanceStats.lastCacheHit = Boolean(reusableUrlAnalysis.cacheHit);
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
  const isDomainOnlyFallbackAnalysis = Boolean(
    normalizedCandidateContext.candidateIsDomainOnlyFallback === true ||
    normalizedCandidateContext.candidateUrlCompleteness === "domain-only-fallback" ||
    /visible-domain/i.test(String(normalizedCandidateContext.candidateSource || ""))
  );
  const currentHash = await sha256Hex(buildStableUrlHashInput({
    analysisUrl,
    normalizedUrl
  }));
  const textComparison = detectDomainMismatch(displayedText || "", analysisUrl);
  const domainPreviouslyFlagged = await checkDomainPreviouslyFlagged(domain);
  const gsbResult = getNormalizedProviderResult(providerResults, "gsb");
  const urlhausResult = getNormalizedProviderResult(providerResults, "urlhaus");
  const virusTotalResult = getNormalizedProviderResult(providerResults, "virustotal");
  const detectedAt = Date.now();
  const baselineFirstSeenAt = Number(existingBaseline?.baselineFirstSeenAt || existingBaseline?.firstSeenAt || detectedAt);
const currentPostTextHash = String(postTextHash || "");
const normalizedCurrentPostText = String(normalizedVisiblePostText || "")
  .replace(/\s+/g, " ")
  .trim();

const previousBaselineState =
  compatibleBaseline?.baselineState ||
  existingBaseline?.baselineState ||
  "";

const canUseNoLinkInjectionBaseline = Boolean(
  isReanalysis &&
  previousBaselineState === "no_link" &&
  compatibleBaseline?.postIdentityStable === true &&
  normalizedCandidateContext.postIdentityStable === true &&
  normalizedCandidateContext.candidateMode === "single"
);

  const linkInsertedAfterBaseline = Boolean(canUseNoLinkInjectionBaseline);
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
  let urlLevelFeatures = applyMainstreamResolvedShortlinkMitigation({
    ...urlLevelFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(urlLevelFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyFacebookWrapperOnlyRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applySameDomainMarketingEncodingMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyKnownBrandedCampaignRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyKnownGoogleFormsRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  const combinedFeaturesBase = {
    ...urlLevelFeatures,
    ...postContextFeatures
  };
  let features = applyMainstreamResolvedShortlinkMitigation({
    ...combinedFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(combinedFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  features = applyFacebookWrapperOnlyRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applySameDomainMarketingEncodingMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyKnownBrandedCampaignRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyKnownGoogleFormsRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  const urlLevelScoring = calculateSafetyScore(urlLevelFeatures);
  const providerOverride = Boolean(gsbResult.flagged || urlhausResult.flagged || virusTotalResult.flagged);
  const urlLevelClassification = providerOverride ? "High Risk" : classifySafetyScore(urlLevelScoring.score);
const scoringStartedAt = nowMs();
const scoring = calculateSafetyScore(features);
performanceStats.lastScoringMs = elapsedMs(scoringStartedAt);
  const endpointResolutionFailed = Boolean(
    !endpointResult?.effectiveEndpoint ||
    endpointResult?.resolutionMethod === "missing-url" ||
    endpointResult?.resolutionMethod === "invalid-url" ||
    (endpointResult?.endpointConfidence === "low" && !endpointResult?.redirectAnalysis?.resolvedUrl && !endpointResult?.resolvedUrl)
  );
  const concreteRiskSignals = Boolean(
    providerOverride ||
    features.integrityHashMismatch ||
    features.googleSafeBrowsingFlagged ||
    features.urlhausFlagged ||
    features.virusTotalFlagged ||
    features.usernamePasswordTrick ||
    features.suspiciousRedirectPattern ||
    features.shortenerToUnrelatedDomain ||
    features.trackingHopToUnrelatedDomain ||
    features.crossDomainRedirectChain ||
    features.textMismatch ||
    features.suspiciousTld ||
    features.suspiciousPath ||
    features.obfuscatedUrl
  );
  const verificationState = endpointResolutionFailed
    ? "unverified"
    : isDomainOnlyFallbackAnalysis
      ? "partial-domain-only"
      : endpointResult?.endpointConfidence === "low"
        ? "low-confidence"
        : "verified";
  const trulyUnresolvedEndpoint = Boolean(endpointResolutionFailed && !endpointResult?.effectiveEndpoint);
  const verificationOnlyUnknown = Boolean(
    !providerOverride &&
    trulyUnresolvedEndpoint &&
    !concreteRiskSignals
  );
  let finalScore = providerOverride ? Math.min(scoring.score, 20) : scoring.score;
  if (!providerOverride && concreteRiskSignals && verificationState === "unverified") {
    finalScore = Math.min(finalScore, 74);
  } else if (!providerOverride && concreteRiskSignals && verificationState === "low-confidence") {
    finalScore = Math.min(finalScore, 79);
  }
  const cappedScore = applySoftUncertaintyCap(finalScore, {
    features,
    endpointResult,
    domain,
    providerOverride
  });
  const softUncertaintyCapApplied = Number(cappedScore) !== Number(finalScore);
  finalScore = cappedScore;
  let finalFeatures = softUncertaintyCapApplied
    ? {
        ...features,
        softUncertaintyCapApplied: true
      }
    : features;
  const originalFinalScore = finalScore;
  const demoScoreBias = await getDemoScoreBiasConfig();
  if (demoScoreBias.enabled) {
    finalScore = Math.max(0, finalScore - demoScoreBias.amount);
    finalFeatures = {
      ...finalFeatures,
      demoScoreBiasApplied: true,
      originalSafetyScore: originalFinalScore,
      demoScoreBiasAmount: demoScoreBias.amount
    };
  }
  const classification = providerOverride
    ? "High Risk"
    : verificationOnlyUnknown
      ? "Unverified"
      : classifySafetyScore(finalScore);
  const interceptionRecommended = shouldRecommendInterceptionForStoredAnalysis({
    classification,
    safetyScore: finalScore,
    features: finalFeatures,
    providerResults
  });
  const nextState = finalFeatures.integrityHashMismatch ? "changed" : "monitored";
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
    verificationState,
    verificationOnlyUnknown,
    concreteRiskSignals,
    interceptionRecommended,
    features: finalFeatures,
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
        currentPostTextHash,
        candidateContext: normalizedCandidateContext,
        features: finalFeatures
      },
      providerResults
    }),
    endpointConfidence: endpointResult.endpointConfidence,
    limitations: buildAnalysisLimitations({ endpointResult, providerResults, candidateContext: normalizedCandidateContext, domain }),
    postIdentityStable: normalizedCandidateContext.postIdentityStable === true,
    integrityComparisonStatus: normalizedCandidateContext.postIdentityStable === true ? "checked" : "skipped-unstable-post-identity",
    redirectAnalysis,
    urlFeatureAnalysis: enrichedUrlFeatures,
    candidateSource: normalizedCandidateContext.candidateSource || "",
    candidateUrlCompleteness: normalizedCandidateContext.candidateUrlCompleteness || "",
    candidateIsDomainOnlyFallback: normalizedCandidateContext.candidateIsDomainOnlyFallback === true,
    lastChecked: Date.now(),
    state: nextState
  };

  if (!record.postIdentityStable) {
    record.limitations = [
      ...(record.limitations || []),
      "Post integrity comparison skipped because no stable Facebook post identity was available."
    ].slice(0, 8);
  }
const storageStartedAt = nowMs();

const storedRecord = persist
  ? existingBaseline
    ? await updatePostAnalysis(postId, record)
    : await setBaseline(postId, record)
  : record;

const storageMs = elapsedMs(storageStartedAt);
performanceStats.lastStorageMs = storageMs;
recordMaxPerformanceStat("maxStorageMs", storageMs);

const providerFlaggedDomain = Boolean(
  gsbResult.flagged ||
  urlhausResult.flagged ||
  virusTotalResult.flagged
);

if (providerFlaggedDomain) {
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
      verificationState,
      verificationOnlyUnknown,
      concreteRiskSignals,
      interceptionRecommended,
      features: finalFeatures,
      providerResults,
      endpointResult,
      endpointConfidence: endpointResult.endpointConfidence,
      limitations: record.limitations,
      providerOverride,
      state: nextState
    });
  }

  sessionInfo.lastActivityAt = Date.now();

  if (finalFeatures.integrityHashMismatch) {
    logDebug(`Edit detection for ${postId}: integrity hash changed.`);
  }

  logDebug(`URL analysis reused=${reusableUrlAnalysis.cacheHit} analysisUrl=${analysisUrl}`);
  logDebug(
    `Provider checks: gsb=${gsbResult.flagged} urlhaus=${urlhausResult.flagged}`
  );
  logDebug(`Scoring result for ${postId}: safety=${finalScore} classification=${classification}`);
const totalMs = elapsedMs(totalStartedAt);
performanceStats.lastTotalAnalysisMs = totalMs;
performanceStats.lastAnalyzedDomain = domain || "";
recordMaxPerformanceStat("maxTotalAnalysisMs", totalMs);

logDebug(
  `Performance: total=${totalMs}ms endpoint=${performanceStats.lastEndpointMs}ms reusable=${performanceStats.lastReusableAnalysisMs}ms provider=${performanceStats.lastProviderMs}ms scoring=${performanceStats.lastScoringMs}ms storage=${performanceStats.lastStorageMs}ms cacheHit=${performanceStats.lastCacheHit}`
);
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

function pickProviderCheckedUrl({ endpointResult = {}, redirectAnalysis = {}, urlFeatures = {} } = {}) {
  const candidates = [
    endpointResult.effectiveEndpoint,
    endpointResult.resolvedUrl,
    redirectAnalysis.resolvedUrl,
    urlFeatures.unwrappedUrl,
    urlFeatures.normalizedUrl
  ];

  const fallbackCandidates = [];

  for (const candidate of candidates) {
    const normalized = normalizeProviderCandidateUrl(candidate);
    if (!normalized) {
      continue;
    }

    fallbackCandidates.push(normalized);

    if (isFacebookWrapperProviderCandidate(normalized)) {
      continue;
    }

    return normalized;
  }

  return fallbackCandidates.find((candidate) => !isFacebookWrapperProviderCandidate(candidate)) || fallbackCandidates[0] || "";
}

function normalizeProviderCandidateUrl(candidate) {
  const value = String(candidate || "").trim();
  if (!value) {
    return "";
  }

  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return "";
    }

    return url.toString();
  } catch {
    return "";
  }
}

function isFacebookWrapperProviderCandidate(candidate) {
  const hostname = safeHostname(candidate);
  return /(^|\.)facebook\.com$/i.test(hostname) && /\/l\.php(?:$|[/?#])/i.test(String(candidate || ""));
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
  const candidateSource = String(candidateContext.candidateSource || fallback.candidateSource || "").trim();
  const candidateUrlCompleteness = String(candidateContext.candidateUrlCompleteness || fallback.candidateUrlCompleteness || "").trim();
  const candidateIsDomainOnlyFallback = candidateContext.candidateIsDomainOnlyFallback === true || fallback.candidateIsDomainOnlyFallback === true;
  const displayText = String(candidateContext.displayText || fallback.displayText || "").trim();
  const visibleText = String(candidateContext.visibleText || fallback.visibleText || displayText || "").trim();
  const rawHref = String(candidateContext.rawHref || fallback.rawHref || "").trim();
  const facebookWrapperUrl = String(candidateContext.facebookWrapperUrl || fallback.facebookWrapperUrl || "").trim();
  const unwrappedCandidateUrl = String(candidateContext.unwrappedCandidateUrl || fallback.unwrappedCandidateUrl || "").trim();

  return {
    candidateMode,
    dominantDomain,
    candidateDomainCount,
    selectedNormalizedTarget,
    postIdentityStable: candidateContext.postIdentityStable === true || fallback.postIdentityStable === true,
    displayText,
    visibleText,
    rawHref,
    facebookWrapperUrl,
    unwrappedCandidateUrl,
    candidateSource,
    candidateUrlCompleteness,
    candidateIsDomainOnlyFallback
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

    const refreshedEntry = await maybeRefreshCachedVirusTotalProviderResult(cachedEntry, urlFeatures);
    const aliasKeys = buildUrlAnalysisCacheKeys(urlFeatures, refreshedEntry.analysisUrl);
    setUrlAnalysisCacheEntry(aliasKeys, stripUrlAnalysisCacheMetadata(refreshedEntry), refreshedEntry.cachedAt);
performanceStats.lastProviderMs = 0;
performanceStats.lastCacheHit = true;
    return {
      ...normalizeReusableUrlAnalysis(refreshedEntry),
      cacheHit: true,
      cacheKey
    };
  }

  const cacheMissKey = initialCacheKeys[0] || normalizeCacheKey(rawUrl) || "unknown-url";
  logDebug(`URL analysis cache miss: ${cacheMissKey}`);

  const safeEndpointResult = endpointResult || {};
  const safeRedirectAnalysis = normalizeRedirectAnalysis(redirectAnalysis || endpointResult?.redirectAnalysis || await analyzeRedirects(rawUrl));
  const analysisUrl = endpointResult?.effectiveEndpoint || resolveAnalysisUrl(urlFeatures, safeRedirectAnalysis);
  const providerCheckedUrl = pickProviderCheckedUrl({
    endpointResult: safeEndpointResult,
    redirectAnalysis: safeRedirectAnalysis,
    urlFeatures
  }) || analysisUrl;
  const domain = safeHostname(analysisUrl || urlFeatures.normalizedUrl);
  const analysisUrlFeatures = analyzeUrlFeatures({
    rawUrl: analysisUrl
  });
const providerStartedAt = nowMs();
const providerResults = normalizeProviderResults(await runThreatIntelligenceChecks(providerCheckedUrl));
const providerMs = elapsedMs(providerStartedAt);
performanceStats.lastProviderMs = providerMs;
recordMaxPerformanceStat("maxProviderMs", providerMs);
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
    providerCheckedUrl,
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

async function maybeRefreshCachedVirusTotalProviderResult(cachedEntry = {}, urlFeatures = {}) {
  const providerResults = normalizeProviderResults(cachedEntry.providerResults || []);
  const vt = providerResults.find((item) => item.provider === "virustotal");

  if (String(vt?.details?.status || "").toLowerCase() !== "pending") {
    return cachedEntry;
  }

  const config = await getRuntimeConfig();
  if (!String(config.VIRUSTOTAL_API_KEY || "").trim()) {
    return cachedEntry;
  }

  const checkedAtMs = Date.parse(vt.checkedAt || "");
  const cacheAgeMs = Number(vt.details?.cacheAgeMs);
  const oldEnough = Number.isFinite(cacheAgeMs)
    ? cacheAgeMs >= VIRUSTOTAL_PENDING_FOLLOWUP_INTERVAL_MS
    : Number.isFinite(checkedAtMs) && Date.now() - checkedAtMs >= VIRUSTOTAL_PENDING_FOLLOWUP_INTERVAL_MS;

  if (!oldEnough) {
    return cachedEntry;
  }

  const providerCheckedUrl =
    vt.checkedUrl ||
    cachedEntry.providerCheckedUrl ||
    cachedEntry.analysisUrl ||
    urlFeatures.normalizedUrl ||
    "";

  if (!providerCheckedUrl) {
    return cachedEntry;
  }

  const refreshedVt = await getCachedOrInFlightProviderResult(
    "virustotal",
    providerCheckedUrl,
    () => lookupVirusTotalUrl(providerCheckedUrl)
  );
  const nextProviderResults = providerResults.map((item) => (
    item.provider === "virustotal" ? refreshedVt : item
  ));
  const nextEntry = {
    ...cachedEntry,
    providerResults: nextProviderResults
  };
  const cacheKeys = buildUrlAnalysisCacheKeys(urlFeatures, cachedEntry.analysisUrl);
  setUrlAnalysisCacheEntry(cacheKeys, stripUrlAnalysisCacheMetadata(nextEntry), cachedEntry.cachedAt || Date.now());

  return nextEntry;
}

function buildUrlLevelFeatures({ redirectAnalysis, providerResults, urlFeatureAnalysis }) {
  const safeProviderResults = normalizeProviderResults(providerResults);
  const safeRedirectAnalysis = normalizeRedirectAnalysis(redirectAnalysis);
  const safeUrlFeatureAnalysis = urlFeatureAnalysis || {};
  const gsbResult = safeProviderResults.find((item) => item.provider === "gsb");
  const urlhausResult = safeProviderResults.find((item) => item.provider === "urlhaus");
  const virusTotalResult = safeProviderResults.find((item) => item.provider === "virustotal");

  const baseFeatures = {
    googleSafeBrowsingFlagged: gsbResult.flagged,
    urlhausFlagged: urlhausResult.flagged,
    virusTotalFlagged: virusTotalResult.flagged,
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

  if (features.googleSafeBrowsingFlagged || features.urlhausFlagged || features.virusTotalFlagged) {
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
  const gsb = values.find((item) => item?.provider === "gsb") || createDefaultProviderResult("gsb", "");
  const urlhaus = values.find((item) => item?.provider === "urlhaus") || createDefaultProviderResult("urlhaus", "");
  const virustotal = values.find((item) => item?.provider === "virustotal") || createDefaultProviderResult("virustotal", "");
  return [gsb, urlhaus, virustotal];
}

function getNormalizedProviderResult(providerResults, providerName) {
  return normalizeProviderResults(providerResults).find((item) => item.provider === providerName) || createDefaultProviderResult(providerName, "");
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
    fetchMethod: safe.fetchMethod || "",
    fetchStatus: safe.fetchStatus || "",
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
// This is a conservative local allowlist for high-confidence HTTPS shortlinks
// resolving to well-known destinations. It does not override provider flags,
// suspicious paths, suspicious TLDs, text mismatch, or post-integrity changes.
function applyMainstreamResolvedShortlinkMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const resolutionChain = Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
    ? endpointResult.resolutionChain
    : reusableUrlAnalysis.redirectAnalysis?.redirectChain || [];
  const sourceDomain = getRedirectSourceDomain(resolutionChain);
  const knownShortenerOwnerRedirect = isKnownShortenerToOwnerDestination(sourceDomain, finalDomain);
  const mainstreamDomains = new Set([
    // Common global/social/e-commerce destinations
    "tiktok.com",
    "shopee.ph",
    "shopee.com",
    "lazada.com.ph",
    "lazada.com",
    "youtube.com",
    "youtu.be",
    "amazon.com",
    "instagram.com",
    "facebook.com",
    "messenger.com",

    // Common Philippine legitimate service destinations often used in ads/promos
    "dito.ph",
    "globe.com.ph",
    "smart.com.ph",
    "pldt.com",
    "gcash.com",
    "maya.ph",
    "bpi.com.ph",
    "bdo.com.ph",
    "securitybank.com",
    "unionbankph.com"
  ]);
  const confidence = String(endpointResult?.endpointConfidence || "").toLowerCase();
  const isEligible = Boolean(
    features.shortenedUrl &&
    (mainstreamDomains.has(finalDomain) || knownShortenerOwnerRedirect) &&
    ["high", "medium"].includes(confidence) &&
    features.httpsEndpoint &&
    !features.googleSafeBrowsingFlagged &&
    !features.urlhausFlagged &&
    !features.virusTotalFlagged &&
    !features.suspiciousPath &&
    !features.suspiciousTld &&
    !features.usernamePasswordTrick &&
    (!features.textMismatch || knownShortenerOwnerRedirect) &&
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
    textMismatch: knownShortenerOwnerRedirect ? false : features.textMismatch,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: true,
    mainstreamResolvedShortlink: true,
    knownShortenerOwnerRedirect
  };
}

function getRiskRelevantRedirectChain(chain = []) {
  return buildRiskRelevantRedirectChain(chain);
}

function getRegistrableDomainsFromChain(chain = []) {
  return [...new Set(
    (Array.isArray(chain) ? chain : [])
      .map((url) => getRegistrableDomain(safeHostname(url)))
      .filter(Boolean)
  )];
}

function isSameDomainOrTrackingCleanupRedirect({ endpointResult, redirectAnalysis, finalDomain }) {
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(redirectAnalysis?.redirectChain)
        ? redirectAnalysis.redirectChain
        : [];

  const riskChain = getRiskRelevantRedirectChain(rawChain);
  const riskDomains = getRegistrableDomainsFromChain(riskChain);

  if (riskDomains.length <= 1 && finalDomain && riskDomains[0] === finalDomain) {
    return true;
  }

  return false;
}

function applyFacebookWrapperOnlyRedirectMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const providerFlagged = Boolean(features.googleSafeBrowsingFlagged || features.urlhausFlagged || features.virusTotalFlagged);
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const sameDomainTrackingCleanup = isSameDomainOrTrackingCleanupRedirect({
    endpointResult,
    redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
    finalDomain
  });

  if (!sameDomainTrackingCleanup || providerFlagged) {
    return features;
  }

  return {
    ...features,
    crossDomainRedirectChain: false,
    redirectChainToDifferentRegistrantLikeTarget: false,
    suspiciousRedirectPattern: false,
    shortenerToUnrelatedDomain: false,
    trackingHopToUnrelatedDomain: false,
    wrapperToExternalDestination: false
  };
}

function applySameDomainMarketingEncodingMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const providerFlagged = Boolean(features.googleSafeBrowsingFlagged || features.urlhausFlagged || features.virusTotalFlagged);
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const sameDomainTrackingCleanup = isSameDomainOrTrackingCleanupRedirect({
    endpointResult,
    redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
    finalDomain
  });

  const eligible = Boolean(
    sameDomainTrackingCleanup &&
    !providerFlagged &&
    features.httpsEndpoint &&
    !features.shortenedUrl &&
    !features.suspiciousTld &&
    !features.suspiciousPath &&
    !features.usernamePasswordTrick &&
    !features.integrityHashMismatch
  );

  if (!eligible) {
    return features;
  }

  return {
    ...features,
    obfuscatedUrl: false,
    excessiveQueryComplexity: false
  };
}

const KNOWN_BRANDED_CAMPAIGN_REDIRECTS = [
  {
    sourceDomain: "hoyo.link",
    allowedFinalDomains: ["twitch.tv", "youtube.com", "hoyoverse.com", "hoyolab.com"],
    requiredPathHints: ["genshinimpactofficial", "hoyoverse", "hoyolab", "genshin"]
  }
];

function applyKnownBrandedCampaignRedirectMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const finalUrl = endpointResult?.effectiveEndpoint || reusableUrlAnalysis.analysisUrl || "";
  const eligible = Boolean(
    isKnownBrandedCampaignRedirect({
      endpointResult,
      redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
      finalDomain,
      finalUrl
    }) &&
    !features.googleSafeBrowsingFlagged &&
    !features.urlhausFlagged &&
    !features.virusTotalFlagged &&
    features.httpsEndpoint &&
    !features.suspiciousTld &&
    !features.suspiciousPath &&
    !features.usernamePasswordTrick &&
    !features.integrityHashMismatch &&
    !features.rawIpHost &&
    !features.suspiciousFileExtension
  );

  if (!eligible) {
    return features;
  }

  return {
    ...features,
    suspiciousRedirectPattern: false,
    shortenerToUnrelatedDomain: false,
    trackingHopToUnrelatedDomain: false,
    crossDomainRedirectChain: false,
    redirectChainToDifferentRegistrantLikeTarget: false,
    wrapperToExternalDestination: false,
    textMismatch: false,
    obfuscatedUrl: false,
    excessiveQueryComplexity: false,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: true,
    knownBrandedCampaignRedirect: true
  };
}

function applyKnownGoogleFormsRedirectMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const finalUrl = endpointResult?.effectiveEndpoint || reusableUrlAnalysis.analysisUrl || "";
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(reusableUrlAnalysis.redirectAnalysis?.redirectChain)
        ? reusableUrlAnalysis.redirectAnalysis.redirectChain
        : [];
  const sourceDomain = getRedirectSourceDomain(rawChain);
  const isFormsGleRedirect = sourceDomain === "forms.gle";
  const isGenericShortenerFormsRedirect = Boolean(!isFormsGleRedirect && features.shortenedUrl);
  const eligible = Boolean(
    (
      isKnownGoogleFormsRedirect({
        endpointResult,
        redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
        finalDomain,
        finalUrl
      }) ||
      (
        isKnownGoogleFormsFinalEndpoint(finalUrl, finalDomain) &&
        isGenericShortenerFormsRedirect
      )
    ) &&
    !features.googleSafeBrowsingFlagged &&
    !features.urlhausFlagged &&
    !features.virusTotalFlagged &&
    features.httpsEndpoint &&
    !features.suspiciousTld &&
    !features.usernamePasswordTrick &&
    !features.integrityHashMismatch &&
    !features.rawIpHost &&
    !features.suspiciousFileExtension
  );

  if (!eligible) {
    return features;
  }

  return {
    ...features,
    suspiciousRedirectPattern: false,
    shortenerToUnrelatedDomain: false,
    trackingHopToUnrelatedDomain: false,
    crossDomainRedirectChain: false,
    redirectChainToDifferentRegistrantLikeTarget: false,
    wrapperToExternalDestination: false,
    textMismatch: false,
    obfuscatedUrl: false,
    excessiveQueryComplexity: false,
    knownGoogleFormsRedirect: true,
    softExternalFormCaution: true,
    googleFormsViaGenericShortener: isGenericShortenerFormsRedirect
  };
}

function isKnownGoogleFormsFinalEndpoint(finalUrl = "", finalDomain = "") {
  const domain = getRegistrableDomain(finalDomain || safeHostname(finalUrl));
  const text = String(finalUrl || "").toLowerCase();

  return (
    domain === "google.com" &&
    /docs\.google\.com\/forms\//i.test(text)
  );
}

function isKnownGoogleFormsRedirect({ endpointResult = {}, redirectAnalysis = {}, finalDomain = "", finalUrl = "" } = {}) {
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(redirectAnalysis?.redirectChain)
        ? redirectAnalysis.redirectChain
        : [];
  const sourceDomain = getRedirectSourceDomain(rawChain);

  return (
    sourceDomain === "forms.gle" &&
    isKnownGoogleFormsFinalEndpoint(finalUrl, finalDomain)
  );
}

function applySoftUncertaintyCap(finalScore, {
  features = {},
  endpointResult = {},
  domain = "",
  providerOverride = false
} = {}) {
  let score = Number(finalScore);

  if (!Number.isFinite(score)) {
    return finalScore;
  }

  if (providerOverride) {
    return score;
  }

  const effectiveDomain = getRegistrableDomain(endpointResult?.effectiveDomain || domain || "");
  const isMessagingPlatform = isMessagingOrCommunityInviteDomain(effectiveDomain);

  if (score === 100 && isMessagingPlatform) {
    score = 95;
  }

  if (score === 100 && features.knownBrandedCampaignRedirect) {
    score = 95;
  }

  if (score === 100 && features.knownGoogleFormsRedirect) {
    score = 90;
  }

  return score;
}

function isKnownBrandedCampaignRedirect({ endpointResult = {}, redirectAnalysis = {}, finalDomain = "", finalUrl = "" } = {}) {
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(redirectAnalysis?.redirectChain)
        ? redirectAnalysis.redirectChain
        : [];
  const sourceDomain = getRedirectSourceDomain(rawChain);
  const normalizedFinalDomain = getRegistrableDomain(finalDomain);
  const finalText = String(finalUrl || "").toLowerCase();

  for (const rule of KNOWN_BRANDED_CAMPAIGN_REDIRECTS) {
    if (sourceDomain !== rule.sourceDomain) {
      continue;
    }

    if (!rule.allowedFinalDomains.includes(normalizedFinalDomain)) {
      continue;
    }

    if (
      Array.isArray(rule.requiredPathHints) &&
      rule.requiredPathHints.length > 0 &&
      !rule.requiredPathHints.some((hint) => finalText.includes(String(hint).toLowerCase()))
    ) {
      continue;
    }

    return true;
  }

  return false;
}

function getKnownShortenerOwnerDomain(shortenerDomain) {
  const normalized = String(shortenerDomain || "")
    .toLowerCase()
    .replace(/^www\./, "");

  const map = {
    "amzn.to": "amazon.com",
    "youtu.be": "youtube.com",
    "fb.me": "facebook.com",
    "t.co": "x.com"
  };

  return map[normalized] || "";
}

function isKnownShortenerToOwnerDestination(sourceDomain, finalDomain) {
  const source = String(sourceDomain || "").toLowerCase().replace(/^www\./, "");
  const finalValue = String(finalDomain || "").toLowerCase().replace(/^www\./, "");
  const owner = getKnownShortenerOwnerDomain(source);

  if (!owner) {
    return false;
  }

  return finalValue === owner || finalValue.endsWith(`.${owner}`);
}

function getRedirectSourceDomain(chain = []) {
  const values = Array.isArray(chain) ? chain : [];
  for (const url of values) {
    if (isFacebookPlatformWrapperUrl(url)) {
      continue;
    }

    const domain = getRegistrableDomain(safeHostname(url));
    if (domain) {
      return domain;
    }
  }

  return "";
}

function buildAnalysisLimitations({ endpointResult, providerResults, candidateContext = {}, domain = "" }) {
  const limitations = [];
  const safeProviderResults = normalizeProviderResults(providerResults);
  const gsb = safeProviderResults.find((item) => item.provider === "gsb");
  const urlhaus = safeProviderResults.find((item) => item.provider === "urlhaus");

  if (!gsb.configured) {
    limitations.push("Google Safe Browsing is not configured.");
  } else if (gsb.details?.status === "error") {
    limitations.push("Google Safe Browsing lookup returned an error.");
  } else if (gsb.configured === true && gsb.checked === true && gsb.details?.status === "checked" && gsb.flagged !== true) {
    limitations.push("Google Safe Browsing completed its endpoint check and did not report this URL as unsafe.");
  }

  if (urlhaus.details?.status === "error") {
    limitations.push("URLhaus public lookup was unavailable.");
  } else if (urlhaus.details?.authKeyConfigured === false || urlhaus.details?.authConfigured === false) {
    limitations.push("URLhaus was checked in public mode.");
  }

  if (!endpointResult?.effectiveEndpoint) {
    limitations.push("DILI could not confidently resolve the final endpoint.");
  }

  const effectiveDomain = getRegistrableDomain(endpointResult?.effectiveDomain || domain || "");
  if (isMessagingOrCommunityInviteDomain(effectiveDomain)) {
    limitations.push("DILI verified the link destination, but it cannot verify the trustworthiness of content inside this messaging or community platform.");
  }

  if (
    candidateContext?.candidateIsDomainOnlyFallback === true ||
    candidateContext?.candidateUrlCompleteness === "domain-only-fallback" ||
    /visible-domain/i.test(String(candidateContext?.candidateSource || ""))
  ) {
    limitations.push("Facebook did not expose a full clickable URL for this card, so DILI checked the visible domain only.");
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
function formatCompactRedirectChainDetail(chain = []) {
  const urls = Array.isArray(chain)
    ? chain.map((url) => String(url || "").trim()).filter(Boolean)
    : [];

  if (urls.length === 0) {
    return "";
  }

  const domains = urls
    .map((url) => safeHostname(url).replace(/^www\./i, ""))
    .filter(Boolean);

  if (domains.length === 0) {
    return "";
  }

  const compactDomains = [];
  for (const domain of domains) {
    if (compactDomains[compactDomains.length - 1] !== domain) {
      compactDomains.push(domain);
    }
  }

  const hopCount = Math.max(urls.length - 1, 0);
  const hopText = hopCount === 1 ? "1 redirect hop" : `${hopCount} redirect hops`;

  if (compactDomains.length === 1) {
    return hopCount > 0
      ? `Redirect chain: ${compactDomains[0]} only (${hopText}; same-domain redirect or tracking cleanup).`
      : `Redirect chain: ${compactDomains[0]} only (no redirect hop observed).`;
  }

  return `Redirect chain: ${compactDomains.join(" -> ")} (${hopText}).`;
}

function isMessagingOrCommunityInviteDomain(domain) {
  const value = String(domain || "").toLowerCase().replace(/^www\./, "");
  return [
    "t.me",
    "telegram.me",
    "discord.gg",
    "discord.com",
    "whatsapp.com",
    "wa.me"
  ].includes(value);
}

function shouldShowRedirectNoteAfterMitigation(note, features = {}) {
  const text = String(note || "");
  const isHarshRedirectWarning =
    /multiple redirects|hands the user across different domains|commonly seen in deceptive links|different website/i.test(text);

  if (!isHarshRedirectWarning) {
    return true;
  }

  const explicitlyMitigated = Boolean(
    features.knownBrandedCampaignRedirect ||
    features.knownGoogleFormsRedirect ||
    features.googleFormsViaGenericShortener ||
    features.mainstreamResolvedShortlink ||
    features.knownShortenerOwnerRedirect ||
    features.softExternalFormCaution ||
    features.trustedEndpointMitigationEligible
  );

  if (explicitlyMitigated) {
    return false;
  }

  return Boolean(
    features.suspiciousRedirectPattern ||
    features.shortenerToUnrelatedDomain ||
    features.trackingHopToUnrelatedDomain ||
    features.redirectChainToDifferentRegistrantLikeTarget ||
    features.crossDomainRedirectChain
  );
}

function isFacebookPlatformWrapperUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    return /(^|\.)facebook\.com$/i.test(url.hostname) && /\/l\.php(?:$|[/?#])/i.test(url.pathname);
  } catch {
    return false;
  }
}

function buildRiskRelevantRedirectChain(chain = []) {
  return (Array.isArray(chain) ? chain : []).filter((url) => !isFacebookPlatformWrapperUrl(url));
}

function prependKnownFacebookWrapperForDisplay(chain = [], facebookWrapperUrl = "") {
  const values = Array.isArray(chain) ? chain.filter(Boolean) : [];
  if (!facebookWrapperUrl || values.some((url) => String(url || "") === String(facebookWrapperUrl))) {
    return values;
  }

  return [facebookWrapperUrl, ...values];
}

function looksLikeUsefulVisibleDestinationText(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();

  if (!text) {
    return false;
  }

  if (isFacebookPlatformWrapperUrl(text)) {
    return false;
  }

  if (/^facebook\.com$/i.test(text) || /^www\.facebook\.com$/i.test(text)) {
    return false;
  }

  if (/^[a-z0-9_-]{20,}$/i.test(text) && !/[./:]/.test(text)) {
    return false;
  }

  if (getHostnameFromUrlOrDomainText(text)) {
    return true;
  }

  return /\b(?:https?:\/\/|www\.)?[a-z0-9][a-z0-9.-]*\.(?:com|net|org|ph|app|ai|edu|gov|io|me|page|shop|site|store|xyz)\b/i.test(text);
}

function getHostnameFromUrlOrDomainText(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }

  try {
    if (/^https?:\/\//i.test(text)) {
      return new URL(text).hostname.toLowerCase();
    }

    if (/^(?:www\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[/?#].*)?$/i.test(text)) {
      return new URL(`https://${text.replace(/^\/+/, "")}`).hostname.toLowerCase();
    }
  } catch {
    return "";
  }

  return "";
}

function buildTechnicalDetails({ endpointResult = {}, redirectAnalysis = {}, urlFeatureAnalysis = {}, analysis = {}, providerResults = [] } = {}) {
  const details = [];
  const effectiveDomain = endpointResult.effectiveDomain || urlFeatureAnalysis.finalDomain || "";
  const candidateContext = analysis.candidateContext || {};
  const finalFeatures = analysis.features || {};
  const isDomainOnlyFallbackAnalysis = Boolean(
    candidateContext?.candidateIsDomainOnlyFallback === true ||
    candidateContext?.candidateUrlCompleteness === "domain-only-fallback" ||
    /visible-domain/i.test(String(candidateContext?.candidateSource || ""))
  );
const redirectChain =
  redirectAnalysis.redirectChain ||
  endpointResult.resolutionChain ||
  [];
  if (endpointResult.isFacebookWrapper && effectiveDomain) {
    details.push(`Facebook wrapper unwrapped to ${effectiveDomain}.`);
  }

if (redirectChain.length > 0) {
  const visiblePostValue =
    candidateContext.unwrappedCandidateUrl ||
    candidateContext.selectedNormalizedTarget ||
    endpointResult.unwrappedUrl ||
    (looksLikeUsefulVisibleDestinationText(candidateContext.visibleText) ? candidateContext.visibleText : "") ||
    (looksLikeUsefulVisibleDestinationText(candidateContext.displayText) ? candidateContext.displayText : "") ||
    "unknown";
  if (visiblePostValue !== "unknown" && !isFacebookPlatformWrapperUrl(visiblePostValue)) {
    details.push(`Visible post URL/text: ${visiblePostValue}.`);
  }

  const facebookWrapperUrl = candidateContext.facebookWrapperUrl || (endpointResult.isFacebookWrapper ? endpointResult.rawUrl : "");
  if (facebookWrapperUrl) {
    details.push(`Facebook click wrapper URL: ${facebookWrapperUrl}.`);
  }

  if (endpointResult.unwrappedUrl) {
    details.push(`Unwrapped URL: ${endpointResult.unwrappedUrl}.`);
  }

  if (endpointResult.effectiveEndpoint && !isDomainOnlyFallbackAnalysis) {
    details.push(`Full endpoint URL: ${endpointResult.effectiveEndpoint}.`);
  } else if (endpointResult.effectiveEndpoint && isDomainOnlyFallbackAnalysis) {
    details.push(`Checked fallback URL: ${endpointResult.effectiveEndpoint}.`);
  }

const observedRedirectChain = prependKnownFacebookWrapperForDisplay(redirectChain, facebookWrapperUrl);
const observedRedirectChainDetail = formatCompactRedirectChainDetail(observedRedirectChain);
if (observedRedirectChainDetail) {
  details.push(observedRedirectChainDetail.replace(/^Redirect chain:/, "Observed redirect chain:"));
}

const riskRelevantRedirectChain = buildRiskRelevantRedirectChain(observedRedirectChain);
const riskRelevantRedirectChainDetail = formatCompactRedirectChainDetail(riskRelevantRedirectChain);
if (
  riskRelevantRedirectChainDetail &&
  riskRelevantRedirectChain.length > 0 &&
  riskRelevantRedirectChain.length !== observedRedirectChain.length
) {
  details.push(riskRelevantRedirectChainDetail.replace(/^Redirect chain:/, "Risk-relevant redirect chain:"));
}
}
  if (urlFeatureAnalysis.sourceNormalizedUrl && urlFeatureAnalysis.sourceRawComparableUrl && urlFeatureAnalysis.sourceNormalizedUrl !== urlFeatureAnalysis.sourceRawComparableUrl) {
    details.push("Tracking parameters were stripped for comparison.");
  }

  if (endpointResult.endpointConfidence) {
    details.push(`Endpoint confidence: ${endpointResult.endpointConfidence}.`);
  }

  if (isMessagingOrCommunityInviteDomain(getRegistrableDomain(effectiveDomain))) {
    details.push("DILI verified the link destination, but it cannot verify the trustworthiness of content inside this messaging or community platform.");
  }

  if (finalFeatures.knownBrandedCampaignRedirect) {
    details.push("Known branded campaign redirect recognized; DILI treated the redirect as lower risk because providers were clean and the final destination matched an expected campaign platform.");
  }

  if (finalFeatures.knownGoogleFormsRedirect) {
    details.push("Known Google Forms redirect recognized; DILI treated the redirect as lower risk because providers were clean and the final destination matched docs.google.com/forms.");
  }

  if (finalFeatures.googleFormsViaGenericShortener) {
    details.push("Google Forms final endpoint recognized through a generic shortener; DILI treated redirect mechanics as lower risk because providers were clean, but form ownership should still be verified.");
  }

  if (finalFeatures.softUncertaintyCapApplied) {
    details.push("Safety score was softly capped because DILI can verify URL reputation, but some destination content remains outside URL-reputation scope.");
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

  if (
    isDomainOnlyFallbackAnalysis
  ) {
    details.push("Candidate source: visible-domain-fallback.");
    details.push("Endpoint source note: Facebook did not expose a full clickable URL for this card, so DILI checked the visible domain only.");
    details.push("Provider checked scope: visible domain only.");
    details.push("Full endpoint extraction status: No full path/query URL was exposed during passive scan.");
    details.push("Click-time note: If the user clicks this card, DILI will re-check the actual clicked destination before navigation.");
  }

  for (const note of redirectAnalysis?.notes || []) {
    const text = String(note || "").trim();
    if (text && shouldShowRedirectNoteAfterMitigation(text, finalFeatures)) {
      details.push(text);
    }
  }

const providerLabels = {
  gsb: "Google Safe Browsing",
  urlhaus: "URLhaus",
  virustotal: "VirusTotal"
};

for (const provider of normalizeProviderResults(providerResults)) {
  if (provider.provider === "virustotal" && !isVirusTotalResultDisplayRelevant(provider)) {
    continue;
  }

  if (!provider?.checkedUrl) {
    continue;
  }

  const label = providerLabels[provider.provider] || provider.provider || "Provider";
  const auditStatus = getProviderAuditStatus(provider);
  const outcomeSummary = provider.resultSummary || getProviderOutcomeSummary(provider);
  const durationMs = Number(provider.durationMs);

  details.push(`${label} checked URL: ${provider.checkedUrl}.`);
  details.push(`${label} result: ${outcomeSummary}`);
  details.push(`${label} status: ${auditStatus}.`);

  if (provider.checkedAt) {
    details.push(`${label} checked at: ${provider.checkedAt}.`);
  }

  if (Number.isFinite(durationMs)) {
    details.push(`${label} response time: ${durationMs} ms`);
  }

  if (provider.details?.fromCache === true || provider.details?.cacheStatus === "hit") {
    details.push(`${label} cache: reused recent result.`);
  }

  if (provider.provider === "virustotal" && auditStatus === "completed") {
    if (Number.isFinite(Number(provider.details?.maliciousCount))) {
      details.push(`${label} malicious detections: ${Number(provider.details.maliciousCount)}.`);
    }
    if (Number.isFinite(Number(provider.details?.suspiciousCount))) {
      details.push(`${label} suspicious detections: ${Number(provider.details.suspiciousCount)}.`);
    }
  }
}
  return [...new Set(details)];

}

function isVirusTotalResultDisplayRelevant(provider = {}) {
  const status = String(provider.details?.status || "").toLowerCase();
  return Boolean(
    provider.configured ||
    provider.checked ||
    provider.flagged ||
    ["pending", "rate-limited", "error", "timeout", "parse-error", "checked"].includes(status)
  );
}

function shouldRecommendInterceptionForStoredAnalysis(analysis = {}) {
  const features = analysis.features || {};
  const score = Number(analysis.safetyScore);
  const classification = String(analysis.classification || "").toLowerCase();
  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const gsb = providerResults.find((item) => item.provider === "gsb");
  const urlhaus = providerResults.find((item) => item.provider === "urlhaus");
  const virusTotal = providerResults.find((item) => item.provider === "virustotal");

  if (gsb?.flagged || urlhaus?.flagged || virusTotal?.flagged) {
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

function compactLiveLinkAnalysis(analysis = {}) {
  return {
    analysisUrl: analysis.analysisUrl,
    normalizedUrl: analysis.normalizedUrl,
    domain: analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
    safetyScore: analysis.safetyScore,
    classification: analysis.classification,
    endpointConfidence: analysis.endpointConfidence,
    providerOverride: Boolean(analysis.providerOverride),
    verificationState: analysis.verificationState,
    interceptionRecommended: analysis.interceptionRecommended,
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
      analyzedLinkCount: analysis.analyzedLinkCount,
      failedLinkCount: analysis.failedLinkCount,
      multiLinkPost: analysis.multiLinkPost,
      lowestScoringLinkDomain: analysis.lowestScoringLinkDomain,
      lowestScoringLinkUrl: analysis.lowestScoringLinkUrl,
      linkScoreSummary: analysis.linkScoreSummary,
      features: analysis.features,
      providerResults: analysis.providerResults,
      endpointResult: analysis.endpointResult,
      endpointConfidence: analysis.endpointConfidence,
      limitations: analysis.limitations,
      providerOverride: Boolean(analysis.providerOverride),
      verificationState: analysis.verificationState,
      verificationOnlyUnknown: analysis.verificationOnlyUnknown,
      concreteRiskSignals: analysis.concreteRiskSignals,
      interceptionRecommended: analysis.interceptionRecommended,
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

function clearProviderCaches({ clearUrlAnalysis = false, clearPendingVirusTotal = false } = {}) {
  providerCacheGeneration += 1;
  providerResultCache.clear();
  providerRequestInFlight.clear();
  if (clearPendingVirusTotal) {
    virusTotalPendingAnalysisCache.clear();
  }

  if (clearUrlAnalysis) {
    urlAnalysisCache.clear();
  }

  logDebug("Provider cache cleared.");
}

function getProviderCacheKey(providerName, checkedUrl) {
  const provider = String(providerName || "").trim().toLowerCase();
  const url = String(checkedUrl || "").trim();
  if (!provider || !url) {
    return "";
  }

  return `${provider}::${url}`;
}

function getProviderCacheEntry(providerName, checkedUrl) {
  pruneProviderResultCache();
  const cacheKey = getProviderCacheKey(providerName, checkedUrl);
  if (!cacheKey) {
    return null;
  }

  const entry = providerResultCache.get(cacheKey);
  if (!entry) {
    return null;
  }

  if (entry.expiresAt <= Date.now()) {
    providerResultCache.delete(cacheKey);
    return null;
  }

  const ageMs = Math.max(0, Date.now() - Number(entry.cachedAt || Date.now()));
  const result = cloneProviderResultForCache(entry.providerResult);
  result.details = {
    ...(result.details || {}),
    fromCache: true,
    cacheAgeMs: ageMs,
    cacheStatus: "hit"
  };

  return result;
}

function setProviderCacheEntry(providerName, checkedUrl, providerResult, ttlMs) {
  const cacheKey = getProviderCacheKey(providerName, checkedUrl);
  if (!cacheKey || !providerResult || !ttlMs || ttlMs <= 0) {
    return;
  }

  const storedResult = cloneProviderResultForCache(providerResult);
  storedResult.details = {
    ...(storedResult.details || {}),
    fromCache: false,
    cacheStatus: "stored"
  };

  const cachedAt = Date.now();
  providerResultCache.set(cacheKey, {
    cachedAt,
    expiresAt: cachedAt + ttlMs,
    providerResult: storedResult
  });

  pruneProviderResultCache();
}

function pruneProviderResultCache() {
  const now = Date.now();

  for (const [cacheKey, entry] of providerResultCache.entries()) {
    if (entry.expiresAt <= now) {
      providerResultCache.delete(cacheKey);
    }
  }

  while (providerResultCache.size > PROVIDER_CACHE_MAX_ENTRIES) {
    const oldestKey = providerResultCache.keys().next().value;
    if (!oldestKey) {
      break;
    }
    providerResultCache.delete(oldestKey);
  }
}

function cloneProviderResultForCache(providerResult) {
  return cloneValue(providerResult || {});
}

function getProviderResultCacheTtl(providerResult) {
  const status = String(providerResult?.details?.status || "").toLowerCase();

  if (!providerResult?.checkedUrl) {
    return 0;
  }

  if (status === "not-configured" || status === "skipped") {
    return 0;
  }

  if (status === "pending") {
    return PROVIDER_PENDING_CACHE_TTL_MS;
  }

  if (status === "error" || status === "timeout" || status === "rate-limited" || status === "parse-error") {
    return PROVIDER_ERROR_CACHE_TTL_MS;
  }

  return PROVIDER_RESULT_CACHE_TTL_MS;
}

async function getCachedOrInFlightProviderResult(providerName, checkedUrl, lookupFn) {
  const cacheKey = getProviderCacheKey(providerName, checkedUrl);
  if (!cacheKey) {
    performanceStats.providerCacheMisses += 1;
    performanceStats.lastProviderCacheStatus = "miss-invalid-key";
    return lookupFn();
  }

  const cachedResult = getProviderCacheEntry(providerName, checkedUrl);
  if (cachedResult) {
    performanceStats.providerCacheHits += 1;
    if (String(cachedResult.details?.status || "").toLowerCase() === "error") {
      performanceStats.providerErrorCacheHits += 1;
    }
    performanceStats.lastProviderCacheStatus = "hit";
    return cachedResult;
  }

  performanceStats.providerCacheMisses += 1;

  if (providerRequestInFlight.has(cacheKey)) {
    performanceStats.providerInFlightJoins += 1;
    performanceStats.lastProviderCacheStatus = "in-flight-joined";
    const joinedResult = await providerRequestInFlight.get(cacheKey);
    const cloned = cloneProviderResultForCache(joinedResult);
    cloned.details = {
      ...(cloned.details || {}),
      fromCache: false,
      cacheStatus: "in-flight-joined"
    };
    return cloned;
  }

  performanceStats.providerRequestsStarted += 1;
  performanceStats.lastProviderCacheStatus = "miss-started";
  const requestGeneration = providerCacheGeneration;

  const requestPromise = Promise.resolve()
    .then(() => lookupFn())
    .then((providerResult) => {
      const result = cloneProviderResultForCache(providerResult);
      const status = String(result.details?.status || "").toLowerCase();
      const message = String(result.details?.message || "");

      if (status === "error" || status === "timeout" || status === "rate-limited" || status === "parse-error") {
        performanceStats.providerRequestsFailed += 1;
      } else {
        performanceStats.providerRequestsCompleted += 1;
      }

      if (status === "timeout" || /abort|timeout|timed out/i.test(message)) {
        performanceStats.providerTimeouts += 1;
      }

      const ttlMs = getProviderResultCacheTtl(result);
      if (requestGeneration === providerCacheGeneration) {
        setProviderCacheEntry(providerName, checkedUrl, result, ttlMs);
      }
      if (ttlMs > 0 && requestGeneration === providerCacheGeneration) {
        result.details = {
          ...(result.details || {}),
          fromCache: false,
          cacheStatus: "stored"
        };
      }
      return result;
    })
    .catch((error) => {
      performanceStats.providerRequestsFailed += 1;
      if (/abort|timeout|timed out/i.test(safeErrorMessage(error, ""))) {
        performanceStats.providerTimeouts += 1;
      }
      throw error;
    })
    .finally(() => {
      if (providerRequestInFlight.get(cacheKey) === requestPromise) {
        providerRequestInFlight.delete(cacheKey);
      }
    });

  providerRequestInFlight.set(cacheKey, requestPromise);
  return requestPromise;
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
  const providerTasks = [
    getCachedOrInFlightProviderResult("gsb", normalizedUrl, () => lookupGoogleSafeBrowsing(normalizedUrl)),
    getCachedOrInFlightProviderResult("urlhaus", normalizedUrl, () => lookupUrlhaus(normalizedUrl)),
    getCachedOrInFlightProviderResult("virustotal", normalizedUrl, () => lookupVirusTotalUrl(normalizedUrl))
  ];

  const settled = await Promise.allSettled(providerTasks);

  return [
    settled[0].status === "fulfilled"
      ? settled[0].value
      : createProviderErrorResult("gsb", normalizedUrl, settled[0].reason),

    settled[1].status === "fulfilled"
      ? settled[1].value
      : createProviderErrorResult("urlhaus", normalizedUrl, settled[1].reason),

    settled[2].status === "fulfilled"
      ? settled[2].value
      : createProviderErrorResult("virustotal", normalizedUrl, settled[2].reason)
  ];
}
async function lookupGoogleSafeBrowsing(normalizedUrl) {
  const startedAt = performance.now();
  const config = await getRuntimeConfig();
  const healthCheckedAt = Date.now();
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
      lastCheckedAt: healthCheckedAt
    });

    return withProviderOutcomeSummary({
      provider: "gsb",
      configured: false,
      checked: false,
      checkedUrl: normalizedUrl,
      ...createProviderTelemetry(startedAt),
      flagged: false,
      category: null,
      details: {
        status: "not-configured",
        message: missingKeyMessage
      }
    });
  }

  let response = null;

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`;
    response = await fetchWithTimeout(endpoint, {
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
    }, 4500);

    if (!response.ok) {
      const errorMessage = `Safe Browsing lookup returned HTTP ${response.status}.`;

      updateGsbHealth({
        configured: true,
        available: false,
        lastStatus: "error",
        lastHttpStatus: response.status,
        lastError: errorMessage,
        lastCheckedAt: healthCheckedAt
      });

      return withProviderOutcomeSummary({
        provider: "gsb",
        configured: true,
        checked: true,
        checkedUrl: normalizedUrl,
        ...createProviderTelemetry(startedAt),
        flagged: false,
        category: null,
        details: {
          status: "error",
          httpStatus: response.status,
          message: errorMessage
        }
      });
    }

    const payload = await response.json();
    const matches = Array.isArray(payload.matches) ? payload.matches : [];
    const flagged = matches.length > 0;
    const category = matches[0]?.threatType || null;

    updateGsbHealth({
      configured: true,
      available: true,
      lastStatus: "ok",
      lastHttpStatus: response.status,
      lastError: null,
      lastCheckedAt: healthCheckedAt
    });

    return withProviderOutcomeSummary({
      provider: "gsb",
      configured: true,
      checked: true,
      checkedUrl: normalizedUrl,
      ...createProviderTelemetry(startedAt),
      flagged,
      category,
      details: {
        status: "checked",
        httpStatus: response.status,
        matchesCount: matches.length,
        queryStatus: flagged ? "matches" : "no-matches"
      }
    });
  } catch (error) {
    const isTimeout = error?.name === "AbortError" || /abort|timeout|timed out/i.test(safeErrorMessage(error, ""));
    const errorMessage = isTimeout
      ? "Google Safe Browsing request timed out."
      : safeErrorMessage(error, "Unknown Safe Browsing error.");

    updateGsbHealth({
      configured: true,
      available: false,
      lastStatus: isTimeout ? "timeout" : "error",
      lastHttpStatus: response?.status ?? null,
      lastError: errorMessage,
      lastCheckedAt: healthCheckedAt
    });

    return withProviderOutcomeSummary({
      provider: "gsb",
      configured: true,
      checked: true,
      checkedUrl: normalizedUrl,
      ...createProviderTelemetry(startedAt),
      flagged: false,
      category: null,
      details: {
        status: isTimeout ? "timeout" : "error",
        httpStatus: response?.status ?? null,
        message: errorMessage
      }
    });
  }
}

async function lookupUrlhaus(normalizedUrl) {
  const startedAt = performance.now();
  const config = await getRuntimeConfig();
  const healthCheckedAt = Date.now();
  const authKey = String(config.URLHAUS_AUTH_KEY || config.URLHAUS_API_KEY || "").trim();
  let publicFallbackUsed = false;
  let firstFailure = null;
  let result = null;

  if (authKey) {
    result = await requestUrlhausLookup(normalizedUrl, { authKey });
    if (!result.ok && shouldFallbackToUrlhausPublic(result)) {
      publicFallbackUsed = true;
      firstFailure = result;
      result = await requestUrlhausLookupWithPublicRetry(normalizedUrl);
    }
  } else {
    result = await requestUrlhausLookupWithPublicRetry(normalizedUrl);
  }

  const authConfigured = Boolean(authKey);
  const checkedResult = result || firstFailure || {
    ok: false,
    mode: authConfigured ? "authenticated" : "public",
    httpStatus: null,
    errorMessage: "URLhaus lookup did not return a result."
  };

  const queryStatus = String(checkedResult.payload?.query_status || "").toLowerCase();
  const flagged = checkedResult.ok && queryStatus === "ok";
  const category = flagged
    ? String(checkedResult.payload?.threat || checkedResult.payload?.tags?.[0] || "malware-oriented")
    : null;
  const status = checkedResult.ok ? "checked" : "error";
  const healthStatus = getUrlhausHealthStatus({
    result: checkedResult,
    authConfigured,
    publicFallbackUsed,
    firstFailure
  });
  const message = getUrlhausResultMessage({
    result: checkedResult,
    firstFailure,
    publicFallbackUsed
  });

  updateUrlhausHealth({
    configured: authConfigured,
    mode: checkedResult.mode || (authConfigured ? "authenticated" : "public"),
    authKeyConfigured: authConfigured,
    available: checkedResult.ok,
    lastStatus: healthStatus,
    lastHttpStatus: checkedResult.httpStatus ?? null,
    lastError: checkedResult.ok ? null : checkedResult.errorMessage || "URLhaus lookup unavailable.",
    lastCheckedAt: healthCheckedAt
  });

  return withProviderOutcomeSummary({
    provider: "urlhaus",
    configured: authConfigured,
    checked: true,
    checkedUrl: normalizedUrl,
    ...createProviderTelemetry(startedAt),
    flagged,
    category,
    details: {
      status,
      httpStatus: checkedResult.httpStatus ?? null,
      mode: checkedResult.mode || (authConfigured ? "authenticated" : "public"),
      authConfigured,
      authKeyConfigured: authConfigured,
      publicModeAvailable: true,
      publicFallbackUsed,
      queryStatus: checkedResult.payload?.query_status || "",
      message
    }
  });
}

async function lookupVirusTotalUrl(normalizedUrl) {
  const startedAt = performance.now();

  return Promise.race([
    lookupVirusTotalUrlWithinBudget(normalizedUrl, startedAt),
    sleep(VIRUSTOTAL_SOFT_DEADLINE_MS).then(() => buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt: Date.now(),
      status: "pending",
      httpStatus: null,
      message: "VirusTotal scan submitted or deferred; result pending."
    }))
  ]);
}

async function lookupVirusTotalUrlWithinBudget(normalizedUrl, startedAt = performance.now()) {
  const config = await getRuntimeConfig();
  const healthCheckedAt = Date.now();
  const key = String(config.VIRUSTOTAL_API_KEY || "").trim();

  if (!key) {
    updateVirusTotalHealth({
      configured: false,
      available: true,
      lastStatus: "off",
      lastHttpStatus: null,
      lastError: null,
      lastCheckedAt: null
    });

    return withProviderOutcomeSummary({
      provider: "virustotal",
      configured: false,
      checked: false,
      checkedUrl: normalizedUrl,
      ...createProviderTelemetry(startedAt),
      flagged: false,
      category: null,
      details: {
        status: "not-configured",
        message: "VirusTotal not configured."
      }
    });
  }

  const pendingEntry = getVirusTotalPendingAnalysisEntry(normalizedUrl);
  if (pendingEntry?.analysisId) {
    const nowForFollowup = Date.now();
    const followupWaitMs = VIRUSTOTAL_PENDING_FOLLOWUP_INTERVAL_MS - (nowForFollowup - Number(pendingEntry.lastFollowupAt || 0));

    if (followupWaitMs > 0) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "pending",
        message: "VirusTotal analysis is still pending.",
        analysisId: pendingEntry.analysisId
      });
    }

    const globalWaitMs = VIRUSTOTAL_MIN_REQUEST_INTERVAL_MS - (nowForFollowup - lastVirusTotalRequestAt);
    if (globalWaitMs > 0) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "pending",
        message: "VirusTotal local rate limit active; result pending.",
        analysisId: pendingEntry.analysisId
      });
    }

    lastVirusTotalRequestAt = nowForFollowup;
    pendingEntry.lastFollowupAt = nowForFollowup;

    const followupResult = await fetchVirusTotalAnalysisResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      key,
      analysisId: pendingEntry.analysisId,
      pendingMessage: "VirusTotal analysis is still pending."
    });

    if (followupResult.details?.status === "checked") {
      virusTotalPendingAnalysisCache.delete(normalizedUrl);
    }

    return followupResult;
  }

  const existingReportResult = await lookupExistingVirusTotalUrlReport({
    normalizedUrl,
    startedAt,
    healthCheckedAt,
    key
  });

  if (existingReportResult) {
    return existingReportResult;
  }

  const now = Date.now();
  const waitMs = VIRUSTOTAL_MIN_REQUEST_INTERVAL_MS - (now - lastVirusTotalRequestAt);
  if (waitMs > 0) {
    updateVirusTotalHealth({
      configured: true,
      available: true,
      lastStatus: "pending",
      lastHttpStatus: null,
      lastError: "Local VirusTotal rate limiter deferred this lookup.",
      lastCheckedAt: healthCheckedAt
    });

    return withProviderOutcomeSummary({
      provider: "virustotal",
      configured: true,
      checked: true,
      checkedUrl: normalizedUrl,
      ...createProviderTelemetry(startedAt),
      flagged: false,
      category: null,
      details: {
        status: "pending",
        httpStatus: null,
        message: "VirusTotal local rate limit active; result pending."
      }
    });
  }

  lastVirusTotalRequestAt = now;

  try {
    const submitResponse = await fetchWithTimeout("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-apikey": key
      },
      body: new URLSearchParams({ url: normalizedUrl }).toString()
    }, 5000);

    if (submitResponse.status === 429) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "rate-limited",
        httpStatus: submitResponse.status,
        message: "VirusTotal rate limit reached."
      });
    }

    if (!submitResponse.ok) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "error",
        httpStatus: submitResponse.status,
        message: `VirusTotal URL submission returned HTTP ${submitResponse.status}.`
      });
    }

    const submitPayload = await submitResponse.json();
    const analysisId = String(submitPayload?.data?.id || "").trim();

    if (!analysisId) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "parse-error",
        httpStatus: submitResponse.status,
        message: "VirusTotal URL submission did not return an analysis ID."
      });
    }

    return fetchVirusTotalAnalysisResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      key,
      analysisId,
      pendingMessage: "VirusTotal scan submitted; result pending."
    });
  } catch (error) {
    const isTimeout = error?.name === "AbortError" || /abort|timeout|timed out/i.test(safeErrorMessage(error, ""));
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: isTimeout ? "timeout" : "error",
      httpStatus: null,
      message: isTimeout
        ? "VirusTotal verification timed out."
        : safeErrorMessage(error, "VirusTotal lookup failed.")
    });
  }
}

async function lookupExistingVirusTotalUrlReport({
  normalizedUrl,
  startedAt,
  healthCheckedAt,
  key
} = {}) {
  const urlId = getVirusTotalUrlId(normalizedUrl);
  if (!urlId) {
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: "parse-error",
      message: "VirusTotal URL identifier could not be generated."
    });
  }

  try {
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(urlId)}`, {
      method: "GET",
      headers: {
        "x-apikey": key
      }
    }, 2200);

    if (response.status === 404) {
      return null;
    }

    if (response.status === 429) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "rate-limited",
        httpStatus: response.status,
        message: "VirusTotal rate limit reached."
      });
    }

    if (!response.ok) {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: response.status === 401 || response.status === 403 ? "error" : "timeout",
        httpStatus: response.status,
        message: response.status === 401 || response.status === 403
          ? `VirusTotal URL report lookup returned HTTP ${response.status}.`
          : "VirusTotal URL report lookup was unavailable."
      });
    }

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "parse-error",
        httpStatus: response.status,
        message: "VirusTotal returned an unreadable URL report."
      });
    }

    const stats = payload?.data?.attributes?.last_analysis_stats;
    if (!stats || typeof stats !== "object") {
      return buildVirusTotalStatusResult({
        normalizedUrl,
        startedAt,
        healthCheckedAt,
        status: "parse-error",
        httpStatus: response.status,
        message: "VirusTotal URL report did not include analysis stats."
      });
    }

    return buildVirusTotalCheckedResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      httpStatus: response.status,
      analysisId: "",
      stats
    });
  } catch (error) {
    const isTimeout = error?.name === "AbortError" || /abort|timeout|timed out/i.test(safeErrorMessage(error, ""));
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: isTimeout ? "timeout" : "error",
      httpStatus: null,
      message: isTimeout
        ? "VirusTotal verification timed out."
        : safeErrorMessage(error, "VirusTotal request failed.")
    });
  }
}

async function fetchVirusTotalAnalysisResult({
  normalizedUrl,
  startedAt,
  healthCheckedAt,
  key,
  analysisId,
  pendingMessage = "VirusTotal scan submitted; result pending."
} = {}) {
  const analysisResponse = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
    method: "GET",
    headers: {
      "x-apikey": key
    }
  }, 2200);

  if (analysisResponse.status === 429) {
    storeVirusTotalPendingAnalysis(normalizedUrl, analysisId);
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: "rate-limited",
      httpStatus: analysisResponse.status,
      message: "VirusTotal rate limit reached.",
      analysisId
    });
  }

  if (!analysisResponse.ok) {
    storeVirusTotalPendingAnalysis(normalizedUrl, analysisId);
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: "pending",
      httpStatus: analysisResponse.status,
      message: pendingMessage,
      analysisId
    });
  }

  let analysisPayload = null;
  try {
    analysisPayload = await analysisResponse.json();
  } catch {
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: "parse-error",
      httpStatus: analysisResponse.status,
      message: "VirusTotal returned an unreadable analysis response.",
      analysisId
    });
  }

  const attributes = analysisPayload?.data?.attributes || {};
  const analysisStatus = String(attributes.status || "").toLowerCase();
  const stats = attributes.stats || {};

  if (analysisStatus && analysisStatus !== "completed") {
    storeVirusTotalPendingAnalysis(normalizedUrl, analysisId);
    return buildVirusTotalStatusResult({
      normalizedUrl,
      startedAt,
      healthCheckedAt,
      status: "pending",
      httpStatus: analysisResponse.status,
      message: pendingMessage,
      analysisId
    });
  }

  virusTotalPendingAnalysisCache.delete(normalizedUrl);
  return buildVirusTotalCheckedResult({
    normalizedUrl,
    startedAt,
    healthCheckedAt,
    httpStatus: analysisResponse.status,
    analysisId,
    stats
  });
}

function buildVirusTotalCheckedResult({
  normalizedUrl,
  startedAt,
  healthCheckedAt,
  httpStatus = null,
  analysisId = "",
  stats = {}
} = {}) {
  const maliciousCount = Number(stats.malicious || 0);
  const suspiciousCount = Number(stats.suspicious || 0);
  const harmlessCount = Number(stats.harmless || 0);
  const undetectedCount = Number(stats.undetected || 0);
  const timeoutCount = Number(stats.timeout || 0);
  const flagged = maliciousCount > 0 || suspiciousCount > 0;

  updateVirusTotalHealth({
    configured: true,
    available: true,
    lastStatus: flagged ? "flagged" : "ok",
    lastHttpStatus: httpStatus,
    lastError: null,
    lastCheckedAt: healthCheckedAt
  });

  return withProviderOutcomeSummary({
    provider: "virustotal",
    configured: true,
    checked: true,
    checkedUrl: normalizedUrl,
    ...createProviderTelemetry(startedAt),
    flagged,
    category: flagged ? "malicious-or-suspicious" : null,
    details: {
      status: "checked",
      httpStatus,
      message: flagged
        ? "VirusTotal reported malicious/suspicious detections."
        : "VirusTotal reported no malicious detections.",
      analysisId,
      maliciousCount,
      suspiciousCount,
      harmlessCount,
      undetectedCount,
      timeoutCount
    }
  });
}

function buildVirusTotalStatusResult({
  normalizedUrl,
  startedAt,
  healthCheckedAt,
  status,
  httpStatus = null,
  message = "",
  analysisId = ""
} = {}) {
  const available = !["error", "timeout", "rate-limited", "parse-error"].includes(status);
  if (status === "pending" && analysisId) {
    storeVirusTotalPendingAnalysis(normalizedUrl, analysisId);
  }

  updateVirusTotalHealth({
    configured: true,
    available,
    lastStatus: status,
    lastHttpStatus: httpStatus,
    lastError: available ? null : message,
    lastCheckedAt: healthCheckedAt
  });

  return withProviderOutcomeSummary({
    provider: "virustotal",
    configured: true,
    checked: true,
    checkedUrl: normalizedUrl,
    ...createProviderTelemetry(startedAt),
    flagged: false,
    category: null,
    details: {
      status,
      httpStatus,
      message,
      analysisId,
      maliciousCount: 0,
      suspiciousCount: 0,
      harmlessCount: 0,
      undetectedCount: 0,
      timeoutCount: 0
    }
  });
}

function getVirusTotalPendingAnalysisEntry(checkedUrl) {
  const key = String(checkedUrl || "").trim();
  if (!key) {
    return null;
  }

  const entry = virusTotalPendingAnalysisCache.get(key);
  if (!entry) {
    return null;
  }

  if (Number(entry.expiresAt || 0) <= Date.now()) {
    virusTotalPendingAnalysisCache.delete(key);
    return null;
  }

  return entry;
}

function storeVirusTotalPendingAnalysis(checkedUrl, analysisId) {
  const key = String(checkedUrl || "").trim();
  const id = String(analysisId || "").trim();
  if (!key || !id) {
    return;
  }

  const existing = virusTotalPendingAnalysisCache.get(key) || {};
  const now = Date.now();
  virusTotalPendingAnalysisCache.set(key, {
    checkedUrl: key,
    analysisId: id,
    submittedAt: Number(existing.submittedAt || now),
    lastFollowupAt: Number(existing.lastFollowupAt || 0),
    expiresAt: now + VIRUSTOTAL_PENDING_TTL_MS
  });
}

function getVirusTotalUrlId(normalizedUrl = "") {
  const value = String(normalizedUrl || "").trim();
  if (!value) {
    return "";
  }

  try {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    const chunkSize = 0x8000;

    for (let index = 0; index < bytes.length; index += chunkSize) {
      const chunk = bytes.slice(index, index + chunkSize);
      binary += String.fromCharCode(...chunk);
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  } catch {
    try {
      return btoa(unescape(encodeURIComponent(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    } catch {
      return "";
    }
  }
}

async function requestUrlhausLookupWithPublicRetry(normalizedUrl) {
  let result = await requestUrlhausLookup(normalizedUrl, { authKey: "" });
  if (!result.ok && shouldRetryUrlhausPublic(result)) {
    await sleep(300);
    result = await requestUrlhausLookup(normalizedUrl, { authKey: "" });
  }

  return result;
}

async function requestUrlhausLookup(normalizedUrl, { authKey = "", timeoutMs = 4500 } = {}) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  if (authKey) {
    headers["Auth-Key"] = authKey;
  }

  try {
    const response = await fetchWithTimeout("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers,
      body: new URLSearchParams({ url: normalizedUrl }).toString()
    }, timeoutMs);

    const httpStatus = response.status;
    if (!response.ok) {
      return {
        ok: false,
        response,
        payload: null,
        mode: authKey ? "authenticated" : "public",
        httpStatus,
        errorMessage: `URLhaus lookup returned HTTP ${httpStatus}.`
      };
    }

    try {
      const payload = await response.json();
      return {
        ok: true,
        response,
        payload,
        mode: authKey ? "authenticated" : "public",
        httpStatus,
        errorMessage: ""
      };
    } catch {
      return {
        ok: false,
        response,
        payload: null,
        mode: authKey ? "authenticated" : "public",
        httpStatus,
        errorMessage: "URLhaus returned an unreadable response."
      };
    }
  } catch (error) {
    return {
      ok: false,
      response: null,
      payload: null,
      mode: authKey ? "authenticated" : "public",
      httpStatus: null,
      errorMessage: safeErrorMessage(error, "Unknown URLhaus lookup error.")
    };
  }
}

async function refreshVirusTotalResultForPost(message = {}) {
  const postId = String(message.postId || "").trim();
  if (!postId) {
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      refreshed: false,
      reason: "missing-post-id"
    };
  }

  const storedAnalysis = await getBaseline(postId);
  if (!storedAnalysis) {
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      refreshed: false,
      reason: "missing-stored-analysis"
    };
  }

  const providerResults = normalizeProviderResults(storedAnalysis.providerResults || []);
  const existingVt = providerResults.find((item) => item.provider === "virustotal");
  const vtStatus = String(existingVt?.details?.status || "").toLowerCase();

  if (!["pending", "timeout", "rate-limited"].includes(vtStatus)) {
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      refreshed: false,
      reason: `virustotal-status-${vtStatus || "unavailable"}`
    };
  }

  const providerCheckedUrl =
    existingVt?.checkedUrl ||
    message.providerCheckedUrl ||
    storedAnalysis.analysisUrl ||
    storedAnalysis.normalizedUrl ||
    message.analysisUrl ||
    message.normalizedUrl ||
    "";

  if (!providerCheckedUrl) {
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      refreshed: false,
      reason: "missing-provider-checked-url"
    };
  }

  const refreshedVt = await getCachedOrInFlightProviderResult(
    "virustotal",
    providerCheckedUrl,
    () => lookupVirusTotalUrl(providerCheckedUrl)
  );
  const updatedProviderResults = providerResults.map((provider) => (
    provider.provider === "virustotal" ? refreshedVt : provider
  ));
  const updatedAnalysis = buildVirusTotalRefreshedAnalysis(storedAnalysis, updatedProviderResults);
  replaceVirusTotalInUrlAnalysisCache({
    analysis: updatedAnalysis,
    providerResult: refreshedVt,
    checkedUrl: providerCheckedUrl
  });

  const persistedAnalysis = await persistPostLevelAnalysis(postId, updatedAnalysis);

  if (refreshedVt.flagged) {
    const flaggedDomain =
      persistedAnalysis.endpointResult?.effectiveDomain ||
      persistedAnalysis.urlFeatureAnalysis?.finalDomain ||
      safeHostname(persistedAnalysis.analysisUrl || providerCheckedUrl);
    await markDomainFlagged(flaggedDomain);
  }

  sessionInfo.lastActivityAt = Date.now();

  return {
    type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
    analysis: persistedAnalysis,
    refreshed: true,
    reason: refreshedVt.flagged ? "virustotal-flagged" : String(refreshedVt.details?.status || "virustotal-refreshed")
  };
}

function buildVirusTotalRefreshedAnalysis(analysis = {}, providerResults = []) {
  const safeProviderResults = normalizeProviderResults(providerResults);
  const gsbResult = getNormalizedProviderResult(safeProviderResults, "gsb");
  const urlhausResult = getNormalizedProviderResult(safeProviderResults, "urlhaus");
  const virusTotalResult = getNormalizedProviderResult(safeProviderResults, "virustotal");
  const providerOverride = Boolean(gsbResult.flagged || urlhausResult.flagged || virusTotalResult.flagged);
  const previousScore = Number(analysis.safetyScore);
  const safetyScore = virusTotalResult.flagged
    ? Math.min(Number.isFinite(previousScore) ? previousScore : 20, 20)
    : analysis.safetyScore;
  const classification = virusTotalResult.flagged
    ? "High Risk"
    : analysis.classification;
  const features = {
    ...(analysis.features || {}),
    virusTotalFlagged: virusTotalResult.flagged === true
  };
  const refreshedAnalysis = {
    ...analysis,
    providerResults: safeProviderResults,
    features,
    providerOverride,
    classification,
    safetyScore,
    concreteRiskSignals: Boolean(analysis.concreteRiskSignals || providerOverride),
    interceptionRecommended: shouldRecommendInterceptionForStoredAnalysis({
      ...analysis,
      providerResults: safeProviderResults,
      features,
      providerOverride,
      classification,
      safetyScore
    }),
    lastChecked: Date.now()
  };

  refreshedAnalysis.technicalDetails = buildTechnicalDetails({
    endpointResult: refreshedAnalysis.endpointResult,
    redirectAnalysis: refreshedAnalysis.redirectAnalysis,
    urlFeatureAnalysis: refreshedAnalysis.urlFeatureAnalysis,
    analysis: {
      ...refreshedAnalysis,
      features,
      candidateContext: refreshedAnalysis.candidateContext || {}
    },
    providerResults: safeProviderResults
  });

  return refreshedAnalysis;
}

function replaceVirusTotalInUrlAnalysisCache({ analysis = {}, providerResult = {}, checkedUrl = "" } = {}) {
  const targetKeys = new Set([
    normalizeCacheKey(checkedUrl),
    normalizeCacheKey(providerResult.checkedUrl),
    normalizeCacheKey(analysis.analysisUrl),
    normalizeCacheKey(analysis.normalizedUrl)
  ].filter(Boolean));

  for (const [cacheKey, entry] of urlAnalysisCache.entries()) {
    const payload = entry?.payload || {};
    const providers = normalizeProviderResults(payload.providerResults || []);
    const cachedVt = providers.find((item) => item.provider === "virustotal");
    const isMatch = Boolean(
      targetKeys.has(cacheKey) ||
      targetKeys.has(normalizeCacheKey(payload.analysisUrl)) ||
      targetKeys.has(normalizeCacheKey(payload.providerCheckedUrl)) ||
      targetKeys.has(normalizeCacheKey(cachedVt?.checkedUrl))
    );

    if (!isMatch) {
      continue;
    }

    entry.payload = {
      ...payload,
      providerResults: providers.map((provider) => (
        provider.provider === "virustotal" ? cloneValue(providerResult) : provider
      ))
    };
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shouldFallbackToUrlhausPublic(result = {}) {
  if (result.ok) {
    return false;
  }

  const status = Number(result.httpStatus);
  return (
    status === 401 ||
    status === 403 ||
    status === 429 ||
    status >= 500 ||
    /unreadable|parse/i.test(String(result.errorMessage || "")) ||
    isUrlhausTimeoutError(result.errorMessage) ||
    !status
  );
}

function shouldRetryUrlhausPublic(result = {}) {
  if (result.ok) {
    return false;
  }

  const status = Number(result.httpStatus);
  return (
    status === 429 ||
    status >= 500 ||
    isUrlhausTimeoutError(result.errorMessage) ||
    !status
  );
}

function isUrlhausTimeoutError(message = "") {
  return /abort|timeout|timed out|network/i.test(String(message || ""));
}

function getUrlhausHealthStatus({ result = {}, authConfigured = false, publicFallbackUsed = false, firstFailure = null } = {}) {
  if (result.ok) {
    if (publicFallbackUsed && firstFailure) {
      return "auth-failed-public-ok";
    }

    return result.mode === "public" ? "public-ok" : "ok";
  }

  if (Number(result.httpStatus) === 429) {
    return "rate-limited";
  }

  if (isUrlhausTimeoutError(result.errorMessage)) {
    return "timeout";
  }

  return "error";
}

function getUrlhausResultMessage({ result = {}, firstFailure = null, publicFallbackUsed = false } = {}) {
  if (result.ok && publicFallbackUsed && firstFailure) {
    return "Authenticated lookup failed; public lookup succeeded.";
  }

  if (result.ok) {
    return result.payload?.urlhaus_reference || result.payload?.reporter || "";
  }

  if (publicFallbackUsed && firstFailure) {
    return `Authenticated lookup failed; public lookup also failed. ${result.errorMessage || ""}`.trim();
  }

  return result.errorMessage || "URLhaus lookup unavailable.";
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
    performanceStats: {
  ...performanceStats
},
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
  await resetSession("manual", { clearRecords: true });

  return {
    success: true,
    message: "Session restarted."
  };
}

async function ensureActiveSession(reason) {
  if (Date.now() - sessionInfo.startedAt < SESSION_TTL_MS) {
    return false;
  }

  await resetSession(`${reason}-expired`, { clearRecords: false });
  return true;
}
async function resetSession(reason, options = {}) {
  const shouldClearRecords = options.clearRecords === true;
  clearProviderCaches({ clearUrlAnalysis: true, clearPendingVirusTotal: true });

  if (shouldClearRecords) {
    await clearAnalysisRecords();
    await clearDomainFlagRecords();
  }
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

await resetSession(reason, { clearRecords: false });
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
      "dili:config:urlhausApiKey",
      "dili:config:virustotalApiKey"
    ]);

    runtimeConfig.GSB_API_KEY = String(stored["dili:config:gsbApiKey"] || GSB_API_KEY || "").trim();
    runtimeConfig.URLHAUS_AUTH_KEY = String(stored["dili:config:urlhausAuthKey"] || URLHAUS_AUTH_KEY || URLHAUS_API_KEY || "").trim();
    runtimeConfig.URLHAUS_API_KEY = String(stored["dili:config:urlhausApiKey"] || URLHAUS_API_KEY || "").trim();
    runtimeConfig.VIRUSTOTAL_API_KEY = String(stored["dili:config:virustotalApiKey"] || VIRUSTOTAL_API_KEY || "").trim();
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
    VIRUSTOTAL_API_KEY: String(VIRUSTOTAL_API_KEY || "").trim(),
    configLoaded: true,
    configSource: CONFIG_FILE_NAME,
    configError: null
  };
}

async function getDemoScoreBiasConfig() {
  try {
    const stored = await chromeStorageGet([
      DEMO_SCORE_BIAS_STORAGE_KEY,
      DEMO_SCORE_BIAS_AMOUNT_STORAGE_KEY
    ]);
    const enabled = stored[DEMO_SCORE_BIAS_STORAGE_KEY] === true;
    const amount = Number(stored[DEMO_SCORE_BIAS_AMOUNT_STORAGE_KEY] ?? 35);

    return {
      enabled,
      amount: Number.isFinite(amount) ? Math.max(0, Math.min(100, Math.round(amount))) : 35
    };
  } catch (error) {
    logDebug(`Demo score bias config read failed: ${safeErrorMessage(error, "unknown error")}`);
    return {
      enabled: false,
      amount: 35
    };
  }
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
    stored["dili:config:urlhausApiKey"] ||
    stored["dili:config:virustotalApiKey"]
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
      configured: false,
      mode: "public",
      authKeyConfigured: false,
      available: true,
      lastStatus: "not-yet-run",
      lastHttpStatus: null,
      lastError: null,
      lastCheckedAt: null
    },
    virustotal: {
      configured: false,
      available: true,
      lastStatus: "off",
      lastHttpStatus: null,
      lastError: null,
      lastCheckedAt: null
    }
  };
}

function applyConfigDiagnostics(config) {
  const gsbKeyLoaded = Boolean(String(config.GSB_API_KEY || "").trim());
  const urlhausAuthKeyLoaded = Boolean(String(config.URLHAUS_AUTH_KEY || "").trim());
  const virusTotalKeyLoaded = Boolean(String(config.VIRUSTOTAL_API_KEY || "").trim());
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
  providerHealth.urlhaus.configured = urlhausAuthKeyLoaded;
  providerHealth.urlhaus.authKeyConfigured = urlhausAuthKeyLoaded;
  providerHealth.urlhaus.available = !["error", "timeout", "rate-limited"].includes(providerHealth.urlhaus.lastStatus);

  if (providerHealth.urlhaus.lastStatus === "not-yet-run") {
    providerHealth.urlhaus.lastStatus = urlhausAuthKeyLoaded ? "not-yet-run" : "not-configured-public-mode";
    providerHealth.urlhaus.lastError = null;
  } else if (urlhausAuthKeyLoaded && providerHealth.urlhaus.lastStatus === "not-configured-public-mode") {
    providerHealth.urlhaus.lastStatus = "not-yet-run";
    providerHealth.urlhaus.lastError = null;
  }

  providerHealth.virustotal.configured = virusTotalKeyLoaded;
  if (!virusTotalKeyLoaded) {
    providerHealth.virustotal.available = true;
    providerHealth.virustotal.lastStatus = "off";
    providerHealth.virustotal.lastHttpStatus = null;
    providerHealth.virustotal.lastError = null;
  } else if (providerHealth.virustotal.lastStatus === "off") {
    providerHealth.virustotal.lastStatus = "not-yet-run";
    providerHealth.virustotal.lastHttpStatus = null;
    providerHealth.virustotal.lastError = null;
    providerHealth.virustotal.available = true;
  }

}

function updateGsbHealth(patch) {
  Object.assign(providerHealth.gsb, patch);
}

function updateUrlhausHealth(patch) {
  Object.assign(providerHealth.urlhaus, patch);
}

function updateVirusTotalHealth(patch) {
  Object.assign(providerHealth.virustotal, patch);
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
      configured: providerHealth.urlhaus.configured,
      mode: providerHealth.urlhaus.mode,
      authKeyConfigured: providerHealth.urlhaus.authKeyConfigured,
      available: providerHealth.urlhaus.available,
      lastStatus: providerHealth.urlhaus.lastStatus,
      lastHttpStatus: providerHealth.urlhaus.lastHttpStatus,
      lastError: providerHealth.urlhaus.lastError,
      lastCheckedAt: providerHealth.urlhaus.lastCheckedAt
    },
    virustotal: {
      configured: providerHealth.virustotal.configured,
      available: providerHealth.virustotal.available,
      lastStatus: providerHealth.virustotal.lastStatus,
      lastHttpStatus: providerHealth.virustotal.lastHttpStatus,
      lastError: providerHealth.virustotal.lastError,
      lastCheckedAt: providerHealth.virustotal.lastCheckedAt
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
      text: formatUrlhausProviderText(snapshot.urlhaus || {})
    },
    virustotal: {
      label: "VT",
      state: getVirusTotalProviderState(snapshot.virustotal || {}),
      text: formatVirusTotalProviderText(snapshot.virustotal || {})
    },
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
  if (["error", "timeout", "rate-limited"].includes(urlhaus.lastStatus) || urlhaus.available === false) {
    return "error";
  }

  if (
    urlhaus.mode === "public" ||
    ["public-ok", "auth-failed-public-ok", "not-configured-public-mode"].includes(urlhaus.lastStatus)
  ) {
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

function formatUrlhausProviderText(urlhaus = {}) {
  switch (urlhaus.lastStatus) {
    case "auth-failed-public-ok":
      return "Public fallback";
    case "public-ok":
    case "not-configured-public-mode":
      return "Public";
    case "timeout":
      return "Timeout";
    case "rate-limited":
      return "Rate limited";
    case "ok":
      return "Ready";
    default:
      return formatCompactProviderText(getUrlhausProviderState(urlhaus));
  }
}

function getVirusTotalProviderState(vt = {}) {
  if (!vt.configured || vt.lastStatus === "off") {
    return "off";
  }

  if (vt.lastStatus === "pending") {
    return "pending";
  }

  if (vt.lastStatus === "rate-limited") {
    return "rate-limited";
  }

  if (["error", "timeout", "parse-error"].includes(vt.lastStatus) || vt.available === false) {
    return "error";
  }

  return "ready";
}

function formatVirusTotalProviderText(vt = {}) {
  switch (vt.lastStatus) {
    case "off":
      return "Off";
    case "pending":
      return "Pending";
    case "rate-limited":
      return "Rate limited";
    case "error":
    case "timeout":
    case "parse-error":
      return "Error";
    case "ok":
    case "flagged":
    case "not-yet-run":
      return "Ready";
    default:
      return formatCompactProviderText(getVirusTotalProviderState(vt));
  }
}

function getProviderDurationMs(startedAt) {
  const elapsed = performance.now() - Number(startedAt);
  return Number.isFinite(elapsed) ? Math.max(0, Math.round(elapsed)) : null;
}

function createProviderTelemetry(startedAt) {
  return {
    checkedAt: new Date().toISOString(),
    durationMs: getProviderDurationMs(startedAt)
  };
}

function withProviderOutcomeSummary(result) {
  return {
    ...result,
    resultSummary: getProviderOutcomeSummary(result)
  };
}

function getProviderOutcomeSummary(result = {}) {
  const provider = String(result.provider || "").toLowerCase();
  const status = String(result.details?.status || "").toLowerCase();

  if (provider === "virustotal") {
    if (!result.configured || status === "not-configured") {
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
    return result.flagged
      ? "VirusTotal reported malicious/suspicious detections."
      : "VirusTotal reported no malicious detections.";
  }

  if (provider === "urlhaus" && status === "error") {
    return "Lookup unavailable after retry.";
  }

  if (provider !== "urlhaus" && (!result.configured || status === "not-configured")) {
    return "Provider not configured.";
  }

  if (status === "timeout") {
    return "Verification timed out.";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return "Request failed.";
  }

  if (!result.checked || status === "skipped" || status === "not-configured") {
    return "Provider not configured.";
  }

  if (provider === "gsb") {
    return result.flagged ? "Unsafe URL reported." : "No unsafe matches reported.";
  }

  if (provider === "urlhaus") {
    return result.flagged ? "Known malware record found." : "No known malware record found.";
  }

  return result.flagged ? "Provider reported a match." : "No provider match reported.";
}

function getProviderAuditStatus(result = {}) {
  const provider = String(result.provider || "").toLowerCase();
  const status = String(result.details?.status || "").toLowerCase();

  if (
    (provider !== "urlhaus" && !result.configured) ||
    status === "not-configured" ||
    status === "skipped" ||
    !result.checked
  ) {
    return "skipped";
  }

  if (status === "timeout") {
    return "timeout";
  }

  if (status === "pending") {
    return "pending";
  }

  if (status === "rate-limited") {
    return "rate-limited";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return "failed";
  }

  return "completed";
}

function createSkippedUrlhausProviderResult(checkedUrl = "") {
  return withProviderOutcomeSummary({
    provider: "urlhaus",
    configured: true,
    checked: false,
    checkedUrl,
    checkedAt: new Date().toISOString(),
    durationMs: 0,
    flagged: false,
    category: null,
    details: {
      status: "skipped",
      message: "URLhaus skipped because GSB completed without provider flags."
    }
  });
}

function createDefaultProviderResult(provider, checkedUrl = "") {
  return withProviderOutcomeSummary({
    provider,
    configured: false,
    checked: false,
    checkedUrl,
    checkedAt: "",
    durationMs: null,
    flagged: false,
    category: null,
    details: {
      status: "not-configured",
      message: "Provider fallback result."
    }
  });
}

function createProviderErrorResult(provider, checkedUrl, error) {
  return withProviderOutcomeSummary({
    provider,
    configured: true,
    checked: true,
    checkedUrl,
    checkedAt: new Date().toISOString(),
    durationMs: null,
    flagged: false,
    category: null,
    details: {
      status: "error",
      message: safeErrorMessage(error, `${provider} lookup failed.`)
    }
  });
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
function nowMs() {
  return typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

function elapsedMs(startMs) {
  return Math.max(0, Math.round(nowMs() - Number(startMs || nowMs())));
}

function recordMaxPerformanceStat(key, value) {
  const numeric = Number(value || 0);
  performanceStats[key] = Math.max(Number(performanceStats[key] || 0), numeric);
}
