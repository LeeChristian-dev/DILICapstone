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
import { analyzeUrlFeatures, detectDomainMismatch, getRegistrableDomain, isShortenerHost, normalizeUrl } from "./utils/urlAnalyzer.js";
import {
  appendAnalysisRecord,
  checkDomainPreviouslyFlagged,
  clearAnalysisRecords,
  clearDomainFlagRecords,
  getAllAnalysisRecords,
  getBaseline,
  getScanEnabledState,
  markDomainFlagged,
  removePostAnalysis,
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
  FINALIZE_PENDING_PROVIDER_STATE: "DILI_FINALIZE_PENDING_PROVIDER_STATE",
  CLEAR_POST_ANALYSIS_STATE: "DILI_CLEAR_POST_ANALYSIS_STATE",
  UPDATE_PERFORMANCE_TIMING: "DILI_UPDATE_PERFORMANCE_TIMING",
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
  providerCacheMisses: 0
};

const CURRENT_ANALYSIS_SCHEMA_VERSION = 4;
const SESSION_TTL_MS = 30 * 60 * 1000;
const POST_INTEGRITY_MIN_BASELINE_AGE_MS = 15 * 1000;
const POST_INTEGRITY_MIN_NO_LINK_BASELINE_AGE_MS = 60 * 1000;
const POST_INTEGRITY_PROVISIONAL_BASELINE_AGE_MS = 60 * 1000;
const POST_INTEGRITY_NO_LINK_BASELINE_STATES = new Set([
  "no_link",
  "observed_no_link_unstable",
  "observed_no_link",
  "provisional_no_link",
  "truncated_unexpanded"
]);
const URL_ANALYSIS_CACHE_TTL_MS = 10 * 60 * 1000;
const PROVIDER_RESULT_CACHE_TTL_MS = 10 * 60 * 1000;
const PROVIDER_ERROR_CACHE_TTL_MS = 60 * 1000;
const PROVIDER_PENDING_CACHE_TTL_MS = 15 * 1000;
const PROVIDER_CACHE_MAX_ENTRIES = 300;

const VIRUSTOTAL_MIN_REQUEST_INTERVAL_MS = 20 * 1000;
const VIRUSTOTAL_SOFT_DEADLINE_MS = 2800;
const VIRUSTOTAL_PENDING_FOLLOWUP_INTERVAL_MS = 20 * 1000;
const VIRUSTOTAL_PENDING_TTL_MS = 30 * 60 * 1000;

let runtimeConfig = createRuntimeConfig();
let providerHealth = createInitialProviderHealth();
let sessionInfo = createSessionState();

const urlAnalysisCache = new Map();
const providerResultCache = new Map();
const providerRequestInFlight = new Map();
const virusTotalPendingAnalysisCache = new Map();

let providerCacheGeneration = 0;
let lastVirusTotalRequestAt = 0;

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
          postSignature: message.postSignature,
          linkFingerprint: message.linkFingerprint,
          performanceTiming: message.performanceTiming,
          baselineContext: buildBaselineContextFromMessage(message),
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
          postSignature: message.postSignature,
          linkFingerprint: message.linkFingerprint,
          performanceTiming: message.performanceTiming,
          baselineContext: buildBaselineContextFromMessage(message),
          isReanalysis: true
        })
      };

    case MESSAGE_TYPES.UPDATE_PERFORMANCE_TIMING:
      return updatePerformanceTimingForPost(message);

    case MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT:
      return refreshVirusTotalResultForPost(message);

    case MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE:
      return finalizePendingProviderStateForPost(message);

    case MESSAGE_TYPES.CLEAR_POST_ANALYSIS_STATE:
      return clearPostAnalysisState(message);

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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  Promise.resolve()
    .then(() => handleMessage(message, sender))
    .then((response) => {
      sendResponse({
        ok: true,
        ...response
      });
    })
    .catch((error) => {
      const errorMessage = safeErrorMessage(error, "Unknown background error.");
      console.warn("[DILI] Background message failed", error);
      sendResponse({
        ok: false,
        error: errorMessage
      });
    });

  return true;
});

bindSessionLifecycleObservers();
getRuntimeConfig().catch((error) => {
  console.warn("[DILI] Runtime config initialization failed", error);
});

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
    postIdentityStable: Boolean(message.postIdentityStable),
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

function buildBaselineContextFromMessage(message = {}) {
  return {
    previousBaselineState: String(message.previousBaselineState || "").trim(),
    hadLinkAtBaseline: message.hadLinkAtBaseline === undefined ? null : message.hadLinkAtBaseline,
    previousUrlHash: String(message.previousUrlHash || "").trim(),
    previousNormalizedUrl: String(message.previousNormalizedUrl || "").trim(),
    previousProviderCheckedUrl: String(message.previousProviderCheckedUrl || "").trim(),
    previousLinkFingerprint: String(message.previousLinkFingerprint || "").trim(),
    baselinePostTextHash: String(message.baselinePostTextHash || "").trim(),
    baselinePostSignature: String(message.baselinePostSignature || "").trim(),
    baselineCreatedAt: Number(message.baselineCreatedAt || 0) || null,
    baselineConfidence: normalizeBaselineConfidence(message.baselineConfidence),
    postIdentityStable: message.postIdentityStable === true,
    identitySource: String(message.identitySource || message.candidateContext?.identitySource || "").trim()
  };
}

function normalizeBaselineConfidence(value) {
  const normalized = String(value || "").toLowerCase().trim();
  return ["stable", "unstable", "provisional", "unknown"].includes(normalized)
    ? normalized
    : "unknown";
}

function mergeBaselineContext(existingBaseline = null, baselineContext = {}) {
  const baseline = existingBaseline && typeof existingBaseline === "object" ? existingBaseline : {};
  const context = baselineContext && typeof baselineContext === "object" ? baselineContext : {};
  const candidateContext = baseline.candidateContext && typeof baseline.candidateContext === "object"
    ? baseline.candidateContext
    : {};

  return {
    ...baseline,
    baselineState: baseline.baselineState || context.previousBaselineState || "",
    hadLinkAtBaseline: baseline.hadLinkAtBaseline === undefined || baseline.hadLinkAtBaseline === null
      ? context.hadLinkAtBaseline
      : baseline.hadLinkAtBaseline,
    urlHash: baseline.urlHash || context.previousUrlHash || "",
    normalizedUrl: baseline.normalizedUrl || context.previousNormalizedUrl || "",
    analysisUrl: baseline.analysisUrl || context.previousNormalizedUrl || "",
    providerCheckedUrl: baseline.providerCheckedUrl || context.previousProviderCheckedUrl || "",
    linkFingerprint: baseline.linkFingerprint || context.previousLinkFingerprint || "",
    postTextHash: baseline.postTextHash || context.baselinePostTextHash || "",
    postSignature: baseline.postSignature || context.baselinePostSignature || candidateContext.signature || "",
    baselineFirstSeenAt: baseline.baselineFirstSeenAt || baseline.firstSeenAt || context.baselineCreatedAt || 0,
    firstSeenAt: baseline.firstSeenAt || baseline.baselineFirstSeenAt || context.baselineCreatedAt || 0,
    baselineConfidence: normalizeBaselineConfidence(baseline.baselineConfidence || context.baselineConfidence),
    identitySource: baseline.identitySource || context.identitySource || "",
    postIdentityStable: baseline.postIdentityStable === true || context.baselineConfidence === "stable"
  };
}

function toTimingTimestamp(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.round(numeric) : null;
}

function durationBetween(start, end) {
  const startedAt = toTimingTimestamp(start);
  const completedAt = toTimingTimestamp(end);

  if (startedAt === null || completedAt === null || completedAt < startedAt) {
    return null;
  }

  return completedAt - startedAt;
}

function normalizePerformanceTiming(timing = {}) {
  const safeTiming = timing && typeof timing === "object" ? timing : {};
  const normalized = {
    detectedAt: toTimingTimestamp(safeTiming.detectedAt),
    analysisStartedAt: toTimingTimestamp(safeTiming.analysisStartedAt),
    endpointResolutionStartedAt: toTimingTimestamp(safeTiming.endpointResolutionStartedAt),
    endpointResolutionCompletedAt: toTimingTimestamp(safeTiming.endpointResolutionCompletedAt),
    redirectAnalysisStartedAt: toTimingTimestamp(safeTiming.redirectAnalysisStartedAt),
    redirectAnalysisCompletedAt: toTimingTimestamp(safeTiming.redirectAnalysisCompletedAt),
    providerVerificationStartedAt: toTimingTimestamp(safeTiming.providerVerificationStartedAt),
    providerVerificationCompletedAt: toTimingTimestamp(safeTiming.providerVerificationCompletedAt),
    panelRenderStartedAt: toTimingTimestamp(safeTiming.panelRenderStartedAt),
    panelRenderedAt: toTimingTimestamp(safeTiming.panelRenderedAt),
    analysisCompletedAt: toTimingTimestamp(safeTiming.analysisCompletedAt)
  };

  normalized.panelRenderingMs = durationBetween(normalized.panelRenderStartedAt, normalized.panelRenderedAt);
  normalized.endpointResolutionMs = durationBetween(normalized.endpointResolutionStartedAt, normalized.endpointResolutionCompletedAt);
  normalized.redirectAnalysisMs = durationBetween(normalized.redirectAnalysisStartedAt, normalized.redirectAnalysisCompletedAt);
  normalized.providerVerificationMs = durationBetween(normalized.providerVerificationStartedAt, normalized.providerVerificationCompletedAt);
  normalized.fullAnalysisCycleMs = durationBetween(
    normalized.detectedAt || normalized.analysisStartedAt,
    normalized.panelRenderedAt || normalized.analysisCompletedAt
  );

  return normalized;
}

function mergePerformanceTiming(...timings) {
  const merged = {};

  for (const timing of timings) {
    if (!timing || typeof timing !== "object") {
      continue;
    }

    const normalized = normalizePerformanceTiming(timing);
    for (const [key, value] of Object.entries(normalized)) {
      if (value !== null && value !== undefined && value !== "") {
        merged[key] = value;
      }
    }
  }

  return normalizePerformanceTiming(merged);
}

async function updatePerformanceTimingForPost(message = {}) {
  const postId = String(message.postId || "").trim();
  if (!postId) {
    return {
      type: MESSAGE_TYPES.UPDATE_PERFORMANCE_TIMING,
      updated: false,
      reason: "missing-post-id"
    };
  }

  const storedAnalysis = await getBaseline(postId);
  if (!storedAnalysis) {
    return {
      type: MESSAGE_TYPES.UPDATE_PERFORMANCE_TIMING,
      updated: false,
      reason: "missing-stored-analysis"
    };
  }

  const performanceTiming = mergePerformanceTiming(storedAnalysis.performanceTiming, message.performanceTiming);
  const updatedAnalysis = {
    ...storedAnalysis,
    performanceTiming,
    lastChecked: Date.now()
  };

  await updatePostAnalysis(postId, updatedAnalysis);
  await appendAnalysisRecord({
    ...updatedAnalysis,
    timestamp: storedAnalysis.timestamp || updatedAnalysis.lastChecked,
    postId,
    performanceTiming
  });

  return {
    type: MESSAGE_TYPES.UPDATE_PERFORMANCE_TIMING,
    updated: true,
    performanceTiming
  };
}
function isAnalysisPendingLike(analysis = {}) {
  const classification = String(analysis.classification || "").toLowerCase();
  const pendingProviders = Array.isArray(analysis.pendingProviders)
    ? analysis.pendingProviders
    : [];

  return (
    classification === "pending" ||
    classification === "scan pending" ||
    analysis.scanFinalized === false ||
    analysis.state === "pending-provider" ||
    analysis.providerPending === true ||
    pendingProviders.length > 0 ||
    analysis.providerCompletion?.hasPendingProvider === true
  );
}

function isStoredLinkAnalysisTerminalIncomplete(analysis = {}) {
  const state = String(analysis.state || "").toLowerCase();
  const classification = String(analysis.classification || "").toLowerCase();

  return Boolean(
    state === "verification-incomplete" ||
    state === "completed-limited" ||
    (
      classification === "unverified" &&
      analysis.scanFinalized === true &&
      toFiniteScoreOrNull(analysis.safetyScore) === null &&
      !isAnalysisPendingLike(analysis)
    )
  );
}

function shouldNormalizeAsVerificationIncomplete(analysis = {}) {
  const state = String(analysis.state || "").toLowerCase();
  const classification = String(analysis.classification || "").toLowerCase();
  const retryStatus = String(analysis.providerRetryPlan?.status || "").toLowerCase();
  const retryBudgetExhausted = Boolean(
    analysis.scoreAudit?.retryBudgetExhausted === true ||
    retryStatus === "exhausted" ||
    retryStatus === "failed"
  );
  const scoreMissing = toFiniteScoreOrNull(analysis.safetyScore) === null;
  const finalized = analysis.scanFinalized === true;
  const hasProviderPending = Boolean(
    analysis.providerPending === true ||
    analysis.providerCompletion?.hasPendingProvider === true ||
    (Array.isArray(analysis.pendingProviders) && analysis.pendingProviders.length > 0)
  );

  return Boolean(
    state === "verification-incomplete" ||
    state === "completed-limited" ||
    retryBudgetExhausted ||
    (
      classification === "unverified" &&
      finalized &&
      scoreMissing &&
      !hasProviderPending
    )
  );
}

function normalizeTerminalIncompleteAnalysis(analysis = {}, reason = "Verification did not complete.") {
  if (!analysis || typeof analysis !== "object" || analysis.providerOverride === true) {
    return analysis;
  }

  const limitations = [
    ...(Array.isArray(analysis.limitations) ? analysis.limitations : []),
    reason
  ].filter(Boolean);
  const providerCompletion = {
    ...((analysis.providerCompletion && typeof analysis.providerCompletion === "object") ? analysis.providerCompletion : {}),
    hasPendingProvider: false,
    allRequiredProvidersTerminal: true,
    pendingProviders: []
  };
  const scoreAudit = {
    ...((analysis.scoreAudit && typeof analysis.scoreAudit === "object") ? analysis.scoreAudit : {}),
    scanFinalized: true,
    displayedScoreWithheld: true,
    verificationIncomplete: true,
    pendingProviders: [],
    terminalIncompleteReason: reason
  };
  const terminalizeChild = (item) => {
    if (!item || typeof item !== "object" || item.providerOverride === true) {
      return item;
    }

    if (!isAnalysisPendingLike(item) && !isStoredLinkAnalysisTerminalIncomplete(item)) {
      return item;
    }

    return {
      ...item,
      classification: "Verification Incomplete",
      safetyScore: null,
      scanFinalized: true,
      state: "verification-incomplete",
      providerPending: false,
      pendingProviders: [],
      providerCompletion: {
        ...((item.providerCompletion && typeof item.providerCompletion === "object") ? item.providerCompletion : {}),
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        pendingProviders: []
      },
      restartable: true
    };
  };

  return {
    ...analysis,
    classification: "Verification Incomplete",
    safetyScore: null,
    scanFinalized: true,
    state: "verification-incomplete",
    providerPending: false,
    pendingProviders: [],
    pendingLinkRefreshTargets: [],
    pendingProviderRefreshTarget: null,
    linkScoreSummary: Array.isArray(analysis.linkScoreSummary)
      ? analysis.linkScoreSummary.map(terminalizeChild)
      : analysis.linkScoreSummary,
    linkAnalysisSnapshots: Array.isArray(analysis.linkAnalysisSnapshots)
      ? analysis.linkAnalysisSnapshots.map(terminalizeChild)
      : analysis.linkAnalysisSnapshots,
    providerCompletion,
    scoreAudit,
    interceptionRecommended: false,
    verificationState: "incomplete",
    limitations: [...new Set(limitations)].slice(0, 8),
    restartable: true
  };
}

function hasRetryablePendingProvider(analysis = {}) {
  if (!analysis || typeof analysis !== "object" || analysis.providerOverride === true) {
    return false;
  }

  const retryPlan = analysis.providerRetryPlan || {};
  const retryStatus = String(retryPlan.status || "").toLowerCase();
  if (["exhausted", "failed", "completed", "finalized"].includes(retryStatus)) {
    return false;
  }

  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const retryableProvider = providerResults.some((provider) => {
    const status = getProviderStatus(provider);
    return (
      status === "pending" &&
      provider?.details?.terminal !== true &&
      provider?.details?.retryable !== false
    );
  });

  const providerCompletion = analysis.providerCompletion || buildProviderCompletionState(providerResults);
  const pendingProviders = Array.isArray(analysis.pendingProviders)
    ? analysis.pendingProviders
    : Array.isArray(providerCompletion.pendingProviders)
      ? providerCompletion.pendingProviders
      : [];

  return Boolean(
    retryableProvider ||
    (
      providerCompletion.hasPendingProvider === true &&
      pendingProviders.length > 0
    )
  );
}

function isDeadOrInvalidShortlinkAnalysis(analysis = {}) {
  const endpointResult = analysis.endpointResult || {};
  const features = analysis.features || {};
  const isShortlink = Boolean(features.shortenedUrl || endpointResult.isShortener);
  if (!isShortlink) {
    return false;
  }

  const effectiveEndpoint =
    normalizeProviderCandidateUrl(endpointResult.effectiveEndpoint) ||
    normalizeProviderCandidateUrl(endpointResult.resolvedUrl) ||
    normalizeProviderCandidateUrl(analysis.analysisUrl) ||
    "";
  const confidence = String(endpointResult.endpointConfidence || analysis.endpointConfidence || "").toLowerCase();
  const evidenceText = [
    endpointResult.resolutionMethod,
    endpointResult.fetchStatus,
    ...(Array.isArray(endpointResult.errors) ? endpointResult.errors : []),
    ...(Array.isArray(endpointResult.warnings) ? endpointResult.warnings : []),
    ...(Array.isArray(analysis.limitations) ? analysis.limitations : [])
  ].join(" ").toLowerCase();

  return Boolean(
    !effectiveEndpoint ||
    endpointResult.invalidDestination === true ||
    endpointResult.unsupportedEndpoint === true ||
    endpointResult.deadShortlink === true ||
    (
      confidence === "low" &&
      /(dead|invalid|unavailable|unsupported|could not be resolved|no usable final|not found|failed)/i.test(evidenceText)
    )
  );
}

function normalizeBackgroundTerminalState(analysis = {}) {
  if (!analysis || typeof analysis !== "object" || analysis.providerOverride === true) {
    return analysis;
  }

  if (isDeadOrInvalidShortlinkAnalysis(analysis)) {
    console.debug("[DILI][terminal-state] Dead shortlink detected.", {
      postId: analysis.postId || "",
      analysisUrl: analysis.analysisUrl || analysis.normalizedUrl || ""
    });
    return normalizeTerminalIncompleteAnalysis(
      analysis,
      "The shortened link appears unavailable or could not be resolved to a valid final destination."
    );
  }

  const state = String(analysis.state || "").toLowerCase();
  const classification = String(analysis.classification || "").toLowerCase();
  const retryStatus = String(analysis.providerRetryPlan?.status || "").toLowerCase();
  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const providerCompletion = analysis.providerCompletion || buildProviderCompletionState(providerResults);
  const pendingProviders = Array.isArray(analysis.pendingProviders)
    ? analysis.pendingProviders
    : Array.isArray(providerCompletion.pendingProviders)
      ? providerCompletion.pendingProviders
      : [];
  const pendingLike = Boolean(
    state === "pending-provider" ||
    classification === "scan pending" ||
    analysis.providerPending === true ||
    analysis.scanFinalized === false ||
    providerCompletion.hasPendingProvider === true ||
    pendingProviders.length > 0
  );

  if (["exhausted", "failed"].includes(retryStatus)) {
    console.debug("[DILI][terminal-state] Provider retry state exhausted; terminalizing analysis.", {
      postId: analysis.postId || "",
      retryStatus
    });
    return normalizeTerminalIncompleteAnalysis(analysis, "Provider verification retry budget was exhausted.");
  }

  if (
    pendingLike &&
    (
      providerCompletion.hasPendingProvider !== true ||
      pendingProviders.length === 0 ||
      !hasRetryablePendingProvider({
        ...analysis,
        providerResults,
        providerCompletion,
        pendingProviders
      })
    )
  ) {
    console.debug("[DILI][terminal-state] Stale pending analysis terminalized.", {
      postId: analysis.postId || "",
      state,
      classification
    });
    return normalizeTerminalIncompleteAnalysis(analysis, "Provider verification could not continue and was finalized as incomplete.");
  }

  if (classification === "unverified" && analysis.scanFinalized === false) {
    return normalizeTerminalIncompleteAnalysis(analysis, "Unverified result was not finalized by provider verification.");
  }

  if (shouldNormalizeAsVerificationIncomplete(analysis)) {
    return normalizeTerminalIncompleteAnalysis(
      analysis,
      analysis.scoreAudit?.terminalIncompleteReason ||
        "Provider verification could not be completed. Restart the scan to try again."
    );
  }

  return {
    ...analysis,
    providerResults,
    providerCompletion
  };
}

function getFirstFiniteCount(...values) {
  for (const value of values) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric >= 0) {
      return numeric;
    }
  }

  return 0;
}

function getVirusTotalStats(provider = {}) {
  const details = provider?.details || {};
  const stats =
    details.last_analysis_stats ||
    details.lastAnalysisStats ||
    provider.last_analysis_stats ||
    provider.lastAnalysisStats ||
    provider.stats ||
    {};

  return {
    maliciousCount: getFirstFiniteCount(
      details.maliciousCount,
      details.malicious,
      provider.maliciousCount,
      provider.malicious,
      stats.malicious
    ),
    suspiciousCount: getFirstFiniteCount(
      details.suspiciousCount,
      details.suspicious,
      provider.suspiciousCount,
      provider.suspicious,
      stats.suspicious
    )
  };
}

function getVirusTotalWarningState(providerResults = []) {
  const vt = Array.isArray(providerResults)
    ? getNormalizedProviderResult(providerResults, "virustotal")
    : providerResults;
  const { maliciousCount, suspiciousCount } = getVirusTotalStats(vt || {});
  const status = getProviderStatus(vt);

  if (maliciousCount >= 2 || (maliciousCount >= 1 && suspiciousCount >= 2)) {
    return {
      maliciousCount,
      suspiciousCount,
      hasStrongConsensus: true,
      hasSuspiciousLevelWarning: false,
      hasCautionOnlyWarning: false,
      warningSeverity: "high",
      warningLabel: "VirusTotal reported multiple malicious or suspicious detections.",
      recoveryCap: 30,
      classificationFloor: "High Risk",
      status
    };
  }

  if (maliciousCount === 1 || (maliciousCount === 0 && suspiciousCount >= 2)) {
    return {
      maliciousCount,
      suspiciousCount,
      hasStrongConsensus: false,
      hasSuspiciousLevelWarning: true,
      hasCautionOnlyWarning: false,
      warningSeverity: "suspicious",
      warningLabel: maliciousCount === 1
        ? "VirusTotal reported one malicious detection. DILI treated this as a suspicious provider warning, but not as a provider-confirmed High Risk result."
        : "VirusTotal reported multiple suspicious detections. DILI treated this as a suspicious provider warning.",
      recoveryCap: 79,
      classificationFloor: "Suspicious",
      status
    };
  }

  if (maliciousCount === 0 && suspiciousCount === 1) {
    return {
      maliciousCount,
      suspiciousCount,
      hasStrongConsensus: false,
      hasSuspiciousLevelWarning: false,
      hasCautionOnlyWarning: true,
      warningSeverity: "caution",
      warningLabel: "VirusTotal reported one suspicious detection. DILI recorded this as a caution note.",
      recoveryCap: 94,
      classificationFloor: null,
      status
    };
  }

  return {
    maliciousCount,
    suspiciousCount,
    hasStrongConsensus: false,
    hasSuspiciousLevelWarning: false,
    hasCautionOnlyWarning: false,
    warningSeverity: "none",
    warningLabel: "",
    recoveryCap: null,
    classificationFloor: null,
    status
  };
}

function getVirusTotalSignalLevel(provider = {}) {
  const { maliciousCount: malicious, suspiciousCount: suspicious } = getVirusTotalWarningState(provider);

  if (malicious >= 2 || (malicious >= 1 && suspicious >= 2)) {
    return "strong";
  }

  if ((malicious === 1 && suspicious <= 1) || (malicious === 0 && suspicious >= 2)) {
    return "warning";
  }

  if (malicious === 0 && suspicious === 1) {
    return "caution";
  }

  return "clean";
}

function buildProviderOverridePolicy(providerResults = []) {
  const providers = normalizeProviderResults(providerResults);
  const gsb = getNormalizedProviderResult(providers, "gsb");
  const urlhaus = getNormalizedProviderResult(providers, "urlhaus");
  const vtWarningState = getVirusTotalWarningState(providers);
  const vtSignalLevel = vtWarningState.warningSeverity === "high"
    ? "strong"
    : vtWarningState.warningSeverity === "suspicious"
      ? "warning"
      : vtWarningState.warningSeverity;

  if (gsb.flagged === true) {
    return {
      providerOverride: true,
      providerOverrideSource: "gsb",
      providerOverrideReason: "Google Safe Browsing flagged this link.",
      virusTotalSignalLevel: vtSignalLevel,
      virusTotalWarningState: vtWarningState
    };
  }

  if (urlhaus.flagged === true) {
    return {
      providerOverride: true,
      providerOverrideSource: "urlhaus",
      providerOverrideReason: "URLhaus flagged this link.",
      virusTotalSignalLevel: vtSignalLevel,
      virusTotalWarningState: vtWarningState
    };
  }

  if (vtWarningState.hasStrongConsensus) {
    return {
      providerOverride: true,
      providerOverrideSource: "virustotal",
      providerOverrideReason: "VirusTotal reported multiple malicious or suspicious detections.",
      virusTotalSignalLevel: vtSignalLevel,
      virusTotalWarningState: vtWarningState
    };
  }

  return {
    providerOverride: false,
    providerOverrideSource: "",
    providerOverrideReason: "",
    virusTotalSignalLevel: vtSignalLevel,
    virusTotalWarningState: vtWarningState
  };
}

function applyVirusTotalWarningScorePolicy(finalScore, finalClassification, vtWarning = {}) {
  const numericScore = toFiniteScoreOrNull(finalScore);
  if (numericScore === null) {
    return {
      finalScore,
      finalClassification,
      providerWarningApplied: false,
      providerCautionApplied: false,
      providerWarningReason: vtWarning.warningLabel || "",
      providerWarningScoreCap: null
    };
  }

  // VirusTotal now contributes through the weighted provider deduction in
  // riskEngine.js. This helper only preserves display/audit wording for older
  // call sites and must not cap or force a classification.
  if (vtWarning.hasStrongConsensus) {
    return {
      finalScore: numericScore,
      finalClassification,
      providerWarningApplied: false,
      providerCautionApplied: false,
      providerWarningReason: vtWarning.warningLabel || "VirusTotal reported multiple malicious or suspicious detections.",
      providerWarningScoreCap: null
    };
  }

  if (vtWarning.hasSuspiciousLevelWarning) {
    return {
      finalScore: numericScore,
      finalClassification,
      providerWarningApplied: false,
      providerCautionApplied: false,
      providerWarningReason: "VirusTotal reported a provider warning signal.",
      providerWarningScoreCap: null
    };
  }

  if (vtWarning.hasCautionOnlyWarning) {
    return {
      finalScore: numericScore,
      finalClassification,
      providerWarningApplied: false,
      providerCautionApplied: true,
      providerWarningReason: "VirusTotal reported one suspicious detection.",
      providerWarningScoreCap: null
    };
  }

  return {
    finalScore: numericScore,
    finalClassification,
    providerWarningApplied: false,
    providerCautionApplied: false,
    providerWarningReason: "",
    providerWarningScoreCap: null
  };
}

function buildVirusTotalProviderWarningReviewRecommendation({
  finalScore,
  finalClassification,
  scoreAudit = {},
  providerOverride = false,
  providerOverrideSource = "",
  virusTotalWarningState = {},
  providerResults = []
} = {}) {
  const score = toFiniteScoreOrNull(finalScore ?? scoreAudit.finalScore ?? scoreAudit.computedSafetyScore);
  const classification = String(finalClassification || scoreAudit.finalClassification || scoreAudit.computedClassification || scoreAudit.classification || "").toLowerCase();
  const providerDeductions = scoreAudit.providerDeductions || {};
  const vtDeduction = toFiniteScoreOrNull(providerDeductions.virustotal);
  const vtHits = Number(virusTotalWarningState.maliciousCount || 0) + Number(virusTotalWarningState.suspiciousCount || 0);
  const normalizedProviders = normalizeProviderResults(providerResults);
  const gsb = normalizedProviders.find((item) => item.provider === "gsb");
  const urlhaus = normalizedProviders.find((item) => item.provider === "urlhaus");
  const strongerProviderWarning = Boolean(
    providerOverride === true && (providerOverrideSource === "gsb" || providerOverrideSource === "urlhaus")
  ) || Boolean(gsb?.flagged === true || urlhaus?.flagged === true) || Boolean((toFiniteScoreOrNull(providerDeductions.gsb) || 0) > 0 || (toFiniteScoreOrNull(providerDeductions.urlhaus) || 0) > 0);

  if (
    providerOverride === true ||
    strongerProviderWarning ||
    score === null ||
    score < 80 ||
    classification !== "safe"
  ) {
    return {
      providerWarningReviewRecommended: false,
      reviewRecommendedReason: ""
    };
  }

  if (vtDeduction > 0 || vtHits > 0) {
    return {
      providerWarningReviewRecommended: true,
      reviewRecommendedReason: "VirusTotal reported low-count malicious/suspicious detections. The score remains Safe, but DILI recommends reviewing the link before opening it."
    };
  }

  return {
    providerWarningReviewRecommended: false,
    reviewRecommendedReason: ""
  };
}

function applyVirusTotalWarningAuditFields(scoreAudit = {}, vtWarning = {}, warningPolicy = {}, reviewRecommendation = {}) {
  return {
    ...scoreAudit,
    providerWarningApplied: warningPolicy.providerWarningApplied === true,
    providerCautionApplied: warningPolicy.providerCautionApplied === true,
    providerWarningReviewRecommended: reviewRecommendation.providerWarningReviewRecommended === true,
    reviewRecommendedReason: reviewRecommendation.reviewRecommendedReason || "",
    providerWarningReason: warningPolicy.providerWarningReason || reviewRecommendation.reviewRecommendedReason || "",
    virusTotalMaliciousDetections: vtWarning.maliciousCount || 0,
    virusTotalSuspiciousDetections: vtWarning.suspiciousCount || 0,
    providerWarningScoreCap: warningPolicy.providerWarningScoreCap ?? null,
    cleanProviderRecoveryBlockedByProviderWarning: Boolean(
      (vtWarning.hasSuspiciousLevelWarning || vtWarning.hasCautionOnlyWarning || vtWarning.hasStrongConsensus) &&
      Array.isArray(scoreAudit.recoveryBlockedReasons) &&
      scoreAudit.recoveryBlockedReasons.includes("VirusTotal reported provider warning detections.")
    )
  };
}

function hasTerminalProviderLimitation(providerResults = []) {
  return normalizeProviderResults(providerResults).some((provider) => {
    const status = getProviderStatus(provider);
    return provider?.configured === true && ["retry-budget-exhausted", "rate-limited", "timeout", "error", "parse-error"].includes(status);
  });
}

function withAnalysisTimeout(promise, timeoutMs, fallbackFactory) {
  let timer = null;

  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => {
      resolve(typeof fallbackFactory === "function" ? fallbackFactory() : null);
    }, timeoutMs);
  });

  return Promise.race([promise, timeoutPromise])
    .finally(() => {
      if (timer !== null) {
        clearTimeout(timer);
      }
    });
}

function buildTimedOutEndpointResult(rawUrl = "") {
  const features = analyzeUrlFeatures({ rawUrl });
  const fallbackUrl =
    normalizeProviderCandidateUrl(features.unwrappedUrl) ||
    normalizeProviderCandidateUrl(features.normalizedUrl) ||
    normalizeProviderCandidateUrl(rawUrl) ||
    String(rawUrl || "").trim();
  const domain = safeHostname(fallbackUrl);

  return {
    rawUrl,
    normalizedRawUrl: features.normalizedUrl || fallbackUrl,
    unwrappedUrl: features.unwrappedUrl || fallbackUrl,
    resolvedUrl: fallbackUrl,
    effectiveEndpoint: fallbackUrl,
    effectiveDomain: domain,
    registrableDomain: getRegistrableDomain(domain),
    isFacebookWrapper: Boolean(features.usesKnownWrapper || features.facebookWrapperUnwrapped),
    isInternalFacebook: false,
    isShortener: Boolean(features.shortenedUrl),
    endpointConfidence: "low",
    resolutionMethod: "resolution-timeout-fallback",
    resolutionChain: [fallbackUrl].filter(Boolean),
    fullObservedRedirectTrace: [fallbackUrl].filter(Boolean),
    fullObservedRedirectEvents: [],
    fullRedirectCount: 0,
    fullRedirectDomains: domain ? [domain] : [],
    redirectAnalysis: null,
    warnings: ["Endpoint resolution timed out. DILI checked the best available URL candidate."],
    errors: ["Endpoint resolution timed out."],
    resolutionTimedOut: true
  };
}

function buildTimedOutRedirectAnalysis(rawUrl = "", endpointResult = {}) {
  const fallbackUrl =
    normalizeProviderCandidateUrl(endpointResult.effectiveEndpoint) ||
    normalizeProviderCandidateUrl(endpointResult.resolvedUrl) ||
    normalizeProviderCandidateUrl(endpointResult.unwrappedUrl) ||
    normalizeProviderCandidateUrl(endpointResult.normalizedRawUrl) ||
    normalizeProviderCandidateUrl(rawUrl) ||
    String(rawUrl || "").trim();
  const domain = safeHostname(fallbackUrl);

  return {
    redirectCount: 0,
    redirectChain: [fallbackUrl].filter(Boolean),
    chain: [fallbackUrl].filter(Boolean),
    fullObservedRedirectTrace: [fallbackUrl].filter(Boolean),
    fullObservedRedirectEvents: [],
    fullRedirectCount: 0,
    fullRedirectDomains: domain ? [domain] : [],
    redirectDomains: domain ? [domain] : [],
    uniqueRegistrableDomains: domain ? [getRegistrableDomain(domain)].filter(Boolean) : [],
    resolvedUrl: fallbackUrl,
    resolutionMethod: "redirect-timeout-fallback",
    fetchMethod: "",
    fetchStatus: "timeout",
    skipped: false,
    skipReason: "",
    protocol: "",
    notes: ["Redirect probing timed out. DILI checked the best available URL candidate."],
    fetchAttempted: true,
    fetchAllowed: true,
    fetchSucceeded: false,
    suspiciousPattern: false,
    multipleRedirects: false,
    crossDomainRedirectChain: false,
    redirectChainToDifferentRegistrantLikeTarget: false,
    wrapperToExternalDestination: false,
    shortenerToUnrelatedDomain: false,
    trackingHopToUnrelatedDomain: false,
    redirectTimedOut: true
  };
}




async function performLinkAnalysis({ postId, rawUrl, links, displayedText, candidateContext, postTextHash, normalizedVisiblePostText, postSignature, linkFingerprint, performanceTiming, baselineContext, isReanalysis }) {
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
        postSignature,
        linkFingerprint,
        performanceTiming,
        baselineContext,
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

  function getAnalysisSortScore(item) {
    if (
      isPendingClassificationLabel(item?.classification) ||
      item?.scanFinalized === false ||
      item?.providerCompletion?.hasPendingProvider === true ||
      (Array.isArray(item?.pendingProviders) && item.pendingProviders.length > 0)
    ) {
      return 101;
    }

    const displayedScore = toFiniteScoreOrNull(item?.safetyScore);
    if (displayedScore !== null) {
      return displayedScore;
    }

    const computedScore = toFiniteScoreOrNull(item?.computedSafetyScore);
    if (computedScore !== null) {
      return computedScore;
    }

    return 101;
  }

  // The post-level result intentionally follows the lowest-scoring successful link
  // so one risky link cannot be hidden by several safe links.
  const worst = analyses
    .slice()
    .sort((left, right) => {
      const leftScore = getAnalysisSortScore(left);
      const rightScore = getAnalysisSortScore(right);
      return leftScore - rightScore;
    })[0];
  const linkAnalysisSnapshots = analyses.map((item, index) => buildStoredLinkAnalysisSnapshot(item, index + 1));
  const pendingLinkRefreshTargets = buildPendingLinkRefreshTargets(linkAnalysisSnapshots);
  const providerOverrideChild = linkAnalysisSnapshots.find((snapshot) => snapshot.providerOverride);
  const hasPendingChild = pendingLinkRefreshTargets.length > 0;
  const linkScoreSummary = buildLinkScoreSummaryFromSnapshots(linkAnalysisSnapshots);
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
    linkScoreSummary,
    linkAnalysisSnapshots,
    pendingLinkRefreshTargets,
    pendingProviderRefreshTarget: pendingLinkRefreshTargets[0] || null
  };

  if (providerOverrideChild) {
    const providerOverrideScore =
      toFiniteScoreOrNull(providerOverrideChild.safetyScore) ??
      toFiniteScoreOrNull(providerOverrideChild.computedSafetyScore);

    enrichedWorst.classification = providerOverrideChild.classification || "High Risk";
    enrichedWorst.safetyScore = providerOverrideScore;
    enrichedWorst.computedClassification = providerOverrideChild.computedClassification || providerOverrideChild.classification || "High Risk";
    enrichedWorst.computedSafetyScore = providerOverrideScore;
    enrichedWorst.scanFinalized = true;
    enrichedWorst.state = "completed";
    enrichedWorst.providerPending = false;
    enrichedWorst.providerOverride = true;
    enrichedWorst.interceptionRecommended = true;
    enrichedWorst.pendingProviders = [];
    enrichedWorst.providerCompletion = {
      ...(providerOverrideChild.providerCompletion || {}),
      hasPendingProvider: false,
      allRequiredProvidersTerminal: true,
      pendingProviders: []
    };
  } else if (hasPendingChild) {
    enrichedWorst.classification = "Scan Pending";
    enrichedWorst.safetyScore = null;
    enrichedWorst.scanFinalized = false;
    enrichedWorst.state = "pending-provider";
    enrichedWorst.providerPending = true;
    enrichedWorst.interceptionRecommended = false;
    enrichedWorst.pendingProviders = [
      ...new Set(
        pendingLinkRefreshTargets.flatMap((target) => target.pendingProviders || [])
      )
    ];
    enrichedWorst.providerCompletion = {
      ...(enrichedWorst.providerCompletion || {}),
      hasPendingProvider: true,
      allRequiredProvidersTerminal: false,
      pendingProviders: enrichedWorst.pendingProviders
    };
    enrichedWorst.pendingLinkRefreshTargets = pendingLinkRefreshTargets;
    enrichedWorst.pendingProviderRefreshTarget = pendingLinkRefreshTargets[0] || null;
  }

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
    linkAnalysisSnapshots,
    pendingLinkRefreshTargets: enrichedWorst.pendingLinkRefreshTargets || [],
    pendingProviderRefreshTarget: enrichedWorst.pendingProviderRefreshTarget || null,
    failedLinkLimitations: limitations,
    limitations: [...(worst.limitations || []), ...limitations].slice(0, 8)
  };
}

function buildStoredLinkAnalysisSnapshot(analysis = {}, index = 0) {
  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const providerCompletion = analysis.providerCompletion || buildProviderCompletionState(providerResults);

  return {
    index,
    url: analysis.url || analysis.displayUrl || analysis.analysisUrl || "",
    displayUrl: analysis.displayUrl || analysis.url || "",
    analysisUrl: analysis.analysisUrl || analysis.url || "",
    normalizedUrl: analysis.normalizedUrl || "",
    providerCheckedUrl: analysis.providerCheckedUrl || analysis.analysisUrl || analysis.url || "",
    domain:
      analysis.endpointResult?.effectiveDomain ||
      analysis.urlFeatureAnalysis?.finalDomain ||
      analysis.domain ||
      "",
    safetyScore: analysis.safetyScore,
    computedSafetyScore: analysis.computedSafetyScore,
    classification: analysis.classification,
    computedClassification: analysis.computedClassification,
    scanFinalized: analysis.scanFinalized,
    state: analysis.state || "",
    providerOverride: analysis.providerOverride === true,
    providerPending: analysis.providerPending === true,
    providerResults,
    providerCompletion,
    providerRetryPlan: cloneValue(analysis.providerRetryPlan || {}),
    providerDeductions: cloneValue(analysis.providerDeductions || analysis.scoreAudit?.providerDeductions || {}),
    heuristicRawCategoryTotals: cloneValue(analysis.heuristicRawCategoryTotals || analysis.scoreAudit?.heuristicRawCategoryTotals || {}),
    heuristicCategoryDeductions: cloneValue(analysis.heuristicCategoryDeductions || analysis.scoreAudit?.heuristicCategoryDeductions || {}),
    heuristicRawTotal: analysis.heuristicRawTotal ?? analysis.scoreAudit?.heuristicRawTotal ?? null,
    heuristicScaledDeduction: analysis.heuristicScaledDeduction ?? analysis.scoreAudit?.heuristicScaledDeduction ?? null,
    totalDeduction: analysis.totalDeduction ?? analysis.scoreAudit?.ruleDeductionTotal ?? null,
    pendingProviders: Array.isArray(analysis.pendingProviders)
      ? analysis.pendingProviders
      : Array.isArray(providerCompletion.pendingProviders)
        ? providerCompletion.pendingProviders
        : [],
    features: cloneValue(analysis.features || {}),
    endpointResult: cloneValue(analysis.endpointResult || {}),
    redirectAnalysis: cloneValue(analysis.redirectAnalysis || {}),
    urlFeatureAnalysis: cloneValue(analysis.urlFeatureAnalysis || {}),
    performanceTiming: cloneValue(analysis.performanceTiming || {}),
    scoreAudit: cloneValue(analysis.scoreAudit || {}),
    verificationState: analysis.verificationState || "",
    verificationOnlyUnknown: analysis.verificationOnlyUnknown === true,
    concreteRiskSignals: analysis.concreteRiskSignals === true,
    limitations: Array.isArray(analysis.limitations) ? analysis.limitations.slice(0, 8) : []
  };
}

function isStoredLinkAnalysisPending(analysis = {}) {
  if (isStoredLinkAnalysisTerminalIncomplete(analysis)) {
    return false;
  }

  const vt = getNormalizedProviderResult(analysis.providerResults || [], "virustotal");
  const vtStatus = getProviderStatus(vt);
  const vtRetryable = vt?.details?.retryable !== false && vt?.details?.terminal !== true;
  const providerCompletion = buildProviderCompletionState(analysis.providerResults || []);

  if (providerCompletion.allRequiredProvidersTerminal && !providerCompletion.hasPendingProvider) {
    return false;
  }

  return Boolean(
    isAnalysisPendingLike(analysis) ||
    (vtRetryable && vtStatus === "pending")
  );
}

function normalizeStoredLinkAnalysisSnapshot(analysis = {}) {
  if (!analysis || typeof analysis !== "object") {
    return analysis;
  }

  const terminalNormalized = normalizeBackgroundTerminalState(analysis);
  if (
    terminalNormalized !== analysis &&
    String(terminalNormalized?.state || "").toLowerCase() === "verification-incomplete"
  ) {
    return terminalNormalized;
  }
  analysis = terminalNormalized;

  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const providerCompletion = buildProviderCompletionState(providerResults);
  const providerPolicy = buildProviderOverridePolicy(providerResults);

  if (providerPolicy.providerOverride) {
    const score = toFiniteScoreOrNull(analysis.safetyScore) ??
      toFiniteScoreOrNull(analysis.computedSafetyScore) ??
      toFiniteScoreOrNull(analysis.scoreAudit?.finalScore) ??
      null;
    const classification = score !== null
      ? classifySafetyScore(score)
      : (analysis.computedClassification || analysis.classification || "Unverified");

    return {
      ...analysis,
      classification,
      safetyScore: score,
      computedClassification: classification,
      computedSafetyScore: score,
      scanFinalized: true,
      state: "completed",
      providerOverride: true,
      providerPending: false,
      providerResults,
      providerCompletion: {
        ...providerCompletion,
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        pendingProviders: []
      },
      pendingProviders: []
    };
  }

  if (
    providerCompletion.allRequiredProvidersTerminal &&
    !providerCompletion.hasPendingProvider &&
    isAnalysisPendingLike(analysis)
  ) {
    const limited = hasTerminalProviderLimitation(providerResults);
    const score = toFiniteScoreOrNull(analysis.computedSafetyScore) ??
      toFiniteScoreOrNull(analysis.scoreAudit?.computedSafetyScore) ??
      toFiniteScoreOrNull(analysis.scoreAudit?.finalScore) ??
      toFiniteScoreOrNull(analysis.safetyScore);
    const classification = limited
      ? "Unverified"
      : analysis.computedClassification || (score !== null ? classifySafetyScore(score) : "Unverified");

    return {
      ...analysis,
      classification,
      safetyScore: limited ? null : score,
      scanFinalized: true,
      state: limited ? "verification-incomplete" : (analysis.state === "pending-provider" ? "monitored" : analysis.state || "monitored"),
      providerPending: false,
      providerResults,
      providerCompletion: {
        ...providerCompletion,
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        pendingProviders: []
      },
      pendingProviders: []
    };
  }

  return {
    ...analysis,
    providerResults,
    providerCompletion
  };
}

function buildPendingLinkRefreshTargets(linkAnalyses = []) {
  return (Array.isArray(linkAnalyses) ? linkAnalyses : [])
    .map(normalizeStoredLinkAnalysisSnapshot)
    .filter(isStoredLinkAnalysisPending);
}

function isPendingProviderRefreshTarget(candidate = {}) {
  if (!candidate || typeof candidate !== "object") {
    return false;
  }

  if (isStoredLinkAnalysisTerminalIncomplete(candidate)) {
    return false;
  }

  const vt = getNormalizedProviderResult(candidate.providerResults || [], "virustotal");
  const status = String(vt?.details?.status || candidate.status || "").toLowerCase();
  const retryable = vt?.details?.retryable !== false && vt?.details?.terminal !== true;

  return Boolean(
    retryable &&
    (
      isAnalysisPendingLike(candidate) ||
      status === "pending"
    )
  );
}

async function performSingleLinkAnalysis({ postId, rawUrl, displayedText, candidateContext, postTextHash, normalizedVisiblePostText, postSignature, linkFingerprint, performanceTiming = {}, baselineContext = {}, isReanalysis, persist = true }) {
  const totalStartedAt = nowMs();
  const backgroundAnalysisStartedAt = Date.now();
  const incomingPerformanceTiming = normalizePerformanceTiming(performanceTiming);

  if (!(await getScanEnabledState())) {
    throw new Error("Scanning is currently disabled.");
  }

  await ensureActiveSession("analysis");

const endpointStartedAt = nowMs();
const endpointResolutionStartedAt = Date.now();
const endpointResult = await withAnalysisTimeout(
  resolveEndpoint(rawUrl),
  10000,
  () => buildTimedOutEndpointResult(rawUrl)
);
const endpointResolutionCompletedAt = Date.now();
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
        fullObservedRedirectTrace: endpointResult.fullObservedRedirectTrace || endpointResult.resolutionChain,
        fullObservedRedirectEvents: endpointResult.fullObservedRedirectEvents || [],
        fullRedirectCount: endpointResult.fullRedirectCount || 0,
        fullRedirectDomains: endpointResult.fullRedirectDomains || [],
        notes: endpointResult.warnings
      },
      performanceTiming: mergePerformanceTiming(incomingPerformanceTiming, {
        analysisStartedAt: incomingPerformanceTiming.analysisStartedAt || backgroundAnalysisStartedAt,
        endpointResolutionStartedAt,
        endpointResolutionCompletedAt,
        analysisCompletedAt: Date.now()
      }),
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
  const integrityBaseline = mergeBaselineContext(existingBaseline, baselineContext);
  const previousBaselineUrl =
    integrityBaseline?.analysisUrl ||
    integrityBaseline?.normalizedUrl ||
    integrityBaseline?.rawUrl ||
    "";
  const compatibleBaseline = getCompatibleBaseline(integrityBaseline);

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
  const providerCheckedUrl =
  reusableUrlAnalysis.providerCheckedUrl ||
  reusableUrlAnalysis.urlFeatureAnalysis?.providerCheckedUrl ||
  endpointResult?.effectiveEndpoint ||
  analysisUrl ||
  normalizedUrl ||
  rawUrl ||
  "";
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
  const detectedAt = incomingPerformanceTiming.detectedAt || Date.now();
  const baselineFirstSeenAt = Number(integrityBaseline?.baselineFirstSeenAt || integrityBaseline?.firstSeenAt || detectedAt);
const currentPostTextHash = String(postTextHash || "");
const normalizedCurrentPostText = String(normalizedVisiblePostText || "")
  .replace(/\s+/g, " ")
  .trim();

const previousBaselineState =
  compatibleBaseline?.baselineState ||
  integrityBaseline?.baselineState ||
  "";

  const previousPostTextHash = String(integrityBaseline?.postTextHash || integrityBaseline?.currentPostTextHash || "");
const postTextChangedSinceBaseline = Boolean(
  isReanalysis &&
  previousPostTextHash &&
  currentPostTextHash &&
  previousPostTextHash !== currentPostTextHash
);
const currentHasUsableLinkCandidate = Boolean(
  normalizedCandidateContext.selectedNormalizedTarget ||
  normalizedCandidateContext.rawHref ||
  normalizedCandidateContext.unwrappedCandidateUrl ||
  analysisUrl ||
  normalizedUrl
);
const baselineFirstSeenTime = Number(
  integrityBaseline?.baselineFirstSeenAt ||
  integrityBaseline?.firstSeenAt ||
  0
);
const baselineAgeMs = baselineFirstSeenTime > 0
  ? Date.now() - baselineFirstSeenTime
  : 0;
const stableIdentityMatch = Boolean(
  compatibleBaseline?.postIdentityStable === true &&
  normalizedCandidateContext.postIdentityStable === true
);
const baselineHadExplicitNoLink = hasNoLinkBaselineMarker(compatibleBaseline || integrityBaseline);
const confirmedNoLinkBaseline = Boolean(
  previousBaselineState === "no_link" &&
  (integrityBaseline?.hadLinkAtBaseline === false || baselineHadExplicitNoLink) &&
  compatibleBaseline?.postIdentityStable === true
);
const provisionalNoLinkBaseline = Boolean(
  baselineHadExplicitNoLink &&
  (
    previousBaselineState !== "no_link" ||
    compatibleBaseline?.postIdentityStable !== true
  )
);
const matureConfirmedNoLinkBaseline = Boolean(
  confirmedNoLinkBaseline &&
  baselineAgeMs >= POST_INTEGRITY_MIN_NO_LINK_BASELINE_AGE_MS
);
  const canUseExistingLinkIntegrityBaseline = Boolean(
    isReanalysis &&
    stableIdentityMatch &&
    compatibleBaseline?.urlHash &&
    !provisionalNoLinkBaseline &&
    baselineAgeMs >= POST_INTEGRITY_MIN_NO_LINK_BASELINE_AGE_MS &&
    currentHasUsableLinkCandidate &&
    normalizedCandidateContext.candidateMode === "single" &&
    normalizedCandidateContext.candidateIsDomainOnlyFallback !== true &&
    normalizedCandidateContext.candidateUrlCompleteness !== "domain-only-fallback"
  );
  const destinationChange = getCompatibleIntegrityDestinationChange(compatibleBaseline, {
    currentHash,
    analysisUrl,
    normalizedUrl,
    candidateContext: normalizedCandidateContext
  });
  const postIntegrityDecision = classifyPostIntegrityEvent({
    baseline: compatibleBaseline || integrityBaseline,
    current: {
      isReanalysis,
      baselineAgeMs,
      currentHasUsableLinkCandidate,
      currentHash,
      analysisUrl,
      normalizedUrl,
      postTextChangedSinceBaseline
    },
    identity: {
      stableIdentityMatch,
      currentPostIdentityStable: normalizedCandidateContext.postIdentityStable === true
    },
    candidate: {
      candidateContext: normalizedCandidateContext,
      canUseExistingLinkIntegrityBaseline,
      destinationChange
    }
  });
  logPostIntegrityDecision(postId, postIntegrityDecision);

  const linkInsertedAfterBaseline = Boolean(
    postIntegrityDecision.eventType === "link-inserted-after-stable-no-link" &&
    postIntegrityDecision.deductionEligible
  );
  const existingLinkIntegrityMismatch = Boolean(
    postIntegrityDecision.deductionEligible &&
    (
      postIntegrityDecision.eventType === "link-destination-changed" ||
      postIntegrityDecision.eventType === "link-url-changed-same-domain"
    )
  );
  const postContextFeatures = {
    domainPreviouslyFlagged,
    textMismatch: textComparison.mismatch,
    postTextChangedSinceBaseline,
    baselineHadNoLink: confirmedNoLinkBaseline || baselineHadExplicitNoLink,
    confirmedNoLinkBaseline,
    provisionalNoLinkBaseline,
    matureConfirmedNoLinkBaseline,
    baselineAgeMs,
    currentHasUsableLinkCandidate,
    linkInsertedAfterBaseline,
    integrityHashMismatch: Boolean(linkInsertedAfterBaseline || existingLinkIntegrityMismatch),
    linkInsertedAfterUnstableBaseline: postIntegrityDecision.eventType === "link-inserted-after-unstable-no-link",
    limitedPostIntegrityEvidence: postIntegrityDecision.confidence === "limited",
    sameDomainLinkChanged: postIntegrityDecision.eventType === "link-url-changed-same-domain",
    postIntegrityAuditOnly: postIntegrityDecision.auditOnly === true,
    postIntegrityConfidence: postIntegrityDecision.confidence,
    postIntegrityReason: postIntegrityDecision.reason,
    trackingOnlyPostIntegrityChange: postIntegrityDecision.eventType === "none" && destinationChange.trackingOnly === true
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
    wrapperToExternalDestination: enrichedUrlFeatures.wrapperToExternalDestination,
    facebookWrapperUnwrapped: enrichedUrlFeatures.facebookWrapperUnwrapped
  };
  let urlLevelFeatures = applyTrustedRedirectDestinationMitigation({
    ...urlLevelFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(urlLevelFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyMainstreamResolvedShortlinkMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyFacebookWrapperOnlyRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applySameDomainMarketingEncodingMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyKnownBrandedCampaignRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyKnownGoogleFormsRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult);
  urlLevelFeatures = applyKnownBrandAliasRedirectMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult, providerResults);
  urlLevelFeatures = applyCleanResolvedMarketingLinkMitigation(urlLevelFeatures, reusableUrlAnalysis, endpointResult, providerResults);
  const combinedFeaturesBase = {
    ...urlLevelFeatures,
    ...postContextFeatures
  };
  let features = applyTrustedRedirectDestinationMitigation({
    ...combinedFeaturesBase,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(combinedFeaturesBase)
  }, reusableUrlAnalysis, endpointResult);
  features = applyMainstreamResolvedShortlinkMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyFacebookWrapperOnlyRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applySameDomainMarketingEncodingMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyKnownBrandedCampaignRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyKnownGoogleFormsRedirectMitigation(features, reusableUrlAnalysis, endpointResult);
  features = applyKnownBrandAliasRedirectMitigation(features, reusableUrlAnalysis, endpointResult, providerResults);
  features = applyCleanResolvedMarketingLinkMitigation(features, reusableUrlAnalysis, endpointResult, providerResults);
  const urlLevelScoring = calculateSafetyScore(urlLevelFeatures, providerResults);
  const providerPolicy = buildProviderOverridePolicy(providerResults);
  const providerOverride = providerPolicy.providerOverride;
  const urlLevelClassification = classifySafetyScore(urlLevelScoring.score);
const scoringStartedAt = nowMs();
const scoring = calculateSafetyScore(features, providerResults);
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
  const providerCapBeforeScore = scoring.score;
  const providerCap = null;
  const providerCapAfterScore = scoring.score;

  let finalScore = scoring.score;

  let verificationCapReason = "";
  const verificationCapBeforeScore = finalScore;

  const verificationCapAfterScore = finalScore;

  const softCapBeforeScore = finalScore;
  const cappedScore = finalScore;
  const softUncertaintyCapApplied = Number(cappedScore) !== Number(finalScore);
  finalScore = cappedScore;
  const softCapAfterScore = finalScore;

  const recoveryBase = buildCleanProviderRecoveryState({
    features,
    endpointResult,
    providerResults,
    visibleUrl: urlFeatures.rawComparableUrl || urlFeatures.unwrappedUrl || urlFeatures.normalizedUrl || analysisUrl,
    providerCheckedUrl,
    finalUrl: endpointResult?.effectiveEndpoint || analysisUrl,
    finalDomain: domain,
    baseScore: finalScore
  });
  const recovery = {
    ...recoveryBase,
    recoveryApplied: false,
    recoveryFloor: null,
    recoveryReason: recoveryBase.recoveryEligible
      ? "Clean-provider mitigation was applied inside weighted heuristic scoring."
      : "",
    recoveryBlockedReasons: recoveryBase.recoveryEligible ? [] : recoveryBase.recoveryBlockedReasons
  };

  let finalFeatures = softUncertaintyCapApplied
    ? {
        ...features,
        softUncertaintyCapApplied: true,
        cleanProviderRecoveryApplied: recovery.recoveryApplied === true
      }
    : {
        ...features,
        cleanProviderRecoveryApplied: recovery.recoveryApplied === true
      };

  const demoScoreBias = { enabled: false, amount: 0 };
  const originalFinalScore = finalScore;
  const demoBiasBeforeScore = finalScore;

  if (demoScoreBias.enabled) {
    finalScore = Math.max(0, finalScore - demoScoreBias.amount);

    finalFeatures = {
      ...finalFeatures,
      demoScoreBiasApplied: true,
      originalSafetyScore: originalFinalScore,
      demoScoreBiasAmount: demoScoreBias.amount
    };
  }

  const demoBiasAfterScore = finalScore;

  let finalClassification = verificationOnlyUnknown
      ? "Unverified"
      : classifySafetyScore(finalScore);
  const virusTotalWarningState = providerPolicy.virusTotalWarningState || getVirusTotalWarningState(providerResults);
  const virusTotalWarningPolicy = applyVirusTotalWarningScorePolicy(finalScore, finalClassification, virusTotalWarningState);
  if (!verificationOnlyUnknown) {
    finalScore = virusTotalWarningPolicy.finalScore;
    finalClassification = virusTotalWarningPolicy.finalClassification;
  }
  if (virusTotalWarningState.warningSeverity === "suspicious") {
    finalFeatures = {
      ...finalFeatures,
      virusTotalProviderWarning: true,
      virusTotalWarningScoreCap: null
    };
  } else if (virusTotalWarningState.warningSeverity === "caution") {
    finalFeatures = {
      ...finalFeatures,
      virusTotalProviderCaution: true,
      virusTotalWarningScoreCap: null
    };
  }
  const rawProviderCompletion = buildProviderCompletionState(providerResults);
  const scanFinalized = providerOverride === true
    ? true
    : rawProviderCompletion.allRequiredProvidersTerminal && !rawProviderCompletion.hasPendingProvider;
  const providerCompletion = providerOverride === true
    ? {
        ...rawProviderCompletion,
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        blockingPendingProviders: [],
        informationalPendingProviders: rawProviderCompletion.pendingProviders || []
      }
    : rawProviderCompletion;

  let displayedScore = finalScore;
  let displayedClassification = finalClassification;
  let displayedState = providerOverride === true
    ? "completed"
    : finalFeatures.integrityHashMismatch ? "changed" : "monitored";
  const terminalProviderLimitation = !providerOverride && scanFinalized && hasTerminalProviderLimitation(providerResults);

  if (terminalProviderLimitation) {
    displayedScore = null;
    displayedClassification = "Unverified";
    displayedState = "verification-incomplete";
  }

  if (!scanFinalized && !providerOverride) {
    displayedScore = null;
    displayedClassification = "Scan Pending";
    displayedState = "pending-provider";
  }

  let scoreAudit = buildScoreAudit({
    scoring,
    providerOverride,
    providerCapBeforeScore,
    providerCapAfterScore,
    verificationState,
    verificationCapReason,
    verificationCapBeforeScore,
    verificationCapAfterScore,
    softUncertaintyCapApplied,
    softCapBeforeScore,
    softCapAfterScore,
    demoScoreBias,
    demoBiasBeforeScore,
    demoBiasAfterScore,
    recovery,
    finalScore,
    finalClassification
  });
  scoreAudit = applyVirusTotalWarningAuditFields(scoreAudit, virusTotalWarningState, virusTotalWarningPolicy);
  const virusTotalReviewRecommendation = buildVirusTotalProviderWarningReviewRecommendation({
    finalScore,
    finalClassification,
    scoreAudit,
    providerOverride,
    providerOverrideSource: providerPolicy.providerOverrideSource,
    virusTotalWarningState,
    providerResults
  });
  scoreAudit = applyVirusTotalWarningAuditFields(scoreAudit, virusTotalWarningState, virusTotalWarningPolicy, virusTotalReviewRecommendation);
  scoreAudit.postIntegrityAudit = {
    eventType: postIntegrityDecision.eventType,
    confidence: postIntegrityDecision.confidence,
    deductionEligible: postIntegrityDecision.deductionEligible,
    auditOnly: postIntegrityDecision.auditOnly,
    reason: postIntegrityDecision.reason
  };
  scoreAudit.scanFinalized = scanFinalized;
  scoreAudit.displayedScoreWithheld = (!scanFinalized && !providerOverride) || terminalProviderLimitation;
  scoreAudit.computedSafetyScore = finalScore;
  scoreAudit.computedClassification = finalClassification;
  scoreAudit.pendingProviders = providerCompletion.pendingProviders;
  scoreAudit.verificationIncomplete = terminalProviderLimitation;
  scoreAudit.providerOverrideSource = providerPolicy.providerOverrideSource;
  scoreAudit.providerOverrideReason = providerPolicy.providerOverrideReason;
  scoreAudit.virusTotalSignalLevel = providerPolicy.virusTotalSignalLevel;
  const initialProviderRetryPlan = providerCompletion.pendingProviders.includes("virustotal")
    ? {
        attempt: 0,
        maxAttempts: 3,
        nextRetryAt: null,
        lastAttemptAt: null,
        lastAttemptStatus: "initial pending result",
        status: "scheduled"
      }
    : null;
  const finalInterceptionRecommended =
    providerOverride === true ||
    finalClassification === "High Risk" ||
    finalClassification === "Suspicious" ||
    Number(finalScore) < 80 ||
    virusTotalReviewRecommendation.providerWarningReviewRecommended === true;
  const finalUrlFeatureAnalysis = {
    ...enrichedUrlFeatures,
    providerCheckedUrl: reusableUrlAnalysis.providerCheckedUrl || "",
    normalizedComparisonUrl:
      reusableUrlAnalysis.urlFeatureAnalysis?.normalizedComparisonUrl ||
      reusableUrlAnalysis.urlFeatureAnalysis?.sourceNormalizedUrl ||
      enrichedUrlFeatures.normalizedUrl ||
      "",
    displayUrl:
      normalizedCandidateContext.unwrappedCandidateUrl ||
      normalizedCandidateContext.selectedNormalizedTarget ||
      normalizedCandidateContext.rawHref ||
      rawUrl ||
      ""
  };
  const analysisCompletedAt = Date.now();
  const analysisPerformanceTiming = mergePerformanceTiming(
    incomingPerformanceTiming,
    reusableUrlAnalysis.performanceTiming,
    {
      detectedAt,
      analysisStartedAt: incomingPerformanceTiming.analysisStartedAt || backgroundAnalysisStartedAt,
      endpointResolutionStartedAt,
      endpointResolutionCompletedAt,
      analysisCompletedAt
    }
  );
  const nextState = finalFeatures.integrityHashMismatch ? "changed" : "monitored";
  let record = {
    postId,
    analysisSchemaVersion: CURRENT_ANALYSIS_SCHEMA_VERSION,
    normalizedUrl,
    analysisUrl,
    rawUrl,
    urlHash: currentHash,
    postSignature: postSignature || normalizedCandidateContext.signature || "",
    linkFingerprint: linkFingerprint || "",
    postTextHash: currentPostTextHash,
    normalizedVisiblePostText: normalizedCurrentPostText,
    previousBaselineUrl,
    previousPostTextHash,
    currentPostTextHash,
    postTextChangedSinceBaseline,
    baselineHadNoLink: confirmedNoLinkBaseline,
    confirmedNoLinkBaseline,
    provisionalNoLinkBaseline,
    matureConfirmedNoLinkBaseline,
    baselineAgeMs,
    baselineFirstSeenAt,
    detectedAt,
    performanceTiming: analysisPerformanceTiming,
    hadLinkAtBaseline: Boolean(integrityBaseline?.hadLinkAtBaseline === true || integrityBaseline?.baselineState === "link"),
    linkInsertedAfterBaseline,
    postIntegrityEvent: postIntegrityDecision.eventType !== "none" ? postIntegrityDecision.eventType : "",
    postIntegrityConfidence: postIntegrityDecision.confidence,
    postIntegrityAuditOnly: postIntegrityDecision.auditOnly === true,
    postIntegrityDeductionEligible: postIntegrityDecision.deductionEligible === true,
    postIntegrityReason: postIntegrityDecision.reason,
    baselineState: compatibleBaseline?.baselineState || integrityBaseline?.baselineState || "",
    candidateMode: normalizedCandidateContext.candidateMode,
    dominantDomain: normalizedCandidateContext.dominantDomain,
    candidateDomainCount: normalizedCandidateContext.candidateDomainCount,
    selectedNormalizedTarget: normalizedCandidateContext.selectedNormalizedTarget,
    candidateContext: normalizedCandidateContext,
    classification: displayedClassification,
    safetyScore: displayedScore,
    computedClassification: finalClassification,
    computedSafetyScore: finalScore,
    scanFinalized,
    providerPending: displayedState === "pending-provider",
    providerCompletion,
    pendingProviders: providerCompletion.pendingProviders,
    providerRetryPlan: initialProviderRetryPlan,
    ruleScore: scoring.score,
    totalDeduction: scoring.totalDeduction,
    categoryDeductions: scoring.categoryDeductions,
    providerDeductions: scoring.providerDeductions,
    heuristicRawCategoryTotals: scoring.heuristicRawCategoryTotals,
    heuristicCategoryDeductions: scoring.heuristicCategoryDeductions,
    heuristicRawTotal: scoring.heuristicRawTotal,
    heuristicScaledDeduction: scoring.heuristicScaledDeduction,
    verificationState,
    verificationOnlyUnknown,
    concreteRiskSignals,
    interceptionRecommended: providerOverride === true ? true : (scanFinalized && !terminalProviderLimitation ? finalInterceptionRecommended : false),
    providerWarningReviewRecommended: virusTotalReviewRecommendation.providerWarningReviewRecommended,
    reviewRecommendedReason: virusTotalReviewRecommendation.reviewRecommendedReason,
    features: finalFeatures,
    deductions: scoring.deductions,
    scoreAudit,
    providerOverride,
    providerResults,
    providerCheckedUrl: reusableUrlAnalysis.providerCheckedUrl || "",
    nonWebProtocolDetected: Boolean(endpointResult.nonWebProtocolDetected),
    nonWebProtocol: endpointResult.nonWebProtocol || "",
    technicalDetails: buildTechnicalDetails({
      endpointResult,
      redirectAnalysis,
      urlFeatureAnalysis: finalUrlFeatureAnalysis,
      analysis: {
        postIntegrityEvent: postIntegrityDecision.eventType !== "none" ? postIntegrityDecision.eventType : "",
        postIntegrityConfidence: postIntegrityDecision.confidence,
        postIntegrityAuditOnly: postIntegrityDecision.auditOnly === true,
        postIntegrityDeductionEligible: postIntegrityDecision.deductionEligible === true,
        postIntegrityReason: postIntegrityDecision.reason,
        linkInsertedAfterBaseline,
        postTextChangedSinceBaseline,
        baselineHadNoLink: confirmedNoLinkBaseline,
        confirmedNoLinkBaseline,
        provisionalNoLinkBaseline,
        matureConfirmedNoLinkBaseline,
        baselineAgeMs,
        currentHasUsableLinkCandidate,
        baselineFirstSeenAt,
        previousBaselineUrl,
        previousPostTextHash,
        currentPostTextHash,
        candidateContext: normalizedCandidateContext,
        features: finalFeatures,
        classification: displayedClassification,
        safetyScore: displayedScore,
        computedClassification: finalClassification,
        computedSafetyScore: finalScore,
        scanFinalized,
        providerCompletion,
        pendingProviders: providerCompletion.pendingProviders,
        providerRetryPlan: initialProviderRetryPlan,
        scoreAudit,
        providerOverride,
        nonWebProtocolDetected: Boolean(endpointResult.nonWebProtocolDetected),
        nonWebProtocol: endpointResult.nonWebProtocol || "",
        interceptionRecommended: providerOverride === true ? true : (scanFinalized && !terminalProviderLimitation ? finalInterceptionRecommended : false),
        deductions: scoring.deductions
      },
      providerResults
    }),
    endpointConfidence: endpointResult.endpointConfidence,
    limitations: buildAnalysisLimitations({ endpointResult, providerResults, candidateContext: normalizedCandidateContext, domain }),
    postIdentityStable: normalizedCandidateContext.postIdentityStable === true,
    integrityComparisonStatus: normalizedCandidateContext.postIdentityStable === true ? "checked" : "skipped-unstable-post-identity",
    redirectAnalysis,
    urlFeatureAnalysis: finalUrlFeatureAnalysis,
    candidateSource: normalizedCandidateContext.candidateSource || "",
    candidateUrlCompleteness: normalizedCandidateContext.candidateUrlCompleteness || "",
    candidateIsDomainOnlyFallback: normalizedCandidateContext.candidateIsDomainOnlyFallback === true,
    lastChecked: Date.now(),
    state: displayedState
  };

  if (!record.postIdentityStable) {
    record.limitations = [
      ...(record.limitations || []),
      postIntegrityDecision.confidence === "limited"
        ? "A prior no-link or different-link state was observed, but the post identity was not stable enough for a full post-integrity deduction."
        : "Post integrity comparison skipped because no stable Facebook post identity was available."
    ].slice(0, 8);
  }

record = normalizeBackgroundTerminalState(record);
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
      safetyScore: record.safetyScore,
      ruleScore: scoring.score,
      totalDeduction: scoring.totalDeduction,
      categoryDeductions: scoring.categoryDeductions,
      providerDeductions: scoring.providerDeductions,
      heuristicRawCategoryTotals: scoring.heuristicRawCategoryTotals,
      heuristicCategoryDeductions: scoring.heuristicCategoryDeductions,
      heuristicRawTotal: scoring.heuristicRawTotal,
      heuristicScaledDeduction: scoring.heuristicScaledDeduction,
      scoreAudit: record.scoreAudit,
      providerDeductions: record.providerDeductions,
      heuristicRawCategoryTotals: record.heuristicRawCategoryTotals,
      heuristicCategoryDeductions: record.heuristicCategoryDeductions,
      heuristicRawTotal: record.heuristicRawTotal,
      heuristicScaledDeduction: record.heuristicScaledDeduction,
      classification: record.classification,
      computedClassification: record.computedClassification,
      computedSafetyScore: record.computedSafetyScore,
      scanFinalized: record.scanFinalized,
      providerCompletion: record.providerCompletion,
      pendingProviders: record.pendingProviders,
      providerRetryPlan: record.providerRetryPlan,
      verificationState: record.verificationState,
      performanceTiming: record.performanceTiming,
      verificationOnlyUnknown,
      concreteRiskSignals,
      interceptionRecommended: record.interceptionRecommended,
      features: record.features,
      providerResults: record.providerResults,
      endpointResult: record.endpointResult,
      endpointConfidence: record.endpointConfidence,
      providerCheckedUrl: reusableUrlAnalysis.providerCheckedUrl || "",
      limitations: record.limitations,
      providerOverride,
      state: record.state
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
  logDebug(`Scoring result for ${postId}: safety=${finalScore} classification=${finalClassification}`);
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
  if (endpointResult.nonWebProtocolDetected) {
    return (
      endpointResult.effectiveEndpoint ||
      endpointResult.resolvedUrl ||
      redirectAnalysis.resolvedUrl ||
      ""
    );
  }

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
  return getCompatibleIntegrityDestinationChange(existingBaseline, currentAnalysis).changed === true;
}

function getCompatibleIntegrityDestinationChange(existingBaseline, currentAnalysis) {
  if (!existingBaseline?.urlHash) {
    return {
      changed: false,
      sameDomain: false,
      trackingOnly: false,
      reason: "No prior URL hash was available."
    };
  }

  const baselineCandidateContext = buildCandidateContext(existingBaseline.candidateContext || existingBaseline, existingBaseline);
  const currentCandidateContext = buildCandidateContext(currentAnalysis.candidateContext, currentAnalysis);
  return hasMeaningfulCandidateDestinationChange(baselineCandidateContext, currentCandidateContext, existingBaseline, currentAnalysis);
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
  const signature = String(candidateContext.signature || fallback.postSignature || fallback.signature || "").trim();

  return {
    candidateMode,
    dominantDomain,
    candidateDomainCount,
    selectedNormalizedTarget,
    signature,
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

function hasMeaningfulCandidateDestinationChange(baselineCandidateContext, currentCandidateContext, baseline = {}, current = {}) {
  if (!baselineCandidateContext || !currentCandidateContext) {
    return {
      changed: false,
      sameDomain: false,
      trackingOnly: false,
      reason: "Missing candidate context."
    };
  }

  const baselineTarget = getCandidateComparisonTarget(baselineCandidateContext, baseline);
  const currentTarget = getCandidateComparisonTarget(currentCandidateContext, current);
  const baselineDomain = baselineCandidateContext.dominantDomain || getRegistrableDomain(safeHostname(baselineTarget));
  const currentDomain = currentCandidateContext.dominantDomain || getRegistrableDomain(safeHostname(currentTarget));
  const normalizedBaselineTarget = normalizePostIntegrityUrlForComparison(baselineTarget, { stripTracking: true });
  const normalizedCurrentTarget = normalizePostIntegrityUrlForComparison(currentTarget, { stripTracking: true });
  const rawBaselineTarget = normalizePostIntegrityUrlForComparison(baselineTarget, { stripTracking: false });
  const rawCurrentTarget = normalizePostIntegrityUrlForComparison(currentTarget, { stripTracking: false });

  if (normalizedBaselineTarget && normalizedCurrentTarget && normalizedBaselineTarget === normalizedCurrentTarget) {
    return {
      changed: false,
      sameDomain: baselineDomain && currentDomain ? baselineDomain === currentDomain : false,
      trackingOnly: rawBaselineTarget && rawCurrentTarget && rawBaselineTarget !== rawCurrentTarget,
      reason: rawBaselineTarget && rawCurrentTarget && rawBaselineTarget !== rawCurrentTarget
        ? "Only tracking parameters changed, so no post-integrity deduction was applied."
        : "The normalized destination did not change."
    };
  }

  if (
    baselineDomain &&
    currentDomain &&
    baselineDomain === currentDomain
  ) {
    return {
      changed: Boolean(normalizedBaselineTarget && normalizedCurrentTarget && normalizedBaselineTarget !== normalizedCurrentTarget),
      sameDomain: true,
      trackingOnly: false,
      reason: "The link URL changed within the same domain. DILI recorded this as a limited post-integrity warning."
    };
  }

  if (
    baselineCandidateContext.selectedNormalizedTarget &&
    currentCandidateContext.selectedNormalizedTarget &&
    baselineCandidateContext.selectedNormalizedTarget === currentCandidateContext.selectedNormalizedTarget
  ) {
    return {
      changed: false,
      sameDomain: false,
      trackingOnly: false,
      reason: "The selected destination did not change."
    };
  }

  return {
    changed: Boolean(
      baselineDomain &&
      currentDomain &&
      baselineDomain !== currentDomain
    ),
    sameDomain: false,
    trackingOnly: false,
    reason: "The link destination changed after the stored baseline."
  };
}

function getCandidateComparisonTarget(candidateContext = {}, fallback = {}) {
  return (
    candidateContext.selectedNormalizedTarget ||
    candidateContext.unwrappedCandidateUrl ||
    candidateContext.rawHref ||
    fallback.analysisUrl ||
    fallback.normalizedUrl ||
    fallback.rawUrl ||
    ""
  );
}

function normalizePostIntegrityUrlForComparison(rawUrl, options = {}) {
  if (!rawUrl) {
    return "";
  }

  try {
    return normalizeUrl(rawUrl, { stripTracking: options.stripTracking !== false });
  } catch {
    return String(rawUrl || "").trim();
  }
}

function hasNoLinkBaselineMarker(baseline = {}) {
  if (!baseline || typeof baseline !== "object") {
    return false;
  }

  const baselineState = String(baseline.baselineState || "").toLowerCase();
  const features = baseline.features && typeof baseline.features === "object" ? baseline.features : {};

  return Boolean(
    POST_INTEGRITY_NO_LINK_BASELINE_STATES.has(baselineState) ||
    baseline.hadLinkAtBaseline === false ||
    features.noLinkBaseline === true ||
    features.baselineHadNoLink === true ||
    features.confirmedNoLinkBaseline === true ||
    features.provisionalNoLinkBaseline === true
  );
}

function getBaselineIntegrityConfidence(baseline = {}) {
  const explicit = normalizeBaselineConfidence(baseline.baselineConfidence || baseline.postIntegrityConfidence);
  if (explicit !== "unknown") {
    return explicit;
  }

  const baselineState = String(baseline.baselineState || "").toLowerCase();
  if (baselineState === "no_link" && baseline.postIdentityStable === true) {
    return "stable";
  }

  if (baselineState === "observed_no_link_unstable") {
    return "unstable";
  }

  if (baselineState === "observed_no_link" || baselineState === "provisional_no_link" || baselineState === "truncated_unexpanded") {
    return "provisional";
  }

  return baseline.postIdentityStable === true ? "stable" : "unknown";
}

function classifyPostIntegrityEvent({ baseline = {}, current = {}, identity = {}, candidate = {} } = {}) {
  const noLinkBaseline = hasNoLinkBaselineMarker(baseline);
  const baselineState = String(baseline.baselineState || "").toLowerCase();
  const baselineConfidence = getBaselineIntegrityConfidence(baseline);
  const baselineAgeMs = Number(current.baselineAgeMs || 0);
  const currentHasLink = current.currentHasUsableLinkCandidate === true;
  const stableIdentityMatch = identity.stableIdentityMatch === true;
  const candidateContext = candidate.candidateContext || {};
  const singleCandidate = candidateContext.candidateMode === "single";
  const usableFullCandidate = Boolean(
    candidateContext.candidateIsDomainOnlyFallback !== true &&
    candidateContext.candidateUrlCompleteness !== "domain-only-fallback"
  );

  if (!current.isReanalysis) {
    return {
      eventType: "none",
      confidence: "none",
      deductionEligible: false,
      auditOnly: false,
      reason: "No previous baseline was being reanalyzed."
    };
  }

  if (noLinkBaseline && currentHasLink) {
    if (
      baselineState === "truncated_unexpanded" ||
      baselineAgeMs < POST_INTEGRITY_PROVISIONAL_BASELINE_AGE_MS ||
      baselineConfidence === "provisional"
    ) {
      return {
        eventType: "provisional-lazy-load",
        confidence: "limited",
        deductionEligible: false,
        auditOnly: true,
        reason: "A provisional no-link baseline later exposed a link, likely due to Facebook lazy-loading. Post-integrity scoring was not applied."
      };
    }

    if (
      baselineConfidence === "stable" &&
      stableIdentityMatch &&
      singleCandidate &&
      baselineAgeMs >= POST_INTEGRITY_MIN_NO_LINK_BASELINE_AGE_MS
    ) {
      return {
        eventType: "link-inserted-after-stable-no-link",
        confidence: "high",
        deductionEligible: true,
        auditOnly: false,
        reason: "A link appeared after the original no-link baseline. DILI treated this as a post-integrity warning, not direct proof of maliciousness."
      };
    }

    return {
      eventType: "link-inserted-after-unstable-no-link",
      confidence: "limited",
      deductionEligible: false,
      auditOnly: true,
      reason: "A link appeared after a prior no-link observation, but the post identity was not stable enough for a full post-integrity deduction."
    };
  }

  if (candidate.destinationChange?.trackingOnly) {
    return {
      eventType: "none",
      confidence: "none",
      deductionEligible: false,
      auditOnly: true,
      reason: "Only tracking parameters changed, so no post-integrity deduction was applied."
    };
  }

  if (candidate.destinationChange?.changed) {
    const stableEligible = Boolean(
      candidate.canUseExistingLinkIntegrityBaseline &&
      stableIdentityMatch &&
      singleCandidate &&
      usableFullCandidate &&
      baselineAgeMs >= POST_INTEGRITY_MIN_BASELINE_AGE_MS
    );

    if (!stableEligible) {
      return {
        eventType: candidate.destinationChange.sameDomain ? "link-url-changed-same-domain" : "link-destination-changed",
        confidence: "limited",
        deductionEligible: false,
        auditOnly: true,
        reason: "A prior no-link or different-link state was observed, but the post identity was not stable enough for a full post-integrity deduction."
      };
    }

    if (candidate.destinationChange.sameDomain) {
      return {
        eventType: "link-url-changed-same-domain",
        confidence: "limited",
        deductionEligible: true,
        auditOnly: false,
        reason: "The link URL changed within the same domain. DILI recorded this as a limited post-integrity warning."
      };
    }

    return {
      eventType: "link-destination-changed",
      confidence: "high",
      deductionEligible: true,
      auditOnly: false,
      reason: "The link destination changed after the stored baseline."
    };
  }

  if (current.postTextChangedSinceBaseline) {
    return {
      eventType: "text-only-change",
      confidence: "limited",
      deductionEligible: false,
      auditOnly: true,
      reason: "Post text changed, but the link destination did not materially change."
    };
  }

  return {
    eventType: "none",
    confidence: "none",
    deductionEligible: false,
    auditOnly: false,
    reason: "No post-integrity event was detected."
  };
}

function logPostIntegrityDecision(postId, decision = {}) {
  const eventType = String(decision.eventType || "none");
  const reason = decision.reason || "";
  const context = { postId, eventType, confidence: decision.confidence, deductionEligible: decision.deductionEligible, reason };

  if (eventType === "link-inserted-after-stable-no-link") {
    logDebug(`[post-integrity] stable no-link to link insertion detected ${JSON.stringify(context)}`);
  } else if (eventType === "link-inserted-after-unstable-no-link") {
    logDebug(`[post-integrity] unstable no-link to link insertion recorded as limited evidence ${JSON.stringify(context)}`);
  } else if (eventType === "link-destination-changed") {
    logDebug(`[post-integrity] link destination changed ${JSON.stringify(context)}`);
  } else if (eventType === "link-url-changed-same-domain") {
    logDebug(`[post-integrity] same-domain URL change detected ${JSON.stringify(context)}`);
  } else if (decision.auditOnly) {
    logDebug(`[post-integrity] post-integrity audit-only evidence recorded ${JSON.stringify(context)}`);
  }

  if (decision.deductionEligible) {
    logDebug(`[post-integrity] post-integrity deduction applied ${JSON.stringify(context)}`);
  }

  if (eventType === "none" && /tracking parameters/i.test(reason)) {
    logDebug(`[post-integrity] tracking-only URL change ignored ${JSON.stringify(context)}`);
  }

  if (decision.confidence === "limited" && !decision.deductionEligible && /identity/i.test(reason)) {
    logDebug(`[post-integrity] post-integrity skipped due to unstable identity ${JSON.stringify(context)}`);
  }
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
      performanceTiming: normalizePerformanceTiming({
        providerVerificationStartedAt: null,
        providerVerificationCompletedAt: null
      }),
      cacheHit: true,
      cacheKey
    };
  }

  const cacheMissKey = initialCacheKeys[0] || normalizeCacheKey(rawUrl) || "unknown-url";
  logDebug(`URL analysis cache miss: ${cacheMissKey}`);

  const safeEndpointResult = endpointResult || {};
  const redirectAnalysisStartedAt = endpointResult?.resolutionTimedOut ? null : Date.now();
  const redirectFallback = endpointResult?.resolutionTimedOut
    ? null
    : await withAnalysisTimeout(
        analyzeRedirects(rawUrl),
        8000,
        () => buildTimedOutRedirectAnalysis(rawUrl, safeEndpointResult)
      );
  const redirectAnalysisCompletedAt = redirectAnalysisStartedAt === null ? null : Date.now();
  const safeRedirectAnalysis = normalizeRedirectAnalysis(
    redirectAnalysis ||
    endpointResult?.redirectAnalysis ||
    redirectFallback
  );
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
const providerVerificationStartedAt = Date.now();
const providerUrlCandidates = buildProviderUrlCandidates({
  rawUrl,
  endpointResult: safeEndpointResult,
  redirectAnalysis: safeRedirectAnalysis,
  urlFeatures,
  providerCheckedUrl
});
const providerResults = normalizeProviderResults(await runThreatIntelligenceChecks(providerCheckedUrl, {
  providerUrlCandidates
}));
const providerVerificationCompletedAt = Date.now();
const providerMs = elapsedMs(providerStartedAt);
performanceStats.lastProviderMs = providerMs;
recordMaxPerformanceStat("maxProviderMs", providerMs);
  const stableUrlFeatureAnalysis = {
    ...analysisUrlFeatures,
    sourceNormalizedUrl: urlFeatures.normalizedUrl,
    sourceUnwrappedUrl: urlFeatures.unwrappedUrl,
    sourceRawComparableUrl: urlFeatures.rawComparableUrl,
    finalAnalysisUrl: analysisUrl,
    providerCheckedUrl,
    nonWebProtocolDetected: Boolean(safeEndpointResult.nonWebProtocolDetected),
    nonWebProtocol: safeEndpointResult.nonWebProtocol || "",
    normalizedComparisonUrl: urlFeatures.normalizedUrl,
    displayUrl: urlFeatures.rawComparableUrl || urlFeatures.unwrappedUrl || urlFeatures.normalizedUrl || "",
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
    nonWebProtocolDetected: Boolean(safeEndpointResult.nonWebProtocolDetected),
    nonWebProtocol: safeEndpointResult.nonWebProtocol || "",
    urlFeatureAnalysis: stableUrlFeatureAnalysis,
    urlLevelFeatures
  };

  setUrlAnalysisCacheEntry(buildUrlAnalysisCacheKeys(urlFeatures, analysisUrl), cacheEntry);

  return {
    ...cacheEntry,
    performanceTiming: normalizePerformanceTiming({
      redirectAnalysisStartedAt,
      redirectAnalysisCompletedAt,
      providerVerificationStartedAt,
      providerVerificationCompletedAt
    }),
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
    facebookWrapperUnwrapped: Boolean(safeUrlFeatureAnalysis.facebookWrapperUnwrapped),
    suspiciousRedirectPattern: safeRedirectAnalysis.suspiciousPattern,
    trackingHopToUnrelatedDomain: safeRedirectAnalysis.trackingHopToUnrelatedDomain,
    shortenerToUnrelatedDomain: safeRedirectAnalysis.shortenerToUnrelatedDomain,
    shortenedUrl: safeUrlFeatureAnalysis.shortenedUrl,
    obfuscatedUrl: safeUrlFeatureAnalysis.obfuscatedUrl,
    obfuscationSignals: Array.isArray(safeUrlFeatureAnalysis.obfuscationSignals)
      ? safeUrlFeatureAnalysis.obfuscationSignals
      : [],
    suspiciousEncoding: Boolean(safeUrlFeatureAnalysis.suspiciousEncoding),
    suspiciousTld: safeUrlFeatureAnalysis.suspiciousTld,
    textMismatch: false,
    excessiveQueryComplexity: safeUrlFeatureAnalysis.excessiveQueryComplexity,
    suspiciousPath: safeUrlFeatureAnalysis.suspiciousPath,
    sensitiveArticleTopicTermsIgnored: safeUrlFeatureAnalysis.sensitiveArticleTopicTermsIgnored,
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

function getProviderStatus(provider = {}) {
  return String(provider?.details?.status || "").toLowerCase();
}

function isProviderConfiguredOrActive(provider = {}) {
  const status = getProviderStatus(provider);

  return Boolean(
    provider?.configured === true ||
    provider?.checked === true ||
    provider?.flagged === true ||
    [
      "pending",
      "checked",
      "completed",
      "not-configured",
      "skipped",
      "unsupported_protocol",
      "retry-budget-exhausted",
      "rate-limited",
      "timeout",
      "error",
      "parse-error"
    ].includes(status)
  );
}

function isProviderPending(provider = {}) {
  return getProviderStatus(provider) === "pending";
}

function isProviderTerminal(provider = {}) {
  const status = getProviderStatus(provider);

  return Boolean(
    provider?.flagged === true ||
    provider?.checked === true ||
    status === "checked" ||
    status === "completed" ||
    status === "not-configured" ||
    status === "skipped" ||
    status === "unsupported_protocol" ||
    status === "retry-budget-exhausted" ||
    status === "rate-limited" ||
    status === "timeout" ||
    status === "error" ||
    status === "parse-error"
  );
}

function buildProviderCompletionState(providerResults = []) {
  const providers = normalizeProviderResults(providerResults);
  const activeProviders = providers.filter(isProviderConfiguredOrActive);
  const pendingProviders = activeProviders.filter(isProviderPending);
  const incompleteProviders = activeProviders.filter((provider) => !isProviderTerminal(provider));

  return {
    providerStates: activeProviders.map((provider) => ({
      provider: provider.provider || "unknown",
      status: getProviderStatus(provider) || (provider.checked ? "checked" : "unknown"),
      checked: provider.checked === true,
      flagged: provider.flagged === true,
      checkedUrl: provider.checkedUrl || "",
      checkedAt: provider.checkedAt || "",
      terminal: isProviderTerminal(provider),
      pending: isProviderPending(provider),
      retryable: provider.details?.retryable !== false && isProviderPending(provider),
      analysisId: provider.details?.analysisId || ""
    })),
    pendingProviders: pendingProviders.map((provider) => provider.provider || "unknown"),
    incompleteProviders: incompleteProviders.map((provider) => provider.provider || "unknown"),
    hasPendingProvider: pendingProviders.length > 0,
    allRequiredProvidersTerminal: incompleteProviders.length === 0 && pendingProviders.length === 0,
    activeProviderCount: activeProviders.length,
    checkedProviderCount: activeProviders.filter((provider) => provider.checked || provider.flagged).length,
    pendingProviderCount: pendingProviders.length
  };
}

function getNormalizedProviderResult(providerResults, providerName) {
  return normalizeProviderResults(providerResults).find((item) => item.provider === providerName) || createDefaultProviderResult(providerName, "");
}

function normalizeRedirectAnalysis(redirectAnalysis = {}) {
  const safe = redirectAnalysis && typeof redirectAnalysis === "object" ? redirectAnalysis : {};
  const fullObservedRedirectTrace = Array.isArray(safe.fullObservedRedirectTrace)
    ? safe.fullObservedRedirectTrace
    : Array.isArray(safe.redirectChain)
      ? safe.redirectChain
      : [];

  return {
    redirectCount: Number(safe.redirectCount || 0),
    redirectChain: Array.isArray(safe.redirectChain) ? safe.redirectChain : Array.isArray(safe.chain) ? safe.chain : [],
    chain: Array.isArray(safe.chain) ? safe.chain : Array.isArray(safe.redirectChain) ? safe.redirectChain : [],
    fullObservedRedirectTrace,
    fullObservedRedirectEvents: Array.isArray(safe.fullObservedRedirectEvents)
      ? safe.fullObservedRedirectEvents
      : [],
    fullRedirectCount: Number.isFinite(Number(safe.fullRedirectCount))
      ? Number(safe.fullRedirectCount)
      : Math.max(0, fullObservedRedirectTrace.length - 1),
    fullRedirectDomains: Array.isArray(safe.fullRedirectDomains)
      ? safe.fullRedirectDomains
      : [],
    redirectDomains: Array.isArray(safe.redirectDomains) ? safe.redirectDomains : [],
    uniqueRegistrableDomains: Array.isArray(safe.uniqueRegistrableDomains) ? safe.uniqueRegistrableDomains : [],
    resolvedUrl: safe.resolvedUrl || "",
    resolutionMethod: safe.resolutionMethod || "unknown",
    fetchMethod: safe.fetchMethod || "",
    fetchStatus: safe.fetchStatus || "",
    skipped: Boolean(safe.skipped),
    skipReason: safe.skipReason || "",
    protocol: safe.protocol || "",
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

const TRUSTED_REDIRECT_DESTINATION_HOSTS = new Set([
  "docs.google.com",
  "forms.google.com",
  "drive.google.com",
  "youtube.com",
  "youtu.be",
  "twitch.tv",
  "discord.com",
  "github.com",
  "notion.so",
  "canva.com"
]);

// Trusted redirect sources are wrappers/shorteners that often hide the final URL
// for measurement or campaign routing; they are not trusted destinations by themselves.
const KNOWN_CAMPAIGN_REDIRECT_SOURCE_DOMAINS = new Set([
  // Brand-owned short links
  "cnn.it",
  "hoyo.link",  
  "nyti.ms",

  // Telecom / commerce campaign domains
  "dito.ph",
  "smrt.ph",
  "coca-cola.com",

  // Google-owned redirect/share shortener
  "forms.gle",

  // Common campaign / tracking redirectors
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "lnkd.in",
  "buff.ly",
  "ow.ly",
  "rebrand.ly",
  "linktr.ee",
  "cutt.ly",
  "shorturl.at",
  "rb.gy"
]);

// Trusted destinations are final landing domains. Mitigation requires both an
// expected redirect source and a trusted destination, with clean providers.
const TRUSTED_REDIRECT_DESTINATION_DOMAINS = new Set([
  // Google productivity/content
  "docs.google.com",
  "forms.google.com",
  "drive.google.com",
  "sites.google.com",

  // Major media/content platforms
  "youtube.com",
  "youtu.be",
  "twitch.tv",

  // Developer/productivity platforms
  "github.com",
  "notion.so",
  "canva.com",

  // Common official/social destinations
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "x.com",
  "twitter.com",

  // Major commerce/payment platforms, still only trusted if providers are clean
  "shopee.ph",
  "lazada.com.ph",
  "amazon.com",
  "securitybank.com",
  "smart.com.ph"
]);

const KNOWN_BRANDED_DOMAIN_ALIASES = [
  {
    brandName: "Philippine National Bank",
    sourceDomain: "pnbph.net",
    allowedFinalDomains: ["pnb.com.ph"],
    requiredPathHints: ["consumer-assistance-process"],
    note: "PNB observed alias/campaign/help link.",
    label: "PNB observed alias/campaign/help link."
  },
  {
    brandName: "Smart Communications",
    sourceDomain: "smrt.ph",
    allowedFinalDomains: ["smart.com.ph"],
    requiredPathHints: [],
    note: "Observed Smart branded short domain.",
    label: "Observed Smart branded short domain."
  }
  // Add only after confirming the source domain is officially used by the brand.
];

const KNOWN_BRANDED_ALIAS_REDIRECTS = KNOWN_BRANDED_DOMAIN_ALIASES;

function stripWww(domain = "") {
  return String(domain || "").trim().toLowerCase().replace(/^www\./, "");
}

function isKnownBrandedDomainAlias(sourceDomain = "", finalDomain = "", url = "") {
  return Boolean(getKnownBrandedDomainAliasMatch(sourceDomain, finalDomain, url));
}

function getKnownBrandedDomainAliasMatch(sourceDomain = "", finalDomain = "", url = "") {
  const source = stripWww(sourceDomain);
  const final = stripWww(finalDomain);
  const fullUrl = String(url || "").toLowerCase();

  if (!source || !final) {
    return null;
  }

  return KNOWN_BRANDED_DOMAIN_ALIASES.find((entry) => {
    const entrySource = stripWww(entry.sourceDomain);
    const allowedFinals = (entry.allowedFinalDomains || []).map(stripWww);

    if (source !== entrySource || !allowedFinals.includes(final)) {
      return false;
    }

    const hints = Array.isArray(entry.requiredPathHints) ? entry.requiredPathHints : [];
    if (hints.length === 0) {
      return true;
    }

    return hints.some((hint) => fullUrl.includes(String(hint || "").toLowerCase()));
  }) || null;
}

const CLEAN_MARKETING_FINAL_DOMAINS = new Set([
  "securitybank.com",
  "smart.com.ph",
  "bsp.gov.ph",
  "dito.ph",
  "globe.com.ph",
  "pldt.com",
  "bpi.com.ph",
  "bdo.com.ph",
  "unionbankph.com",
  "gcash.com",
  "maya.ph"
]);

function applyTrustedRedirectDestinationMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  const finalUrl = endpointResult?.effectiveEndpoint || reusableUrlAnalysis.analysisUrl || "";
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || safeHostname(finalUrl) || reusableUrlAnalysis.domain || "");
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(reusableUrlAnalysis.redirectAnalysis?.redirectChain)
        ? reusableUrlAnalysis.redirectAnalysis.redirectChain
        : [];
  const sourceDomain = getRedirectSourceDomain(rawChain);
  const trustedDestination = isTrustedRedirectDestination(finalUrl, finalDomain);
  const providerFlagged = Boolean(features.googleSafeBrowsingFlagged || features.urlhausFlagged || features.virusTotalFlagged);
  // Provider detections always win; this mitigation only reduces redirect-only
  // false positives after reputation providers and severe heuristics are clean.
  const strongLocalSignal = Boolean(
    features.suspiciousTld ||
    features.suspiciousPath ||
    features.usernamePasswordTrick ||
    hasSevereObfuscationSignal(features) ||
    features.integrityHashMismatch ||
    features.rawIpHost ||
    features.suspiciousFileExtension
  );

  if (!trustedDestination || providerFlagged || !features.httpsEndpoint || strongLocalSignal) {
    return features;
  }

  const knownCampaignSource = Boolean(
    isKnownCampaignRedirectSource(sourceDomain) ||
    isKnownBrandedCampaignRedirect({
      endpointResult,
      redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
      finalDomain,
      finalUrl
    }) ||
    endpointResult?.isFacebookWrapper ||
    features.facebookWrapperUnwrapped
  );
  const unknownShortenerSource = Boolean(features.shortenedUrl && !knownCampaignSource);

  if (!knownCampaignSource && !unknownShortenerSource) {
    return features;
  }

  const tier = knownCampaignSource ? "A" : "B";

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
    trustedRedirectDestination: true,
    trustedRedirectDestinationDomain: finalDomain,
    trustedRedirectSourceDomain: sourceDomain,
    trustedRedirectTier: tier,
    knownCampaignRedirectToTrustedDestination: knownCampaignSource,
    trustedDestinationUnknownShortenerRedirect: unknownShortenerSource,
    expectedRedirectBehavior: true,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: knownCampaignSource
  };
}

function isKnownCampaignRedirectSource(sourceDomain = "") {
  const normalized = String(sourceDomain || "").toLowerCase().replace(/^www\./, "");
  return KNOWN_CAMPAIGN_REDIRECT_SOURCE_DOMAINS.has(normalized);
}

function hasSevereObfuscationSignal(features = {}) {
  const signals = Array.isArray(features.obfuscationSignals)
    ? features.obfuscationSignals.map((signal) => String(signal || "").toLowerCase())
    : [];

  return Boolean(
    features.usernamePasswordTrick ||
    signals.includes("double-encoding") ||
    signals.includes("nested-url")
  );
}

function isTrustedRedirectDestination(finalUrl = "", finalDomain = "") {
  const host = safeHostname(finalUrl) || String(finalDomain || "").toLowerCase();
  const normalizedHost = String(host || "").toLowerCase().replace(/^www\./, "");
  const normalizedDomain = String(
    finalDomain || getRegistrableDomain(normalizedHost) || ""
  )
    .toLowerCase()
    .replace(/^www\./, "");

  for (const trustedHost of TRUSTED_REDIRECT_DESTINATION_HOSTS) {
    if (
      normalizedHost === trustedHost ||
      normalizedHost.endsWith(`.${trustedHost}`)
    ) {
      return true;
    }
  }

  if (TRUSTED_REDIRECT_DESTINATION_DOMAINS.has(normalizedHost)) {
    return true;
  }

  if (TRUSTED_REDIRECT_DESTINATION_DOMAINS.has(normalizedDomain)) {
    return true;
  }

  return false;
}

// This is a conservative local allowlist for high-confidence HTTPS shortlinks
// resolving to well-known destinations. It does not override provider flags,
// suspicious paths, suspicious TLDs, text mismatch, or post-integrity changes.
function applyMainstreamResolvedShortlinkMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}) {
  if (features.trustedDestinationUnknownShortenerRedirect) {
    return features;
  }

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
    sourceDomain: "cnn.it",
    allowedFinalDomains: ["cnn.com"]
  },
    {
    sourceDomain: "nyti.ms",
    allowedFinalDomains: ["nytimes.com"]
  },
  {
    sourceDomain: "hoyo.link",
    allowedFinalDomains: ["twitch.tv", "youtube.com", "hoyoverse.com", "hoyolab.com"],
    requiredPathHints: ["genshinimpactofficial", "hoyoverse", "hoyolab", "genshin"]
  },
  {
    sourceDomain: "dito.ph",
    allowedFinalDomains: ["dito.ph"]
  },
  {
    sourceDomain: "coca-cola.com",
    allowedFinalDomains: ["coca-cola.com"]
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

function applyKnownBrandAliasRedirectMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}, providerResults = []) {
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || reusableUrlAnalysis.domain || "");
  const finalUrl = endpointResult?.effectiveEndpoint || reusableUrlAnalysis.analysisUrl || "";
  const visibleUrl = reusableUrlAnalysis?.urlFeatureAnalysis?.displayUrl || reusableUrlAnalysis?.urlFeatureAnalysis?.sourceRawComparableUrl || reusableUrlAnalysis.analysisUrl || "";
  const visibleDomain = getRegistrableDomain(safeHostname(visibleUrl || finalUrl || reusableUrlAnalysis.analysisUrl || ""));
  const alias = getKnownBrandedDomainAliasMatch(visibleDomain, finalDomain, `${visibleUrl} ${finalUrl}`.trim()) || getKnownBrandAliasRedirect({
    endpointResult,
    redirectAnalysis: reusableUrlAnalysis.redirectAnalysis,
    finalDomain,
    url: finalUrl
  });
  const eligible = Boolean(
    alias &&
    isCleanHighConfidenceResolvedEndpoint({
      features,
      endpointResult,
      providerResults,
      finalUrl,
      finalDomain
    }) &&
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
    suspiciousPath: false,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: true,
    knownBrandAliasRedirect: true,
    knownBrandedDomainAlias: true,
    knownBrandedDomainAliasName: alias.brandName || alias.label || "configured branded alias relationship",
    knownBrandedDomainAliasSourceDomain: alias.sourceDomain,
    knownBrandedDomainAliasFinalDomain: finalDomain,
    knownBrandedDomainAliasNote: alias.note || alias.label || "configured branded alias relationship",
    knownBrandAliasSourceDomain: alias.sourceDomain,
    knownBrandAliasFinalDomain: finalDomain,
    knownBrandAliasLabel: alias.label || alias.note || "configured branded alias relationship"
  };
}

function applyCleanResolvedMarketingLinkMitigation(features = {}, reusableUrlAnalysis = {}, endpointResult = {}, providerResults = []) {
  const finalUrl = endpointResult?.effectiveEndpoint || reusableUrlAnalysis.analysisUrl || "";
  const finalDomain = getRegistrableDomain(endpointResult?.effectiveDomain || safeHostname(finalUrl) || reusableUrlAnalysis.domain || "");
  const redirectLike = Boolean(
    features.shortenedUrl ||
    features.wrapperToExternalDestination ||
    features.facebookWrapperUnwrapped ||
    features.crossDomainRedirectChain ||
    features.shortenerToUnrelatedDomain ||
    features.trackingHopToUnrelatedDomain ||
    features.suspiciousRedirectPattern ||
    Number(features.redirectCount || 0) > 0
  );
  const eligible = Boolean(
    redirectLike &&
    CLEAN_MARKETING_FINAL_DOMAINS.has(finalDomain) &&
    isCleanHighConfidenceResolvedEndpoint({
      features,
      endpointResult,
      providerResults,
      finalUrl,
      finalDomain
    }) &&
    !features.suspiciousTld &&
    !features.usernamePasswordTrick &&
    !features.integrityHashMismatch &&
    !features.rawIpHost &&
    !features.suspiciousFileExtension &&
    !hasSevereObfuscationSignal(features)
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
    suspiciousPath: false,
    trustedEndpoint: true,
    trustedEndpointMitigationEligible: true,
    cleanResolvedMarketingLink: true,
    cleanResolvedMarketingFinalDomain: finalDomain
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

  if (score === 100 && features.knownCampaignRedirectToTrustedDestination) {
    score = 95;
  }

  if (features.trustedDestinationUnknownShortenerRedirect) {
    score = Math.min(score, 89);
  }

  if (score === 100 && features.knownGoogleFormsRedirect) {
    score = 90;
  }

  return score;
}

function sumPositiveTriggeredDeductions(deductions = []) {
  return (Array.isArray(deductions) ? deductions : []).reduce((sum, item) => {
    const value = Number(item?.deduction);
    return item?.triggered && Number.isFinite(value) && value > 0 ? sum + value : sum;
  }, 0);
}

function sumTriggeredMitigationCredits(deductions = []) {
  return (Array.isArray(deductions) ? deductions : []).reduce((sum, item) => {
    const value = Number(item?.deduction);
    return item?.triggered && Number.isFinite(value) && value < 0 ? sum + Math.abs(value) : sum;
  }, 0);
}

function formatScoreAuditClassification(classification) {
  return String(classification || "Unknown").trim() || "Unknown";
}

function toFiniteScoreOrNull(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function isFinalClassificationLabel(label = "") {
  const value = String(label || "").trim().toLowerCase();
  return value === "safe" || value === "suspicious" || value === "high risk" || value === "unverified";
}

function isPendingClassificationLabel(label = "") {
  const value = String(label || "").trim().toLowerCase();
  return value === "pending" || value === "scan pending";
}

function getBestStoredComputedScore(analysis = {}) {
  const scoreWasWithheld = Boolean(
    isPendingClassificationLabel(analysis.classification) ||
    analysis.scanFinalized === false ||
    analysis.scoreAudit?.displayedScoreWithheld === true
  );
  const candidates = [
    analysis.computedSafetyScore,
    analysis.scoreAudit?.computedSafetyScore,
    scoreWasWithheld ? null : analysis.scoreAudit?.finalScore,
    analysis.scoreAudit?.ruleScore,
    scoreWasWithheld ? null : analysis.safetyScore
  ];

  for (const candidate of candidates) {
    const value = toFiniteScoreOrNull(candidate);
    if (value !== null) {
      return value;
    }
  }

  return null;
}

function getBestStoredComputedClassification(analysis = {}, score = null) {
  const candidates = [
    analysis.computedClassification,
    analysis.scoreAudit?.computedClassification,
    analysis.scoreAudit?.classification,
    analysis.classification
  ];

  for (const candidate of candidates) {
    if (isFinalClassificationLabel(candidate)) {
      return String(candidate);
    }
  }

  const numericScore = toFiniteScoreOrNull(score);
  return numericScore !== null ? classifySafetyScore(numericScore) : "Unverified";
}

function buildScoreAudit({
  scoring = {},
  providerOverride = false,
  providerCapBeforeScore,
  providerCapAfterScore,
  verificationState = "",
  verificationCapReason = "",
  verificationCapBeforeScore,
  verificationCapAfterScore,
  softUncertaintyCapApplied = false,
  softCapBeforeScore,
  softCapAfterScore,
  demoScoreBias = {},
  demoBiasBeforeScore,
  demoBiasAfterScore,
  recovery = {},
  finalScore,
  finalClassification
} = {}) {
  const deductions = Array.isArray(scoring.deductions) ? scoring.deductions : [];
  const baselineScore = 100;
  const ruleDeductionTotal = Number(scoring.totalDeduction);
  const ruleScore = Number(scoring.score);
  const providerBefore = Number(providerCapBeforeScore);
  const providerAfter = Number(providerCapAfterScore);
  const verificationBefore = Number(verificationCapBeforeScore);
  const verificationAfter = Number(verificationCapAfterScore);
  const softBefore = Number(softCapBeforeScore);
  const softAfter = Number(softCapAfterScore);
  const demoBefore = Number(demoBiasBeforeScore);
  const demoAfter = Number(demoBiasAfterScore);
  const displayedFinalScore = Number(finalScore);

  return {
    baselineScore,
    listedTriggeredDeductionTotal: sumPositiveTriggeredDeductions(deductions),
    triggeredMitigationCreditTotal: sumTriggeredMitigationCredits(deductions),
    ruleDeductionTotal: Number.isFinite(ruleDeductionTotal) ? ruleDeductionTotal : null,
    ruleScore: Number.isFinite(ruleScore) ? ruleScore : null,
    providerDeductions: scoring.providerDeductions || { gsb: 0, urlhaus: 0, virustotal: 0 },
    providerDeductionTotal: Number.isFinite(Number(scoring.providerDeductionTotal))
      ? Number(scoring.providerDeductionTotal)
      : null,
    providerAudit: scoring.providerAudit || {},
    heuristicRawCategoryTotals: scoring.heuristicRawCategoryTotals || {},
    heuristicCategoryDeductions: scoring.heuristicCategoryDeductions || {},
    heuristicRawTotal: Number.isFinite(Number(scoring.heuristicRawTotal))
      ? Number(scoring.heuristicRawTotal)
      : null,
    heuristicScaledDeduction: Number.isFinite(Number(scoring.heuristicScaledDeduction))
      ? Number(scoring.heuristicScaledDeduction)
      : null,
    scoreFormula: scoring.scoreFormula || "100 - (D_GSB + D_URLHaus + D_VT + D_H)",
    categoryDeductions: scoring.categoryDeductions || {},
    categoryAudit: scoring.categoryAudit || {},
    providerFlag: {
      recorded: providerOverride === true,
      beforeScore: Number.isFinite(providerBefore) ? providerBefore : null,
      afterScore: Number.isFinite(providerAfter) ? providerAfter : null
    },
    verificationCap: {
      applied: Boolean(
        verificationCapReason &&
        Number.isFinite(verificationBefore) &&
        Number.isFinite(verificationAfter) &&
        verificationAfter < verificationBefore
      ),
      state: verificationState || "",
      reason: verificationCapReason || "",
      beforeScore: Number.isFinite(verificationBefore) ? verificationBefore : null,
      afterScore: Number.isFinite(verificationAfter) ? verificationAfter : null
    },
    softUncertaintyCap: {
      applied: Boolean(
        softUncertaintyCapApplied &&
        Number.isFinite(softBefore) &&
        Number.isFinite(softAfter) &&
        softAfter < softBefore
      ),
      beforeScore: Number.isFinite(softBefore) ? softBefore : null,
      afterScore: Number.isFinite(softAfter) ? softAfter : null
    },
    demoScoreBias: {
      applied: Boolean(
        demoScoreBias?.enabled &&
        Number.isFinite(demoBefore) &&
        Number.isFinite(demoAfter) &&
        demoAfter < demoBefore
      ),
      amount: Number.isFinite(Number(demoScoreBias?.amount)) ? Number(demoScoreBias.amount) : 0,
      beforeScore: Number.isFinite(demoBefore) ? demoBefore : null,
      afterScore: Number.isFinite(demoAfter) ? demoAfter : null
    },
    recoveryApplied: recovery.recoveryApplied === true,
    recoveryFloor: recovery.recoveryFloor ?? null,
    recoveryReason: recovery.recoveryReason || "",
    recoveryBlockedReasons: Array.isArray(recovery.recoveryBlockedReasons) ? recovery.recoveryBlockedReasons : [],
    activeHeuristicGroups: Array.isArray(recovery.activeHeuristicGroups) ? recovery.activeHeuristicGroups : [],
    mitigatedHeuristicGroups: Array.isArray(recovery.mitigatedHeuristicGroups) ? recovery.mitigatedHeuristicGroups : [],
    finalScore: Number.isFinite(displayedFinalScore) ? displayedFinalScore : null,
    classification: formatScoreAuditClassification(finalClassification)
  };
}

function refreshScoreAuditForProviderResult(analysis = {}, {
  providerOverride = false,
  safetyScore,
  classification
} = {}) {
  const previousAudit = analysis.scoreAudit && typeof analysis.scoreAudit === "object"
    ? analysis.scoreAudit
    : {};
  const previousScore = toFiniteScoreOrNull(
    analysis.safetyScore ??
    analysis.computedSafetyScore ??
    analysis.scoreAudit?.finalScore
  );
  const refreshedScore = toFiniteScoreOrNull(safetyScore);

  return {
    ...previousAudit,
    providerFlag: {
      ...(previousAudit.providerFlag || {}),
      recorded: providerOverride === true,
      beforeScore: previousScore !== null ? previousScore : (previousAudit.providerFlag?.beforeScore ?? null),
      afterScore: refreshedScore !== null ? refreshedScore : (previousAudit.providerFlag?.afterScore ?? null)
    },
    finalScore: refreshedScore !== null ? refreshedScore : (previousAudit.finalScore ?? null),
    classification: formatScoreAuditClassification(
      isFinalClassificationLabel(classification)
        ? classification
        : getBestStoredComputedClassification(analysis, refreshedScore)
    )
  };
}

function recomputeStoredFinalScoreFromFeatures(analysis = {}, features = {}, providerOverride = false, providerResults = []) {
  if (!features || typeof features !== "object" || Object.keys(features).length === 0) {
    return null;
  }

  const scoring = calculateSafetyScore(features, providerResults);
  const providerCapBeforeScore = scoring.score;
  const providerCapAfterScore = scoring.score;
  let finalScore = scoring.score;
  const verificationState = String(analysis.verificationState || "").toLowerCase();
  const concreteRiskSignals = Boolean(
    providerOverride ||
    features.googleSafeBrowsingFlagged ||
    features.urlhausFlagged ||
    features.virusTotalFlagged ||
    features.integrityHashMismatch ||
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
  let verificationCapReason = "";
  const verificationCapBeforeScore = finalScore;

  const verificationCapAfterScore = finalScore;
  const softCapBeforeScore = finalScore;
  const softCapAfterScore = finalScore;
  const softUncertaintyCapApplied = Number(softCapAfterScore) !== Number(finalScore);
  finalScore = softCapAfterScore;

  const recoveryBase = buildCleanProviderRecoveryState({
    features,
    endpointResult: analysis.endpointResult || {},
    providerResults,
    visibleUrl: analysis.urlFeatureAnalysis?.displayUrl || analysis.urlFeatureAnalysis?.sourceRawComparableUrl || analysis.analysisUrl || "",
    providerCheckedUrl: analysis.endpointResult?.effectiveEndpoint || analysis.analysisUrl || "",
    finalUrl: analysis.endpointResult?.effectiveEndpoint || analysis.analysisUrl || "",
    finalDomain: analysis.domain || analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
    baseScore: finalScore
  });
  const recovery = {
    ...recoveryBase,
    recoveryApplied: false,
    recoveryFloor: null,
    recoveryReason: recoveryBase.recoveryEligible
      ? "Clean-provider mitigation was applied inside weighted heuristic scoring."
      : "",
    recoveryBlockedReasons: recoveryBase.recoveryEligible ? [] : recoveryBase.recoveryBlockedReasons
  };

  let finalFeatures = softUncertaintyCapApplied
    ? {
        ...features,
        softUncertaintyCapApplied: true,
        cleanProviderRecoveryApplied: recovery.recoveryApplied === true
      }
    : {
        ...features,
        cleanProviderRecoveryApplied: recovery.recoveryApplied === true
      };
  let finalClassification = analysis.verificationOnlyUnknown === true
      ? "Unverified"
      : classifySafetyScore(finalScore);
  const virusTotalWarningState = getVirusTotalWarningState(providerResults);
  const virusTotalWarningPolicy = applyVirusTotalWarningScorePolicy(finalScore, finalClassification, virusTotalWarningState);
  if (analysis.verificationOnlyUnknown !== true) {
    finalScore = virusTotalWarningPolicy.finalScore;
    finalClassification = virusTotalWarningPolicy.finalClassification;
  }
  if (virusTotalWarningState.warningSeverity === "suspicious") {
    finalFeatures = {
      ...finalFeatures,
      virusTotalProviderWarning: true,
      virusTotalWarningScoreCap: null
    };
  } else if (virusTotalWarningState.warningSeverity === "caution") {
    finalFeatures = {
      ...finalFeatures,
      virusTotalProviderCaution: true,
      virusTotalWarningScoreCap: null
    };
  }
  let scoreAudit = buildScoreAudit({
    scoring,
    providerOverride,
    providerCapBeforeScore,
    providerCapAfterScore,
    verificationState,
    verificationCapReason,
    verificationCapBeforeScore,
    verificationCapAfterScore,
    softUncertaintyCapApplied,
    softCapBeforeScore,
    softCapAfterScore,
    demoScoreBias: analysis.scoreAudit?.demoScoreBias || {},
    demoBiasBeforeScore: analysis.scoreAudit?.demoScoreBias?.beforeScore,
    demoBiasAfterScore: analysis.scoreAudit?.demoScoreBias?.afterScore,
    recovery,
    finalScore,
    finalClassification
  });
  scoreAudit = applyVirusTotalWarningAuditFields(scoreAudit, virusTotalWarningState, virusTotalWarningPolicy);

  return {
    scoring,
    features: finalFeatures,
    finalScore,
    finalClassification,
    scoreAudit,
    concreteRiskSignals
  };
}

function deriveConcreteRiskSignalsFromFeatures(features = {}, providerOverride = false) {
  return Boolean(
    providerOverride ||
    features.googleSafeBrowsingFlagged ||
    features.urlhausFlagged ||
    features.virusTotalFlagged ||
    features.integrityHashMismatch ||
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

function getKnownBrandAliasRedirect({ endpointResult = {}, redirectAnalysis = {}, finalDomain = "", url = "" } = {}) {
  const rawChain =
    Array.isArray(endpointResult?.resolutionChain) && endpointResult.resolutionChain.length > 0
      ? endpointResult.resolutionChain
      : Array.isArray(redirectAnalysis?.redirectChain)
        ? redirectAnalysis.redirectChain
        : [];
  const sourceDomain = getRedirectSourceDomain(rawChain);
  const normalizedFinalDomain = getRegistrableDomain(finalDomain);

  return getKnownBrandedDomainAliasMatch(sourceDomain, normalizedFinalDomain, url) || null;
}

function isCleanHighConfidenceResolvedEndpoint({
  features = {},
  endpointResult = {},
  providerResults = [],
  finalUrl = "",
  finalDomain = ""
} = {}) {
  const confidence = String(endpointResult?.endpointConfidence || "").toLowerCase();
  const providerCheckedUrl = getPrimaryProviderCheckedUrl(providerResults);
  const providerCheckedDomain = getRegistrableDomain(safeHostname(providerCheckedUrl));
  const finalHost = safeHostname(finalUrl || endpointResult?.effectiveEndpoint || "");
  const normalizedFinalDomain = getRegistrableDomain(finalDomain || finalHost);

  return Boolean(
    confidence === "high" &&
    isHttpsUrl(finalUrl || endpointResult?.effectiveEndpoint) &&
    normalizedFinalDomain &&
    !isShortenerHost(finalHost) &&
    providerCheckedDomain === normalizedFinalDomain &&
    !features.googleSafeBrowsingFlagged &&
    !features.urlhausFlagged &&
    !features.virusTotalFlagged &&
    areProvidersCleanForMarketingMitigation(providerResults)
  );
}

function buildCleanProviderRecoveryState({
  features = {},
  endpointResult = {},
  providerResults = [],
  visibleUrl = "",
  providerCheckedUrl = "",
  finalUrl = "",
  finalDomain = "",
  baseScore = null
} = {}) {
  const recoveryBlockedReasons = [];
  const effectiveFinalUrl = finalUrl || endpointResult?.effectiveEndpoint || "";
  const effectiveFinalDomain = getRegistrableDomain(finalDomain || endpointResult?.effectiveDomain || safeHostname(effectiveFinalUrl) || "");
  const effectiveVisibleUrl = visibleUrl || endpointResult?.displayUrl || endpointResult?.analysisUrl || endpointResult?.normalizedUrl || "";
  const brandedAliasMatch = getKnownBrandedDomainAliasMatch(
    getRegistrableDomain(safeHostname(effectiveVisibleUrl)),
    effectiveFinalDomain,
    providerCheckedUrl || effectiveFinalUrl || effectiveVisibleUrl
  );
  const redirectLike = Boolean(
    features.shortenedUrl ||
    features.wrapperToExternalDestination ||
    features.facebookWrapperUnwrapped ||
    features.crossDomainRedirectChain ||
    features.shortenerToUnrelatedDomain ||
    features.trackingHopToUnrelatedDomain ||
    features.suspiciousRedirectPattern ||
    features.redirectChainToDifferentRegistrantLikeTarget ||
    features.knownBrandAliasRedirect ||
    features.knownBrandedCampaignRedirect ||
    features.knownGoogleFormsRedirect ||
    features.cleanResolvedMarketingLink ||
    features.trustedRedirectDestination ||
    Number(features.redirectCount || 0) > 0
  );
  const vtWarning = getVirusTotalWarningState(providerResults);

  if (!areProvidersCleanForMarketingMitigation(providerResults)) {
    recoveryBlockedReasons.push("provider checks were not all completed clean");
  }

  if (vtWarning.hasStrongConsensus || vtWarning.hasSuspiciousLevelWarning || vtWarning.hasCautionOnlyWarning) {
    recoveryBlockedReasons.push("VirusTotal reported provider warning detections.");
  }

  if (!isCleanHighConfidenceResolvedEndpoint({
    features,
    endpointResult,
    providerResults,
    finalUrl: effectiveFinalUrl,
    finalDomain: effectiveFinalDomain
  })) {
    recoveryBlockedReasons.push("endpoint was not a high-confidence HTTPS final destination checked by providers");
  }

  if (!redirectLike) {
    recoveryBlockedReasons.push("remaining warning signs were not explainable redirect/tracking/shortener behavior");
  }

  if (features.suspiciousTld) {
    recoveryBlockedReasons.push("suspicious top-level domain");
  }

  if (features.usernamePasswordTrick) {
    recoveryBlockedReasons.push("username/password URL trick");
  }

  if (features.obfuscatedUrl || hasSevereObfuscationSignal(features)) {
    recoveryBlockedReasons.push("obfuscated URL structure");
  }

  if (features.textMismatch && !features.knownBrandAliasRedirect && !features.knownBrandedCampaignRedirect && !features.cleanResolvedMarketingLink && !brandedAliasMatch) {
    recoveryBlockedReasons.push("visible domain mismatch remains after normalization");
  }

  if (features.integrityHashMismatch && (features.suspiciousRedirectPattern || features.shortenerToUnrelatedDomain || features.trackingHopToUnrelatedDomain)) {
    recoveryBlockedReasons.push("verified post-integrity change combined with suspicious or unrelated redirect behavior");
  }

  const numericScore = toFiniteScoreOrNull(baseScore);
  const eligible = recoveryBlockedReasons.length === 0;

  return {
    recoveryEligible: eligible,
    recoveryApplied: Boolean(eligible && numericScore !== null && numericScore < 80),
    recoveryFloor: eligible ? 80 : null,
    recoveryReason: eligible
      ? brandedAliasMatch
        ? "Clean providers and a high-confidence resolved endpoint limited the remaining warnings to explainable redirect/tracking behavior, including a configured branded alias relationship."
        : "Clean providers and a high-confidence resolved endpoint limited the remaining warnings to explainable redirect/tracking behavior."
      : "",
    recoveryBlockedReasons,
    activeHeuristicGroups: getActiveHeuristicGroups(features),
    mitigatedHeuristicGroups: getMitigatedHeuristicGroups(features)
  };
}

function getActiveHeuristicGroups(features = {}) {
  const groups = [];

  if (features.domainPreviouslyFlagged) groups.push("provider_history");
  if (features.shortenedUrl || features.wrapperToExternalDestination) groups.push("endpoint_destination");
  if (features.crossDomainRedirectChain || features.suspiciousRedirectPattern || features.shortenerToUnrelatedDomain || features.trackingHopToUnrelatedDomain || features.redirectChainToDifferentRegistrantLikeTarget) groups.push("redirect_behavior");
  if (features.obfuscatedUrl || features.usernamePasswordTrick) groups.push("obfuscation");
  if (features.textMismatch) groups.push("display_mismatch");
  if (features.suspiciousPath) groups.push("content_context");
  if (features.suspiciousTld || features.excessiveQueryComplexity || features.excessiveSubdomainDepth) groups.push("technical_security");
  if (features.integrityHashMismatch || features.linkInsertedAfterBaseline) groups.push("post_integrity");

  return [...new Set(groups)];
}

function getMitigatedHeuristicGroups(features = {}) {
  const groups = [];

  if (features.cleanResolvedMarketingLink || features.knownBrandAliasRedirect || features.knownBrandedCampaignRedirect || features.trustedRedirectDestination || features.knownGoogleFormsRedirect || features.mainstreamResolvedShortlink) {
    groups.push("endpoint_destination", "redirect_behavior", "display_mismatch");
  }

  if (features.cleanResolvedMarketingLink || features.knownBrandAliasRedirect || features.knownBrandedCampaignRedirect) {
    groups.push("content_context");
  }

  return [...new Set(groups)];
}

function isHttpsUrl(rawUrl = "") {
  try {
    return new URL(String(rawUrl || "")).protocol === "https:";
  } catch {
    return false;
  }
}

function areProvidersCleanForMarketingMitigation(providerResults = []) {
  const providers = normalizeProviderResults(providerResults);
  const gsb = providers.find((item) => item.provider === "gsb");
  const urlhaus = providers.find((item) => item.provider === "urlhaus");
  const vt = providers.find((item) => item.provider === "virustotal");
  const vtStatus = getProviderStatus(vt);
  const vtWarning = getVirusTotalWarningState(providers);

  return Boolean(
    gsb?.checked === true &&
    gsb?.flagged !== true &&
    urlhaus?.checked === true &&
    urlhaus?.flagged !== true &&
    (
      vtStatus === "not-configured" ||
      vtStatus === "skipped" ||
      (
        vt?.checked === true &&
        vt?.flagged !== true &&
        ["checked", "completed"].includes(vtStatus) &&
        vtWarning.maliciousCount === 0 &&
        vtWarning.suspiciousCount === 0
      )
    )
  );
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

function formatRedirectTraceDomains(chain = []) {
  const domains = (Array.isArray(chain) ? chain : [])
    .map((url) => safeHostname(url).replace(/^www\./i, ""))
    .filter(Boolean);

  const compact = [];

  for (const domain of domains) {
    if (compact[compact.length - 1] !== domain) {
      compact.push(domain);
    }
  }

  if (compact.length === 0) {
    return "unavailable";
  }

  const hopCount = Math.max(0, compact.length - 1);
  const hopText = hopCount === 1 ? "1 domain change shown" : `${hopCount} domain changes shown`;

  return `${compact.join(" -> ")} (${hopText})`;
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
    features.trustedRedirectDestination ||
    features.knownCampaignRedirectToTrustedDestination ||
    features.trustedDestinationUnknownShortenerRedirect ||
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

function getPrimaryProviderCheckedUrl(providerResults = []) {
  for (const provider of normalizeProviderResults(providerResults)) {
    const checkedUrl = String(provider?.checkedUrl || "").trim();
    if (checkedUrl) {
      return checkedUrl;
    }
  }

  return "";
}

function hasPathOrQueryUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    return ["http:", "https:"].includes(url.protocol) && Boolean((url.pathname && url.pathname !== "/") || url.search);
  } catch {
    return false;
  }
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
const fullObservedRedirectTrace =
  redirectAnalysis.fullObservedRedirectTrace ||
  endpointResult.fullObservedRedirectTrace ||
  redirectAnalysis.redirectChain ||
  endpointResult.resolutionChain ||
  [];
const riskRelevantRedirectChain =
  redirectAnalysis.redirectChain ||
  endpointResult.resolutionChain ||
  [];
  const candidateSource = String(candidateContext.candidateSource || "").trim();
  const candidateCompleteness = String(candidateContext.candidateUrlCompleteness || "").trim();
  const providerCheckedUrl = getPrimaryProviderCheckedUrl(providerResults) || urlFeatureAnalysis.providerCheckedUrl || "";
  const normalizedComparisonUrl = urlFeatureAnalysis.normalizedComparisonUrl || urlFeatureAnalysis.sourceNormalizedUrl || "";
  const displayUrl = urlFeatureAnalysis.displayUrl || candidateContext.unwrappedCandidateUrl || candidateContext.selectedNormalizedTarget || candidateContext.rawHref || "";

  if (candidateSource) {
    details.push(`Candidate source: ${candidateSource}.`);
  }

  if (candidateCompleteness) {
    details.push(`Candidate completeness: ${candidateCompleteness}.`);
  }

  if (providerCheckedUrl) {
    if (!isDomainOnlyFallbackAnalysis && hasPathOrQueryUrl(providerCheckedUrl)) {
      details.push(`Provider checked full endpoint URL: ${providerCheckedUrl}.`);
    } else if (isDomainOnlyFallbackAnalysis) {
      details.push("Provider checked scope: visible domain only.");
    } else {
      details.push(`Provider checked URL: ${providerCheckedUrl}.`);
    }
  }

  if (normalizedComparisonUrl) {
    details.push(`Normalized comparison URL: ${normalizedComparisonUrl}.`);
  }

  if (displayUrl) {
    details.push(`Display URL: ${displayUrl}.`);
  }

  if (endpointResult.isFacebookWrapper && effectiveDomain) {
    details.push(`Facebook wrapper unwrapped to ${effectiveDomain}.`);
  }

if (redirectChain.length > 0 || fullObservedRedirectTrace.length > 0 || riskRelevantRedirectChain.length > 0) {
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

  if (endpointResult.effectiveEndpoint && !isDomainOnlyFallbackAnalysis && hasPathOrQueryUrl(endpointResult.effectiveEndpoint)) {
    details.push(`Full endpoint URL: ${endpointResult.effectiveEndpoint}.`);
  } else if (endpointResult.effectiveEndpoint && !isDomainOnlyFallbackAnalysis) {
    details.push(`Endpoint URL: ${endpointResult.effectiveEndpoint}.`);
  } else if (endpointResult.effectiveEndpoint && isDomainOnlyFallbackAnalysis) {
    details.push(`Checked fallback URL: ${endpointResult.effectiveEndpoint}.`);
  }

const fullObservedDisplayChain = prependKnownFacebookWrapperForDisplay(fullObservedRedirectTrace, facebookWrapperUrl);
if (fullObservedDisplayChain.length > 0) {
  details.push(`Full observed redirect trace: ${formatRedirectTraceDomains(fullObservedDisplayChain)}.`);
}

const riskRelevantDisplayChain = buildRiskRelevantRedirectChain(prependKnownFacebookWrapperForDisplay(riskRelevantRedirectChain, facebookWrapperUrl));
if (riskRelevantDisplayChain.length > 0) {
  details.push(`Risk-relevant redirect chain: ${formatRedirectTraceDomains(riskRelevantDisplayChain)}.`);
}
}
  if (urlFeatureAnalysis.sourceNormalizedUrl && urlFeatureAnalysis.sourceRawComparableUrl && urlFeatureAnalysis.sourceNormalizedUrl !== urlFeatureAnalysis.sourceRawComparableUrl) {
    details.push("Tracking parameters were stripped for comparison.");
  }

  if (endpointResult.endpointConfidence) {
    details.push(`Endpoint confidence: ${endpointResult.endpointConfidence}.`);
  }

  if (
    endpointResult.isShortener &&
    String(endpointResult.endpointConfidence || "").toLowerCase() === "low" &&
    isShortenerHost(safeHostname(endpointResult.effectiveEndpoint || endpointResult.resolvedUrl || ""))
  ) {
    details.push("Shortener resolution was limited; DILI checked the available shortener URL but did not confirm it as the final website.");
  }

  const nonWebProtocol =
    endpointResult.nonWebProtocol ||
    analysis.nonWebProtocol ||
    urlFeatureAnalysis.nonWebProtocol ||
    redirectAnalysis.protocol ||
    "";
  if (endpointResult.nonWebProtocolDetected || analysis.nonWebProtocolDetected || urlFeatureAnalysis.nonWebProtocolDetected) {
    details.push(
      `The redirect chain ended in a non-web application protocol (${nonWebProtocol}). Network verification was limited because the destination is intended for an external application.`
    );
  }

  if (isMessagingOrCommunityInviteDomain(getRegistrableDomain(effectiveDomain))) {
    details.push("DILI verified the link destination, but it cannot verify the trustworthiness of content inside this messaging or community platform.");
  }

  if (finalFeatures.knownBrandedCampaignRedirect) {
    details.push("Known branded redirect recognized.");
    details.push("Redirect mitigation applied: initial and final domains belong to expected brand family.");
    details.push("Known branded campaign redirect recognized; DILI treated the redirect as lower risk because providers were clean and the final destination matched an expected campaign platform.");
  }

  if (finalFeatures.sensitiveArticleTopicTermsIgnored) {
    details.push("Sensitive article-topic terms were not treated as phishing terms by themselves.");
  }

  if (finalFeatures.knownGoogleFormsRedirect) {
    details.push("Known Google Forms redirect recognized; DILI treated the redirect as lower risk because providers were clean and the final destination matched docs.google.com/forms.");
  }

  if (finalFeatures.googleFormsViaGenericShortener) {
    details.push("Google Forms final endpoint recognized through a generic shortener; DILI treated redirect mechanics as lower risk because providers were clean, but form ownership should still be verified.");
  }

  if (finalFeatures.knownCampaignRedirectToTrustedDestination) {
    details.push("Known campaign redirect resolved to trusted destination.");
  }

  if (finalFeatures.knownBrandedDomainAlias) {
    const brandName = finalFeatures.knownBrandedDomainAliasName || finalFeatures.knownBrandAliasLabel || "configured branded alias relationship";
    const sourceDomain = finalFeatures.knownBrandedDomainAliasSourceDomain || finalFeatures.knownBrandAliasSourceDomain || "";
    const finalDomain = finalFeatures.knownBrandedDomainAliasFinalDomain || finalFeatures.knownBrandAliasFinalDomain || "";
    details.push(`Configured branded alias matched: ${brandName}${sourceDomain && finalDomain ? ` (${sourceDomain} -> ${finalDomain})` : ""}.`);
    details.push("Visible domain and final domain were treated as a configured branded alias relationship.");
  } else if (finalFeatures.knownBrandAliasRedirect) {
    details.push("The visible domain and final domain were treated as a configured branded alias relationship for mismatch scoring.");
  }

  if (finalFeatures.cleanResolvedMarketingLink) {
    details.push("Clean provider results and a high-confidence resolved endpoint mitigated normal shortener, wrapper, and marketing tracking signals.");
  }

  if (finalFeatures.trustedDestinationUnknownShortenerRedirect) {
    details.push("Redirect trust tier B: unknown shortener resolved to a trusted destination with clean providers.");
  }

  if (finalFeatures.softUncertaintyCapApplied) {
    details.push("Safety score was softly capped because DILI can verify URL reputation, but some destination content remains outside URL-reputation scope.");
  }

  const providerFlagged = normalizeProviderResults(providerResults).some((provider) => provider?.flagged === true);
  if (analysis.interceptionRecommended === true) {
    const score = toFiniteScoreOrNull(analysis.safetyScore);
    if (providerFlagged || analysis.providerOverride === true) {
      details.push("Navigation pause reason: provider flagged this URL.");
    } else if (analysis.classification === "High Risk") {
      details.push("Navigation pause reason: High Risk classification.");
    } else if (analysis.classification === "Suspicious") {
      details.push("Navigation pause reason: Suspicious classification.");
    } else if (score !== null && score < 80) {
      details.push("Navigation pause reason: final score below 80.");
    }
  }

  for (const detail of buildCombinedRiskTechnicalDetails(finalFeatures)) {
    details.push(detail);
  }

  if (analysis.postIntegrityEvent) {
    details.push(`Post integrity event: ${String(analysis.postIntegrityEvent).replace(/_/g, " ")}.`);
  }

  if (analysis?.postTextChangedSinceBaseline || analysis?.features?.postTextChangedSinceBaseline) {
    details.push("Post text changed after the stored baseline.");
  }

  if (analysis?.baselineHadNoLink || analysis?.features?.baselineHadNoLink) {
    details.push("Stored baseline had no detected external link.");
  }

  if (analysis?.linkInsertedAfterBaseline || analysis?.features?.linkInsertedAfterBaseline) {
    details.push("A link appeared after the original no-link baseline. DILI treated this as a post-integrity warning, not direct proof of maliciousness.");
  }

  if (analysis?.features?.linkInsertedAfterUnstableBaseline) {
    details.push("A link appeared after a prior no-link observation, but the post identity was not stable enough for a full post-integrity deduction.");
  }

  if (analysis?.features?.integrityHashMismatch && !analysis?.features?.linkInsertedAfterBaseline) {
    details.push("The post hyperlink changed after the original link baseline was stored. DILI treated this as contextual warning evidence, not direct proof of maliciousness.");
  }

  if (analysis?.features?.sameDomainLinkChanged) {
    details.push("The link URL changed within the same domain. DILI recorded this as a limited post-integrity warning.");
  }

  if (analysis?.features?.trackingOnlyPostIntegrityChange) {
    details.push("Only tracking parameters changed, so no post-integrity deduction was applied.");
  }

  if (analysis?.features?.limitedPostIntegrityEvidence || analysis?.features?.postIntegrityAuditOnly) {
    details.push(analysis?.features?.postIntegrityReason || "A prior no-link or different-link state was observed, but the post identity was not stable enough for a full post-integrity deduction.");
  }

  if (analysis?.previousBaselineUrl && analysis?.features?.integrityHashMismatch) {
    details.push(`Previous baseline URL: ${analysis.previousBaselineUrl}.`);
  }

  const provisionalNoLinkBaseline = Boolean(analysis?.provisionalNoLinkBaseline || analysis?.features?.provisionalNoLinkBaseline);
  const currentHasUsableLinkCandidate = Boolean(analysis?.currentHasUsableLinkCandidate || analysis?.features?.currentHasUsableLinkCandidate);
  if (provisionalNoLinkBaseline && currentHasUsableLinkCandidate) {
    details.push("A provisional no-link baseline later exposed a link, likely due to Facebook lazy-loading. Post-integrity scoring was not applied.");
  }

  const confirmedNoLinkBaseline = Boolean(analysis?.confirmedNoLinkBaseline || analysis?.features?.confirmedNoLinkBaseline);
  const matureConfirmedNoLinkBaseline = Boolean(analysis?.matureConfirmedNoLinkBaseline || analysis?.features?.matureConfirmedNoLinkBaseline);
  if (confirmedNoLinkBaseline && !matureConfirmedNoLinkBaseline) {
    details.push("A no-link baseline was too recent to treat this as post-publication link insertion.");
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
    details.push("Endpoint source note: Facebook did not expose a full clickable URL for this card, so DILI checked the visible domain only.");
    details.push("Passive scan did not expose a full path/query endpoint.");
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
  const outcomeSummary = getProviderOutcomeSummary(provider) || provider.resultSummary;
  const durationMs = Number(provider.durationMs);

  details.push(`${label} checked URL: ${provider.checkedUrl}.`);
  if (Array.isArray(provider.details?.checkedUrls) && provider.details.checkedUrls.length > 1) {
    details.push(`${label} checked URL candidates: ${provider.details.checkedUrls.join(" | ")}.`);
  }
  if (provider.details?.flaggedCandidateUrl) {
    details.push(`${label} flagged candidate URL: ${provider.details.flaggedCandidateUrl}.`);
  }
  details.push(`${label} result: ${outcomeSummary}`);
  details.push(`${label} status: ${auditStatus}.`);

  if (provider.provider === "virustotal" && provider.details?.reason === "retry_budget_exhausted") {
    details.push("VirusTotal did not complete within the retry window.");
  }

  if (provider.provider === "virustotal") {
    if (provider.details?.analysisId) {
      details.push(`VirusTotal analysis ID: ${provider.details.analysisId}.`);
    }
    if (provider.details?.retryable !== undefined || provider.details?.terminal !== undefined) {
      details.push(`VirusTotal retry state: ${provider.details?.retryable === false ? "not retryable" : "retryable"}, ${provider.details?.terminal === true ? "terminal" : "not terminal"}.`);
    }
  }

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
    const vtWarning = getVirusTotalWarningState(provider);
    details.push(`${label} malicious detections: ${vtWarning.maliciousCount}.`);
    details.push(`${label} suspicious detections: ${vtWarning.suspiciousCount}.`);
  }
}
  const retryPlan = analysis.providerRetryPlan || {};
  if (retryPlan && typeof retryPlan === "object" && (retryPlan.attempt || retryPlan.status || retryPlan.nextRetryAt || retryPlan.lastAttemptAt)) {
    if (retryPlan.attempt || retryPlan.maxAttempts) {
      details.push(`VirusTotal retry attempt: ${retryPlan.attempt || 0}/${retryPlan.maxAttempts || "unknown"}.`);
    }
    if (retryPlan.status) {
      details.push(`VirusTotal retry status: ${retryPlan.status}.`);
    }
    if (retryPlan.lastAttemptAt) {
      details.push(`VirusTotal last retry attempt: ${new Date(Number(retryPlan.lastAttemptAt)).toISOString()}.`);
    }
    if (retryPlan.nextRetryAt) {
      details.push(`VirusTotal next retry time: ${new Date(Number(retryPlan.nextRetryAt)).toISOString()}.`);
    }
    if (retryPlan.lastAttemptStatus) {
      details.push(`VirusTotal last refresh result: ${retryPlan.lastAttemptStatus}.`);
    }
  }
  return [...new Set(details)];

}

function buildCombinedRiskTechnicalDetails(features = {}) {
  const details = [];
  const redirectCount = Number(features.redirectCount || 0);
  const hasRedirect = Boolean(
    redirectCount > 0 ||
    features.wrapperToExternalDestination ||
    features.crossDomainRedirectChain ||
    features.suspiciousRedirectPattern ||
    features.shortenerToUnrelatedDomain
  );

  if (features.shortenedUrl && (features.crossDomainRedirectChain || features.shortenerToUnrelatedDomain || features.redirectChainToDifferentRegistrantLikeTarget)) {
    details.push("Combined risk: shortener and cross-domain redirect.");
  }

  if (features.shortenedUrl && features.textMismatch) {
    details.push("Combined risk: hidden destination and visible/final mismatch.");
  }

  if (features.shortenedUrl && features.wrapperToExternalDestination && (features.facebookWrapperUnwrapped || features.crossDomainRedirectChain || features.shortenerToUnrelatedDomain)) {
    details.push("Combined risk: Facebook wrapper, shortener, and external final destination.");
  }

  if (features.obfuscatedUrl && hasRedirect) {
    details.push("Combined risk: obfuscated or encoded URL plus redirect behavior.");
  }

  if (features.suspiciousPath && (features.shortenedUrl || hasRedirect)) {
    details.push("Combined risk: credential/payment/prize path indicators plus hidden destination behavior.");
  }

  if (features.integrityHashMismatch && features.linkInsertedAfterBaseline) {
    details.push("Combined risk: post-integrity change introduced a new link.");
  }

  if (features.domainPreviouslyFlagged && (features.shortenedUrl || features.wrapperToExternalDestination || features.crossDomainRedirectChain || features.textMismatch || features.obfuscatedUrl)) {
    details.push("Combined risk: weak reputation signal plus structural destination hiding.");
  }

  return details;
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
  const score = toFiniteScoreOrNull(analysis.safetyScore);
  const classification = String(analysis.classification || analysis.computedClassification || analysis.scoreAudit?.classification || analysis.scoreAudit?.computedClassification || "").toLowerCase();
  const providerResults = normalizeProviderResults(analysis.providerResults || []);
  const gsb = providerResults.find((item) => item.provider === "gsb");
  const urlhaus = providerResults.find((item) => item.provider === "urlhaus");
  const virusTotal = providerResults.find((item) => item.provider === "virustotal");
  const reviewRecommended = Boolean(
    analysis.providerWarningReviewRecommended === true ||
    analysis.scoreAudit?.providerWarningReviewRecommended === true ||
    (
      score !== null &&
      score >= 80 &&
      classification === "safe" &&
      !analysis.providerOverride &&
      !gsb?.flagged &&
      !urlhaus?.flagged &&
      (
        toFiniteScoreOrNull(analysis.providerDeductions?.virustotal) > 0 ||
        toFiniteScoreOrNull(analysis.scoreAudit?.providerDeductions?.virustotal) > 0 ||
        Number(analysis.scoreAudit?.virusTotalMaliciousDetections || 0) + Number(analysis.scoreAudit?.virusTotalSuspiciousDetections || 0) > 0
      )
    )
  );

  if (analysis.providerOverride === true || gsb?.flagged || urlhaus?.flagged || virusTotal?.flagged) {
    return true;
  }
  if (reviewRecommended) {
    return true;
  }
  if (classification.includes("high risk") || classification.includes("suspicious")) {
    return true;
  }

  if (score !== null && score < 80) {
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
    scoreAudit: analysis.scoreAudit,
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

  analysis = normalizeBackgroundTerminalState({
    ...analysis,
    postId: analysis.postId || postId
  });

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
      performanceTiming: analysis.performanceTiming,
      hadLinkAtBaseline: analysis.hadLinkAtBaseline,
      linkInsertedAfterBaseline: analysis.linkInsertedAfterBaseline,
      postIntegrityEvent: analysis.postIntegrityEvent,
      baselineState: analysis.baselineState,
      normalizedVisiblePostText: analysis.normalizedVisiblePostText,
      safetyScore: analysis.safetyScore,
      computedSafetyScore: analysis.computedSafetyScore,
      computedClassification: analysis.computedClassification,
      scanFinalized: analysis.scanFinalized,
      providerPending: analysis.providerPending,
      providerCompletion: analysis.providerCompletion,
      pendingProviders: analysis.pendingProviders,
      providerDeductions: analysis.providerDeductions,
      heuristicRawCategoryTotals: analysis.heuristicRawCategoryTotals,
      heuristicCategoryDeductions: analysis.heuristicCategoryDeductions,
      heuristicRawTotal: analysis.heuristicRawTotal,
      heuristicScaledDeduction: analysis.heuristicScaledDeduction,
      totalDeduction: analysis.totalDeduction,
      scoreAudit: analysis.scoreAudit,
      classification: analysis.classification,
      analyzedLinkCount: analysis.analyzedLinkCount,
      failedLinkCount: analysis.failedLinkCount,
      multiLinkPost: analysis.multiLinkPost,
      lowestScoringLinkDomain: analysis.lowestScoringLinkDomain,
      lowestScoringLinkUrl: analysis.lowestScoringLinkUrl,
      linkScoreSummary: analysis.linkScoreSummary,
      linkAnalysisSnapshots: analysis.linkAnalysisSnapshots,
      pendingLinkRefreshTargets: analysis.pendingLinkRefreshTargets,
      pendingProviderRefreshTarget: analysis.pendingProviderRefreshTarget,
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

async function clearPostAnalysisState(message = {}) {
  const postId = String(message.postId || "").trim();
  const reason = String(message.reason || "manual-post-restart").trim() || "manual-post-restart";

  if (!postId) {
    return {
      type: MESSAGE_TYPES.CLEAR_POST_ANALYSIS_STATE,
      cleared: false,
      reason: "missing-post-id"
    };
  }

  const storedAnalysis = await getBaseline(postId);
  const relatedUrls = collectAnalysisCacheUrls(storedAnalysis);
  const clearStoredRecord = isClearablePostAnalysis(storedAnalysis);

  if (clearStoredRecord) {
    await removePostAnalysis(postId);
  }

  for (const url of relatedUrls) {
    const cacheKey = normalizeCacheKey(url);
    if (!cacheKey) {
      continue;
    }

    urlAnalysisCache.delete(cacheKey);
    virusTotalPendingAnalysisCache.delete(cacheKey);
    providerResultCache.delete(`virustotal::${cacheKey}`);
  }

  logDebug(`Cleared stale analysis state for post ${postId}. Reason: ${reason}. Stored record cleared: ${clearStoredRecord}. URL cache entries considered: ${relatedUrls.length}.`);

  return {
    type: MESSAGE_TYPES.CLEAR_POST_ANALYSIS_STATE,
    cleared: true,
    postId,
    reason,
    storedRecordCleared: clearStoredRecord
  };
}

function isClearablePostAnalysis(analysis = {}) {
  if (!analysis || typeof analysis !== "object") {
    return true;
  }

  if (analysis.providerOverride === true) {
    return false;
  }

  const state = String(analysis.state || "").toLowerCase();
  const classification = String(analysis.classification || "").toLowerCase();

  return Boolean(
    analysis.scanFinalized === false ||
    analysis.providerPending === true ||
    state === "pending-provider" ||
    state === "verification-incomplete" ||
    state === "completed-limited" ||
    state === "failed-local" ||
    classification === "scan pending" ||
    classification === "unverified" ||
    classification === "verification incomplete"
  );
}

function collectAnalysisCacheUrls(analysis = {}) {
  if (!analysis || typeof analysis !== "object") {
    return [];
  }

  const values = [
    analysis.rawUrl,
    analysis.url,
    analysis.normalizedUrl,
    analysis.analysisUrl,
    analysis.providerCheckedUrl,
    analysis.endpointResult?.normalizedRawUrl,
    analysis.endpointResult?.unwrappedUrl,
    analysis.endpointResult?.resolvedUrl,
    analysis.endpointResult?.effectiveEndpoint,
    analysis.urlFeatureAnalysis?.displayUrl,
    analysis.urlFeatureAnalysis?.normalizedUrl,
    analysis.urlFeatureAnalysis?.unwrappedUrl,
    analysis.urlFeatureAnalysis?.providerCheckedUrl,
    ...(Array.isArray(analysis.endpointResult?.resolutionChain) ? analysis.endpointResult.resolutionChain : []),
    ...(Array.isArray(analysis.endpointResult?.fullObservedRedirectTrace) ? analysis.endpointResult.fullObservedRedirectTrace : []),
    ...(Array.isArray(analysis.redirectAnalysis?.redirectChain) ? analysis.redirectAnalysis.redirectChain : []),
    ...(Array.isArray(analysis.redirectAnalysis?.fullObservedRedirectTrace) ? analysis.redirectAnalysis.fullObservedRedirectTrace : [])
  ];

  for (const provider of normalizeProviderResults(analysis.providerResults || [])) {
    values.push(provider.checkedUrl);
    if (Array.isArray(provider.details?.checkedUrls)) {
      values.push(...provider.details.checkedUrls);
    }
  }

  for (const child of analysis.linkAnalysisSnapshots || []) {
    values.push(...collectAnalysisCacheUrls(child));
  }

  return [...new Set(
    values
      .map((value) => normalizeCacheKey(value))
      .filter(Boolean)
  )];
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
function buildProviderUrlCandidates({ rawUrl = "", endpointResult = {}, redirectAnalysis = {}, urlFeatures = {}, providerCheckedUrl = "" } = {}) {
  const redirectChain = [
    ...(Array.isArray(redirectAnalysis?.redirectChain) ? redirectAnalysis.redirectChain : []),
    ...(Array.isArray(redirectAnalysis?.fullObservedRedirectTrace) ? redirectAnalysis.fullObservedRedirectTrace : []),
    ...(Array.isArray(endpointResult?.resolutionChain) ? endpointResult.resolutionChain : []),
    ...(Array.isArray(endpointResult?.fullObservedRedirectTrace) ? endpointResult.fullObservedRedirectTrace : [])
  ];
  const candidates = [
    rawUrl,
    urlFeatures.rawComparableUrl,
    urlFeatures.displayUrl,
    endpointResult.normalizedRawUrl,
    endpointResult.unwrappedUrl,
    urlFeatures.unwrappedUrl,
    urlFeatures.normalizedUrl,
    ...redirectChain,
    endpointResult.resolvedUrl,
    endpointResult.effectiveEndpoint,
    providerCheckedUrl
  ];
  const seen = new Set();

  return candidates
    .map((candidate) => normalizeProviderCandidateUrl(candidate))
    .filter((candidate) => {
      if (!candidate || seen.has(candidate) || !isProviderScannableUrl(candidate)) {
        return false;
      }
      seen.add(candidate);
      return true;
    })
    .slice(0, 12);
}

async function runThreatIntelligenceChecks(normalizedUrl, { providerUrlCandidates = [] } = {}) {
  if (!isProviderScannableUrl(normalizedUrl)) {
    return normalizeProviderResults([
      createSkippedUnsupportedProtocolProviderResult("gsb", normalizedUrl),
      createSkippedUnsupportedProtocolProviderResult("urlhaus", normalizedUrl),
      createSkippedUnsupportedProtocolProviderResult("virustotal", normalizedUrl)
    ]);
  }

  const providerCandidates = Array.isArray(providerUrlCandidates) && providerUrlCandidates.length > 0
    ? providerUrlCandidates
    : [normalizedUrl];
  const providerTasks = [
    lookupGoogleSafeBrowsingCandidateSet(providerCandidates),
    lookupUrlhausCandidateSet(providerCandidates),
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

async function lookupUrlhausCandidateSet(candidateUrls = []) {
  const candidates = (Array.isArray(candidateUrls) ? candidateUrls : []).filter(Boolean);
  const checkedUrls = [];
  let firstResult = null;
  let lastResult = null;

  for (const candidate of candidates) {
    const result = await getCachedOrInFlightProviderResult("urlhaus", candidate, () => lookupUrlhaus(candidate));
    checkedUrls.push(candidate);
    lastResult = result;
    if (!firstResult) {
      firstResult = result;
    }

    if (result?.flagged === true) {
      return withProviderOutcomeSummary({
        ...result,
        checkedUrl: candidate,
        details: {
          ...(result.details || {}),
          checkedUrls,
          candidateCount: checkedUrls.length,
          flaggedCandidateUrl: candidate
        }
      });
    }
  }

  const baseResult = lastResult || firstResult || createProviderErrorResult("urlhaus", candidates[0] || "", new Error("URLhaus candidate lookup did not run."));
  const completedClean = baseResult?.checked === true &&
    String(baseResult?.details?.status || "").toLowerCase() === "checked" &&
    baseResult?.flagged !== true;
  return withProviderOutcomeSummary({
    ...baseResult,
    checkedUrl: checkedUrls[checkedUrls.length - 1] || baseResult.checkedUrl || "",
    flagged: false,
    details: {
      ...(baseResult.details || {}),
      checkedUrls,
      candidateCount: checkedUrls.length,
      message: completedClean
        ? "URLhaus found no known malware record for the checked URL candidate(s)."
        : "URLhaus check did not complete."
    }
  });
}

async function lookupGoogleSafeBrowsingCandidateSet(candidateUrls = []) {
  const candidates = (Array.isArray(candidateUrls) ? candidateUrls : []).filter(Boolean);
  const checkedUrls = [];
  let firstResult = null;
  let lastResult = null;

  for (const candidate of candidates) {
    const result = await getCachedOrInFlightProviderResult("gsb", candidate, () => lookupGoogleSafeBrowsing(candidate));
    checkedUrls.push(candidate);
    lastResult = result;
    if (!firstResult) {
      firstResult = result;
    }

    if (result?.flagged === true) {
      return withProviderOutcomeSummary({
        ...result,
        checkedUrl: candidate,
        details: {
          ...(result.details || {}),
          checkedUrls,
          candidateCount: checkedUrls.length,
          flaggedCandidateUrl: candidate
        }
      });
    }
  }

  const baseResult = lastResult || firstResult || createProviderErrorResult("gsb", candidates[0] || "", new Error("Google Safe Browsing candidate lookup did not run."));
  const completedClean = baseResult?.checked === true &&
    String(baseResult?.details?.status || "").toLowerCase() === "checked" &&
    baseResult?.flagged !== true;
  return withProviderOutcomeSummary({
    ...baseResult,
    checkedUrl: checkedUrls[checkedUrls.length - 1] || baseResult.checkedUrl || "",
    flagged: false,
    details: {
      ...(baseResult.details || {}),
      checkedUrls,
      candidateCount: checkedUrls.length,
      message: completedClean
        ? "Google Safe Browsing did not flag the checked URL candidate(s)."
        : "Google Safe Browsing check did not complete."
    }
  });
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
  const vtWarning = getVirusTotalWarningState({
    details: {
      maliciousCount,
      malicious: maliciousCount,
      suspiciousCount,
      suspicious: suspiciousCount,
      last_analysis_stats: stats
    }
  });
  const signalLevel = vtWarning.warningSeverity === "high"
    ? "strong"
    : vtWarning.warningSeverity === "suspicious"
      ? "warning"
      : vtWarning.warningSeverity;
  const flagged = signalLevel === "strong";

  updateVirusTotalHealth({
    configured: true,
    available: true,
    lastStatus: flagged ? "flagged" : signalLevel === "clean" ? "ok" : signalLevel,
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
    category: flagged ? "strong-malicious-consensus" : signalLevel !== "clean" ? signalLevel : null,
    details: {
      status: "checked",
      httpStatus,
      message: flagged
        ? "VirusTotal reported multiple malicious or suspicious detections."
        : signalLevel === "warning"
          ? vtWarning.warningLabel
          : signalLevel === "caution"
            ? vtWarning.warningLabel
            : "VirusTotal reported no malicious or suspicious detections.",
      analysisId,
      terminal: true,
      retryable: false,
      signalLevel,
      maliciousCount,
      malicious: maliciousCount,
      suspiciousCount,
      suspicious: suspiciousCount,
      last_analysis_stats: stats,
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
  const terminal = status !== "pending";
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
      terminal,
      retryable: status === "pending",
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

function selectPendingProviderRefreshTarget(storedAnalysis = {}, message = {}) {
  const candidates = [
    storedAnalysis.pendingProviderRefreshTarget,
    ...(Array.isArray(storedAnalysis.pendingLinkRefreshTargets) ? storedAnalysis.pendingLinkRefreshTargets : []),
    ...(Array.isArray(storedAnalysis.linkAnalysisSnapshots) ? storedAnalysis.linkAnalysisSnapshots : [])
  ].filter(Boolean);
  const pendingCandidates = candidates.filter(isPendingProviderRefreshTarget);

  const messageIndex = Number.isInteger(message.pendingLinkIndex)
    ? message.pendingLinkIndex
    : null;

  if (messageIndex !== null) {
    const byIndex = pendingCandidates.find((candidate) => candidate.index === messageIndex);
    if (byIndex) {
      return byIndex;
    }
  }

  if (message.providerCheckedUrl) {
    const byCheckedUrl = pendingCandidates.find((candidate) => candidate.providerCheckedUrl === message.providerCheckedUrl);
    if (byCheckedUrl) {
      return byCheckedUrl;
    }
  }

  const byPendingStatus = pendingCandidates.find((candidate) => {
    const vt = getNormalizedProviderResult(candidate.providerResults || [], "virustotal");
    const status = String(vt?.details?.status || candidate.status || "").toLowerCase();

    return status === "pending" || status === "timeout" || status === "rate-limited" || isAnalysisPendingLike(candidate);
  });

  if (byPendingStatus) {
    return byPendingStatus;
  }

  if (!Array.isArray(storedAnalysis.linkAnalysisSnapshots) || storedAnalysis.linkAnalysisSnapshots.length === 0) {
    return storedAnalysis;
  }

  return null;
}

function buildProviderRetryPlanFromMessage(message = {}, status = "waiting-response", lastAttemptStatus = "") {
  const attempt = Number(message.retryAttempt || message.attempt || 0);
  const maxAttempts = Number(message.retryMaxAttempts || message.maxAttempts || 0);
  const nextRetryAt = Number(message.nextRetryAt || 0);
  const lastAttemptAt = Number(message.lastAttemptAt || Date.now());

  return {
    attempt: Number.isFinite(attempt) && attempt > 0 ? attempt : null,
    maxAttempts: Number.isFinite(maxAttempts) && maxAttempts > 0 ? maxAttempts : null,
    nextRetryAt: Number.isFinite(nextRetryAt) && nextRetryAt > 0 ? nextRetryAt : null,
    lastAttemptAt: Number.isFinite(lastAttemptAt) && lastAttemptAt > 0 ? lastAttemptAt : Date.now(),
    lastAttemptStatus: lastAttemptStatus || String(message.lastAttemptStatus || ""),
    status
  };
}

function mergeProviderRetryPlan(analysis = {}, retryPlan = {}) {
  if (!analysis || typeof analysis !== "object") {
    return analysis;
  }

  return {
    ...analysis,
    providerRetryPlan: {
      ...(analysis.providerRetryPlan || {}),
      ...Object.fromEntries(
        Object.entries(retryPlan || {}).filter(([, value]) => value !== null && value !== undefined && value !== "")
      )
    }
  };
}

function buildTerminalVirusTotalResult(existingVt = {}, {
  providerCheckedUrl = "",
  status = "retry-budget-exhausted",
  reason = "retry_budget_exhausted",
  message = "VirusTotal did not return a completed result within the retry window."
} = {}) {
  return withProviderOutcomeSummary({
    ...(existingVt || {}),
    provider: "virustotal",
    configured: existingVt?.configured === true,
    checked: existingVt?.checked === true,
    checkedUrl: providerCheckedUrl || existingVt?.checkedUrl || "",
    checkedAt: existingVt?.checkedAt || new Date().toISOString(),
    durationMs: existingVt?.durationMs ?? null,
    flagged: false,
    category: null,
    details: {
      ...(existingVt?.details || {}),
      status,
      reason,
      terminal: true,
      retryable: false,
      message
    }
  });
}

function hasLegacyPendingChildWithoutRefreshMetadata(storedAnalysis = {}) {
  const hasSnapshots = Array.isArray(storedAnalysis.linkAnalysisSnapshots) && storedAnalysis.linkAnalysisSnapshots.length > 0;
  const summary = Array.isArray(storedAnalysis.linkScoreSummary) ? storedAnalysis.linkScoreSummary : [];

  return Boolean(
    !hasSnapshots &&
    summary.some((item) => (
      isPendingClassificationLabel(item?.classification) ||
      item?.scanFinalized === false ||
      item?.providerCompletion?.hasPendingProvider === true ||
      (Array.isArray(item?.pendingProviders) && item.pendingProviders.length > 0)
    ))
  );
}

function replaceStoredLinkAnalysisSnapshot(linkAnalyses = [], updatedChild = {}) {
  const updatedIndex = Number(updatedChild.index);
  const updatedUrl = normalizeCacheKey(updatedChild.analysisUrl || updatedChild.normalizedUrl);

  return (Array.isArray(linkAnalyses) ? linkAnalyses : []).map((item) => {
    const itemIndex = Number(item.index);
    const itemUrl = normalizeCacheKey(item.analysisUrl || item.normalizedUrl);
    if (
      (Number.isFinite(updatedIndex) && updatedIndex > 0 && itemIndex === updatedIndex) ||
      (updatedUrl && itemUrl === updatedUrl)
    ) {
      return updatedChild;
    }

    return item;
  });
}

function buildLinkScoreSummaryFromSnapshots(linkAnalyses = []) {
  return (Array.isArray(linkAnalyses) ? linkAnalyses : []).map((item, index) => ({
    index: item.index || index + 1,
    url: item.analysisUrl || item.normalizedUrl || item.url || "",
    domain: item.domain || item.endpointResult?.effectiveDomain || item.urlFeatureAnalysis?.finalDomain || "",
    safetyScore: item.safetyScore,
    computedSafetyScore: item.computedSafetyScore,
    classification: item.classification,
    computedClassification: item.computedClassification,
    state: item.state,
    scanFinalized: item.scanFinalized,
    providerOverride: item.providerOverride,
    providerPending: item.providerPending,
    providerCompletion: item.providerCompletion,
    providerRetryPlan: item.providerRetryPlan,
    pendingProviders: item.pendingProviders
  })).slice(0, 8);
}

function aggregatePostAnalysisFromLinkSnapshots(storedAnalysis = {}, linkAnalyses = []) {
  const snapshots = (Array.isArray(linkAnalyses) ? linkAnalyses : []).map((item, index) => ({
    ...normalizeStoredLinkAnalysisSnapshot(item),
    index: item.index || index + 1
  }));
  const linkScoreSummary = buildLinkScoreSummaryFromSnapshots(snapshots);
  const pendingChildren = snapshots.filter(isStoredLinkAnalysisPending);
  const terminalIncompleteChildren = snapshots.filter(isStoredLinkAnalysisTerminalIncomplete);
  const providerOverrideChildren = snapshots.filter((item) => item.providerOverride === true);
  const pendingLinkRefreshTargets = buildPendingLinkRefreshTargets(snapshots);
  const selectable = providerOverrideChildren.length > 0
    ? providerOverrideChildren
    : snapshots.filter((item) => !isStoredLinkAnalysisPending(item));
  const selected = selectable
    .map((item) => ({
      item,
      score: toFiniteScoreOrNull(item.safetyScore) ?? toFiniteScoreOrNull(item.computedSafetyScore) ?? 101
    }))
    .sort((left, right) => left.score - right.score)[0]?.item || snapshots[0] || {};
  const aggregated = {
    ...storedAnalysis,
    ...selected,
    analyzedLinkCount: snapshots.length || storedAnalysis.analyzedLinkCount,
    multiLinkPost: snapshots.length > 1 || storedAnalysis.multiLinkPost === true,
    linkAnalysisSnapshots: snapshots,
    linkScoreSummary,
    pendingLinkRefreshTargets,
    pendingProviderRefreshTarget: pendingLinkRefreshTargets[0] || null,
    lowestScoringLinkUrl: selected.analysisUrl || selected.normalizedUrl || "",
    lowestScoringLinkDomain: selected.domain || selected.endpointResult?.effectiveDomain || selected.urlFeatureAnalysis?.finalDomain || ""
  };

  if (providerOverrideChildren.length > 0) {
    const selectedScore = toFiniteScoreOrNull(selected.safetyScore) ?? toFiniteScoreOrNull(selected.computedSafetyScore);
    const selectedClassification = selected.classification || selected.computedClassification || (selectedScore !== null ? classifySafetyScore(selectedScore) : "Unverified");
    aggregated.classification = selectedClassification;
    aggregated.safetyScore = selected.safetyScore;
    aggregated.computedClassification = selected.computedClassification || selectedClassification;
    aggregated.computedSafetyScore = selected.computedSafetyScore;
    aggregated.providerOverride = true;
    aggregated.scanFinalized = true;
    aggregated.providerPending = false;
    aggregated.state = "completed";
    aggregated.interceptionRecommended = true;
    aggregated.pendingProviders = [];
    aggregated.providerCompletion = {
      ...(selected.providerCompletion || {}),
      hasPendingProvider: false,
      allRequiredProvidersTerminal: true,
      pendingProviders: []
    };
    return aggregated;
  }
  if (pendingChildren.length > 0) {
    const pendingProviders = [
      ...new Set(pendingChildren.flatMap((item) => (
        Array.isArray(item.pendingProviders)
          ? item.pendingProviders
          : Array.isArray(item.providerCompletion?.pendingProviders)
            ? item.providerCompletion.pendingProviders
            : []
      )))
    ];

    aggregated.classification = "Scan Pending";
    aggregated.safetyScore = null;
    aggregated.scanFinalized = false;
    aggregated.providerPending = true;
    aggregated.state = "pending-provider";
    aggregated.interceptionRecommended = false;
    aggregated.pendingProviders = pendingProviders;
    aggregated.providerCompletion = {
      ...(aggregated.providerCompletion || {}),
      hasPendingProvider: true,
      allRequiredProvidersTerminal: false,
      pendingProviders
    };
    return aggregated;
  }

  if (terminalIncompleteChildren.length > 0) {
    const selectedIncomplete = terminalIncompleteChildren[0] || selected;

    aggregated.classification = "Unverified";
    aggregated.safetyScore = null;
    aggregated.computedClassification = selectedIncomplete.computedClassification || "Unverified";
    aggregated.computedSafetyScore = selectedIncomplete.computedSafetyScore ?? null;
    aggregated.scanFinalized = true;
    aggregated.providerPending = false;
    aggregated.state = "verification-incomplete";
    aggregated.interceptionRecommended = Boolean(selectedIncomplete.interceptionRecommended);
    aggregated.pendingProviders = [];
    aggregated.providerCompletion = {
      ...(selectedIncomplete.providerCompletion || {}),
      hasPendingProvider: false,
      allRequiredProvidersTerminal: true,
      pendingProviders: []
    };
    aggregated.pendingLinkRefreshTargets = [];
    aggregated.pendingProviderRefreshTarget = null;
    return aggregated;
  }

  aggregated.scanFinalized = true;
  aggregated.state = aggregated.state === "pending-provider" ? "monitored" : (aggregated.state || "monitored");
  aggregated.pendingProviders = [];
  aggregated.providerCompletion = {
    ...(aggregated.providerCompletion || {}),
    hasPendingProvider: false,
    allRequiredProvidersTerminal: true,
    pendingProviders: []
  };

  return aggregated;
}

function reAggregateStoredMultiLinkAnalysis(storedAnalysis = {}, updatedChild = {}) {
  const snapshots = Array.isArray(storedAnalysis.linkAnalysisSnapshots)
    ? storedAnalysis.linkAnalysisSnapshots.slice()
    : [];

  if (snapshots.length === 0) {
    return {
      ...storedAnalysis,
      ...updatedChild
    };
  }

  const childIndex = Number.isInteger(updatedChild.index) ? updatedChild.index : null;
  const updatedSnapshots = snapshots.map((snapshot) => {
    if (childIndex !== null && snapshot.index === childIndex) {
      return {
        ...snapshot,
        ...updatedChild
      };
    }

    return snapshot;
  });

  return aggregatePostAnalysisFromLinkSnapshots(storedAnalysis, updatedSnapshots);
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

  if (hasLegacyPendingChildWithoutRefreshMetadata(storedAnalysis)) {
    const legacyAnalysis = normalizeTerminalIncompleteAnalysis(
      storedAnalysis,
      "Pending child-link refresh metadata was unavailable for this older analysis record; restart the scan to try again."
    );
    const persistedLegacyAnalysis = await persistPostLevelAnalysis(postId, legacyAnalysis);
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      analysis: persistedLegacyAnalysis,
      refreshed: false,
      reason: "missing-pending-child-refresh-metadata"
    };
  }

  const refreshTarget = selectPendingProviderRefreshTarget(storedAnalysis, message)
    || (!Array.isArray(storedAnalysis.linkAnalysisSnapshots) || storedAnalysis.linkAnalysisSnapshots.length === 0 ? storedAnalysis : null);
  if (!refreshTarget) {
    const finalizedMissingTarget = normalizeTerminalIncompleteAnalysis(
      storedAnalysis,
      "Pending provider refresh target was unavailable. Restart the scan to try again."
    );
    const persistedMissingTarget = await persistPostLevelAnalysis(postId, finalizedMissingTarget);
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      analysis: persistedMissingTarget,
      refreshed: false,
      reason: "missing-pending-provider-target"
    };
  }
  const providerResults = normalizeProviderResults(refreshTarget.providerResults || []);
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
    message.providerCheckedUrl ||
    refreshTarget.providerCheckedUrl ||
    refreshTarget.analysisUrl ||
    refreshTarget.url ||
    storedAnalysis.providerCheckedUrl ||
    storedAnalysis.analysisUrl ||
    storedAnalysis.normalizedUrl ||
    message.analysisUrl ||
    message.normalizedUrl ||
    existingVt?.checkedUrl ||
    "";

  if (!providerCheckedUrl) {
    const missingCheckedUrlAnalysis = normalizeTerminalIncompleteAnalysis(
      storedAnalysis,
      "Pending provider checked URL was unavailable. Restart the scan to try again."
    );
    const persistedMissingCheckedUrl = await persistPostLevelAnalysis(postId, missingCheckedUrlAnalysis);
    return {
      type: MESSAGE_TYPES.REFRESH_VIRUSTOTAL_RESULT,
      analysis: persistedMissingCheckedUrl,
      refreshed: false,
      reason: "missing-provider-checked-url"
    };
  }

  const refreshedVt = await getCachedOrInFlightProviderResult(
    "virustotal",
    providerCheckedUrl,
    () => lookupVirusTotalUrl(providerCheckedUrl)
  );
  const refreshedStatus = String(refreshedVt?.details?.status || "").toLowerCase();
  const terminalVt = ["rate-limited"].includes(refreshedStatus)
    ? buildTerminalVirusTotalResult(refreshedVt, {
        providerCheckedUrl,
        status: refreshedStatus,
        reason: refreshedStatus === "rate-limited" ? "rate_limited" : refreshedStatus,
        message: refreshedVt?.details?.message || "VirusTotal could not complete this URL scan."
      })
    : refreshedVt;
  const updatedProviderResults = providerResults.map((provider) => (
    provider.provider === "virustotal" ? terminalVt : provider
  ));
  const retryPlan = buildProviderRetryPlanFromMessage(
    message,
    terminalVt.details?.status === "pending" ? "waiting-response" : "completed",
    terminalVt.details?.status || ""
  );
  const refreshedTargetAnalysis = mergeProviderRetryPlan(
    buildVirusTotalRefreshedAnalysis(refreshTarget, updatedProviderResults),
    retryPlan
  );
  const refreshedChild = {
    ...refreshTarget,
    ...refreshedTargetAnalysis,
    index: refreshTarget.index
  };
  const updatedAnalysis = Array.isArray(storedAnalysis.linkAnalysisSnapshots) && storedAnalysis.linkAnalysisSnapshots.length > 0 && refreshTarget !== storedAnalysis
    ? reAggregateStoredMultiLinkAnalysis(storedAnalysis, refreshedChild)
    : mergeProviderRetryPlan(buildVirusTotalRefreshedAnalysis(storedAnalysis, updatedProviderResults), retryPlan);
  replaceVirusTotalInUrlAnalysisCache({
    analysis: refreshTarget !== storedAnalysis ? refreshedTargetAnalysis : updatedAnalysis,
    providerResult: terminalVt,
    checkedUrl: providerCheckedUrl
  });

  const persistedAnalysis = await persistPostLevelAnalysis(postId, updatedAnalysis);

  if (terminalVt.flagged) {
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
    reason: terminalVt.flagged ? "virustotal-flagged" : String(terminalVt.details?.status || "virustotal-refreshed"),
    providerRefreshStatus: String(terminalVt.details?.status || ""),
    providerRefreshCheckedAt: terminalVt.checkedAt || "",
    providerRefreshReason: terminalVt.details?.reason || "",
    providerRetryPlan: retryPlan
  };
}

async function finalizePendingProviderStateForPost(message = {}) {
  const postId = String(message.postId || "").trim();
  if (!postId) {
    return {
      type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
      finalized: false,
      reason: "missing-post-id"
    };
  }

  const storedAnalysis = await getBaseline(postId);
  if (!storedAnalysis) {
    return {
      type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
      finalized: false,
      reason: "missing-stored-analysis"
    };
  }

  if (hasLegacyPendingChildWithoutRefreshMetadata(storedAnalysis)) {
    const legacyAnalysis = normalizeTerminalIncompleteAnalysis(
      storedAnalysis,
      "Pending child-link refresh metadata was unavailable for this older analysis record; restart the scan to try again."
    );
    const persistedLegacyAnalysis = await persistPostLevelAnalysis(postId, legacyAnalysis);
    return {
      type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
      analysis: persistedLegacyAnalysis,
      finalized: true,
      reason: "missing-pending-child-refresh-metadata"
    };
  }

  const childTarget = selectPendingProviderRefreshTarget(storedAnalysis, message)
    || (!Array.isArray(storedAnalysis.linkAnalysisSnapshots) || storedAnalysis.linkAnalysisSnapshots.length === 0 ? storedAnalysis : null);
  if (!childTarget) {
    const finalizedMissingTarget = normalizeTerminalIncompleteAnalysis(
      storedAnalysis,
      "Pending provider refresh target was unavailable. Restart the scan to try again."
    );
    const persisted = await persistPostLevelAnalysis(postId, finalizedMissingTarget);
    return {
      type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
      analysis: persisted,
      finalized: true,
      reason: "missing-pending-provider-target"
    };
  }

  const finalizeSource = childTarget || storedAnalysis;
  const providerResults = normalizeProviderResults(finalizeSource.providerResults || []);
  const existingVt = providerResults.find((item) => item.provider === "virustotal");
  const vtStatus = String(existingVt?.details?.status || "").toLowerCase();

  if (vtStatus !== "pending") {
    const retryPlan = buildProviderRetryPlanFromMessage(message, "completed", vtStatus || "already-terminal");
    const alreadyFinalChildAnalysis = mergeProviderRetryPlan(
      buildVirusTotalRefreshedAnalysis(finalizeSource, providerResults),
      retryPlan
    );
    const alreadyFinalAnalysis = childTarget
      ? aggregatePostAnalysisFromLinkSnapshots(
          storedAnalysis,
          replaceStoredLinkAnalysisSnapshot(
            storedAnalysis.linkAnalysisSnapshots,
          buildStoredLinkAnalysisSnapshot(alreadyFinalChildAnalysis, Number(childTarget.index || 1))
          )
        )
      : mergeProviderRetryPlan(buildVirusTotalRefreshedAnalysis(storedAnalysis, providerResults), retryPlan);
    const persistedAlreadyFinalAnalysis = await persistPostLevelAnalysis(postId, alreadyFinalAnalysis);
    return {
      type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
      analysis: persistedAlreadyFinalAnalysis,
      finalized: true,
      reason: `virustotal-status-${vtStatus || "unavailable"}`,
      providerRefreshStatus: vtStatus,
      providerRefreshReason: existingVt?.details?.reason || "",
      providerRetryPlan: retryPlan
    };
  }

  const providerCheckedUrl =
    existingVt?.checkedUrl ||
    finalizeSource.providerCheckedUrl ||
    message.providerCheckedUrl ||
    storedAnalysis.providerCheckedUrl ||
    finalizeSource.analysisUrl ||
    finalizeSource.normalizedUrl ||
    message.analysisUrl ||
    message.normalizedUrl ||
    "";
  const timedOutVt = buildTerminalVirusTotalResult(existingVt, {
    providerCheckedUrl,
    status: "retry-budget-exhausted",
    reason: "retry_budget_exhausted",
    message: "VirusTotal did not return a completed result within the retry window."
  });
  const updatedProviderResults = providerResults.map((provider) => (
    provider.provider === "virustotal" ? timedOutVt : provider
  ));
  const retryPlan = buildProviderRetryPlanFromMessage(message, "exhausted", "retry_budget_exhausted");
  const updatedChildAnalysis = mergeProviderRetryPlan(
    buildVirusTotalRefreshedAnalysis(finalizeSource, updatedProviderResults),
    retryPlan
  );
  const updatedAnalysis = childTarget && Array.isArray(storedAnalysis.linkAnalysisSnapshots) && storedAnalysis.linkAnalysisSnapshots.length > 0
    ? reAggregateStoredMultiLinkAnalysis(storedAnalysis, {
        ...childTarget,
        ...updatedChildAnalysis,
        index: childTarget.index
      })
    : mergeProviderRetryPlan(buildVirusTotalRefreshedAnalysis(storedAnalysis, updatedProviderResults), retryPlan);

  replaceVirusTotalInUrlAnalysisCache({
    analysis: childTarget ? updatedChildAnalysis : updatedAnalysis,
    providerResult: timedOutVt,
    checkedUrl: providerCheckedUrl
  });

  const persistedAnalysis = await persistPostLevelAnalysis(postId, updatedAnalysis);
  sessionInfo.lastActivityAt = Date.now();

  return {
    type: MESSAGE_TYPES.FINALIZE_PENDING_PROVIDER_STATE,
    analysis: persistedAnalysis,
    finalized: true,
    reason: "virustotal-timeout-retry-budget-exhausted",
    providerRefreshStatus: "retry-budget-exhausted",
    providerRefreshReason: "retry_budget_exhausted",
    providerRetryPlan: retryPlan
  };
}

function buildVirusTotalRefreshedAnalysis(analysis = {}, providerResults = []) {
  const safeProviderResults = normalizeProviderResults(providerResults);
  const gsbResult = getNormalizedProviderResult(safeProviderResults, "gsb");
  const urlhausResult = getNormalizedProviderResult(safeProviderResults, "urlhaus");
  const virusTotalResult = getNormalizedProviderResult(safeProviderResults, "virustotal");
  const providerPolicy = buildProviderOverridePolicy(safeProviderResults);
  const providerOverride = providerPolicy.providerOverride;
  const retryBudgetExhausted = String(virusTotalResult.details?.reason || "").toLowerCase() === "retry_budget_exhausted";
  const rawProviderCompletion = buildProviderCompletionState(safeProviderResults);
  const scanFinalized = providerOverride === true
    ? true
    : rawProviderCompletion.allRequiredProvidersTerminal && !rawProviderCompletion.hasPendingProvider;
  const providerCompletion = providerOverride === true
    ? {
        ...rawProviderCompletion,
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        blockingPendingProviders: [],
        informationalPendingProviders: rawProviderCompletion.pendingProviders || []
      }
    : rawProviderCompletion;
  let refreshedFeatures = {
    ...(analysis.features || {}),
    googleSafeBrowsingFlagged: gsbResult.flagged === true,
    urlhausFlagged: urlhausResult.flagged === true,
    virusTotalFlagged: virusTotalResult.flagged === true
  };
  const reusableAnalysisContext = {
    analysisUrl: analysis.analysisUrl || analysis.endpointResult?.effectiveEndpoint || "",
    domain: analysis.domain || analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
    redirectAnalysis: analysis.redirectAnalysis || analysis.endpointResult?.redirectAnalysis || {},
    urlFeatureAnalysis: analysis.urlFeatureAnalysis || {}
  };
  refreshedFeatures = applyTrustedRedirectDestinationMitigation({
    ...refreshedFeatures,
    trustedEndpointMitigationEligible: isTrustedEndpointMitigationEligible(refreshedFeatures)
  }, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applyMainstreamResolvedShortlinkMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applyFacebookWrapperOnlyRedirectMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applySameDomainMarketingEncodingMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applyKnownBrandedCampaignRedirectMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applyKnownGoogleFormsRedirectMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {});
  refreshedFeatures = applyKnownBrandAliasRedirectMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {}, safeProviderResults);
  refreshedFeatures = applyCleanResolvedMarketingLinkMitigation(refreshedFeatures, reusableAnalysisContext, analysis.endpointResult || {}, safeProviderResults);
  const recomputed = recomputeStoredFinalScoreFromFeatures(
    analysis,
    refreshedFeatures,
    providerOverride,
    safeProviderResults
  );
  const previousComputedScore = recomputed?.finalScore ?? getBestStoredComputedScore(analysis);
  let safetyScore = previousComputedScore;
  let recoveredSafetyScore = safetyScore !== null
    ? safetyScore
    : toFiniteScoreOrNull(analysis.scoreAudit?.ruleScore);
  let classification = recomputed?.finalClassification || getBestStoredComputedClassification(analysis, recoveredSafetyScore);
  const virusTotalWarningState = providerPolicy.virusTotalWarningState || getVirusTotalWarningState(safeProviderResults);
  const virusTotalWarningPolicy = applyVirusTotalWarningScorePolicy(safetyScore, classification, virusTotalWarningState);
  if (safetyScore !== null) {
    safetyScore = virusTotalWarningPolicy.finalScore;
    recoveredSafetyScore = safetyScore;
    classification = virusTotalWarningPolicy.finalClassification;
  }
  let displayedScore = recoveredSafetyScore;
  let displayedClassification = classification;
  let displayedState = providerOverride === true
    ? "completed"
    : !scanFinalized ? "pending-provider" : (analysis.state === "pending-provider" ? "monitored" : analysis.state);
  const terminalProviderLimitation = !providerOverride && scanFinalized && hasTerminalProviderLimitation(safeProviderResults);

  if ((retryBudgetExhausted || terminalProviderLimitation) && !providerOverride) {
    displayedScore = null;
    displayedClassification = "Verification Incomplete";
    displayedState = "verification-incomplete";
  }

  if (!scanFinalized && !providerOverride) {
    displayedScore = null;
    displayedClassification = "Scan Pending";
    displayedState = "pending-provider";
  }

  if (!retryBudgetExhausted && scanFinalized && !providerOverride && isPendingClassificationLabel(displayedClassification)) {
    displayedClassification = getBestStoredComputedClassification(analysis, recoveredSafetyScore);
  }

  if (!retryBudgetExhausted && scanFinalized && !providerOverride && displayedScore === null) {
    displayedScore = recoveredSafetyScore;
  }

  const features = recomputed?.features || refreshedFeatures;
  let scoreAudit = recomputed?.scoreAudit || refreshScoreAuditForProviderResult(analysis, {
    providerOverride,
    safetyScore: recoveredSafetyScore,
    classification
  });
  scoreAudit = applyVirusTotalWarningAuditFields(scoreAudit, virusTotalWarningState, virusTotalWarningPolicy);
  const virusTotalReviewRecommendation = buildVirusTotalProviderWarningReviewRecommendation({
    finalScore: recoveredSafetyScore,
    finalClassification: classification,
    scoreAudit,
    providerOverride,
    providerOverrideSource: providerPolicy.providerOverrideSource,
    virusTotalWarningState,
    providerResults: safeProviderResults
  });
  scoreAudit = applyVirusTotalWarningAuditFields(scoreAudit, virusTotalWarningState, virusTotalWarningPolicy, virusTotalReviewRecommendation);
  scoreAudit.scanFinalized = scanFinalized;
  scoreAudit.displayedScoreWithheld = (!scanFinalized && !providerOverride) || ((retryBudgetExhausted || terminalProviderLimitation) && !providerOverride);
  scoreAudit.computedSafetyScore = recoveredSafetyScore;
  scoreAudit.computedClassification = classification;
  scoreAudit.retryBudgetExhausted = retryBudgetExhausted;
  scoreAudit.verificationIncomplete = terminalProviderLimitation || retryBudgetExhausted;
  if (retryBudgetExhausted || terminalProviderLimitation) {
    scoreAudit.terminalIncompleteReason = retryBudgetExhausted
      ? "VirusTotal did not return a completed result within the retry window."
      : "One or more provider checks ended in a terminal limited state.";
  }
  scoreAudit.pendingProviders = providerCompletion.pendingProviders;
  scoreAudit.providerOverrideSource = providerPolicy.providerOverrideSource;
  scoreAudit.providerOverrideReason = providerPolicy.providerOverrideReason;
  scoreAudit.virusTotalSignalLevel = providerPolicy.virusTotalSignalLevel;
  const refreshedAnalysis = {
    ...analysis,
    performanceTiming: mergePerformanceTiming(analysis.performanceTiming, {
      analysisCompletedAt: Date.now()
    }),
    providerResults: safeProviderResults,
    features,
    providerOverride,
    classification: displayedClassification,
    safetyScore: displayedScore,
    computedSafetyScore: recoveredSafetyScore,
    computedClassification: classification,
    scanFinalized,
    providerCompletion,
    pendingProviders: providerCompletion.pendingProviders,
    providerPending: displayedState === "pending-provider",
    state: displayedState,
    providerWarningReviewRecommended: virusTotalReviewRecommendation.providerWarningReviewRecommended,
    reviewRecommendedReason: virusTotalReviewRecommendation.reviewRecommendedReason,
    scoreAudit,
    providerDeductions: recomputed?.scoring?.providerDeductions || scoreAudit.providerDeductions || analysis.providerDeductions,
    heuristicRawCategoryTotals: recomputed?.scoring?.heuristicRawCategoryTotals || scoreAudit.heuristicRawCategoryTotals || analysis.heuristicRawCategoryTotals,
    heuristicCategoryDeductions: recomputed?.scoring?.heuristicCategoryDeductions || scoreAudit.heuristicCategoryDeductions || analysis.heuristicCategoryDeductions,
    heuristicRawTotal: recomputed?.scoring?.heuristicRawTotal ?? scoreAudit.heuristicRawTotal ?? analysis.heuristicRawTotal,
    heuristicScaledDeduction: recomputed?.scoring?.heuristicScaledDeduction ?? scoreAudit.heuristicScaledDeduction ?? analysis.heuristicScaledDeduction,
    totalDeduction: recomputed?.scoring?.totalDeduction ?? scoreAudit.ruleDeductionTotal ?? analysis.totalDeduction,
    concreteRiskSignals: Boolean(recomputed?.concreteRiskSignals || providerOverride),
    interceptionRecommended: providerOverride === true
      ? true
      : (scanFinalized && !terminalProviderLimitation
        ? shouldRecommendInterceptionForStoredAnalysis({
            ...analysis,
            providerResults: safeProviderResults,
            features,
            providerOverride,
            classification,
            safetyScore: recoveredSafetyScore,
            scoreAudit,
            providerWarningReviewRecommended: virusTotalReviewRecommendation.providerWarningReviewRecommended,
            reviewRecommendedReason: virusTotalReviewRecommendation.reviewRecommendedReason
          })
        : false),
    lastChecked: Date.now()
  };

  if (Array.isArray(analysis.linkScoreSummary) && analysis.linkScoreSummary.length > 0) {
    const refreshedSummary = buildRefreshedLinkScoreSummary(analysis.linkScoreSummary, {
      analysis,
      virusTotalResult,
      displayedScore,
      displayedClassification,
      recoveredSafetyScore,
      classification,
      scanFinalized,
      providerCompletion
    });
    const pendingSummaryItems = refreshedSummary.filter(isLinkScoreSummaryPending);
    refreshedAnalysis.linkScoreSummary = refreshedSummary;

    if (retryBudgetExhausted && !providerOverride) {
      refreshedAnalysis.linkScoreSummary = refreshedSummary.map((item) => {
        if (!isLinkScoreSummaryPending(item)) {
          return item;
        }

        return {
          ...item,
          safetyScore: null,
          computedSafetyScore: recoveredSafetyScore,
          classification: "Verification Incomplete",
          computedClassification: classification,
          scanFinalized: true,
          state: "verification-incomplete",
          providerPending: false,
          providerCompletion: {
            ...(providerCompletion || {}),
            hasPendingProvider: false,
            allRequiredProvidersTerminal: true,
            pendingProviders: []
          },
          pendingProviders: []
        };
      });
      refreshedAnalysis.classification = "Verification Incomplete";
      refreshedAnalysis.safetyScore = null;
      refreshedAnalysis.scanFinalized = true;
      refreshedAnalysis.state = "verification-incomplete";
      refreshedAnalysis.interceptionRecommended = false;
      refreshedAnalysis.pendingProviders = [];
      refreshedAnalysis.providerPending = false;
      refreshedAnalysis.providerCompletion = {
        ...(refreshedAnalysis.providerCompletion || {}),
        hasPendingProvider: false,
        allRequiredProvidersTerminal: true,
        pendingProviders: []
      };
    } else if (pendingSummaryItems.length > 0 && !providerOverride) {
      refreshedAnalysis.classification = "Scan Pending";
      refreshedAnalysis.safetyScore = null;
      refreshedAnalysis.scanFinalized = false;
      refreshedAnalysis.state = "pending-provider";
      refreshedAnalysis.interceptionRecommended = false;
      refreshedAnalysis.pendingProviders = [
        ...new Set(pendingSummaryItems.flatMap((item) => (
          Array.isArray(item.pendingProviders)
            ? item.pendingProviders
            : Array.isArray(item.providerCompletion?.pendingProviders)
              ? item.providerCompletion.pendingProviders
              : []
        )))
      ];
      refreshedAnalysis.providerCompletion = {
        ...(refreshedAnalysis.providerCompletion || {}),
        hasPendingProvider: true,
        allRequiredProvidersTerminal: false,
        pendingProviders: refreshedAnalysis.pendingProviders
      };
    } else if (!providerOverride) {
      const lowest = pickLowestFinalLinkScoreSummary(refreshedSummary);
      if (lowest) {
        refreshedAnalysis.safetyScore = lowest.safetyScore;
        refreshedAnalysis.classification = lowest.classification || classifySafetyScore(lowest.safetyScore);
        refreshedAnalysis.scanFinalized = true;
        refreshedAnalysis.state = refreshedAnalysis.state === "pending-provider" ? "monitored" : refreshedAnalysis.state;
      }
    }
  }

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

  if ((retryBudgetExhausted || terminalProviderLimitation) && !providerOverride) {
    return normalizeTerminalIncompleteAnalysis(
      refreshedAnalysis,
      retryBudgetExhausted
        ? "VirusTotal did not return a completed result within the retry window."
        : "One or more provider checks ended in a terminal limited state."
    );
  }

  return normalizeBackgroundTerminalState(refreshedAnalysis);
}

function buildRefreshedLinkScoreSummary(linkScoreSummary = [], {
  analysis = {},
  virusTotalResult = {},
  displayedScore = null,
  displayedClassification = "",
  recoveredSafetyScore = null,
  classification = "",
  scanFinalized = false,
  providerCompletion = {}
} = {}) {
  const pendingIndexes = linkScoreSummary
    .map((item, index) => isLinkScoreSummaryPending(item) ? index : -1)
    .filter((index) => index >= 0);
  const checkedUrl = normalizeCacheKey(virusTotalResult.checkedUrl);
  const analysisUrl = normalizeCacheKey(analysis.analysisUrl);
  const normalizedUrl = normalizeCacheKey(analysis.normalizedUrl);

  return linkScoreSummary.map((item, index) => {
    const itemUrl = normalizeCacheKey(item?.url);
    const shouldUpdate = Boolean(
      isLinkScoreSummaryPending(item) &&
      (
        pendingIndexes.length === 1 ||
        (itemUrl && (itemUrl === checkedUrl || itemUrl === analysisUrl || itemUrl === normalizedUrl))
      )
    );

    if (!shouldUpdate) {
      return item;
    }

    return {
      ...item,
      safetyScore: displayedScore,
      computedSafetyScore: recoveredSafetyScore,
      classification: displayedClassification,
      computedClassification: classification,
      scanFinalized,
      providerCompletion,
      pendingProviders: providerCompletion.pendingProviders || []
    };
  });
}

function isLinkScoreSummaryPending(item = {}) {
  return Boolean(
    isPendingClassificationLabel(item?.classification) ||
    item?.scanFinalized === false ||
    item?.providerCompletion?.hasPendingProvider === true ||
    (Array.isArray(item?.pendingProviders) && item.pendingProviders.length > 0)
  );
}

function pickLowestFinalLinkScoreSummary(linkScoreSummary = []) {
  return (Array.isArray(linkScoreSummary) ? linkScoreSummary : [])
    .filter((item) => !isLinkScoreSummaryPending(item))
    .map((item) => ({
      ...item,
      safetyScore: toFiniteScoreOrNull(item.safetyScore) ?? toFiniteScoreOrNull(item.computedSafetyScore)
    }))
    .filter((item) => item.safetyScore !== null)
    .sort((left, right) => left.safetyScore - right.safetyScore)[0] || null;
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
        safetyScore: (() => {
          const state = String(record.state || "").toLowerCase();
          const scanFinalized = record.scanFinalized === true || (record.scanFinalized !== false && state && state !== "pending-provider");

          if (!scanFinalized || state === "pending-provider" || state === "verification-incomplete" || state === "completed-limited") {
            return null;
          }

          const score = Number.isFinite(record.safetyScore) ? record.safetyScore : record.score;
          return Number.isFinite(score) ? score : null;
        })(),
        scanFinalized: record.scanFinalized === true || (record.scanFinalized !== false && String(record.state || "").toLowerCase() && String(record.state || "").toLowerCase() !== "pending-provider"),
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
    try {
      await injectContentScript(activeTab.id);
      await chrome.tabs.sendMessage(activeTab.id, {
        type: MESSAGE_TYPES.RESCAN_NOW
      });

      return {
        success: true,
        message: "Content script was reconnected; scan command sent to the active Facebook tab."
      };
    } catch (retryError) {
      logDebug(`Rescan reconnect failed: ${safeErrorMessage(retryError, safeErrorMessage(error, "unknown error"))}`);
      return {
        success: false,
        message: "Unable to reconnect the content script on the active Facebook tab. Reload the page and try again."
      };
    }
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
  const now = Date.now();

  sessionInfo = {
    ...createSessionState(now),
    lastResetAt: now,
    lastResetReason: reason || "manual"
  };

  clearProviderCaches({ clearUrlAnalysis: true, clearPendingVirusTotal: true });

  if (shouldClearRecords) {
    await clearAnalysisRecords();
    await clearDomainFlagRecords();
  }

  return sessionInfo;
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
  const reason = String(result.details?.reason || "").toLowerCase();

  if (status === "skipped" && reason === "unsupported_protocol") {
    return "Provider skipped because the destination uses a non-web protocol.";
  }

  if (provider === "virustotal") {
    const vtWarning = getVirusTotalWarningState(result);
    if (!result.configured || status === "not-configured") {
      return "VirusTotal check did not complete.";
    }
    if (status === "pending") {
      return "VirusTotal check did not complete.";
    }
    if (status === "rate-limited") {
      return "VirusTotal check did not complete.";
    }
    if (status === "timeout") {
      return "VirusTotal check did not complete.";
    }
    if (status === "error" || status === "parse-error") {
      return "VirusTotal check did not complete.";
    }
    if (vtWarning.maliciousCount > 0) {
      return `VirusTotal reported ${vtWarning.maliciousCount} malicious detection${vtWarning.maliciousCount === 1 ? "" : "s"}.`;
    }
    if (vtWarning.suspiciousCount > 0) {
      return `VirusTotal reported ${vtWarning.suspiciousCount} suspicious detection${vtWarning.suspiciousCount === 1 ? "" : "s"}.`;
    }
    if (status !== "checked" && status !== "completed") {
      return "VirusTotal check did not complete.";
    }
    return result.flagged
      ? "VirusTotal reported malicious/suspicious detections."
      : "VirusTotal reported no malicious or suspicious detections.";
  }

  if (provider === "gsb" && (!result.configured || status === "not-configured")) {
    return "Google Safe Browsing check did not complete.";
  }

  if (provider === "urlhaus" && status === "not-configured") {
    return "URLhaus check did not complete.";
  }

  if (status === "timeout") {
    return provider === "gsb"
      ? "Google Safe Browsing check did not complete."
      : provider === "urlhaus"
        ? "URLhaus check did not complete."
        : "Provider check did not complete.";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return provider === "gsb"
      ? "Google Safe Browsing check did not complete."
      : provider === "urlhaus"
        ? "URLhaus check did not complete."
        : "Provider check did not complete.";
  }

  if (!result.checked || status === "skipped" || status === "not-configured") {
    return provider === "gsb"
      ? "Google Safe Browsing check did not complete."
      : provider === "urlhaus"
        ? "URLhaus check did not complete."
        : "Provider check did not complete.";
  }

  if (provider === "gsb") {
    return result.flagged ? "Unsafe URL reported." : "Google Safe Browsing did not flag the checked URL candidate(s).";
  }

  if (provider === "urlhaus") {
    return result.flagged ? "Known malware record found." : "URLhaus found no known malware record for the checked URL candidate(s).";
  }

  return result.flagged ? "Provider reported a match." : "No provider match reported.";
}

function getProviderAuditStatus(result = {}) {
  const provider = String(result.provider || "").toLowerCase();
  const status = String(result.details?.status || "").toLowerCase();

  if (status === "timeout") {
    return "timeout";
  }

  if (status === "pending") {
    return "pending";
  }

  if (status === "rate-limited") {
    return "rate-limited";
  }

  if (status === "error" || status === "parse-error") {
    return "failed";
  }

  if (
    (provider !== "urlhaus" && !result.configured) ||
    status === "not-configured" ||
    status === "skipped" ||
    !result.checked
  ) {
    return "skipped";
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

function createSkippedUnsupportedProtocolProviderResult(provider, checkedUrl = "") {
  return withProviderOutcomeSummary({
    provider,
    configured: true,
    checked: false,
    checkedUrl,
    checkedAt: new Date().toISOString(),
    durationMs: 0,
    flagged: false,
    category: null,
    details: {
      status: "skipped",
      reason: "unsupported_protocol",
      message: "Provider lookup skipped because the URL uses a non-web protocol."
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

function isProviderScannableUrl(url) {
  try {
    const parsed = new URL(String(url || "").trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:";
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
