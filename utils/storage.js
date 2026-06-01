const POST_PREFIX = "dili:post:";
const DOMAIN_PREFIX = "dili:domain:";
const ANALYSIS_LOG_KEY = "dili:analysis:records";
const ANALYSIS_LOG_LIMIT = 50;
const ANALYSIS_LOG_TTL_MS = 60 * 60 * 1000;
const SCAN_STATE_KEY = "dili:scan:enabled";
const DEDUPE_WINDOW_MS = 10 * 60 * 1000;
const STORED_TEXT_LIMIT = 260;
const PROTECTED_KEYS = new Set([
  "dili:config:gsbApiKey",
  "dili:config:urlhausAuthKey",
  "dili:config:urlhausApiKey",
  "dili:config:virustotalApiKey",
  "dili:scan:enabled"
]);

/**
 * Get the stored baseline or analysis record for a Facebook post.
 * @param {string} postId
 * @returns {Promise<object | null>}
 */
export async function getBaseline(postId) {
  const result = await storageGet(postStorageKey(postId));
  return result[postStorageKey(postId)] || null;
}

/**
 * Persist a baseline record for a Facebook post.
 * @param {string} postId
 * @param {object} data
 * @returns {Promise<object>}
 */
export async function setBaseline(postId, data) {
  const record = {
    postId,
    ...data
  };

  await storageSet({
    [postStorageKey(postId)]: compactPersistentRecord(record)
  });

  return record;
}

/**
 * Merge new analysis values into an existing post record.
 * @param {string} postId
 * @param {object} data
 * @returns {Promise<object>}
 */
export async function updatePostAnalysis(postId, data) {
  const existing = await getBaseline(postId);
  const record = {
    ...(existing || {}),
    postId,
    ...data
  };

  await storageSet({
    [postStorageKey(postId)]: compactPersistentRecord(record)
  });

  return record;
}

/**
 * Remove the stored baseline or analysis record for one Facebook post.
 * @param {string} postId
 * @returns {Promise<boolean>}
 */
export async function removePostAnalysis(postId) {
  if (!postId) {
    return false;
  }

  await storageRemove(postStorageKey(postId));
  return true;
}

/**
 * Mark a domain as flagged by local history.
 * @param {string} domain
 * @returns {Promise<void>}
 */
export async function markDomainFlagged(domain) {
  if (!domain) {
    return;
  }

  await storageSet({
    [domainStorageKey(domain)]: {
      domain: String(domain).toLowerCase(),
      flaggedAt: Date.now()
    }
  });
}

/**
 * Check whether a domain has been flagged during earlier local analyses.
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
export async function checkDomainPreviouslyFlagged(domain) {
  if (!domain) {
    return false;
  }

  const result = await storageGet(domainStorageKey(domain));
  return Boolean(result[domainStorageKey(domain)]);
}

/**
 * Append a single analysis event record for demo-friendly history tracking.
 * @param {object} record
 * @returns {Promise<object>}
 */
export async function appendAnalysisRecord(record) {
  const compactRecord = compactPersistentRecord(record);
  const logs = await readPrunedAnalysisRecords();
  const duplicate = logs
    .slice()
    .reverse()
    .find((item) => isDuplicateAnalysisRecord(item, compactRecord));

  if (duplicate) {
    duplicate.lastChecked = compactRecord.lastChecked || compactRecord.timestamp || Date.now();
    duplicate.timestamp = duplicate.timestamp || compactRecord.timestamp || Date.now();
    duplicate.seenCount = Number(duplicate.seenCount || 1) + 1;
  } else {
    logs.push({
      seenCount: 1,
      firstSeenAt: compactRecord.timestamp || Date.now(),
      lastChecked: compactRecord.lastChecked || compactRecord.timestamp || Date.now(),
      ...compactRecord
    });
  }

  const trimmedLogs = logs.slice(-ANALYSIS_LOG_LIMIT);
  await storageSet({
    [ANALYSIS_LOG_KEY]: trimmedLogs
  });

  return compactRecord;
}

/**
 * Return every stored analysis event in insertion order.
 * @returns {Promise<object[]>}
 */
export async function getAllAnalysisRecords() {
  return readPrunedAnalysisRecords();
}

/**
 * Clear all historical analysis events.
 * @returns {Promise<void>}
 */
export async function clearAnalysisRecords() {
  await storageSet({
    [ANALYSIS_LOG_KEY]: []
  });
}
/**
 * Clear locally flagged domain records.
 * This is useful for testing because locally flagged domains can otherwise
 * affect future scoring even after the analysis log is cleared.
 * @returns {Promise<number>}
 */
export async function clearDomainFlagRecords() {
  const allValues = await storageGet(null);
  const domainKeys = Object.keys(allValues).filter((key) => key.startsWith(DOMAIN_PREFIX));

  if (domainKeys.length === 0) {
    return 0;
  }

  await storageRemove(domainKeys);
  return domainKeys.length;
}
/**
 * Read the global scan-enabled state. Defaults to true when unset.
 * @returns {Promise<boolean>}
 */
export async function getScanEnabledState() {
  const result = await storageGet(SCAN_STATE_KEY);
  return result[SCAN_STATE_KEY] !== false;
}

/**
 * Persist the global scan-enabled state.
 * @param {boolean} enabled
 * @returns {Promise<boolean>}
 */
export async function setScanEnabledState(enabled) {
  const normalized = Boolean(enabled);

  await storageSet({
    [SCAN_STATE_KEY]: normalized
  });

  return normalized;
}

async function readPrunedAnalysisRecords() {
  const result = await storageGet(ANALYSIS_LOG_KEY);
  const logs = Array.isArray(result[ANALYSIS_LOG_KEY]) ? result[ANALYSIS_LOG_KEY] : [];
  const oldestAllowedTimestamp = Date.now() - ANALYSIS_LOG_TTL_MS;
  const prunedLogs = logs.filter((record) => Number(record?.timestamp || 0) >= oldestAllowedTimestamp);

  if (prunedLogs.length !== logs.length) {
    await storageSet({
      [ANALYSIS_LOG_KEY]: prunedLogs
    });
  }

  return prunedLogs;
}

function postStorageKey(postId) {
  return `${POST_PREFIX}${postId}`;
}

function domainStorageKey(domain) {
  return `${DOMAIN_PREFIX}${String(domain).toLowerCase()}`;
}

function storageGet(key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(key, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve(result);
    });
  });
}

function storageSet(value) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(value, () => {
      if (chrome.runtime.lastError) {
        const message = chrome.runtime.lastError.message || "";
        if (isQuotaError(message)) {
          pruneStorageForQuota()
            .then(() => {
              chrome.storage.local.set(value, () => {
                if (chrome.runtime.lastError) {
                  console.warn(`[DILI] Storage write skipped after quota pruning: ${chrome.runtime.lastError.message || "unknown error"}`);
                }
                resolve();
              });
            })
            .catch(() => {
              console.warn(`[DILI] Storage write skipped because quota pruning failed: ${message}`);
              resolve();
            });
          return;
        }

        reject(new Error(message));
        return;
      }

      resolve();
    });
  });
}

function compactPersistentRecord(record = {}) {
  const finalSite = clampText(record.finalSite || record.domain || safeHostname(record.analysisUrl || record.url) || "");
  const originalDomain = clampText(record.originalDomain || safeHostname(record.originalUrl || record.normalizedUrl || record.rawUrl) || "");
  const endpointResult = record.endpointResult || {};
  const features = record.features || {};
  const limitations = [
    ...(record.limitations || []),
    ...(endpointResult.warnings || [])
  ];
  const providerResults = Array.isArray(record.providerResults) ? record.providerResults : [];

  return {
    postId: clampText(record.postId || ""),
    analysisSchemaVersion: Number(record.analysisSchemaVersion || 0),
    timestamp: Number(record.timestamp || Date.now()),
    urlHash: clampText(record.urlHash || ""),
    normalizedUrl: clampText(record.normalizedUrl || record.originalUrl || ""),
    analysisUrl: clampText(record.analysisUrl || record.url || ""),
    finalSite,
    domain: finalSite,
    originalDomain,
    linkType: clampText(record.linkType || features.linkType || (features.shortenedUrl ? "shortened" : "external")),
    score: normalizeScore(record.score ?? record.safetyScore),
    safetyScore: normalizeScore(record.safetyScore ?? record.score),
    computedSafetyScore: normalizeScore(record.computedSafetyScore),
    computedClassification: clampText(record.computedClassification || "", 60),
    classification: clampText(record.classification || ""),
    scanFinalized: record.scanFinalized === true,
    providerPending: record.providerPending === true,
    providerCompletion: compactProviderCompletion(record.providerCompletion),
    pendingProviders: clampList(record.pendingProviders || [], 8),
    providerRetryPlan: compactProviderRetryPlan(record.providerRetryPlan),
    analyzedLinkCount: Number(record.analyzedLinkCount || 0),
    failedLinkCount: Number(record.failedLinkCount || 0),
    multiLinkPost: record.multiLinkPost === true || Number(record.analyzedLinkCount || 0) > 1,
    lowestScoringLinkDomain: clampText(record.lowestScoringLinkDomain || ""),
    lowestScoringLinkUrl: clampText(record.lowestScoringLinkUrl || ""),
    linkScoreSummary: compactLinkScoreSummary(record.linkScoreSummary),
    linkAnalysisSnapshots: compactLinkAnalysisSnapshots(record.linkAnalysisSnapshots),
    pendingLinkRefreshTargets: compactLinkAnalysisSnapshots(record.pendingLinkRefreshTargets),
    pendingProviderRefreshTarget: compactLinkAnalysisSnapshot(record.pendingProviderRefreshTarget),
    endpointConfidence: clampText(record.endpointConfidence || endpointResult.endpointConfidence || ""),
    baselineState: clampText(record.baselineState || ""),
    hadLinkAtBaseline: record.hadLinkAtBaseline === true,
    postTextHash: clampText(record.postTextHash || ""),
    previousPostTextHash: clampText(record.previousPostTextHash || ""),
    currentPostTextHash: clampText(record.currentPostTextHash || ""),
    normalizedVisiblePostText: clampText(record.normalizedVisiblePostText || ""),
    baselineFirstSeenAt: Number(record.baselineFirstSeenAt || record.firstSeenAt || 0),
    baselineLastSeenAt: Number(record.baselineLastSeenAt || record.lastSeenAt || 0),
    mainRiskReasons: clampList(record.mainRiskReasons || extractMainReasons(record.deductions), 8),
    limitations: clampList(limitations, 8),
    domainChain: clampList(record.domainChain || chainToDomains(record.redirectAnalysis?.redirectChain || endpointResult.resolutionChain), 8),
    features: compactFeatureFlags(features),
    providerResults: compactProviderResults(providerResults),
    providerOverride: Boolean(record.providerOverride),
    providerWarningReviewRecommended: record.providerWarningReviewRecommended === true,
    reviewRecommendedReason: clampText(record.reviewRecommendedReason || "", 180),
    providerDeductions: compactNumericMap(record.providerDeductions || record.scoreAudit?.providerDeductions),
    heuristicRawCategoryTotals: compactNumericMap(record.heuristicRawCategoryTotals || record.scoreAudit?.heuristicRawCategoryTotals),
    heuristicCategoryDeductions: compactNumericMap(record.heuristicCategoryDeductions || record.scoreAudit?.heuristicCategoryDeductions),
    heuristicRawTotal: normalizeScore(record.heuristicRawTotal ?? record.scoreAudit?.heuristicRawTotal),
    heuristicScaledDeduction: normalizeScore(record.heuristicScaledDeduction ?? record.scoreAudit?.heuristicScaledDeduction),
    totalDeduction: normalizeScore(record.totalDeduction ?? record.scoreAudit?.ruleDeductionTotal),
    scoreAudit: compactScoreAudit(record.scoreAudit),
    candidateSource: clampText(record.candidateSource || record.candidateContext?.candidateSource || ""),
    candidateUrlCompleteness: clampText(record.candidateUrlCompleteness || record.candidateContext?.candidateUrlCompleteness || ""),
    candidateIsDomainOnlyFallback: record.candidateIsDomainOnlyFallback === true || record.candidateContext?.candidateIsDomainOnlyFallback === true,
    candidateContext: {
      displayText: clampText(record.candidateContext?.displayText || ""),
      visibleText: clampText(record.candidateContext?.visibleText || ""),
      rawHref: clampText(record.candidateContext?.rawHref || "", 500),
      facebookWrapperUrl: clampText(record.candidateContext?.facebookWrapperUrl || "", 500),
      unwrappedCandidateUrl: clampText(record.candidateContext?.unwrappedCandidateUrl || "", 500),
      selectedNormalizedTarget: clampText(record.candidateContext?.selectedNormalizedTarget || record.selectedNormalizedTarget || "", 500),
      candidateSource: clampText(record.candidateContext?.candidateSource || record.candidateSource || ""),
      candidateUrlCompleteness: clampText(record.candidateContext?.candidateUrlCompleteness || record.candidateUrlCompleteness || ""),
      candidateIsDomainOnlyFallback: record.candidateContext?.candidateIsDomainOnlyFallback === true || record.candidateIsDomainOnlyFallback === true
    },
    postIdentityStable: record.postIdentityStable === true,
    integrityComparisonStatus: clampText(record.integrityComparisonStatus || ""),
    linkInsertedAfterBaseline: record.linkInsertedAfterBaseline === true,
    postIntegrityEvent: clampText(record.postIntegrityEvent || ""),
    detectedAt: Number(record.detectedAt || 0),
    seenCount: Number(record.seenCount || 1),
    firstSeenAt: Number(record.firstSeenAt || record.timestamp || Date.now()),
    lastChecked: Number(record.lastChecked || record.timestamp || Date.now()),
    lastSeenAt: Number(record.lastSeenAt || record.lastChecked || record.timestamp || Date.now()),
    state: clampText(record.state || "")
  };
}

function compactLinkScoreSummary(summary = []) {
  if (!Array.isArray(summary)) {
    return [];
  }

  return summary
    .slice(0, 8)
    .map((item, index) => ({
      index: Number(item?.index || index + 1),
      domain: clampText(item?.domain || safeHostname(item?.url || ""), 120),
      url: clampText(item?.url || "", 220),
      safetyScore: Number.isFinite(Number(item?.safetyScore)) ? Number(item.safetyScore) : null,
      computedSafetyScore: normalizeScore(item?.computedSafetyScore),
      classification: clampText(item?.classification || "", 60),
      computedClassification: clampText(item?.computedClassification || "", 60),
      state: clampText(item?.state || "", 60),
      scanFinalized: item?.scanFinalized === true,
      providerOverride: item?.providerOverride === true,
      providerPending: item?.providerPending === true,
      providerDeductions: compactNumericMap(item?.providerDeductions || item?.scoreAudit?.providerDeductions),
      heuristicRawCategoryTotals: compactNumericMap(item?.heuristicRawCategoryTotals || item?.scoreAudit?.heuristicRawCategoryTotals),
      heuristicCategoryDeductions: compactNumericMap(item?.heuristicCategoryDeductions || item?.scoreAudit?.heuristicCategoryDeductions),
      heuristicRawTotal: normalizeScore(item?.heuristicRawTotal ?? item?.scoreAudit?.heuristicRawTotal),
      heuristicScaledDeduction: normalizeScore(item?.heuristicScaledDeduction ?? item?.scoreAudit?.heuristicScaledDeduction),
      totalDeduction: normalizeScore(item?.totalDeduction ?? item?.scoreAudit?.ruleDeductionTotal),
      providerCompletion: compactProviderCompletion(item?.providerCompletion),
      providerRetryPlan: compactProviderRetryPlan(item?.providerRetryPlan),
      pendingProviders: clampList(item?.pendingProviders || [], 8)
    }));
}

function compactLinkAnalysisSnapshots(snapshots = []) {
  if (!Array.isArray(snapshots)) {
    return [];
  }

  return snapshots
    .slice(0, 8)
    .map((item, index) => compactLinkAnalysisSnapshot(item, index + 1))
    .filter(Boolean);
}

function compactLinkAnalysisSnapshot(item = {}, fallbackIndex = 1) {
  if (!item || typeof item !== "object") {
    return null;
  }

  return {
    index: Number(item.index || fallbackIndex),
    url: clampText(item.url || "", 500),
    displayUrl: clampText(item.displayUrl || item.url || "", 500),
    analysisUrl: clampText(item.analysisUrl || item.url || "", 500),
    normalizedUrl: clampText(item.normalizedUrl || "", 500),
    providerCheckedUrl: clampText(item.providerCheckedUrl || item.analysisUrl || "", 500),
    domain: clampText(item.domain || safeHostname(item.analysisUrl || item.url) || "", 120),
    safetyScore: normalizeScore(item.safetyScore),
    computedSafetyScore: normalizeScore(item.computedSafetyScore),
    classification: clampText(item.classification || "", 60),
    computedClassification: clampText(item.computedClassification || "", 60),
    scanFinalized: item.scanFinalized === true,
    state: clampText(item.state || "", 60),
    providerOverride: item.providerOverride === true,
    providerPending: item.providerPending === true,
    providerDeductions: compactNumericMap(item.providerDeductions || item.scoreAudit?.providerDeductions),
    heuristicRawCategoryTotals: compactNumericMap(item.heuristicRawCategoryTotals || item.scoreAudit?.heuristicRawCategoryTotals),
    heuristicCategoryDeductions: compactNumericMap(item.heuristicCategoryDeductions || item.scoreAudit?.heuristicCategoryDeductions),
    heuristicRawTotal: normalizeScore(item.heuristicRawTotal ?? item.scoreAudit?.heuristicRawTotal),
    heuristicScaledDeduction: normalizeScore(item.heuristicScaledDeduction ?? item.scoreAudit?.heuristicScaledDeduction),
    totalDeduction: normalizeScore(item.totalDeduction ?? item.scoreAudit?.ruleDeductionTotal),
    scoreAudit: compactScoreAudit(item.scoreAudit),
    providerResults: compactProviderResults(item.providerResults || []),
    providerCompletion: compactProviderCompletion(item.providerCompletion),
    providerRetryPlan: compactProviderRetryPlan(item.providerRetryPlan),
    pendingProviders: clampList(item.pendingProviders || [], 8),
    verificationState: clampText(item.verificationState || "", 80),
    limitations: clampList(item.limitations || [], 8)
  };
}

function compactProviderCompletion(completion = {}) {
  if (!completion || typeof completion !== "object") {
    return null;
  }

  return {
    pendingProviders: clampList(completion.pendingProviders || [], 8),
    incompleteProviders: clampList(completion.incompleteProviders || [], 8),
    hasPendingProvider: completion.hasPendingProvider === true,
    allRequiredProvidersTerminal: completion.allRequiredProvidersTerminal === true,
    activeProviderCount: Number(completion.activeProviderCount || 0),
    checkedProviderCount: Number(completion.checkedProviderCount || 0),
    pendingProviderCount: Number(completion.pendingProviderCount || 0),
    providerStates: Array.isArray(completion.providerStates)
      ? completion.providerStates.slice(0, 8).map((provider) => ({
          provider: clampText(provider?.provider || "", 40),
          status: clampText(provider?.status || "", 60),
          checked: provider?.checked === true,
          flagged: provider?.flagged === true,
          terminal: provider?.terminal === true,
          pending: provider?.pending === true,
          retryable: provider?.retryable !== false,
          checkedUrl: clampText(provider?.checkedUrl || "", 500),
          checkedAt: clampText(provider?.checkedAt || "", 80),
          analysisId: clampText(provider?.analysisId || "", 160)
        }))
      : []
  };
}

function compactProviderRetryPlan(plan = {}) {
  if (!plan || typeof plan !== "object") {
    return null;
  }

  return {
    attempt: Number(plan.attempt || 0),
    maxAttempts: Number(plan.maxAttempts || 0),
    nextRetryAt: Number(plan.nextRetryAt || 0) || null,
    nextRetryInMs: Number(plan.nextRetryInMs || 0) || null,
    lastAttemptAt: Number(plan.lastAttemptAt || 0) || null,
    lastAttemptStatus: clampText(plan.lastAttemptStatus || "", 160),
    status: clampText(plan.status || "", 60)
  };
}

function isDuplicateAnalysisRecord(existing, next) {
  if (!existing || !next) {
    return false;
  }

  const existingTime = Number(existing.lastChecked || existing.timestamp || 0);
  const nextTime = Number(next.lastChecked || next.timestamp || Date.now());

  return (
    nextTime - existingTime <= DEDUPE_WINDOW_MS &&
    existing.postId === next.postId &&
    (existing.finalSite || existing.domain) === (next.finalSite || next.domain) &&
    existing.classification === next.classification &&
    Number(existing.safetyScore ?? existing.score) === Number(next.safetyScore ?? next.score) &&
    existing.linkType === next.linkType
  );
}

async function pruneStorageForQuota() {
  const allValues = await storageGet(null);
  const removableKeys = Object.keys(allValues)
    .filter((key) => !PROTECTED_KEYS.has(key))
    .filter((key) => key === ANALYSIS_LOG_KEY || key.startsWith(POST_PREFIX) || key.startsWith(DOMAIN_PREFIX));

  const oldPostKeys = removableKeys
    .filter((key) => key.startsWith(POST_PREFIX))
    .sort((left, right) => Number(allValues[left]?.lastChecked || 0) - Number(allValues[right]?.lastChecked || 0));
  const keysToRemove = [
    ...oldPostKeys.slice(0, Math.ceil(oldPostKeys.length / 2)),
    ...removableKeys.filter((key) => key.startsWith(DOMAIN_PREFIX))
  ];

  await storageSetDirect({
    [ANALYSIS_LOG_KEY]: []
  });

  if (keysToRemove.length > 0) {
    await storageRemove(keysToRemove);
  }
}

function storageSetDirect(value) {
  return new Promise((resolve) => {
    chrome.storage.local.set(value, () => resolve());
  });
}

function storageRemove(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(keys, () => resolve());
  });
}

function isQuotaError(message) {
  return /quota|MAX_WRITE_OPERATIONS|kQuotaBytes/i.test(String(message || ""));
}

function extractMainReasons(deductions) {
  if (!Array.isArray(deductions)) {
    return [];
  }

  return deductions
    .filter((item) => item?.triggered && item?.label)
    .slice(0, 8)
    .map((item) => item.label);
}

function chainToDomains(chain) {
  if (!Array.isArray(chain)) {
    return [];
  }

  return [...new Set(chain.map((url) => safeHostname(url)).filter(Boolean))];
}

function normalizeScore(value) {
  const score = Number(value);
  return Number.isFinite(score) ? score : null;
}

function compactNumericMap(value = {}) {
  if (!value || typeof value !== "object") {
    return {};
  }

  return Object.entries(value).reduce((result, [key, rawValue]) => {
    const numeric = Number(rawValue);
    if (Number.isFinite(numeric)) {
      result[clampText(key, 80)] = numeric;
    }
    return result;
  }, {});
}

function compactScoreAudit(scoreAudit = {}) {
  if (!scoreAudit || typeof scoreAudit !== "object") {
    return null;
  }

  return {
    baselineScore: normalizeScore(scoreAudit.baselineScore),
    scoreFormula: clampText(scoreAudit.scoreFormula || ""),
    providerDeductions: compactNumericMap(scoreAudit.providerDeductions),
    providerDeductionTotal: normalizeScore(scoreAudit.providerDeductionTotal),
    heuristicRawCategoryTotals: compactNumericMap(scoreAudit.heuristicRawCategoryTotals),
    heuristicCategoryDeductions: compactNumericMap(scoreAudit.heuristicCategoryDeductions),
    heuristicRawTotal: normalizeScore(scoreAudit.heuristicRawTotal),
    heuristicScaledDeduction: normalizeScore(scoreAudit.heuristicScaledDeduction),
    ruleDeductionTotal: normalizeScore(scoreAudit.ruleDeductionTotal),
    ruleScore: normalizeScore(scoreAudit.ruleScore),
    categoryDeductions: compactNumericMap(scoreAudit.categoryDeductions),
    finalScore: normalizeScore(scoreAudit.finalScore),
    classification: clampText(scoreAudit.classification || "", 60),
    computedSafetyScore: normalizeScore(scoreAudit.computedSafetyScore),
    computedClassification: clampText(scoreAudit.computedClassification || "", 60),
    scanFinalized: scoreAudit.scanFinalized === true,
    displayedScoreWithheld: scoreAudit.displayedScoreWithheld === true,
    verificationIncomplete: scoreAudit.verificationIncomplete === true,
    pendingProviders: clampList(scoreAudit.pendingProviders || [], 8),
    retryBudgetExhausted: scoreAudit.retryBudgetExhausted === true,
    activeHeuristicGroups: clampList(scoreAudit.activeHeuristicGroups || [], 8),
    mitigatedHeuristicGroups: clampList(scoreAudit.mitigatedHeuristicGroups || [], 8),
    recoveryApplied: scoreAudit.recoveryApplied === true,
    recoveryBlockedReasons: clampList(scoreAudit.recoveryBlockedReasons || [], 6),
    providerWarningApplied: scoreAudit.providerWarningApplied === true,
    providerCautionApplied: scoreAudit.providerCautionApplied === true,
    providerWarningReviewRecommended: scoreAudit.providerWarningReviewRecommended === true,
    reviewRecommendedReason: clampText(scoreAudit.reviewRecommendedReason || "", 180),
    providerWarningReason: clampText(scoreAudit.providerWarningReason || "", 180),
    virusTotalMaliciousDetections: Number(scoreAudit.virusTotalMaliciousDetections || 0),
    virusTotalSuspiciousDetections: Number(scoreAudit.virusTotalSuspiciousDetections || 0)
  };
}

function clampList(values, limit) {
  return [...new Set((values || []).map((value) => clampText(value)).filter(Boolean))].slice(0, limit);
}

function clampText(value, maxLength = STORED_TEXT_LIMIT) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

function compactFeatureFlags(features = {}) {
  return {
    redirectCount: Number(features.redirectCount || 0),
    shortenedUrl: features.shortenedUrl === true,
    suspiciousTld: features.suspiciousTld === true,
    obfuscatedUrl: features.obfuscatedUrl === true,
    textMismatch: features.textMismatch === true,
    integrityHashMismatch: features.integrityHashMismatch === true,
    suspiciousRedirectPattern: features.suspiciousRedirectPattern === true,
    crossDomainRedirectChain: features.crossDomainRedirectChain === true,
    shortenerToUnrelatedDomain: features.shortenerToUnrelatedDomain === true,
    trackingHopToUnrelatedDomain: features.trackingHopToUnrelatedDomain === true,
    usernamePasswordTrick: features.usernamePasswordTrick === true,
    suspiciousPath: features.suspiciousPath === true,
    providerOverride: features.providerOverride === true,
    virusTotalFlagged: features.virusTotalFlagged === true,
    domainPreviouslyFlagged: features.domainPreviouslyFlagged === true,
    mainstreamResolvedShortlink: features.mainstreamResolvedShortlink === true,
    knownShortenerOwnerRedirect: features.knownShortenerOwnerRedirect === true,
    knownBrandedCampaignRedirect: features.knownBrandedCampaignRedirect === true,
    knownGoogleFormsRedirect: features.knownGoogleFormsRedirect === true,
    googleFormsViaGenericShortener: features.googleFormsViaGenericShortener === true,
    softExternalFormCaution: features.softExternalFormCaution === true,
    trustedEndpointMitigationEligible: features.trustedEndpointMitigationEligible === true,
    softUncertaintyCapApplied: features.softUncertaintyCapApplied === true,
    demoScoreBiasApplied: features.demoScoreBiasApplied === true,
    originalSafetyScore: Number.isFinite(Number(features.originalSafetyScore))
      ? Number(features.originalSafetyScore)
      : null,
    demoScoreBiasAmount: Number.isFinite(Number(features.demoScoreBiasAmount))
      ? Number(features.demoScoreBiasAmount)
      : null
  };
}

function compactProviderResults(providerResults) {
  if (!Array.isArray(providerResults)) {
    return [];
  }

  return providerResults.map((item) => ({
    provider: clampText(item?.provider || ""),
    configured: item?.configured === true,
    checked: item?.checked === true,
    checkedUrl: clampText(item?.checkedUrl || "", 500),
    checkedAt: clampText(item?.checkedAt || "", 80),
    durationMs: Number.isFinite(Number(item?.durationMs)) ? Number(item.durationMs) : null,
    resultSummary: clampText(item?.resultSummary || "", 200),
    flagged: item?.flagged === true,
    category: clampText(item?.category || ""),
    details: {
      status: clampText(item?.details?.status || ""),
      httpStatus: item?.details?.httpStatus ?? null,
      mode: clampText(item?.details?.mode || ""),
      message: clampText(item?.details?.message || "", 300),
      reason: clampText(item?.details?.reason || "", 120),
      terminal: item?.details?.terminal === true,
      retryable: item?.details?.retryable !== false,
      queryStatus: clampText(item?.details?.queryStatus || ""),
      checkedUrls: clampList(item?.details?.checkedUrls || [], 12),
      flaggedCandidateUrl: clampText(item?.details?.flaggedCandidateUrl || "", 500),
      matchesCount: Number(item?.details?.matchesCount || 0),
      analysisId: clampText(item?.details?.analysisId || "", 160),
      maliciousCount: Number(item?.details?.maliciousCount || 0),
      suspiciousCount: Number(item?.details?.suspiciousCount || 0),
      harmlessCount: Number(item?.details?.harmlessCount || 0),
      undetectedCount: Number(item?.details?.undetectedCount || 0),
      timeoutCount: Number(item?.details?.timeoutCount || 0)
    }
  }));
}
function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}
