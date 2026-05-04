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
    classification: clampText(record.classification || ""),
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
    providerOverride: Boolean(record.providerOverride),
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

function clampList(values, limit) {
  return [...new Set((values || []).map((value) => clampText(value)).filter(Boolean))].slice(0, limit);
}

function clampText(value, maxLength = STORED_TEXT_LIMIT) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}
