const POST_PREFIX = "dili:post:";
const DOMAIN_PREFIX = "dili:domain:";
const ANALYSIS_LOG_KEY = "dili:analysis:records";
const ANALYSIS_LOG_LIMIT = 2000;

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
    [postStorageKey(postId)]: record
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
    [postStorageKey(postId)]: record
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
  const logs = await getAllAnalysisRecords();
  logs.push(record);

  const trimmedLogs = logs.slice(-ANALYSIS_LOG_LIMIT);
  await storageSet({
    [ANALYSIS_LOG_KEY]: trimmedLogs
  });

  return record;
}

/**
 * Return every stored analysis event in insertion order.
 * @returns {Promise<object[]>}
 */
export async function getAllAnalysisRecords() {
  const result = await storageGet(ANALYSIS_LOG_KEY);
  const logs = result[ANALYSIS_LOG_KEY];
  return Array.isArray(logs) ? logs : [];
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
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve();
    });
  });
}