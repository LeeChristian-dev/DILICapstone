import {
  canonicalizeUrl,
  extractLikelyRedirectTarget,
  getRegistrableDomain,
  isFacebookWrapperHost,
  isShortenerHost,
  normalizeUrl,
  safeHostname
} from "./urlAnalyzer.js";

const MAX_REDIRECT_DEPTH = 6;
const FETCH_TIMEOUT_MS = 4000;
const SUPPORTED_NETWORK_PROTOCOLS = new Set([
  "http:",
  "https:"
]);
const ACTIVE_PROBE_REDIRECT_HOSTS = new Set([
  "l.facebook.com",
  "lm.facebook.com",
  "m.facebook.com",
  "bit.ly",
  "bitly.com",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "cutt.ly",
  "tiny.cc",
  "is.gd",
  "rebrand.ly",
  "shorturl.at",
  "lnkd.in",
  "rb.gy",
  "s.id",
  "bl.ink",
  "cnn.it",
  "hoyo.link",
  "dito.ph",
  "eshop.dito.ph",
  "my.dito.ph",
  "coca-cola.com"
]);

export function isFetchableNetworkProtocol(url) {
  try {
    const parsed = new URL(String(url || "").trim());
    return SUPPORTED_NETWORK_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

export function getProtocolName(url) {
  try {
    return new URL(String(url || "").trim()).protocol || "";
  } catch {
    return "";
  }
}

function isUnsupportedNetworkProtocol(url) {
  const protocol = getProtocolName(url);
  return Boolean(protocol && !SUPPORTED_NETWORK_PROTOCOLS.has(protocol));
}

function normalizeRedirectCandidate(url, options = {}) {
  const value = String(url || "").trim();
  if (isUnsupportedNetworkProtocol(value)) {
    return value;
  }

  return safelyCanonicalize(value, options) || value;
}

/**
 * Analyze redirect wrappers and optional low-cost network redirects.
 * @param {string} rawUrl
 * @returns {Promise<{
 *   redirectCount: number,
 *   redirectChain: string[],
 *   chain: string[],
 *   fullObservedRedirectTrace: string[],
 *   fullObservedRedirectEvents: Array<{ url: string, host: string, registrableDomain: string, method: string, status: string, source: string, note: string }>,
 *   fullRedirectCount: number,
 *   fullRedirectDomains: string[],
 *   fullUniqueRegistrableDomains: string[],
 *   redirectDomains: string[],
 *   uniqueRegistrableDomains: string[],
 *   resolvedUrl: string,
 *   resolutionMethod: string,
 *   notes: string[],
 *   fetchAttempted: boolean,
 *   fetchAllowed: boolean,
 *   suspiciousPattern: boolean,
 *   multipleRedirects: boolean,
 *   crossDomainRedirectChain: boolean,
 *   redirectChainToDifferentRegistrantLikeTarget: boolean,
 *   wrapperToExternalDestination: boolean,
 *   shortenerToUnrelatedDomain: boolean,
 *   trackingHopToUnrelatedDomain: boolean
 * }>}
 */
export async function analyzeRedirects(rawUrl) {
  const notes = [];
  const redirectChain = [];
  const fullObservedRedirectTrace = [];
  const fullObservedRedirectEvents = [];
  const visited = new Set();

  let currentUrl = isUnsupportedNetworkProtocol(rawUrl)
    ? String(rawUrl || "").trim()
    : canonicalizeUrl(rawUrl, { stripTracking: false });

  for (let depth = 0; depth < MAX_REDIRECT_DEPTH; depth += 1) {
    const currentCanonical = normalizeRedirectCandidate(currentUrl, { stripTracking: false });

    if (visited.has(currentCanonical)) {
      pushUniqueNote(notes, "Redirect parsing stopped because the same URL appeared twice.");
      break;
    }

    visited.add(currentCanonical);
    redirectChain.push(currentCanonical);
    pushObservedRedirectTrace(fullObservedRedirectTrace, fullObservedRedirectEvents, currentCanonical, {
      method: "wrapper-param",
      source: "heuristic-wrapper"
    });

    const nextUrl = extractLikelyRedirectTarget(currentCanonical);
    if (!nextUrl) {
      break;
    }

    const nextCanonical = normalizeRedirectCandidate(nextUrl, { stripTracking: false });
    const currentHost = safeHostname(currentCanonical);
    const nextHost = safeHostname(nextCanonical);
    const currentDomain = getRegistrableDomain(currentHost);
    const nextDomain = getRegistrableDomain(nextHost);

    if (!looksLikeRedirectWrapper(currentCanonical, currentHost, currentDomain, nextDomain)) {
      break;
    }

    pushObservedRedirectTrace(fullObservedRedirectTrace, fullObservedRedirectEvents, nextCanonical, {
      method: "wrapper-param",
      source: "heuristic-wrapper-target"
    });
    currentUrl = nextCanonical;
  }

  const probeInputUrl = normalizeRedirectCandidate(redirectChain[redirectChain.length - 1] || currentUrl, { stripTracking: true });
  const probeInputHost = safeHostname(probeInputUrl);
  const fetchResolution = await attemptNetworkResolution(probeInputUrl, {
    originalUrl: rawUrl,
    redirectChain
  });
  mergeObservedRedirectTrace(fullObservedRedirectTrace, fullObservedRedirectEvents, fetchResolution);
  if (fetchResolution.note && (fetchResolution.fetchAttempted || fetchResolution.shouldReportNote)) {
    pushUniqueNote(notes, fetchResolution.note);
  }

  if (fetchResolution.success && fetchResolution.finalUrl && !isSameComparableUrl(fetchResolution.finalUrl, redirectChain[redirectChain.length - 1])) {
    const finalCanonical = normalizeRedirectCandidate(fetchResolution.finalUrl, { stripTracking: false });
    redirectChain.push(finalCanonical);
    pushObservedRedirectTrace(fullObservedRedirectTrace, fullObservedRedirectEvents, finalCanonical, {
      method: fetchResolution.method || "network-follow",
      status: fetchResolution.status || "",
      source: "network-resolution",
      note: "Network probing observed this final URL."
    });
    currentUrl = finalCanonical;
    pushUniqueNote(notes, "Network probing observed an additional redirect hop.");

    const probeDomain = getRegistrableDomain(probeInputHost);
    const finalDomain = getRegistrableDomain(safeHostname(finalCanonical));

    if (isShortenerHost(probeInputHost) && probeDomain && finalDomain && probeDomain !== finalDomain) {
      pushUniqueNote(notes, "A shortened URL resolved to an external destination.");
      pushUniqueNote(notes, "The final destination differs from the initial shortener domain.");
    }
  }

  if (redirectChain.length === 0) {
    redirectChain.push(currentUrl);
    pushObservedRedirectTrace(fullObservedRedirectTrace, fullObservedRedirectEvents, currentUrl, {
      method: "legacy-chain",
      source: "redirect-chain"
    });
  }

  const redirectSummary = summarizeRedirectChain(redirectChain);
  const returnedObservedTrace = fullObservedRedirectTrace.length > 0 ? fullObservedRedirectTrace : redirectChain;
  const returnedObservedEvents = fullObservedRedirectEvents.length > 0
    ? fullObservedRedirectEvents
    : redirectChain.map((url) => ({
        url,
        host: safeHostname(url),
        registrableDomain: getRegistrableDomain(safeHostname(url)),
        method: "legacy-chain",
        status: "",
        source: "redirect-chain",
        note: ""
      }));
  const fullObservedSummary = summarizeObservedRedirectTrace(returnedObservedTrace);

  if (redirectSummary.wrapperToExternalDestination) {
    pushUniqueNote(notes, "A Facebook wrapper concealed an external destination.");
  }

  if (redirectSummary.shortenerToUnrelatedDomain) {
    if (!notes.includes("A shortened URL resolved to an external destination.")) {
      pushUniqueNote(notes, "A shortened URL redirects to a different external domain.");
    }
  }

  if (redirectSummary.trackingHopToUnrelatedDomain) {
    pushUniqueNote(notes, "A tracking or wrapper hop leads to a different external domain.");
  }

  if (redirectSummary.multipleRedirects) {
    pushUniqueNote(notes, "The link passes through multiple redirects before reaching the final destination.");
  }

  if (redirectSummary.crossDomainRedirectChain) {
    pushUniqueNote(notes, "The redirect chain hands the user across different domains.");
  }

  if (redirectSummary.suspiciousPattern) {
    pushUniqueNote(notes, "The redirect chain uses a pattern commonly seen in deceptive links.");
  }

  return {
    redirectCount: redirectSummary.redirectCount,
    redirectChain,
    chain: redirectChain,
    fullObservedRedirectTrace: returnedObservedTrace,
    fullObservedRedirectEvents: returnedObservedEvents,
    fullRedirectCount: fullObservedSummary.fullRedirectCount,
    fullRedirectDomains: fullObservedSummary.fullRedirectDomains,
    fullUniqueRegistrableDomains: fullObservedSummary.fullUniqueRegistrableDomains,
    redirectDomains: redirectSummary.redirectDomains,
    uniqueRegistrableDomains: redirectSummary.uniqueRegistrableDomains,
    resolvedUrl: isUnsupportedNetworkProtocol(currentUrl)
      ? currentUrl
      : normalizeUrl(currentUrl, { stripTracking: false }),
    resolutionMethod: fetchResolution.skipReason === "unsupported_protocol"
      ? fetchResolution.method
      : fetchResolution.fetchAllowed ? fetchResolution.method : "heuristic-only",
    fetchMethod: fetchResolution.method,
    fetchStatus: fetchResolution.status || "",
    skipped: Boolean(fetchResolution.skipped),
    skipReason: fetchResolution.skipReason || "",
    protocol: fetchResolution.protocol || "",
    notes,
    fetchAttempted: fetchResolution.fetchAttempted,
    fetchAllowed: fetchResolution.fetchAllowed,
    fetchSucceeded: fetchResolution.success,
    suspiciousPattern: redirectSummary.suspiciousPattern,
    multipleRedirects: redirectSummary.multipleRedirects,
    crossDomainRedirectChain: redirectSummary.crossDomainRedirectChain,
    redirectChainToDifferentRegistrantLikeTarget: redirectSummary.redirectChainToDifferentRegistrantLikeTarget,
    wrapperToExternalDestination: redirectSummary.wrapperToExternalDestination,
    shortenerToUnrelatedDomain: redirectSummary.shortenerToUnrelatedDomain,
    trackingHopToUnrelatedDomain: redirectSummary.trackingHopToUnrelatedDomain
  };
}

async function attemptNetworkResolution(rawUrl, context = {}) {
  const host = safeHostname(rawUrl);
  const probePolicy = getActiveProbePolicy(rawUrl, context);

  if (!isFetchableNetworkProtocol(rawUrl)) {
    const protocol = getProtocolName(rawUrl);
    console.debug(
      "[DILI] Skipped network probing for unsupported protocol:",
      protocol,
      rawUrl
    );
    return {
      redirected: true,
      finalUrl: rawUrl,
      skipped: true,
      skipReason: "unsupported_protocol",
      protocol,
      method: "unsupported-protocol",
      status: "",
      chain: [rawUrl],
      fetchAllowed: false,
      fetchAttempted: false,
      success: true,
      fullObservedRedirectTrace: [rawUrl],
      fullObservedRedirectEvents: buildObservedEventsFromTrace([rawUrl], {
        method: "unsupported-protocol",
        status: "",
        source: "unsupported-protocol",
        note: "Network probing skipped because the endpoint uses a non-web protocol."
      }),
      shouldReportNote: true,
      note: "Network probing was skipped because the redirect chain ended in a non-web application protocol."
    };
  }

  if (!probePolicy.allowed) {
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: false,
      method: "heuristic-only",
      finalUrl: null,
      status: "skipped",
      fullObservedRedirectTrace: [],
      fullObservedRedirectEvents: [],
      shouldReportNote: probePolicy.shouldReportNote,
      note: probePolicy.note
    };
  }

  if (!self.fetch) {
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: false,
      method: "heuristic-only",
      finalUrl: null,
      status: "skipped",
      fullObservedRedirectTrace: [],
      fullObservedRedirectEvents: [],
      shouldReportNote: true,
      note: "Fetch is not available in the current extension context."
    };
  }

  const headResult = await attemptFetch(rawUrl, "HEAD");
  const headResolvedElsewhere = Boolean(headResult.success && headResult.finalUrl && !isSameComparableUrl(headResult.finalUrl, rawUrl));
  if (headResolvedElsewhere) {
    return headResult;
  }

  const getResult = await attemptFetch(rawUrl, "GET");
  if (getResult.success) {
    return getResult;
  }

  return headResult.success ? headResult : getResult.fetchAttempted ? getResult : headResult;
}

async function attemptFetch(rawUrl, method) {
  if (!isFetchableNetworkProtocol(rawUrl)) {
    const protocol = getProtocolName(rawUrl);
    console.debug(
      "[DILI] Skipped network probing for unsupported protocol:",
      protocol,
      rawUrl
    );
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: true,
      skipped: true,
      skipReason: "unsupported_protocol",
      protocol,
      method: "unsupported-protocol",
      status: "",
      finalUrl: rawUrl,
      fullObservedRedirectTrace: [rawUrl],
      fullObservedRedirectEvents: buildObservedEventsFromTrace([rawUrl], {
        method: "unsupported-protocol",
        status: "",
        source: "unsupported-protocol",
        note: "Network probing skipped because the endpoint uses a non-web protocol."
      }),
      note: "Network probing was skipped because the redirect chain ended in a non-web application protocol."
    };
  }

  const manualResult = await attemptManualRedirectFetch(rawUrl, method);
  if (manualResult.success || manualResult.status === "timeout") {
    return manualResult;
  }

  const controller = new AbortController();
  const timeoutId = self.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(rawUrl, {
      method,
      redirect: "follow",
      cache: "no-store",
      signal: controller.signal
    });

    return {
      fetchAllowed: true,
      fetchAttempted: true,
      success: true,
      method: method.toLowerCase() + "-follow",
      status: `http-${response.status}`,
      finalUrl: response.url || rawUrl,
      fullObservedRedirectTrace: compactObservedTrace([rawUrl, response.url || rawUrl]),
      fullObservedRedirectEvents: response.url && !isSameComparableUrl(response.url, rawUrl)
        ? buildObservedEventsFromTrace([rawUrl, response.url], {
            method: method.toLowerCase() + "-follow",
            status: `http-${response.status}`,
            source: "network-follow",
            note: "Network probing observed this final URL."
          })
        : [],
      note: ""
    };
  } catch (error) {
    const timedOut = error?.name === "AbortError";
    return {
      fetchAllowed: true,
      fetchAttempted: true,
      success: false,
      method: method.toLowerCase() + "-follow",
      status: timedOut ? "timeout" : "failed",
      finalUrl: null,
      fullObservedRedirectTrace: [],
      fullObservedRedirectEvents: [],
      note: timedOut
        ? "Active redirect probing timed out before a final endpoint was confirmed."
        : "DILI could not fully confirm whether this custom shortlink redirects further."
    };
  } finally {
    self.clearTimeout(timeoutId);
  }
}

async function attemptManualRedirectFetch(rawUrl, method) {
  const trace = [];
  const events = [];
  const startedAt = Date.now();
  let currentUrl = normalizeRedirectCandidate(rawUrl, { stripTracking: false });

  if (!isFetchableNetworkProtocol(currentUrl)) {
    const protocol = getProtocolName(currentUrl);
    console.debug(
      "[DILI] Skipped network probing for unsupported protocol:",
      protocol,
      currentUrl
    );
    return buildManualFetchResult({
      success: true,
      method: "unsupported-protocol",
      status: "",
      finalUrl: currentUrl,
      trace: [currentUrl],
      events: buildObservedEventsFromTrace([currentUrl], {
        method: "unsupported-protocol",
        status: "",
        source: "unsupported-protocol",
        note: "Network probing skipped because the endpoint uses a non-web protocol."
      }),
      note: "Network probing was skipped because the redirect chain ended in a non-web application protocol.",
      fetchAllowed: false,
      fetchAttempted: false,
      skipped: true,
      skipReason: "unsupported_protocol",
      protocol
    });
  }

  pushObservedRedirectTrace(trace, events, currentUrl, {
    method: method.toLowerCase() + "-manual",
    source: "network-start"
  });

  for (let depth = 0; depth < MAX_REDIRECT_DEPTH; depth += 1) {
    const remainingMs = Math.max(0, FETCH_TIMEOUT_MS - (Date.now() - startedAt));
    if (remainingMs <= 0) {
      return buildManualFetchResult({
        success: false,
        method,
        status: "timeout",
        finalUrl: null,
        trace,
        events,
        note: "Active redirect probing timed out before a final endpoint was confirmed."
      });
    }

    const controller = new AbortController();
    const timeoutId = self.setTimeout(() => controller.abort(), remainingMs);

    try {
      const response = await fetch(currentUrl, {
        method,
        redirect: "manual",
        cache: "no-store",
        signal: controller.signal
      });

      if (response.type === "opaqueredirect" || Number(response.status) === 0) {
        return buildManualFetchResult({
          success: false,
          method,
          status: "manual-location-unavailable",
          finalUrl: null,
          trace,
          events,
          note: ""
        });
      }

      const status = `http-${response.status}`;
      const location = response.headers?.get("location") || "";

      if (isRedirectStatus(response.status)) {
        if (!location) {
          return buildManualFetchResult({
            success: false,
            method,
            status: "manual-location-unavailable",
            finalUrl: null,
            trace,
            events,
            note: ""
          });
        }

        const nextUrl = resolveRedirectLocation(location, currentUrl);
        if (!nextUrl) {
          return buildManualFetchResult({
            success: false,
            method,
            status: "manual-location-invalid",
            finalUrl: null,
            trace,
            events,
            note: ""
          });
        }

        const nextCanonical = normalizeRedirectCandidate(nextUrl, { stripTracking: false });
        pushObservedRedirectTrace(trace, events, nextCanonical, {
          method: method.toLowerCase() + "-manual",
          status,
          source: "network-location",
          note: "Network probing observed this redirect stage."
        });

        if (!isFetchableNetworkProtocol(nextCanonical)) {
          const protocol = getProtocolName(nextCanonical);
          console.debug(
            "[DILI] Skipped network probing for unsupported protocol:",
            protocol,
            nextCanonical
          );
          return buildManualFetchResult({
            success: true,
            method: "unsupported-protocol",
            status: "unsupported_protocol",
            finalUrl: nextCanonical,
            trace,
            events,
            note: "Network probing was skipped because the redirect chain ended in a non-web application protocol.",
            fetchAllowed: true,
            fetchAttempted: true,
            skipped: true,
            skipReason: "unsupported_protocol",
            protocol
          });
        }

        if (isSameComparableUrl(nextCanonical, currentUrl)) {
          return buildManualFetchResult({
            success: true,
            method,
            status,
            finalUrl: nextCanonical,
            trace,
            events,
            note: "Redirect parsing stopped because the same URL appeared twice."
          });
        }

        currentUrl = nextCanonical;
        continue;
      }

      return buildManualFetchResult({
        success: true,
        method,
        status,
        finalUrl: currentUrl,
        trace,
        events,
        note: ""
      });
    } catch (error) {
      const timedOut = error?.name === "AbortError";
      return buildManualFetchResult({
        success: false,
        method,
        status: timedOut ? "timeout" : "failed",
        finalUrl: null,
        trace,
        events,
        note: timedOut
          ? "Active redirect probing timed out before a final endpoint was confirmed."
          : ""
      });
    } finally {
      self.clearTimeout(timeoutId);
    }
  }

  return buildManualFetchResult({
    success: true,
    method,
    status: "max-depth",
    finalUrl: currentUrl,
    trace,
    events,
    note: "Redirect parsing stopped after the maximum redirect depth."
  });
}

function buildManualFetchResult({
  success,
  method,
  status,
  finalUrl,
  trace,
  events,
  note,
  fetchAllowed = true,
  fetchAttempted = true,
  skipped = false,
  skipReason = "",
  protocol = ""
}) {
  const normalizedMethod = String(method || "").includes("-")
    ? String(method || "")
    : String(method || "").toLowerCase() + "-manual";

  return {
    fetchAllowed,
    fetchAttempted,
    success,
    skipped,
    skipReason,
    protocol,
    method: normalizedMethod,
    status,
    finalUrl,
    fullObservedRedirectTrace: compactObservedTrace(trace),
    fullObservedRedirectEvents: Array.isArray(events) ? events : [],
    note
  };
}

function getActiveProbePolicy(rawUrl, context = {}) {
  const host = safeHostname(rawUrl);
  const normalizedHost = String(host || "").toLowerCase();
  const originalUrl = String(context.originalUrl || "").trim();
  const chain = Array.isArray(context.redirectChain) ? context.redirectChain : [];
  const chainHosts = chain.map((url) => safeHostname(url)).filter(Boolean);

  if (!isHttpUrl(rawUrl)) {
    return {
      allowed: false,
      shouldReportNote: false,
      note: "Active redirect probing was skipped for this domain."
    };
  }

  if (isProviderApiHost(normalizedHost) || isInternalFacebookProbeUrl(rawUrl)) {
    return {
      allowed: false,
      shouldReportNote: false,
      note: "Active redirect probing was skipped for this domain."
    };
  }

  const cameFromFacebookWrapper = chainHosts.some((candidateHost) => isFacebookWrapperHost(candidateHost)) || isFacebookWrapperHost(safeHostname(originalUrl));
  const sourceWasKnownShortener = chainHosts.some((candidateHost) => isShortenerHost(candidateHost)) || isShortenerHost(safeHostname(originalUrl));
  const hostIsProbeable = isActivelyProbeableHost(normalizedHost);
  const looksLikeShortlink = looksLikeCustomShortlinkUrl(rawUrl);

  if (hostIsProbeable || cameFromFacebookWrapper || sourceWasKnownShortener || looksLikeShortlink) {
    return {
      allowed: true,
      shouldReportNote: false,
      note: ""
    };
  }

  return {
    allowed: false,
    shouldReportNote: looksLikeShortlink,
    note: "Active redirect probing was skipped for this domain."
  };
}

function isHttpUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isProviderApiHost(hostname) {
  const normalized = String(hostname || "").toLowerCase();
  return (
    normalized === "safebrowsing.googleapis.com" ||
    normalized.endsWith(".safebrowsing.googleapis.com") ||
    normalized === "urlhaus-api.abuse.ch" ||
    normalized.endsWith(".urlhaus-api.abuse.ch") ||
    normalized === "abuse.ch" ||
    normalized.endsWith(".abuse.ch")
  );
}

function isInternalFacebookProbeUrl(rawUrl) {
  const host = safeHostname(rawUrl);
  if (!isFacebookWrapperHost(host)) {
    return false;
  }

  return !extractLikelyRedirectTarget(rawUrl);
}

function looksLikeCustomShortlinkUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.toLowerCase();
    const registrable = getRegistrableDomain(host);
    const pathSegments = parsed.pathname.split("/").filter(Boolean);

    if (isShortenerHost(host) || isFacebookWrapperHost(host)) {
      return true;
    }

    if (pathSegments.length !== 1) {
      return false;
    }

    const slug = pathSegments[0] || "";
    const compactDomain = registrable && registrable.split(".")[0]?.length <= 7;
    const compactSlug = slug.length >= 4 && slug.length <= 40 && /^[a-z0-9][a-z0-9_-]*$/i.test(slug);

    return Boolean(compactDomain && compactSlug && !parsed.search);
  } catch {
    return false;
  }
}

function looksLikeTrackingHop(rawUrl, hostname) {
  const source = String(rawUrl || "").toLowerCase();
  const normalizedHost = String(hostname || "").toLowerCase();

  return (
    normalizedHost.includes("track") ||
    normalizedHost.includes("redir") ||
    normalizedHost.includes("redirect") ||
    normalizedHost.includes("out") ||
    source.includes("redirect") ||
    source.includes("redir") ||
    source.includes("away") ||
    source.includes("out=")
  );
}

function resolveRedirectLocation(location, baseUrl) {
  try {
    return new URL(String(location || "").trim(), baseUrl).toString();
  } catch {
    return "";
  }
}

function isRedirectStatus(status) {
  return [301, 302, 303, 307, 308].includes(Number(status));
}

function pushObservedRedirectTrace(trace, events, url, meta = {}) {
  const value = safelyCanonicalize(url, { stripTracking: false }) || String(url || "").trim();

  if (!value) {
    return;
  }

  if (trace[trace.length - 1] !== value) {
    trace.push(value);
    events.push({
      url: value,
      host: safeHostname(value),
      registrableDomain: getRegistrableDomain(safeHostname(value)),
      method: meta.method || "unknown",
      status: meta.status || "",
      source: meta.source || "observed",
      note: meta.note || ""
    });
  }
}

function summarizeObservedRedirectTrace(trace = []) {
  const urls = Array.isArray(trace) ? trace.filter(Boolean) : [];
  const domains = urls.map((url) => safeHostname(url)).filter(Boolean);
  const registrableDomains = domains.map((domain) => getRegistrableDomain(domain)).filter(Boolean);
  const uniqueRegistrableDomains = unique(registrableDomains);

  return {
    fullRedirectCount: Math.max(0, urls.length - 1),
    fullRedirectDomains: domains,
    fullUniqueRegistrableDomains: uniqueRegistrableDomains
  };
}

function compactObservedTrace(values = []) {
  const trace = [];
  const events = [];

  for (const value of Array.isArray(values) ? values : []) {
    pushObservedRedirectTrace(trace, events, value);
  }

  return trace;
}

function buildObservedEventsFromTrace(trace = [], meta = {}) {
  const compactTrace = [];
  const events = [];

  for (const value of Array.isArray(trace) ? trace : []) {
    pushObservedRedirectTrace(compactTrace, events, value, meta);
  }

  return events;
}

function mergeObservedRedirectTrace(trace, events, fetchResolution = {}) {
  const observedTrace = Array.isArray(fetchResolution.fullObservedRedirectTrace)
    ? fetchResolution.fullObservedRedirectTrace
    : [];
  const observedEvents = Array.isArray(fetchResolution.fullObservedRedirectEvents)
    ? fetchResolution.fullObservedRedirectEvents
    : [];

  observedTrace.forEach((url, index) => {
    const event = observedEvents[index] || {};
    pushObservedRedirectTrace(trace, events, url, {
      method: event.method || fetchResolution.method || "network-follow",
      status: event.status || fetchResolution.status || "",
      source: event.source || "network-resolution",
      note: event.note || ""
    });
  });
}

function looksLikeRedirectWrapper(rawUrl, hostname, currentDomain, nextDomain) {
  const source = String(rawUrl || "").toLowerCase();

  if (isFacebookWrapperHost(hostname)) {
    return true;
  }

  if (looksLikeTrackingHop(rawUrl, hostname)) {
    return true;
  }

  if (source.includes("url=") || source.includes("target=") || source.includes("destination=") || source.includes("redirect=") || source.includes("u=")) {
    return true;
  }

  return Boolean(currentDomain && nextDomain && currentDomain !== nextDomain && /(?:\/redirect|\/redir|\/away|\/out\b|[?&](?:next|continue|dest|destination|target|url|u)=)/i.test(source));
}

function summarizeRedirectChain(redirectChain) {
  const redirectDomains = redirectChain.map((url) => safeHostname(url)).filter(Boolean);
  const registrableDomains = redirectDomains.map((domain) => getRegistrableDomain(domain)).filter(Boolean);
  const uniqueRegistrableDomains = unique(registrableDomains);
  const redirectCount = Math.max(0, redirectChain.length - 1);
  const simpleSingleHopShortenerOrWrapper = isSimpleSingleHopShortenerOrWrapperChain(redirectChain, redirectDomains);
  const multipleRedirects = redirectCount >= 2;
  const crossDomainRedirectChain = uniqueRegistrableDomains.length >= 2 && redirectCount > 0 && !simpleSingleHopShortenerOrWrapper;
  const redirectChainToDifferentRegistrantLikeTarget =
    redirectCount > 0 &&
    uniqueRegistrableDomains[0] !== uniqueRegistrableDomains[uniqueRegistrableDomains.length - 1] &&
    !simpleSingleHopShortenerOrWrapper;

  let wrapperToExternalDestination = false;
  let shortenerToUnrelatedDomain = false;
  let trackingHopToUnrelatedDomain = false;

  for (let index = 0; index < redirectChain.length - 1; index += 1) {
    const currentUrl = redirectChain[index];
    const nextUrl = redirectChain[index + 1];
    const currentHost = safeHostname(currentUrl);
    const nextHost = safeHostname(nextUrl);
    const currentDomain = getRegistrableDomain(currentHost);
    const nextDomain = getRegistrableDomain(nextHost);

    if (!currentDomain || !nextDomain || currentDomain === nextDomain) {
      continue;
    }

    if (isFacebookWrapperHost(currentHost)) {
      wrapperToExternalDestination = true;
    }

    if (isShortenerHost(currentHost) && (!simpleSingleHopShortenerOrWrapper || redirectChain.length > 2)) {
      shortenerToUnrelatedDomain = true;
    }

    if (looksLikeTrackingHop(currentUrl, currentHost)) {
      trackingHopToUnrelatedDomain = true;
    }
  }

  const suspiciousPattern = Boolean(
    shortenerToUnrelatedDomain ||
    trackingHopToUnrelatedDomain ||
    (multipleRedirects && crossDomainRedirectChain) ||
    countDomainTransitions(registrableDomains) >= 2
  );

  return {
    redirectDomains,
    uniqueRegistrableDomains,
    redirectCount,
    multipleRedirects,
    crossDomainRedirectChain,
    redirectChainToDifferentRegistrantLikeTarget,
    wrapperToExternalDestination,
    shortenerToUnrelatedDomain,
    trackingHopToUnrelatedDomain,
    suspiciousPattern
  };
}

function isSimpleSingleHopShortenerOrWrapperChain(redirectChain, redirectDomains) {
  if (redirectChain.length !== 2 || redirectDomains.length !== 2) {
    return false;
  }

  const firstHost = redirectDomains[0];
  const secondHost = redirectDomains[1];
  const firstDomain = getRegistrableDomain(firstHost);
  const secondDomain = getRegistrableDomain(secondHost);

  if (!firstDomain || !secondDomain || firstDomain === secondDomain) {
    return false;
  }

  return isFacebookWrapperHost(firstHost) || isShortenerHost(firstHost);
}

function isActivelyProbeableHost(hostname) {
  const normalized = String(hostname || "").toLowerCase();

  return Boolean(normalized) && (
    ACTIVE_PROBE_REDIRECT_HOSTS.has(normalized) ||
    isFacebookWrapperHost(normalized) ||
    isShortenerHost(normalized)
  );
}

function countDomainTransitions(domains) {
  let transitions = 0;

  for (let index = 1; index < domains.length; index += 1) {
    if (domains[index] !== domains[index - 1]) {
      transitions += 1;
    }
  }

  return transitions;
}

function pushUniqueNote(notes, message) {
  if (message && !notes.includes(message)) {
    notes.push(message);
  }
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function isSameComparableUrl(left, right) {
  return (safelyCanonicalize(left, { stripTracking: false }) || String(left || "")) === (safelyCanonicalize(right, { stripTracking: false }) || String(right || ""));
}

function safelyCanonicalize(rawUrl, options) {
  try {
    return canonicalizeUrl(rawUrl, options);
  } catch {
    return null;
  }
}
