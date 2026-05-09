import { analyzeRedirects } from "./redirectAnalyzer.js";
import {
  canonicalizeUrl,
  getRegistrableDomain,
  isFacebookWrapperHost,
  isShortenerHost,
  normalizeUrl,
  safeHostname,
  unwrapKnownRedirectWrappers
} from "./urlAnalyzer.js";

const FACEBOOK_HOST_PATTERN = /(^|\.)facebook\.com$/i;

/**
 * Resolve the effective endpoint for a Facebook-visible URL.
 * @param {string} rawUrl
 * @returns {Promise<{
 *   rawUrl: string,
 *   normalizedRawUrl: string,
 *   unwrappedUrl: string,
 *   resolvedUrl: string,
 *   effectiveEndpoint: string,
 *   effectiveDomain: string,
 *   registrableDomain: string,
 *   isFacebookWrapper: boolean,
 *   isInternalFacebook: boolean,
 *   isShortener: boolean,
 *   endpointConfidence: "high" | "medium" | "low",
 *   resolutionMethod: string,
 *   resolutionChain: string[],
 *   warnings: string[],
 *   errors: string[]
 * }>}
 */
export async function resolveEndpoint(rawUrl) {
  const warnings = [];
  const errors = [];
  const source = String(rawUrl || "").trim();

  if (!source) {
    return buildEmptyResult(source, "missing-url", ["Missing URL."]);
  }

  let normalizedRawUrl = "";
  let wrapperAnalysis = null;

  try {
    normalizedRawUrl = canonicalizeUrl(source, { stripTracking: true });
    wrapperAnalysis = unwrapKnownRedirectWrappers(source);
  } catch (error) {
    errors.push(error?.message || "URL normalization failed.");
    return buildEmptyResult(source, "invalid-url", errors);
  }

  const rawHost = safeHostname(normalizedRawUrl);
  const isFacebookWrapper = isFacebookWrapperHost(rawHost);
  const unwrappedUrl = safelyNormalize(wrapperAnalysis?.finalUrl || normalizedRawUrl) || normalizedRawUrl;
  const unwrappedHost = safeHostname(unwrappedUrl);
  const internalFacebook = isFacebookHost(unwrappedHost);
  const isShortener = isShortenerHost(rawHost) || isShortenerHost(unwrappedHost);

  if (isFacebookWrapper && internalFacebook) {
    return buildEndpointResult({
      rawUrl: source,
      normalizedRawUrl,
      unwrappedUrl,
      resolvedUrl: unwrappedUrl,
      effectiveEndpoint: unwrappedUrl,
      resolutionChain: compactChain([...(wrapperAnalysis?.chain || []), unwrappedUrl]),
      resolutionMethod: "internal-facebook-wrapper-ignored",
      endpointConfidence: "high",
      warnings,
      errors,
      isFacebookWrapper,
      isInternalFacebook: true,
      isShortener
    });
  }

  if (internalFacebook && !isFacebookWrapper) {
    return buildEndpointResult({
      rawUrl: source,
      normalizedRawUrl,
      unwrappedUrl,
      resolvedUrl: unwrappedUrl,
      effectiveEndpoint: unwrappedUrl,
      resolutionChain: [unwrappedUrl],
      resolutionMethod: "internal-facebook-link-ignored",
      endpointConfidence: "high",
      warnings,
      errors,
      isFacebookWrapper,
      isInternalFacebook: true,
      isShortener
    });
  }

  let redirectAnalysis = null;
  let resolvedUrl = unwrappedUrl;
  let resolutionMethod = wrapperAnalysis?.usedWrapper ? "wrapper-unwrapped" : "normalized";
  let endpointConfidence = wrapperAnalysis?.usedWrapper || !isShortener ? "medium" : "low";

  try {
    redirectAnalysis = await analyzeRedirects(source);
    if (redirectAnalysis?.resolvedUrl) {
      resolvedUrl = normalizeUrl(redirectAnalysis.resolvedUrl);
      resolutionMethod = redirectAnalysis.resolutionMethod || resolutionMethod;
      endpointConfidence = redirectAnalysis.fetchAttempted
        ? redirectAnalysis.fetchSucceeded && redirectAnalysis.resolvedUrl
          ? "high"
          : "low"
        : endpointConfidence;
    }

    for (const note of redirectAnalysis?.notes || []) {
      pushUnique(warnings, note);
    }
  } catch (error) {
    endpointConfidence = "low";
    pushUnique(warnings, "Endpoint resolution was limited because redirect probing failed.");
    errors.push(error?.message || "Redirect probing failed.");
  }

  const resolutionChain = compactChain([
    ...(wrapperAnalysis?.chain || []),
    ...(redirectAnalysis?.redirectChain || []),
    resolvedUrl
  ]);

  if (isShortener && resolutionChain.length <= 1) {
    endpointConfidence = "low";
    pushUnique(warnings, "Shortened URL could not be resolved to a final endpoint.");
  }

  return buildEndpointResult({
    rawUrl: source,
    normalizedRawUrl,
    unwrappedUrl,
    resolvedUrl,
    redirectAnalysis,
    effectiveEndpoint: resolvedUrl || unwrappedUrl || normalizedRawUrl,
    resolutionChain,
    resolutionMethod,
    endpointConfidence,
    warnings,
    errors,
    isFacebookWrapper,
    isInternalFacebook: false,
    isShortener
  });
}

export function isInternalFacebookUrl(rawUrl) {
  return isFacebookHost(safeHostname(rawUrl));
}

function buildEndpointResult(input) {
  const effectiveEndpoint = input.effectiveEndpoint || input.resolvedUrl || input.unwrappedUrl || input.normalizedRawUrl || "";
  const effectiveDomain = safeHostname(effectiveEndpoint) || "";
  const registrableDomain = getRegistrableDomain(effectiveDomain);

  return {
    rawUrl: input.rawUrl,
    normalizedRawUrl: input.normalizedRawUrl,
    unwrappedUrl: input.unwrappedUrl,
    resolvedUrl: input.resolvedUrl,
    effectiveEndpoint,
    effectiveDomain,
    registrableDomain,
    isFacebookWrapper: Boolean(input.isFacebookWrapper),
    isInternalFacebook: Boolean(input.isInternalFacebook),
    isShortener: Boolean(input.isShortener),
    redirectAnalysis: input.redirectAnalysis || null,
    endpointConfidence: input.endpointConfidence || "low",
    resolutionMethod: input.resolutionMethod || "unknown",
    resolutionChain: compactChain(input.resolutionChain || []),
    warnings: unique(input.warnings || []),
    errors: unique(input.errors || [])
  };
}

function buildEmptyResult(rawUrl, method, errors) {
  return buildEndpointResult({
    rawUrl,
    normalizedRawUrl: "",
    unwrappedUrl: "",
    resolvedUrl: "",
    effectiveEndpoint: "",
    resolutionMethod: method,
    endpointConfidence: "low",
    warnings: [],
    errors,
    isFacebookWrapper: false,
    isInternalFacebook: false,
    isShortener: false,
    resolutionChain: []
  });
}

function isFacebookHost(hostname) {
  return FACEBOOK_HOST_PATTERN.test(String(hostname || "").toLowerCase());
}

function safelyNormalize(rawUrl) {
  try {
    return normalizeUrl(rawUrl);
  } catch {
    return String(rawUrl || "").trim();
  }
}

function compactChain(values) {
  const chain = [];
  for (const value of values) {
    const normalized = safelyNormalize(value);
    if (normalized && chain[chain.length - 1] !== normalized) {
      chain.push(normalized);
    }
  }
  return chain;
}

function pushUnique(list, value) {
  const text = String(value || "").trim();
  if (text && !list.includes(text)) {
    list.push(text);
  }
}

function unique(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}
