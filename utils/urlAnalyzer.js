const DEFAULT_BASE_URL = self.location?.origin || "https://example.invalid";

const SHORTENER_HOSTS = new Set([
  "bit.ly",
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
  "bitly.com",
  "bl.ink"
]);

const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "click",
  "work",
  "gq",
  "ml",
  "cf",
  "tk",
  "top",
  "xyz",
  "cam",
  "support",
  "country",
  "download"
]);

const TRACKING_PARAMS = new Set([
  "fbclid",
  "gclid",
  "yclid",
  "mc_cid",
  "mc_eid",
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content",
  "__cft__",
  "__tn__",
  "h",
  "eid",
  "paipv",
  "ref",
  "refsrc",
  "mibextid"
]);

const REDIRECT_PARAM_NAMES = [
  "url",
  "u",
  "target",
  "dest",
  "destination",
  "redirect",
  "redirect_url",
  "redirect_uri",
  "redir",
  "continue",
  "next",
  "r",
  "link",
  "to",
  "out",
  "goto"
];

const FACEBOOK_REDIRECT_HOSTS = new Set([
  "l.facebook.com",
  "lm.facebook.com",
  "m.facebook.com",
  "facebook.com",
  "www.facebook.com"
]);

const GENERIC_DISPLAY_TEXT_PATTERNS = [
  /^click here$/i,
  /^learn more$/i,
  /^read more$/i,
  /^open link$/i,
  /^open$/i,
  /^visit$/i,
  /^continue$/i,
  /^tap here$/i,
  /^go here$/i,
  /^view more$/i,
  /^watch now$/i,
  /^buy now$/i,
  /^sign in$/i
];

const SUSPICIOUS_PATH_TOKEN_PATTERNS = [
  "login",
  "signin",
  "verify",
  "verification",
  "secure",
  "account",
  "wallet",
  "invoice",
  "payment",
  "confirm",
  "update",
  "recovery",
  "unlock",
  "password",
  "auth",
  "banking",
  "webscr",
  "reset",
  "claim"
];

const SUSPICIOUS_QUERY_KEYS = new Set([
  "token",
  "session",
  "auth",
  "login",
  "password",
  "verify",
  "verification",
  "account",
  "redirect",
  "redirect_uri",
  "continue",
  "next",
  "dest",
  "destination",
  "return",
  "callback"
]);

const TRUSTED_ENDPOINT_DOMAINS = new Set([
  "monday.com",
  "securitybank.com",
  "shopee.com",
  "shopee.ph",
  "tiktok.com",
  "lazada.com.ph",
  "lazada.com",
  "youtube.com",
  "youtu.be",
  "instagram.com",
  "facebook.com",
  "messenger.com"
]);

/**
 * Normalize a URL for stable hashing and comparisons.
 * @param {string} rawUrl
 * @param {{ unwrapWrappers?: boolean, stripTracking?: boolean }} options
 * @returns {string}
 */
export function normalizeUrl(rawUrl, options = {}) {
  const unwrapWrappers = options.unwrapWrappers !== false;
  const stripTracking = options.stripTracking !== false;
  const candidate = unwrapWrappers ? unwrapKnownRedirectWrappers(rawUrl).finalUrl : rawUrl;
  return canonicalizeUrl(candidate, { stripTracking });
}

/**
 * Canonicalize a URL without recursively unwrapping redirect wrappers.
 * @param {string} rawUrl
 * @param {{ stripTracking?: boolean }} options
 * @returns {string}
 */
export function canonicalizeUrl(rawUrl, options = {}) {
  if (!rawUrl) {
    throw new Error("Missing URL.");
  }

  const stripTracking = options.stripTracking !== false;
  const url = new URL(rawUrl, DEFAULT_BASE_URL);

  url.hash = "";
  url.protocol = url.protocol.toLowerCase();
  url.hostname = url.hostname.toLowerCase();

  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }

  if (stripTracking) {
    for (const param of [...url.searchParams.keys()]) {
      if (TRACKING_PARAMS.has(param.toLowerCase())) {
        url.searchParams.delete(param);
      }
    }
  }

  const entries = [...url.searchParams.entries()].sort((left, right) => {
    if (left[0] === right[0]) {
      return left[1].localeCompare(right[1]);
    }

    return left[0].localeCompare(right[0]);
  });

  url.search = "";
  for (const [key, value] of entries) {
    url.searchParams.append(key, value);
  }

  if (url.pathname !== "/") {
    url.pathname = url.pathname.replace(/\/+$/, "") || "/";
  }

  return url.toString();
}

/**
 * Unwrap known redirect wrappers like Facebook link shims and generic redirect parameters.
 * @param {string} rawUrl
 * @param {{ maxDepth?: number }} options
 * @returns {{ finalUrl: string, chain: string[], wrapperHosts: string[], usedWrapper: boolean, wrapperToExternalDestination: boolean, notes: string[] }}
 */
export function unwrapKnownRedirectWrappers(rawUrl, options = {}) {
  const maxDepth = Number(options.maxDepth || 5);
  const chain = [];
  const wrapperHosts = [];
  const notes = [];
  const visited = new Set();

  let currentUrl = toAbsoluteUrl(rawUrl);
  let usedWrapper = false;
  let wrapperToExternalDestination = false;

  if (!currentUrl) {
    throw new Error("Missing URL.");
  }

  for (let depth = 0; depth < maxDepth; depth += 1) {
    const normalizedCurrent = safelyCanonicalize(currentUrl, { stripTracking: false }) || currentUrl;
    if (visited.has(normalizedCurrent)) {
      notes.push("Wrapper unwrapping stopped because the same URL appeared twice.");
      break;
    }

    visited.add(normalizedCurrent);
    chain.push(normalizedCurrent);

    const currentParsed = safeUrl(normalizedCurrent);
    const target = extractLikelyRedirectTarget(normalizedCurrent);

    if (!currentParsed || !target) {
      break;
    }

    const nextCanonical = safelyCanonicalize(target, { stripTracking: false }) || target;
    const currentDomain = getRegistrableDomain(currentParsed.hostname);
    const nextDomain = getRegistrableDomain(safeHostname(nextCanonical));
    const wrapperDetected = isKnownWrapperHost(currentParsed.hostname) || looksLikeWrapperPath(currentParsed.pathname) || hasWrapperQuery(currentParsed);

    if (!wrapperDetected) {
      break;
    }

    usedWrapper = true;
    wrapperHosts.push(currentParsed.hostname.toLowerCase());

    if (currentDomain && nextDomain && currentDomain !== nextDomain) {
      wrapperToExternalDestination = true;
      if (isFacebookWrapperHost(currentParsed.hostname)) {
        notes.push("A Facebook wrapper concealed an external destination.");
      }
    }

    currentUrl = nextCanonical;
  }

  if (chain.length === 0) {
    chain.push(currentUrl);
  }

  return {
    finalUrl: currentUrl,
    chain,
    wrapperHosts: unique(wrapperHosts),
    usedWrapper,
    wrapperToExternalDestination,
    notes
  };
}

/**
 * Detect whether a URL uses a well-known shortening service.
 * @param {string} rawUrl
 * @returns {boolean}
 */
export function isShortenedUrl(rawUrl) {
  try {
    const url = new URL(rawUrl, DEFAULT_BASE_URL);
    return isShortenerHost(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Detect whether a host belongs to a known shortening service.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isShortenerHost(hostname) {
  return SHORTENER_HOSTS.has(String(hostname || "").toLowerCase());
}

/**
 * Detect whether the TLD is in a local suspicious list.
 * @param {string} rawUrl
 * @returns {boolean}
 */
export function hasSuspiciousTld(rawUrl) {
  try {
    const url = new URL(rawUrl, DEFAULT_BASE_URL);
    const parts = url.hostname.toLowerCase().split(".");
    const tld = parts[parts.length - 1] || "";
    return SUSPICIOUS_TLDS.has(tld);
  } catch {
    return false;
  }
}

/**
 * Detect basic encoding and obfuscation signals in a URL string.
 * @param {string} rawUrl
 * @param {string} normalizedUrl
 * @returns {{ flagged: boolean, signals: string[], suspiciousEncoding: boolean, usernamePasswordTrick: boolean }}
 */
export function detectObfuscationIndicators(rawUrl, normalizedUrl = rawUrl) {
  const source = String(rawUrl || "");
  const normalizedSource = String(normalizedUrl || "");
  const signals = [];

  if ((source.match(/%[0-9a-f]{2}/gi) || []).length >= 2) {
    signals.push("percent-encoding");
  }

  if (/%25[0-9a-f]{2}/i.test(source)) {
    signals.push("double-encoding");
  }

  if (/xn--/i.test(normalizedSource)) {
    signals.push("punycode");
  }

  if (/https?:.*https?:/i.test(source) || /https?%3a/i.test(source)) {
    signals.push("nested-url");
  }

  if (/[A-Za-z0-9+/]{24,}={0,2}/.test(source)) {
    signals.push("long-token");
  }

  if ((source.match(/[0-9]/g) || []).length >= 12) {
    signals.push("digit-heavy");
  }

  const parsed = safeUrl(source) || safeUrl(normalizedSource);
  if (parsed?.username || parsed?.password || /https?:\/\/[^/?#\s]+@/i.test(source)) {
    signals.push("username-segment");
  }

  const usernamePasswordTrick = signals.includes("username-segment");
  const suspiciousEncoding = signals.includes("percent-encoding") || signals.includes("double-encoding") || signals.includes("nested-url");

  return {
    flagged: signals.length > 0,
    signals,
    suspiciousEncoding,
    usernamePasswordTrick
  };
}

/**
 * Compare displayed link text against the actual destination host.
 * @param {string} displayText
 * @param {string} rawUrl
 * @returns {{ mismatch: boolean, displayDomain: string | null, actualDomain: string | null, genericText: boolean, displayTextLooksLikeDomain: boolean }}
 */
export function detectDomainMismatch(displayText, rawUrl) {
  const actualDomain = safeHostname(rawUrl);
  const displayAnalysis = analyzeDisplayText(displayText);
  const displayDomain = displayAnalysis.domain;

  if (!displayDomain || !actualDomain || displayAnalysis.genericText || isShortenerHost(displayDomain)) {
    return {
      mismatch: false,
      displayDomain,
      actualDomain,
      genericText: displayAnalysis.genericText,
      displayTextLooksLikeDomain: displayAnalysis.looksLikeDomain
    };
  }

  const displayRegistrable = getRegistrableDomain(displayDomain);
  const actualRegistrable = getRegistrableDomain(actualDomain);

  return {
    mismatch: Boolean(displayRegistrable && actualRegistrable && displayRegistrable !== actualRegistrable),
    displayDomain,
    actualDomain,
    genericText: displayAnalysis.genericText,
    displayTextLooksLikeDomain: displayAnalysis.looksLikeDomain
  };
}

/**
 * Run local heuristic checks against the URL and related anchor text.
 * @param {{ rawUrl: string, displayedText?: string }} input
 * @returns {{
 *   normalizedUrl: string,
 *   rawComparableUrl: string,
 *   unwrappedUrl: string,
 *   shortenedUrl: boolean,
 *   suspiciousTld: boolean,
 *   obfuscatedUrl: boolean,
 *   obfuscationSignals: string[],
 *   suspiciousEncoding: boolean,
 *   usernamePasswordTrick: boolean,
 *   excessiveQueryComplexity: boolean,
 *   queryComplexity: number,
 *   queryParamCount: number,
 *   suspiciousQueryKeys: string[],
 *   suspiciousPath: boolean,
 *   suspiciousPathTokens: string[],
 *   nestedUrlInPath: boolean,
 *   excessiveSubdomainDepth: boolean,
 *   subdomainDepth: number,
 *   textMismatch: boolean,
 *   displayDomain: string | null,
 *   actualDomain: string | null,
 *   displayTextLooksLikeDomain: boolean,
 *   genericDisplayText: boolean,
 *   httpsEndpoint: boolean,
 *   finalHostname: string,
 *   finalRegistrableDomain: string,
 *   trustedEndpoint: boolean,
 *   trustedEndpointMatch: string | null,
 *   usesKnownWrapper: boolean,
 *   wrapperToExternalDestination: boolean,
 *   wrapperChain: string[],
 *   wrapperHosts: string[]
 * }}
 */
export function analyzeUrlFeatures(input) {
  const rawUrl = String(input.rawUrl || "");
  const wrapperAnalysis = unwrapKnownRedirectWrappers(rawUrl);
  const normalizedUrl = normalizeUrl(rawUrl);
  const rawComparableUrl = normalizeUrl(rawUrl, { unwrapWrappers: false });
  const unwrappedUrl = normalizeUrl(wrapperAnalysis.finalUrl, { unwrapWrappers: false });
  const comparisonUrl = unwrappedUrl || normalizedUrl;
  const obfuscation = detectObfuscationIndicators(comparisonUrl, comparisonUrl);
  const mismatch = detectDomainMismatch(input.displayedText || "", comparisonUrl);
  const parsed = safeUrl(comparisonUrl);
  const finalHostname = safeHostname(comparisonUrl) || "";
  const finalRegistrableDomain = getRegistrableDomain(finalHostname);
  const trustedEndpointMatch = isTrustedEndpointDomain(finalHostname) ? finalRegistrableDomain : null;
  const queryAnalysis = analyzeQueryComplexity(parsed);
  const pathAnalysis = analyzePathRisk(parsed);
  const subdomainDepth = getSubdomainDepth(parsed?.hostname);

  return {
    normalizedUrl,
    rawComparableUrl,
    unwrappedUrl,
    shortenedUrl: isShortenedUrl(comparisonUrl),
    suspiciousTld: hasSuspiciousTld(comparisonUrl),
    obfuscatedUrl: obfuscation.flagged,
    obfuscationSignals: obfuscation.signals,
    suspiciousEncoding: obfuscation.suspiciousEncoding,
    usernamePasswordTrick: obfuscation.usernamePasswordTrick,
    excessiveQueryComplexity: queryAnalysis.flagged,
    queryComplexity: queryAnalysis.score,
    queryParamCount: queryAnalysis.paramCount,
    suspiciousQueryKeys: queryAnalysis.suspiciousKeys,
    suspiciousPath: pathAnalysis.flagged,
    suspiciousPathTokens: pathAnalysis.tokens,
    nestedUrlInPath: pathAnalysis.nestedUrlInPath,
    excessiveSubdomainDepth: subdomainDepth >= 3,
    subdomainDepth,
    textMismatch: mismatch.mismatch,
    displayDomain: mismatch.displayDomain,
    actualDomain: mismatch.actualDomain,
    displayTextLooksLikeDomain: mismatch.displayTextLooksLikeDomain,
    genericDisplayText: mismatch.genericText,
    httpsEndpoint: parsed?.protocol === "https:",
    finalHostname,
    finalRegistrableDomain,
    trustedEndpoint: Boolean(trustedEndpointMatch),
    trustedEndpointMatch,
    usesKnownWrapper: wrapperAnalysis.usedWrapper,
    wrapperToExternalDestination: wrapperAnalysis.wrapperToExternalDestination,
    wrapperChain: wrapperAnalysis.chain,
    wrapperHosts: wrapperAnalysis.wrapperHosts
  };
}

/**
 * Extract a likely redirect target from wrapper parameters or path segments.
 * @param {string} rawUrl
 * @returns {string | null}
 */
export function extractLikelyRedirectTarget(rawUrl) {
  const parsed = safeUrl(rawUrl);
  if (!parsed) {
    return null;
  }

  for (const name of REDIRECT_PARAM_NAMES) {
    const nested = parsed.searchParams.get(name);
    if (!nested) {
      continue;
    }

    const candidate = normalizeNestedTarget(nested, parsed.origin);
    if (candidate && !isSameComparableUrl(candidate, parsed.toString())) {
      return candidate;
    }
  }

  const combinedPath = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  const embeddedMatch = combinedPath.match(/(https?:\/\/[^\s"'<>]+)/i) || combinedPath.match(/(https?%3A%2F%2F[^\s"'<>]+)/i);
  if (embeddedMatch) {
    const candidate = normalizeNestedTarget(embeddedMatch[1], parsed.origin);
    if (candidate && !isSameComparableUrl(candidate, parsed.toString())) {
      return candidate;
    }
  }

  return null;
}

/**
 * Return the lowercase hostname for a URL string.
 * @param {string} rawUrl
 * @returns {string | null}
 */
export function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl, DEFAULT_BASE_URL).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Extract a domain-like token from user-visible text.
 * @param {string} displayText
 * @returns {string | null}
 */
export function extractDomainFromText(displayText) {
  const source = String(displayText || "").trim();
  if (!source) {
    return null;
  }

  const match = source.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:\b|\/)/i);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Reduce a hostname to a registrable-domain approximation.
 * @param {string} hostname
 * @returns {string}
 */
export function getRegistrableDomain(hostname) {
  const parts = String(hostname || "").split(".").filter(Boolean);
  if (parts.length <= 2) {
    return parts.join(".");
  }

  const compoundSuffix = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (["co.uk", "com.au", "com.br", "co.jp", "co.kr", "com.sg"].includes(compoundSuffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

/**
 * Identify whether a host belongs to Facebook's wrapper system.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isFacebookWrapperHost(hostname) {
  return FACEBOOK_REDIRECT_HOSTS.has(String(hostname || "").toLowerCase());
}

function isTrustedEndpointDomain(hostname) {
  const registrableDomain = getRegistrableDomain(hostname);
  return Boolean(registrableDomain) && TRUSTED_ENDPOINT_DOMAINS.has(registrableDomain);
}

function analyzeDisplayText(displayText) {
  const source = String(displayText || "").trim();
  const normalizedSource = source.replace(/\s+/g, " ").trim();
  const genericText = !normalizedSource || GENERIC_DISPLAY_TEXT_PATTERNS.some((pattern) => pattern.test(normalizedSource));
  const domain = extractDomainFromText(normalizedSource);

  return {
    genericText,
    domain,
    looksLikeDomain: Boolean(domain)
  };
}

function analyzeQueryComplexity(parsedUrl) {
  if (!parsedUrl) {
    return {
      flagged: false,
      score: 0,
      paramCount: 0,
      suspiciousKeys: []
    };
  }

  const entries = [...parsedUrl.searchParams.entries()];
  const longValues = entries.filter(([, value]) => value.length >= 40).length;
  const suspiciousKeys = entries
    .map(([key]) => key.toLowerCase())
    .filter((key) => SUSPICIOUS_QUERY_KEYS.has(key));
  const encodedParams = entries.filter(([, value]) => /%[0-9a-f]{2}/i.test(value)).length;
  const totalLength = entries.reduce((sum, [key, value]) => sum + key.length + value.length, 0);
  const score = entries.length + (longValues * 2) + (suspiciousKeys.length * 2) + encodedParams + (totalLength >= 180 ? 3 : 0);

  return {
    flagged: score >= 10 || entries.length >= 7,
    score,
    paramCount: entries.length,
    suspiciousKeys: unique(suspiciousKeys)
  };
}

function analyzePathRisk(parsedUrl) {
  if (!parsedUrl) {
    return {
      flagged: false,
      tokens: [],
      nestedUrlInPath: false
    };
  }

  const pathSource = `${parsedUrl.pathname} ${parsedUrl.search}`.toLowerCase();
  const tokens = SUSPICIOUS_PATH_TOKEN_PATTERNS.filter((token) => pathSource.includes(token));
  const nestedUrlInPath = /https?:\/\//i.test(parsedUrl.pathname) || /https?%3a%2f%2f/i.test(parsedUrl.pathname);

  return {
    flagged: tokens.length > 0 || nestedUrlInPath,
    tokens,
    nestedUrlInPath
  };
}

function getSubdomainDepth(hostname) {
  const parts = String(hostname || "").split(".").filter(Boolean);
  if (parts.length <= 2) {
    return 0;
  }

  const registrable = getRegistrableDomain(hostname);
  const registrableParts = registrable ? registrable.split(".").length : 0;
  return Math.max(0, parts.length - registrableParts);
}

function isKnownWrapperHost(hostname) {
  const normalized = String(hostname || "").toLowerCase();
  if (!normalized) {
    return false;
  }

  return isFacebookWrapperHost(normalized) || /(^|\.)(redirect|redir|tracking|trk|out|go)\./i.test(normalized);
}

function looksLikeWrapperPath(pathname) {
  const source = String(pathname || "").toLowerCase();
  return source.includes("redirect") || source.includes("redir") || source.includes("away") || source.includes("out") || source.endsWith("/l.php");
}

function hasWrapperQuery(parsedUrl) {
  for (const name of REDIRECT_PARAM_NAMES) {
    if (parsedUrl.searchParams.has(name)) {
      return true;
    }
  }

  return false;
}

function normalizeNestedTarget(value, origin) {
  let candidate = String(value || "").trim();
  if (!candidate) {
    return null;
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const decoded = tryDecode(candidate);
    if (decoded === candidate) {
      break;
    }
    candidate = decoded;
  }

  try {
    const parsed = new URL(candidate, origin || DEFAULT_BASE_URL);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
}

function isSameComparableUrl(left, right) {
  const normalizedLeft = safelyCanonicalize(left, { stripTracking: false }) || String(left || "");
  const normalizedRight = safelyCanonicalize(right, { stripTracking: false }) || String(right || "");
  return normalizedLeft === normalizedRight;
}

function safeUrl(rawUrl) {
  try {
    return new URL(rawUrl, DEFAULT_BASE_URL);
  } catch {
    return null;
  }
}

function safelyCanonicalize(rawUrl, options) {
  try {
    return canonicalizeUrl(rawUrl, options);
  } catch {
    return null;
  }
}

function toAbsoluteUrl(rawUrl) {
  const parsed = safeUrl(rawUrl);
  return parsed ? parsed.toString() : null;
}

function tryDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}
