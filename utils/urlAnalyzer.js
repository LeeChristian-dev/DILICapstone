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
  "utm_content"
]);

const FACEBOOK_REDIRECT_HOSTS = new Set([
  "l.facebook.com",
  "lm.facebook.com",
  "m.facebook.com"
]);

/**
 * Normalize a URL for stable hashing and comparisons.
 * @param {string} rawUrl
 * @returns {string}
 */
export function normalizeUrl(rawUrl) {
  if (!rawUrl) {
    throw new Error("Missing URL.");
  }

  const firstPass = new URL(rawUrl, location.origin);
  const unwrapped = unwrapFacebookRedirect(firstPass);
  const url = new URL(unwrapped);

  url.hash = "";
  url.protocol = url.protocol.toLowerCase();
  url.hostname = url.hostname.toLowerCase();

  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }

  for (const param of [...url.searchParams.keys()]) {
    if (TRACKING_PARAMS.has(param.toLowerCase())) {
      url.searchParams.delete(param);
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
 * Detect whether a URL uses a well-known shortening service.
 * @param {string} rawUrl
 * @returns {boolean}
 */
export function isShortenedUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return SHORTENER_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * Detect whether the TLD is in a local suspicious list.
 * @param {string} rawUrl
 * @returns {boolean}
 */
export function hasSuspiciousTld(rawUrl) {
  try {
    const url = new URL(rawUrl);
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
 * @returns {{ flagged: boolean, signals: string[] }}
 */
export function detectObfuscationIndicators(rawUrl) {
  const source = String(rawUrl || "");
  const signals = [];

  if (/%[0-9a-f]{2}/i.test(source)) {
    signals.push("percent-encoding");
  }

  if (/xn--/i.test(source)) {
    signals.push("punycode");
  }

  if (/@/.test(source)) {
    signals.push("username-segment");
  }

  if (/https?:.*https?:/i.test(source)) {
    signals.push("nested-url");
  }

  if ((source.match(/[0-9]/g) || []).length >= 10) {
    signals.push("digit-heavy");
  }

  return {
    flagged: signals.length > 0,
    signals
  };
}

/**
 * Compare displayed link text against the actual destination host.
 * @param {string} displayText
 * @param {string} rawUrl
 * @returns {{ mismatch: boolean, displayDomain: string | null, actualDomain: string | null }}
 */
export function detectDomainMismatch(displayText, rawUrl) {
  const actualDomain = safeHostname(rawUrl);
  const displayDomain = extractDomainFromText(displayText);

  if (!displayDomain || !actualDomain) {
    return {
      mismatch: false,
      displayDomain,
      actualDomain
    };
  }

  return {
    mismatch: getRegistrableDomain(displayDomain) !== getRegistrableDomain(actualDomain),
    displayDomain,
    actualDomain
  };
}

/**
 * Run local heuristic checks against the URL and related anchor text.
 * @param {{ rawUrl: string, displayedText?: string }} input
 * @returns {{ normalizedUrl: string, shortenedUrl: boolean, suspiciousTld: boolean, obfuscatedUrl: boolean, obfuscationSignals: string[], textMismatch: boolean, displayDomain: string | null, actualDomain: string | null }}
 */
export function analyzeUrlFeatures(input) {
  const normalizedUrl = normalizeUrl(input.rawUrl);
  const obfuscation = detectObfuscationIndicators(normalizedUrl);
  const mismatch = detectDomainMismatch(input.displayedText || "", normalizedUrl);

  return {
    normalizedUrl,
    shortenedUrl: isShortenedUrl(normalizedUrl),
    suspiciousTld: hasSuspiciousTld(normalizedUrl),
    obfuscatedUrl: obfuscation.flagged,
    obfuscationSignals: obfuscation.signals,
    textMismatch: mismatch.mismatch,
    displayDomain: mismatch.displayDomain,
    actualDomain: mismatch.actualDomain
  };
}

function unwrapFacebookRedirect(inputUrl) {
  if (!FACEBOOK_REDIRECT_HOSTS.has(inputUrl.hostname.toLowerCase())) {
    return inputUrl.toString();
  }

  const nested = inputUrl.searchParams.get("u") || inputUrl.searchParams.get("url");
  if (!nested) {
    return inputUrl.toString();
  }

  try {
    return decodeURIComponent(nested);
  } catch {
    return nested;
  }
}

function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function extractDomainFromText(displayText) {
  const source = String(displayText || "").trim();
  if (!source) {
    return null;
  }

  const match = source.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:\b|\/)/i);
  return match ? match[1].toLowerCase() : null;
}

function getRegistrableDomain(hostname) {
  const parts = String(hostname || "").split(".").filter(Boolean);
  if (parts.length <= 2) {
    return parts.join(".");
  }

  return parts.slice(-2).join(".");
}