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
  "link"
];

/**
 * Analyze obvious redirect patterns in a URL and optionally attempt a safe HEAD request.
 * @param {string} rawUrl
 * @returns {Promise<{ redirectCount: number, chain: string[], resolvedUrl: string, resolutionMethod: string, notes: string[], fetchAttempted: boolean, fetchAllowed: boolean }>}
 */
export async function analyzeRedirects(rawUrl) {
  const notes = [];
  const chain = [];
  const visited = new Set();
  let currentUrl = rawUrl;

  for (let depth = 0; depth < 6; depth += 1) {
    if (visited.has(currentUrl)) {
      notes.push("Redirect parsing stopped because the same URL appeared twice.");
      break;
    }

    visited.add(currentUrl);
    chain.push(currentUrl);

    const nextUrl = extractNestedRedirectTarget(currentUrl);
    if (!nextUrl) {
      break;
    }

    currentUrl = nextUrl;
  }

  const fetchResolution = await attemptHeadResolution(chain[chain.length - 1] || rawUrl);

  if (!fetchResolution.fetchAllowed) {
    notes.push("Network redirect resolution was skipped because cross-origin access is not guaranteed in this environment.");
  } else if (!fetchResolution.success) {
    notes.push(fetchResolution.note);
  } else if (fetchResolution.finalUrl && fetchResolution.finalUrl !== currentUrl) {
    chain.push(fetchResolution.finalUrl);
    currentUrl = fetchResolution.finalUrl;
  }

  return {
    redirectCount: Math.max(0, chain.length - 1),
    chain,
    resolvedUrl: currentUrl,
    resolutionMethod: fetchResolution.fetchAllowed ? fetchResolution.method : "heuristic-only",
    notes,
    fetchAttempted: fetchResolution.fetchAttempted,
    fetchAllowed: fetchResolution.fetchAllowed
  };
}

function extractNestedRedirectTarget(rawUrl) {
  try {
    const url = new URL(rawUrl);
    for (const name of REDIRECT_PARAM_NAMES) {
      const nested = url.searchParams.get(name);
      if (!nested) {
        continue;
      }

      const decoded = tryDecode(nested);
      try {
        return new URL(decoded, url.origin).toString();
      } catch {
        continue;
      }
    }
  } catch {
    return null;
  }

  return null;
}

async function attemptHeadResolution(rawUrl) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: false,
      method: "heuristic-only",
      note: "The redirect target could not be parsed as a URL."
    };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: false,
      method: "heuristic-only",
      note: "Only HTTP and HTTPS URLs are eligible for redirect probing."
    };
  }

  if (!self.fetch) {
    return {
      fetchAllowed: false,
      fetchAttempted: false,
      success: false,
      method: "heuristic-only",
      note: "Fetch is not available in the current extension context."
    };
  }

  try {
    const response = await fetch(url.toString(), {
      method: "HEAD",
      redirect: "follow",
      cache: "no-store"
    });

    return {
      fetchAllowed: true,
      fetchAttempted: true,
      success: true,
      method: "head-follow",
      finalUrl: response.url || url.toString(),
      note: ""
    };
  } catch (error) {
    return {
      fetchAllowed: true,
      fetchAttempted: true,
      success: false,
      method: "head-follow",
      note: `Redirect probing failed: ${error.message || "unknown error"}.`
    };
  }
}

function tryDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}