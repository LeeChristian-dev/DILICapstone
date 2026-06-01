export const SAFETY_SCORE_BANDS = {
  SAFE_MIN: 80,
  SUSPICIOUS_MIN: 50
};

const PROVIDER_MAX_DEDUCTION = 30;
const HEURISTIC_RAW_TOTAL_CAP = 30;
const HEURISTIC_MAX_DEDUCTION = 10;

const HEURISTIC_CATEGORY_CAPS = {
  url_structure: 8,
  redirect_behavior: 8,
  link_manipulation: 7,
  facebook_post_behavior: 7
};

const SEVERITY_POINTS = {
  mild: 1,
  moderate: 2,
  high: 3
};

const HEURISTIC_RULES = [
  {
    id: "suspiciousTld",
    category: "url_structure",
    severity: "moderate",
    label: "The URL uses a top-level domain that DILI treats as higher risk."
  },
  {
    id: "excessiveSubdomainDepth",
    category: "url_structure",
    severity: "mild",
    label: "The destination uses unusually deep subdomains."
  },
  {
    id: "obfuscatedUrl",
    category: "url_structure",
    severity: "high",
    label: "The URL contains encoded or obfuscated indicators."
  },
  {
    id: "usernamePasswordTrick",
    category: "url_structure",
    severity: "high",
    label: "The URL uses a username-style segment that can hide the true host."
  },
  {
    id: "suspiciousPath",
    category: "url_structure",
    severity: "moderate",
    label: "The destination path contains credential, payment, prize, or account-themed keywords."
  },
  {
    id: "excessiveQueryComplexity",
    category: "url_structure",
    severity: "mild",
    label: "The destination URL uses an unusually complex query string."
  },
  {
    id: "shortenedUrl",
    category: "redirect_behavior",
    severity: "mild",
    label: "The URL uses a shortening service."
  },
  {
    id: "wrapperToExternalDestination",
    category: "redirect_behavior",
    severity: "moderate",
    label: "A Facebook or tracking wrapper concealed an external destination."
  },
  {
    id: "crossDomainRedirectChain",
    category: "redirect_behavior",
    severity: "moderate",
    label: "The link passes through more than one website before reaching the final destination."
  },
  {
    id: "shortenerToUnrelatedDomain",
    category: "redirect_behavior",
    severity: "high",
    label: "A shortened URL redirects to an unrelated external domain."
  },
  {
    id: "trackingHopToUnrelatedDomain",
    category: "redirect_behavior",
    severity: "moderate",
    label: "A tracking or wrapper hop leads to a different external domain."
  },
  {
    id: "suspiciousRedirectPattern",
    category: "redirect_behavior",
    severity: "high",
    label: "The redirect pattern makes the final destination harder to verify."
  },
  {
    id: "redirectChainToDifferentRegistrantLikeTarget",
    category: "redirect_behavior",
    severity: "moderate",
    label: "The redirect chain ends on a different registrable domain than it started on."
  },
  {
    id: "textMismatch",
    category: "link_manipulation",
    severity: "high",
    label: "The visible link text suggests a different destination domain."
  },
  {
    id: "suspiciousEncoding",
    category: "link_manipulation",
    severity: "high",
    label: "The URL uses suspicious encoding that can conceal the destination."
  },
  {
    id: "linkManipulationObfuscatedUrl",
    featureId: "obfuscatedUrl",
    category: "link_manipulation",
    severity: "high",
    label: "Obfuscation indicators can make the real destination harder to inspect."
  },
  {
    id: "linkManipulationExcessiveQueryComplexity",
    featureId: "excessiveQueryComplexity",
    category: "link_manipulation",
    severity: "mild",
    label: "Complex query parameters can obscure the meaningful destination."
  },
  {
    id: "nestedOrEncodedUrl",
    category: "link_manipulation",
    severity: "moderate",
    label: "Nested or encoded URL indicators were found."
  },
  {
    id: "integrityHashMismatch",
    category: "facebook_post_behavior",
    severity: "high",
    label: "The post hyperlink changed after the original baseline was stored."
  },
  {
    id: "linkInsertedAfterBaseline",
    category: "facebook_post_behavior",
    severity: "high",
    label: "A link was inserted after a stored no-link baseline."
  },
  {
    id: "postIntegrityEvent",
    category: "facebook_post_behavior",
    severity: "moderate",
    label: "A post-integrity event was recorded for this link."
  },
  {
    id: "changedLinkDestination",
    category: "facebook_post_behavior",
    severity: "high",
    label: "The post appears to have changed to a different link destination."
  },
  {
    id: "suspiciousLinkInjection",
    category: "facebook_post_behavior",
    severity: "high",
    label: "The post behavior matches a suspicious link-injection signal."
  },
  {
    id: "postTextUnrelatedToDestination",
    category: "facebook_post_behavior",
    severity: "moderate",
    label: "The post text appears unrelated to the destination."
  }
];

/**
 * Calculate DILI's weighted safety score. Numeric thresholds are DILI project
 * thresholds for this extension, not official provider risk thresholds.
 * @param {object} features
 * @param {object[]} providerResults
 * @returns {{ score: number, totalDeduction: number, providerDeductions: object, heuristicRawCategoryTotals: object, heuristicCategoryDeductions: object, heuristicRawTotal: number, heuristicScaledDeduction: number, categoryDeductions: object, categoryAudit: object, deductions: Array<{ id: string, category: string, label: string, deduction: number, triggered: boolean }> }}
 */
export function calculateSafetyScore(features = {}, providerResults = []) {
  const explicitProviderResults = Array.isArray(providerResults) && providerResults.length > 0
    ? providerResults
    : Array.isArray(features?.providerResults)
      ? features.providerResults
      : [];
  const providerAudit = calculateProviderDeductions(explicitProviderResults);
  const heuristicAudit = calculateHeuristicRawScore(features);
  const providerDeductions = providerAudit.providerDeductions;
  const providerTotal = roundScore(
    providerDeductions.gsb +
    providerDeductions.urlhaus +
    providerDeductions.virustotal
  );
  const totalDeduction = roundScore(clamp(providerTotal + heuristicAudit.heuristicScaledDeduction, 0, 100));
  const score = roundScore(clamp(100 - totalDeduction, 0, 100));
  const categoryDeductions = {
    gsb: providerDeductions.gsb,
    urlhaus: providerDeductions.urlhaus,
    virustotal: providerDeductions.virustotal,
    ...heuristicAudit.heuristicCategoryDeductions
  };
  const categoryAudit = {
    gsb: providerAudit.providerAudit.gsb,
    urlhaus: providerAudit.providerAudit.urlhaus,
    virustotal: providerAudit.providerAudit.virustotal,
    ...heuristicAudit.categoryAudit
  };

  return {
    score,
    totalDeduction,
    providerDeductions,
    providerDeductionTotal: providerTotal,
    providerAudit: providerAudit.providerAudit,
    heuristicRawCategoryTotals: heuristicAudit.heuristicRawCategoryTotals,
    heuristicCategoryDeductions: heuristicAudit.heuristicCategoryDeductions,
    heuristicRawTotal: heuristicAudit.heuristicRawTotal,
    heuristicScaledDeduction: heuristicAudit.heuristicScaledDeduction,
    categoryDeductions,
    categoryAudit,
    deductions: [
      ...providerAudit.deductions,
      ...heuristicAudit.deductions
    ],
    scoreFormula: "100 - (D_GSB + D_URLHaus + D_VT + D_H)",
    baselineScore: 100,
    ruleScore: score,
    ruleDeductionTotal: totalDeduction
  };
}

export function calculateProviderDeductions(providerResults = []) {
  const providers = normalizeProviderResults(providerResults);
  const gsb = providers.find((item) => item.provider === "gsb") || {};
  const urlhaus = providers.find((item) => item.provider === "urlhaus") || {};
  const vt = providers.find((item) => item.provider === "virustotal") || {};
  const vtAudit = calculateVirusTotalDeduction(vt);
  const gsbTerminal = getProviderTerminalStatus(gsb);
  const urlhausTerminal = getProviderTerminalStatus(urlhaus);
  const gsbDeduction = gsbTerminal.completed && gsb.flagged === true ? PROVIDER_MAX_DEDUCTION : 0;
  const urlhausDeduction = urlhausTerminal.completed && urlhaus.flagged === true ? PROVIDER_MAX_DEDUCTION : 0;

  return {
    providerDeductions: {
      gsb: gsbDeduction,
      urlhaus: urlhausDeduction,
      virustotal: vtAudit.deduction
    },
    providerAudit: {
      gsb: {
        provider: "gsb",
        status: gsbTerminal.status,
        completed: gsbTerminal.completed,
        flagged: gsb.flagged === true,
        maxDeduction: PROVIDER_MAX_DEDUCTION,
        appliedDeduction: gsbDeduction,
        note: gsbDeduction > 0
          ? "Google Safe Browsing completed and reported a threat match."
          : gsbTerminal.completed
            ? "Google Safe Browsing completed clean."
            : "Google Safe Browsing did not complete; no deduction was applied and the limitation remains visible."
      },
      urlhaus: {
        provider: "urlhaus",
        status: urlhausTerminal.status,
        completed: urlhausTerminal.completed,
        flagged: urlhaus.flagged === true,
        maxDeduction: PROVIDER_MAX_DEDUCTION,
        appliedDeduction: urlhausDeduction,
        note: urlhausDeduction > 0
          ? "URLHaus completed and reported a known malware match."
          : urlhausTerminal.completed
            ? "URLHaus completed clean."
            : "URLHaus did not complete; no deduction was applied and the limitation remains visible."
      },
      virustotal: vtAudit
    },
    deductions: [
      {
        id: "gsbProviderDeduction",
        category: "gsb",
        label: gsbDeduction > 0
          ? "Google Safe Browsing reported a threat match."
          : "Google Safe Browsing did not add a provider deduction.",
        deduction: gsbDeduction,
        triggered: gsbDeduction > 0
      },
      {
        id: "urlhausProviderDeduction",
        category: "urlhaus",
        label: urlhausDeduction > 0
          ? "URLHaus reported a known malware match."
          : "URLHaus did not add a provider deduction.",
        deduction: urlhausDeduction,
        triggered: urlhausDeduction > 0
      },
      {
        id: "virustotalProviderDeduction",
        category: "virustotal",
        label: vtAudit.label,
        deduction: vtAudit.deduction,
        triggered: vtAudit.deduction > 0
      }
    ]
  };
}

export function calculateVirusTotalDeduction(vtProviderResult = {}) {
  const terminal = getProviderTerminalStatus(vtProviderResult);
  const stats = getVirusTotalStats(vtProviderResult);
  const hits = stats.maliciousCount + stats.suspiciousCount;
  const primaryTotal = hits + stats.harmlessCount + stats.undetectedCount + stats.timeoutCount;
  const fallbackTotal = hits + stats.harmlessCount + stats.undetectedCount;
  const totalEngines = primaryTotal > 0 ? primaryTotal : fallbackTotal;
  let deduction = 0;
  let note = "";
  let label = "";

  if (!terminal.completed) {
    note = "VirusTotal did not complete; no deduction was applied and pending/limitation handling remains active.";
  } else if (totalEngines <= 0) {
    note = "VirusTotal completed without usable engine totals; no deduction was applied.";
  } else if (hits === 0) {
    note = "VirusTotal reported zero malicious or suspicious detections.";
  } else if (hits <= 3) {
    deduction = 20;
    note = "VirusTotal reported 1-3 malicious or suspicious detections; DILI applies a fixed 20-point warning deduction.";
  } else {
    deduction = Math.min(PROVIDER_MAX_DEDUCTION, 20 + ((hits / totalEngines) * PROVIDER_MAX_DEDUCTION));
    note = `VirusTotal reported ${hits} malicious/suspicious detection${hits === 1 ? "" : "s"} across ${totalEngines || "unknown"} engine${totalEngines === 1 ? "" : "s"}; DILI applies the 20-point base plus proportional detection-ratio formula capped at 30 points.`;
  }

  deduction = roundScore(deduction);
  label = deduction > 0
    ? hits <= 3
      ? `VirusTotal reported ${hits} malicious/suspicious detection${hits === 1 ? "" : "s"}; fixed 20-point VirusTotal warning deduction applied.`
      : `VirusTotal reported ${hits} malicious/suspicious detection${hits === 1 ? "" : "s"} across ${totalEngines || "unknown"} engine${totalEngines === 1 ? "" : "s"}; 20-point base plus proportional detection-ratio formula applied.`
    : note || "VirusTotal did not add a provider deduction.";

  return {
    provider: "virustotal",
    status: terminal.status,
    completed: terminal.completed,
    flagged: vtProviderResult?.flagged === true,
    maxDeduction: PROVIDER_MAX_DEDUCTION,
    appliedDeduction: deduction,
    deduction,
    maliciousCount: stats.maliciousCount,
    suspiciousCount: stats.suspiciousCount,
    harmlessCount: stats.harmlessCount,
    undetectedCount: stats.undetectedCount,
    timeoutCount: stats.timeoutCount,
    hits,
    totalEngines,
    note,
    label
  };
}

export function calculateHeuristicRawScore(features = {}) {
  const normalizedFeatures = applyHeuristicMitigations(features);
  const rawCategoryTotals = createZeroedHeuristicCategories();
  const positiveRawCategoryTotals = createZeroedHeuristicCategories();
  const deductions = [];

  for (const rule of HEURISTIC_RULES) {
    const featureId = rule.featureId || rule.id;
    const triggered = isHeuristicTriggered(rule, normalizedFeatures, features);
    const rawPoints = triggered ? classifyHeuristicSeverity(rule.severity) : 0;

    if (triggered) {
      rawCategoryTotals[rule.category] += rawPoints;
      positiveRawCategoryTotals[rule.category] += rawPoints;
    }

    deductions.push({
      id: rule.id,
      category: rule.category,
      label: rule.label,
      deduction: rawPoints,
      rawPoints,
      triggered,
      severity: rule.severity,
      sourceFeature: featureId
    });
  }

  const redirectCountPoints = getRedirectCountSeverityPoints(normalizedFeatures.redirectCount);
  if (redirectCountPoints > 0) {
    rawCategoryTotals.redirect_behavior += redirectCountPoints;
    positiveRawCategoryTotals.redirect_behavior += redirectCountPoints;
  }
  deductions.push({
    id: "redirectCount",
    category: "redirect_behavior",
    label: getRedirectCountLabel(normalizedFeatures.redirectCount),
    deduction: redirectCountPoints,
    rawPoints: redirectCountPoints,
    triggered: redirectCountPoints > 0,
    severity: redirectCountPoints >= 3 ? "high" : redirectCountPoints >= 2 ? "moderate" : redirectCountPoints === 1 ? "mild" : "none"
  });

  const cappedRawCategoryTotals = {};
  const heuristicCategoryDeductions = {};
  const categoryAudit = {};
  let heuristicRawTotal = 0;

  for (const category of Object.keys(HEURISTIC_CATEGORY_CAPS)) {
    const rawTotal = roundScore(rawCategoryTotals[category] || 0);
    const cap = HEURISTIC_CATEGORY_CAPS[category];
    const cappedRaw = roundScore(clamp(rawTotal, 0, cap));
    const scaledDeduction = roundScore((cappedRaw / HEURISTIC_RAW_TOTAL_CAP) * HEURISTIC_MAX_DEDUCTION);

    cappedRawCategoryTotals[category] = cappedRaw;
    heuristicCategoryDeductions[category] = scaledDeduction;
    heuristicRawTotal += cappedRaw;
    categoryAudit[category] = {
      rawTotal,
      positiveDeductions: positiveRawCategoryTotals[category] || 0,
      mitigationCredits: 0,
      cap,
      cappedRawTotal: cappedRaw,
      appliedDeduction: scaledDeduction,
      maxScaledDeduction: HEURISTIC_MAX_DEDUCTION,
      wasCapped: rawTotal > cap,
      wasFloored: rawTotal < 0 && cappedRaw === 0
    };
  }

  heuristicRawTotal = roundScore(clamp(heuristicRawTotal, 0, HEURISTIC_RAW_TOTAL_CAP));
  const heuristicScaledDeduction = roundScore(
    Math.min(HEURISTIC_MAX_DEDUCTION, (heuristicRawTotal / HEURISTIC_RAW_TOTAL_CAP) * HEURISTIC_MAX_DEDUCTION)
  );

  return {
    heuristicRawCategoryTotals: cappedRawCategoryTotals,
    heuristicRawPositiveCategoryTotals: positiveRawCategoryTotals,
    heuristicCategoryDeductions,
    heuristicRawTotal,
    heuristicScaledDeduction,
    categoryAudit,
    deductions
  };
}

export function classifyHeuristicSeverity(severity) {
  return SEVERITY_POINTS[String(severity || "").toLowerCase()] || 0;
}

export function getProviderTerminalStatus(provider = {}) {
  const status = normalizeProviderStatus(provider);
  const completed = Boolean(
    provider?.checked === true &&
    (
      status === "checked" ||
      status === "completed" ||
      (provider?.flagged === true && status !== "pending")
    )
  );
  const terminal = Boolean(
    completed ||
    status === "not-configured" ||
    status === "skipped" ||
    status === "unsupported_protocol" ||
    status === "retry-budget-exhausted" ||
    status === "rate-limited" ||
    status === "timeout" ||
    status === "error" ||
    status === "parse-error"
  );

  return {
    status,
    completed,
    terminal,
    pending: status === "pending",
    limited: terminal && !completed
  };
}

/**
 * Convert a numeric score into the extension's safety classification.
 * @param {number} score
 * @returns {"Safe" | "Suspicious" | "High Risk" | "Unverified"}
 */
export function classifySafetyScore(score) {
  const value = Number(score);

  if (!Number.isFinite(value)) {
    return "Unverified";
  }

  if (value >= SAFETY_SCORE_BANDS.SAFE_MIN) {
    return "Safe";
  }

  if (value >= SAFETY_SCORE_BANDS.SUSPICIOUS_MIN) {
    return "Suspicious";
  }

  return "High Risk";
}

function isHeuristicTriggered(rule, normalizedFeatures, originalFeatures) {
  if (rule.id === "postIntegrityEvent") {
    const event = String(originalFeatures?.postIntegrityEvent || normalizedFeatures?.postIntegrityEvent || "");
    return Boolean(event && event !== "link_inserted_after_no_link_baseline");
  }

  if (rule.id === "nestedOrEncodedUrl") {
    return hasNestedOrEncodedUrlSignal(originalFeatures) || hasNestedOrEncodedUrlSignal(normalizedFeatures);
  }

  return Boolean(normalizedFeatures[rule.featureId || rule.id]);
}

function applyHeuristicMitigations(features = {}) {
  const mitigated = { ...(features || {}) };
  const explainableRedirectMitigation = Boolean(
    mitigated.trustedEndpointMitigationEligible ||
    mitigated.trustedRedirectDestination ||
    mitigated.knownCampaignRedirectToTrustedDestination ||
    mitigated.knownBrandedCampaignRedirect ||
    mitigated.knownGoogleFormsRedirect ||
    mitigated.googleFormsViaGenericShortener ||
    mitigated.knownBrandAliasRedirect ||
    mitigated.knownBrandedDomainAlias ||
    mitigated.cleanResolvedMarketingLink ||
    mitigated.mainstreamResolvedShortlink ||
    mitigated.knownShortenerOwnerRedirect
  );

  if (explainableRedirectMitigation) {
    mitigated.wrapperToExternalDestination = false;
    mitigated.crossDomainRedirectChain = false;
    mitigated.shortenerToUnrelatedDomain = false;
    mitigated.trackingHopToUnrelatedDomain = false;
    mitigated.suspiciousRedirectPattern = false;
    mitigated.redirectChainToDifferentRegistrantLikeTarget = false;
    mitigated.textMismatch = false;
    mitigated.excessiveQueryComplexity = false;
  }

  if (mitigated.cleanResolvedMarketingLink || mitigated.knownBrandAliasRedirect || mitigated.knownBrandedCampaignRedirect) {
    mitigated.suspiciousPath = false;
    mitigated.obfuscatedUrl = false;
  }

  if (mitigated.knownGoogleFormsRedirect || mitigated.googleFormsViaGenericShortener) {
    mitigated.obfuscatedUrl = false;
    mitigated.excessiveQueryComplexity = false;
  }

  return mitigated;
}

function normalizeProviderResults(providerResults = []) {
  const values = Array.isArray(providerResults) ? providerResults : [];
  return ["gsb", "urlhaus", "virustotal"].map((providerName) => (
    values.find((item) => String(item?.provider || "").toLowerCase() === providerName) || { provider: providerName }
  ));
}

function normalizeProviderStatus(provider = {}) {
  return String(provider?.details?.status || (provider?.checked ? "checked" : "") || "").toLowerCase();
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
    maliciousCount: firstFiniteCount(
      details.maliciousCount,
      details.malicious,
      provider.maliciousCount,
      provider.malicious,
      stats.malicious
    ),
    suspiciousCount: firstFiniteCount(
      details.suspiciousCount,
      details.suspicious,
      provider.suspiciousCount,
      provider.suspicious,
      stats.suspicious
    ),
    harmlessCount: firstFiniteCount(
      details.harmlessCount,
      details.harmless,
      provider.harmlessCount,
      provider.harmless,
      stats.harmless
    ),
    undetectedCount: firstFiniteCount(
      details.undetectedCount,
      details.undetected,
      provider.undetectedCount,
      provider.undetected,
      stats.undetected
    ),
    timeoutCount: firstFiniteCount(
      details.timeoutCount,
      details.timeout,
      provider.timeoutCount,
      provider.timeout,
      stats.timeout
    )
  };
}

function firstFiniteCount(...values) {
  for (const value of values) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric >= 0) {
      return numeric;
    }
  }

  return 0;
}

function createZeroedHeuristicCategories() {
  return Object.keys(HEURISTIC_CATEGORY_CAPS).reduce((result, category) => {
    result[category] = 0;
    return result;
  }, {});
}

function getRedirectCountSeverityPoints(redirectCountValue) {
  const redirectCount = Number(redirectCountValue || 0);

  if (!Number.isFinite(redirectCount) || redirectCount <= 1) {
    return 0;
  }

  if (redirectCount <= 3) {
    return SEVERITY_POINTS.mild;
  }

  if (redirectCount <= 5) {
    return SEVERITY_POINTS.moderate;
  }

  return SEVERITY_POINTS.high;
}

function getRedirectCountLabel(redirectCountValue) {
  const redirectCount = Number(redirectCountValue || 0);

  if (!Number.isFinite(redirectCount) || redirectCount <= 1) {
    return "No material redirect-chain length deduction was applied.";
  }

  if (redirectCount <= 3) {
    return "The URL uses a short redirect chain.";
  }

  if (redirectCount <= 5) {
    return "The URL uses a longer redirect chain than usual.";
  }

  return "The URL uses an unusually long redirect chain.";
}

function hasNestedOrEncodedUrlSignal(features = {}) {
  const signals = Array.isArray(features?.obfuscationSignals)
    ? features.obfuscationSignals.map((item) => String(item || "").toLowerCase())
    : [];

  return Boolean(
    features?.nestedUrl === true ||
    features?.nestedURL === true ||
    features?.encodedUrl === true ||
    features?.encodedURL === true ||
    signals.includes("nested-url") ||
    signals.includes("double-encoding") ||
    signals.includes("encoded-url")
  );
}

function roundScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Number(numeric.toFixed(2));
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}
