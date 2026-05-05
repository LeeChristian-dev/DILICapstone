const DEDUCTION_RULES = [
  {
    id: "googleSafeBrowsingFlagged",
    category: "provider_reputation",
    deduction: 70,
    label: "Google Safe Browsing flagged the URL."
  },
  {
    id: "urlhausFlagged",
    category: "provider_reputation",
    deduction: 60,
    label: "URLhaus flagged the URL as malicious or suspicious."
  },
  {
    id: "domainPreviouslyFlagged",
    category: "provider_reputation",
    deduction: 10,
    label: "This domain was flagged locally in an earlier analysis."
  },
  {
    id: "wrapperToExternalDestination",
    category: "endpoint_resolution",
    deduction: 6,
    label: "A Facebook or tracking wrapper concealed an external destination."
  },
  {
    id: "shortenedUrl",
    category: "endpoint_resolution",
    deduction: 8,
    label: "The URL uses a shortening service."
  },
  {
    id: "shortenerToUnrelatedDomain",
    category: "redirect_behavior",
    deduction: 8,
    label: "A shortened URL redirects to an unrelated external domain."
  },
  {
    id: "obfuscatedUrl",
    category: "obfuscation",
    deduction: 10,
    label: "The URL contains encoded or obfuscated indicators."
  },
  {
    id: "usernamePasswordTrick",
    category: "obfuscation",
    deduction: 24,
    label: "The URL uses a username-style segment that can hide the true host."
  },
  {
    id: "suspiciousTld",
    category: "technical_security",
    deduction: 12,
    label: "The URL uses a TLD often abused in phishing campaigns."
  },
  {
    id: "textMismatch",
    category: "display_mismatch",
    deduction: 12,
    label: "The visible link text suggests a different destination domain."
  },
  {
    id: "suspiciousPath",
    category: "content_context",
    deduction: 12,
    label: "The destination path contains phishing or credential-themed keywords."
  },
  {
    id: "excessiveQueryComplexity",
    category: "technical_security",
    deduction: 4,
    label: "The destination URL uses an unusually complex query string."
  },
  {
    id: "excessiveSubdomainDepth",
    category: "technical_security",
    deduction: 5,
    label: "The destination uses unusually deep subdomains."
  },
  {
    id: "crossDomainRedirectChain",
    category: "redirect_behavior",
    deduction: 16,
    label: "The redirect chain hands the user across different domains."
  },
  {
    id: "redirectChainToDifferentRegistrantLikeTarget",
    category: "redirect_behavior",
    deduction: 6,
    label: "The redirect chain ends on a different registrable domain than it started on."
  },
  {
    id: "trackingHopToUnrelatedDomain",
    category: "redirect_behavior",
    deduction: 6,
    label: "A tracking or wrapper hop leads to a different external domain."
  },
  {
    id: "suspiciousRedirectPattern",
    category: "redirect_behavior",
    deduction: 18,
    label: "The redirect chain uses a pattern commonly seen in deceptive links."
  },
  {
    id: "integrityHashMismatch",
    category: "post_integrity",
    deduction: 50,
    label: "The post hyperlink changed after the original baseline was stored."
  }
];

const CATEGORY_CAPS = {
  provider_reputation: 90,
  endpoint_resolution: 20,
  redirect_behavior: 25,
  obfuscation: 30,
  display_mismatch: 25,
  post_integrity: 60,
  content_context: 20,
  technical_security: 15
};

const COMBINATION_RULES = [
  {
    id: "shortenerRedirectCombo",
    deduction: 10,
    label: "A shortened URL is combined with suspicious redirect behavior.",
    when(features) {
      return Boolean(
        features.shortenedUrl &&
        (
          features.suspiciousRedirectPattern ||
          features.shortenerToUnrelatedDomain ||
          (features.multipleRedirects && Number(features.redirectCount || 0) >= 4)
        )
      );
    }
  },
  {
    id: "wrapperMismatchCombo",
    deduction: 10,
    label: "A wrapped link concealed a destination that does not match the visible text.",
    when(features) {
      return Boolean(features.wrapperToExternalDestination && features.textMismatch);
    }
  },
  {
    id: "providerRedirectCombo",
    deduction: 10,
    label: "Threat-intelligence flags are reinforced by suspicious redirect behavior.",
    when(features) {
      return Boolean((features.googleSafeBrowsingFlagged || features.urlhausFlagged) && (features.crossDomainRedirectChain || features.suspiciousRedirectPattern));
    }
  },
  {
    id: "integrityRedirectCombo",
    deduction: 15,
    label: "The link changed and now uses suspicious redirect behavior.",
    when(features) {
      return Boolean(features.integrityHashMismatch && (features.suspiciousRedirectPattern || features.wrapperToExternalDestination));
    }
  },
  {
    id: "obfuscationRedirectCombo",
    deduction: 10,
    label: "Obfuscation indicators are combined with redirect-based concealment.",
    when(features) {
      return Boolean(features.obfuscatedUrl && (features.wrapperToExternalDestination || features.suspiciousRedirectPattern));
    }
  }
];

const MITIGATION_RULES = [
  {
    id: "trustedEndpointMitigation",
    credit: 18,
    label: "The resolved destination is a trusted endpoint and did not show strong contradictory warning signs.",
    when(features) {
      return Boolean(features.trustedEndpointMitigationEligible);
    }
  }
];

export const SAFETY_SCORE_BANDS = {
  SAFE_MIN: 90,
  LOW_CAUTION_MIN: 75,
  CAUTION_MIN: 60,
  SUSPICIOUS_MIN: 40
};

/**
 * Calculate a transparent weighted safety score from collected link features.
 * @param {object} features
 * @returns {{ score: number, totalDeduction: number, deductions: Array<{ id: string, label: string, deduction: number, triggered: boolean }> }}
 */
export function calculateSafetyScore(features = {}) {
  const deductions = [];
  const categoryTotals = {};

  for (const rule of DEDUCTION_RULES) {
    const triggered = Boolean(features[rule.id]);
    const appliedDeduction = triggered ? rule.deduction : 0;

    if (triggered) {
      addCategoryDeduction(categoryTotals, rule.category, rule.deduction);
    }

    deductions.push({
      id: rule.id,
      label: rule.label,
      deduction: appliedDeduction,
      triggered
    });
  }

  const redirectCount = Number(features.redirectCount || 0);
  let redirectDeduction = 0;
  let redirectLabel = "No material redirect chain was detected.";

  if (redirectCount === 1) {
    redirectLabel = "The URL uses a single redirect hop, which is common and only mildly informative.";
  } else if (redirectCount >= 2 && redirectCount <= 3) {
    redirectLabel = "The URL uses a short redirect chain, which is common in marketing and analytics links.";
  } else if (redirectCount >= 4 && redirectCount <= 5) {
    redirectDeduction = 6;
    redirectLabel = "The URL uses a longer redirect chain than usual.";
  } else if (redirectCount > 5) {
    redirectDeduction = 12;
    redirectLabel = "The URL uses an unusually long redirect chain.";
  }

  addCategoryDeduction(categoryTotals, "redirect_behavior", redirectDeduction);
  deductions.push({
    id: "redirectCount",
    label: redirectLabel,
    deduction: redirectDeduction,
    triggered: redirectDeduction > 0
  });

  for (const rule of COMBINATION_RULES) {
    const triggered = Boolean(rule.when(features));
    const appliedDeduction = triggered ? rule.deduction : 0;

    if (triggered) {
      addCategoryDeduction(categoryTotals, inferRuleCategory(rule.id), rule.deduction);
    }

    deductions.push({
      id: rule.id,
      label: rule.label,
      deduction: appliedDeduction,
      triggered
    });
  }

  for (const rule of MITIGATION_RULES) {
    const triggered = Boolean(rule.when(features));
    const appliedCredit = triggered ? rule.credit : 0;

    if (triggered) {
      addCategoryDeduction(categoryTotals, "technical_security", -rule.credit);
    }

    deductions.push({
      id: rule.id,
      label: rule.label,
      deduction: triggered ? -appliedCredit : 0,
      triggered
    });
  }

  const cappedCategoryDeductions = {};
  let totalDeduction = 0;

  for (const [category, value] of Object.entries(categoryTotals)) {
    const cappedValue = clamp(value, 0, CATEGORY_CAPS[category] ?? 100);
    cappedCategoryDeductions[category] = cappedValue;
    totalDeduction += cappedValue;
  }

  const boundedTotalDeduction = clamp(totalDeduction, 0, 100);
  const score = clamp(100 - boundedTotalDeduction, 0, 100);

  return {
    score,
    totalDeduction: boundedTotalDeduction,
    categoryDeductions: cappedCategoryDeductions,
    deductions
  };
}

/**
 * Convert a numeric score into the extension's safety classification.
 * @param {number} score
 * @returns {"Safe" | "Low Caution" | "Caution" | "Suspicious" | "High Risk" | "Unverified"}
 */
export function classifySafetyScore(score) {
  const value = Number(score);

  if (!Number.isFinite(value)) {
    return "Unverified";
  }

  if (value >= SAFETY_SCORE_BANDS.SAFE_MIN) {
    return "Safe";
  }

  if (value >= SAFETY_SCORE_BANDS.LOW_CAUTION_MIN) {
    return "Low Caution";
  }

  if (value >= SAFETY_SCORE_BANDS.CAUTION_MIN) {
    return "Caution";
  }

  if (value >= SAFETY_SCORE_BANDS.SUSPICIOUS_MIN) {
    return "Suspicious";
  }

  return "High Risk";
}

function addCategoryDeduction(categoryTotals, category, deduction) {
  if (!deduction) {
    return;
  }

  const key = category || "technical_security";
  categoryTotals[key] = (categoryTotals[key] || 0) + deduction;
}

function inferRuleCategory(ruleId) {
  if (String(ruleId || "").includes("Redirect")) {
    return "redirect_behavior";
  }

  if (String(ruleId || "").includes("integrity")) {
    return "post_integrity";
  }

  if (String(ruleId || "").includes("Mismatch")) {
    return "display_mismatch";
  }

  return "technical_security";
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}
