const DEDUCTION_RULES = [
{
  id: "domainPreviouslyFlagged",
  category: "provider_reputation",
  deduction: 4,
  label: "This domain matched a previous provider-flagged result in this browser."
},
  {
    id: "wrapperToExternalDestination",
    category: "endpoint_resolution",
    deduction: 3,
    label: "A Facebook or tracking wrapper concealed an external destination."
  },
  {
    id: "shortenedUrl",
    category: "endpoint_resolution",
    deduction: 4,
    label: "The URL uses a shortening service."
  },
  {
    id: "shortenerToUnrelatedDomain",
    category: "redirect_behavior",
    deduction: 4,
    label: "A shortened URL redirects to an unrelated external domain."
  },
  {
    id: "obfuscatedUrl",
    category: "obfuscation",
    deduction: 5,
    label: "The URL contains encoded or obfuscated indicators."
  },
  {
    id: "usernamePasswordTrick",
    category: "obfuscation",
    deduction: 8,
    label: "The URL uses a username-style segment that can hide the true host."
  },
  {
    id: "suspiciousTld",
    category: "technical_security",
    deduction: 4,
    label: "The URL uses a TLD often abused in phishing campaigns."
  },
  {
    id: "textMismatch",
    category: "display_mismatch",
    deduction: 4,
    label: "The visible link text suggests a different destination domain."
  },
  {
    id: "suspiciousPath",
    category: "content_context",
    deduction: 4,
    label: "The destination path contains phishing or credential-themed keywords."
  },
  {
    id: "excessiveQueryComplexity",
    category: "technical_security",
    deduction: 1,
    label: "The destination URL uses an unusually complex query string."
  },
  {
    id: "excessiveSubdomainDepth",
    category: "technical_security",
    deduction: 2,
    label: "The destination uses unusually deep subdomains."
  },
{
  id: "crossDomainRedirectChain",
  category: "redirect_behavior",
  deduction: 5,
  label: "The link passes through more than one website before reaching the final destination."
},
  {
    id: "redirectChainToDifferentRegistrantLikeTarget",
    category: "redirect_behavior",
    deduction: 4,
    label: "The redirect chain ends on a different registrable domain than it started on."
  },
  {
    id: "trackingHopToUnrelatedDomain",
    category: "redirect_behavior",
    deduction: 4,
    label: "A tracking or wrapper hop leads to a different external domain."
  },
{
  id: "suspiciousRedirectPattern",
  category: "redirect_behavior",
  deduction: 6,
  label: "The redirect pattern makes the final destination harder to verify."
},
  {
    id: "integrityHashMismatch",
    category: "post_integrity",
    deduction: 6,
    label: "The post hyperlink changed after the original baseline was stored."
  }
];

const CATEGORY_CAPS = {
  provider_reputation: 4,
  endpoint_resolution: 10,
  redirect_behavior: 18,
  obfuscation: 18,
  display_mismatch: 10,
  post_integrity: 12,
  content_context: 8,
  technical_security: 10
};

const COMBINATION_RULES = [
  {
    id: "shortenerCrossDomainRedirectCombo",
    category: "redirect_behavior",
    deduction: 4,
    label: "A shortened URL also redirects across domains.",
    when(features) {
      return Boolean(
        features.shortenedUrl &&
        (
          features.crossDomainRedirectChain ||
          features.shortenerToUnrelatedDomain ||
          features.redirectChainToDifferentRegistrantLikeTarget
        )
      );
    }
  },
  {
    id: "shortenerVisibleMismatchCombo",
    category: "display_mismatch",
    deduction: 4,
    label: "A shortened URL hides a destination that does not match the visible text.",
    when(features) {
      return Boolean(features.shortenedUrl && features.textMismatch);
    }
  },
  {
    id: "facebookWrapperShortenerExternalCombo",
    category: "endpoint_resolution",
    deduction: 4,
    label: "A Facebook wrapper and shortened URL add multiple layers before the external destination.",
    when(features) {
      return Boolean(
        features.shortenedUrl &&
        features.wrapperToExternalDestination &&
        (features.facebookWrapperUnwrapped || features.crossDomainRedirectChain || features.shortenerToUnrelatedDomain)
      );
    }
  },
  {
    id: "suspiciousPathHiddenDestinationCombo",
    category: "obfuscation",
    deduction: 6,
    label: "Credential, payment, or prize-themed path indicators are combined with hidden destination behavior.",
    when(features) {
      const redirectCount = Number(features.redirectCount || 0);
      return Boolean(
        features.suspiciousPath &&
        (
          features.shortenedUrl ||
          features.wrapperToExternalDestination ||
          features.crossDomainRedirectChain ||
          features.suspiciousRedirectPattern ||
          redirectCount > 0
        )
      );
    }
  },
  {
    id: "integrityLinkInjectionCombo",
    category: "post_integrity",
    deduction: 6,
    label: "A newly introduced link matches the post-integrity link-injection threat model.",
    when(features) {
      return Boolean(features.integrityHashMismatch && features.linkInsertedAfterBaseline);
    }
  },
  {
    id: "weakProviderStructuralHidingCombo",
    category: "provider_reputation",
    deduction: 4,
    label: "A weak reputation signal is combined with structural destination hiding.",
    when(features) {
      return Boolean(
        features.domainPreviouslyFlagged &&
        (
          features.shortenedUrl ||
          features.wrapperToExternalDestination ||
          features.crossDomainRedirectChain ||
          features.textMismatch ||
          features.obfuscatedUrl
        )
      );
    }
  },
  {
    id: "shortenerRedirectCombo",
    deduction: 4,
    label: "A shortened URL is combined with stronger warning signs.",
    when(features) {
      const redirectCount = Number(features.redirectCount || 0);

      return Boolean(
        features.shortenedUrl &&
        (
          features.googleSafeBrowsingFlagged ||
          features.urlhausFlagged ||
          features.virusTotalFlagged ||
          features.textMismatch ||
          features.suspiciousTld ||
          features.suspiciousPath ||
          features.usernamePasswordTrick ||
          features.integrityHashMismatch ||
          redirectCount >= 4
        )
      );
    }
  },
  {
    id: "wrapperMismatchCombo",
    deduction: 4,
    label: "A wrapped link concealed a destination that does not match the visible text.",
    when(features) {
      return Boolean(features.wrapperToExternalDestination && features.textMismatch);
    }
  },
  {
    id: "providerRedirectCombo",
    category: "provider_reputation",
    deduction: 4,
    label: "Threat-intelligence flags are reinforced by suspicious redirect behavior.",
    when(features) {
      return Boolean(
        (
          features.googleSafeBrowsingFlagged ||
          features.urlhausFlagged ||
          features.virusTotalFlagged
        ) &&
        (
          features.crossDomainRedirectChain ||
          features.suspiciousRedirectPattern
        )
      );
    }
  },
  {
    id: "integrityRedirectCombo",
    deduction: 6,
    label: "The link changed and now uses suspicious redirect behavior.",
    when(features) {
      return Boolean(features.integrityHashMismatch && (features.suspiciousRedirectPattern || features.wrapperToExternalDestination));
    }
  },
  {
    id: "obfuscationRedirectCombo",
    category: "obfuscation",
    deduction: 6,
    label: "Obfuscation indicators are combined with redirect-based concealment.",
    when(features) {
      const redirectCount = Number(features.redirectCount || 0);
      return Boolean(
        features.obfuscatedUrl &&
        (
          features.wrapperToExternalDestination ||
          features.suspiciousRedirectPattern ||
          features.crossDomainRedirectChain ||
          redirectCount > 0
        )
      );
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
  SAFE_MIN: 80,
  SUSPICIOUS_MIN: 50
};

/**
 * Calculate a transparent weighted safety score from collected link features.
 * @param {object} features
 * @returns {{ score: number, totalDeduction: number, categoryDeductions: object, categoryAudit: object, deductions: Array<{ id: string, category: string, label: string, deduction: number, triggered: boolean }> }}
 */
export function calculateSafetyScore(features = {}) {
  const deductions = [];
  const categoryTotals = {};
  const rawCategoryTotals = {};
  const rawCategoryPositiveDeductions = {};
  const rawCategoryMitigationCredits = {};

  for (const rule of DEDUCTION_RULES) {
    const triggered = Boolean(features[rule.id]);
    const appliedDeduction = triggered ? rule.deduction : 0;

    if (triggered) {
      addCategoryDeduction(categoryTotals, rule.category, rule.deduction);
      addCategoryAuditValue(rawCategoryTotals, rule.category, rule.deduction);
      addCategoryAuditValue(rawCategoryPositiveDeductions, rule.category, rule.deduction);
    }

    deductions.push({
      id: rule.id,
      category: rule.category,
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
    redirectDeduction = 4;
    redirectLabel = "The URL uses a longer redirect chain than usual.";
  } else if (redirectCount > 5) {
    redirectDeduction = 6;
    redirectLabel = "The URL uses an unusually long redirect chain.";
  }

  addCategoryDeduction(categoryTotals, "redirect_behavior", redirectDeduction);
  addCategoryAuditValue(rawCategoryTotals, "redirect_behavior", redirectDeduction);
  addCategoryAuditValue(rawCategoryPositiveDeductions, "redirect_behavior", redirectDeduction);
  deductions.push({
    id: "redirectCount",
    category: "redirect_behavior",
    label: redirectLabel,
    deduction: redirectDeduction,
    triggered: redirectDeduction > 0
  });

  for (const rule of COMBINATION_RULES) {
    const triggered = Boolean(rule.when(features));
    const appliedDeduction = triggered ? rule.deduction : 0;
    const category = rule.category || inferRuleCategory(rule.id);

    if (triggered) {
      addCategoryDeduction(categoryTotals, category, rule.deduction);
      addCategoryAuditValue(rawCategoryTotals, category, rule.deduction);
      addCategoryAuditValue(rawCategoryPositiveDeductions, category, rule.deduction);
    }

    deductions.push({
      id: rule.id,
      category,
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
      addCategoryAuditValue(rawCategoryTotals, "technical_security", -rule.credit);
      addCategoryAuditValue(rawCategoryMitigationCredits, "technical_security", rule.credit);
    }

    deductions.push({
      id: rule.id,
      category: "technical_security",
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

  const categoryAudit = {};

  for (const category of new Set([
    ...Object.keys(rawCategoryTotals),
    ...Object.keys(rawCategoryPositiveDeductions),
    ...Object.keys(rawCategoryMitigationCredits),
    ...Object.keys(cappedCategoryDeductions)
  ])) {
    const rawTotal = rawCategoryTotals[category] || 0;
    const positiveDeductions = rawCategoryPositiveDeductions[category] || 0;
    const mitigationCredits = rawCategoryMitigationCredits[category] || 0;
    const cap = CATEGORY_CAPS[category] ?? 100;
    const appliedDeduction = cappedCategoryDeductions[category] || 0;

    categoryAudit[category] = {
      rawTotal,
      positiveDeductions,
      mitigationCredits,
      cap,
      appliedDeduction,
      wasCapped: positiveDeductions > cap,
      wasFloored: rawTotal < 0 && appliedDeduction === 0
    };
  }

  const boundedTotalDeduction = clamp(totalDeduction, 0, 100);
  const score = clamp(100 - boundedTotalDeduction, 0, 100);

  return {
    score,
    totalDeduction: boundedTotalDeduction,
    categoryDeductions: cappedCategoryDeductions,
    categoryAudit,
    deductions
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

function addCategoryDeduction(categoryTotals, category, deduction) {
  if (!deduction) {
    return;
  }

  const key = category || "technical_security";
  categoryTotals[key] = (categoryTotals[key] || 0) + deduction;
}

function addCategoryAuditValue(target, category, value) {
  if (!value) {
    return;
  }

  const key = category || "technical_security";
  target[key] = (target[key] || 0) + value;
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
