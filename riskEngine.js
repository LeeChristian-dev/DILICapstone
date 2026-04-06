const DEDUCTION_RULES = [
  {
    id: "googleSafeBrowsingFlagged",
    deduction: 70,
    label: "Google Safe Browsing flagged the URL."
  },
  {
    id: "urlhausFlagged",
    deduction: 60,
    label: "URLhaus flagged the URL as malicious or suspicious."
  },
  {
    id: "domainPreviouslyFlagged",
    deduction: 10,
    label: "This domain was flagged locally in an earlier analysis."
  },
  {
    id: "wrapperToExternalDestination",
    deduction: 12,
    label: "A Facebook or tracking wrapper concealed an external destination."
  },
  {
    id: "shortenedUrl",
    deduction: 16,
    label: "The URL uses a shortening service."
  },
  {
    id: "shortenerToUnrelatedDomain",
    deduction: 14,
    label: "A shortened URL redirects to an unrelated external domain."
  },
  {
    id: "obfuscatedUrl",
    deduction: 14,
    label: "The URL contains encoded or obfuscated indicators."
  },
  {
    id: "usernamePasswordTrick",
    deduction: 24,
    label: "The URL uses a username-style segment that can hide the true host."
  },
  {
    id: "suspiciousTld",
    deduction: 20,
    label: "The URL uses a TLD often abused in phishing campaigns."
  },
  {
    id: "textMismatch",
    deduction: 15,
    label: "The visible link text suggests a different destination domain."
  },
  {
    id: "suspiciousPath",
    deduction: 12,
    label: "The destination path contains phishing or credential-themed keywords."
  },
  {
    id: "excessiveQueryComplexity",
    deduction: 8,
    label: "The destination URL uses an unusually complex query string."
  },
  {
    id: "excessiveSubdomainDepth",
    deduction: 8,
    label: "The destination uses unusually deep subdomains."
  },
  {
    id: "multipleRedirects",
    deduction: 12,
    label: "The link passes through multiple redirects before reaching the final destination."
  },
  {
    id: "crossDomainRedirectChain",
    deduction: 16,
    label: "The redirect chain hands the user across different domains."
  },
  {
    id: "redirectChainToDifferentRegistrantLikeTarget",
    deduction: 10,
    label: "The redirect chain ends on a different registrable domain than it started on."
  },
  {
    id: "trackingHopToUnrelatedDomain",
    deduction: 10,
    label: "A tracking or wrapper hop leads to a different external domain."
  },
  {
    id: "suspiciousRedirectPattern",
    deduction: 18,
    label: "The redirect chain uses a pattern commonly seen in deceptive links."
  },
  {
    id: "integrityHashMismatch",
    deduction: 50,
    label: "The post hyperlink changed after the original baseline was stored."
  }
];

const COMBINATION_RULES = [
  {
    id: "shortenerRedirectCombo",
    deduction: 10,
    label: "A shortened URL is combined with suspicious redirect behavior.",
    when(features) {
      return Boolean(features.shortenedUrl && (features.multipleRedirects || features.suspiciousRedirectPattern || features.shortenerToUnrelatedDomain));
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

/**
 * Calculate a transparent weighted safety score from collected link features.
 * @param {object} features
 * @returns {{ score: number, totalDeduction: number, deductions: Array<{ id: string, label: string, deduction: number, triggered: boolean }> }}
 */
export function calculateSafetyScore(features = {}) {
  const deductions = [];
  let totalDeduction = 0;

  for (const rule of DEDUCTION_RULES) {
    const triggered = Boolean(features[rule.id]);
    const appliedDeduction = triggered ? rule.deduction : 0;

    if (triggered) {
      totalDeduction += rule.deduction;
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
  } else if (redirectCount === 2) {
    redirectDeduction = 6;
    redirectLabel = "The URL uses a short redirect chain.";
  } else if (redirectCount >= 3 && redirectCount <= 4) {
    redirectDeduction = 12;
    redirectLabel = "The URL uses a moderate redirect chain.";
  } else if (redirectCount > 4) {
    redirectDeduction = 18;
    redirectLabel = "The URL uses a long redirect chain.";
  }

  totalDeduction += redirectDeduction;
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
      totalDeduction += rule.deduction;
    }

    deductions.push({
      id: rule.id,
      label: rule.label,
      deduction: appliedDeduction,
      triggered
    });
  }

  const score = clamp(100 - totalDeduction, 0, 100);

  return {
    score,
    totalDeduction,
    deductions
  };
}

/**
 * Convert a numeric score into the extension's safety classification.
 * @param {number} score
 * @returns {"Safe" | "Suspicious" | "High Risk"}
 */
export function classifySafetyScore(score) {
  if (score >= 80) {
    return "Safe";
  }

  if (score >= 50) {
    return "Suspicious";
  }

  return "High Risk";
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}
