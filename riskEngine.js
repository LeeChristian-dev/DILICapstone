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
    deduction: 40,
    label: "This domain was flagged locally in an earlier analysis."
  },
  {
    id: "shortenedUrl",
    deduction: 20,
    label: "The URL uses a shortening service."
  },
  {
    id: "obfuscatedUrl",
    deduction: 15,
    label: "The URL contains encoded or obfuscated indicators."
  },
  {
    id: "suspiciousTld",
    deduction: 20,
    label: "The URL uses a TLD often abused in phishing campaigns."
  },
  {
    id: "textMismatch",
    deduction: 30,
    label: "Displayed link text does not match the actual destination domain."
  },
  {
    id: "integrityHashMismatch",
    deduction: 50,
    label: "The post hyperlink changed after the original baseline was stored."
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
  let redirectLabel = "No redirect indicators were detected.";

  if (redirectCount >= 1 && redirectCount <= 2) {
    redirectDeduction = 10;
    redirectLabel = "The URL appears to use a short redirect chain.";
  } else if (redirectCount >= 3 && redirectCount <= 4) {
    redirectDeduction = 25;
    redirectLabel = "The URL appears to use a moderate redirect chain.";
  } else if (redirectCount > 4) {
    redirectDeduction = 40;
    redirectLabel = "The URL appears to use a long redirect chain.";
  }

  totalDeduction += redirectDeduction;
  deductions.push({
    id: "redirectCount",
    label: redirectLabel,
    deduction: redirectDeduction,
    triggered: redirectDeduction > 0
  });

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
