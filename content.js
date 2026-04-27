(function initializeDili() {
  const MESSAGE_TYPES = {
    ANALYZE_LINK: "DILI_ANALYZE_LINK",
    REANALYZE_LINK: "DILI_REANALYZE_LINK",
    GET_POST_STATE: "DILI_GET_POST_STATE",
    SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
    GET_SCAN_STATE: "DILI_GET_SCAN_STATE",
    RESCAN_NOW: "DILI_RESCAN_NOW"
  };

  const POST_SELECTORS = [
    'div[role="article"]',
    'article',
    '[data-pagelet*="FeedUnit"]',
    '[aria-posinset]'
  ];
  const MAIN_POST_CONTENT_SELECTORS = [
    '[data-ad-preview="message"]',
    '[data-ad-comet-preview="message"]',
    '[data-testid="post_message"]',
    '[dir="auto"]'
  ];
  const EXCLUDED_CANDIDATE_CONTROL_PATTERNS = [
    /\blike\b/i,
    /\bcomment\b/i,
    /\breply\b/i,
    /\bshare\b/i,
    /\breaction\b/i,
    /\breact\b/i,
    /\bclose\b/i,
    /\bdismiss\b/i,
    /\bmenu\b/i,
    /\boptions\b/i,
    /\breport\b/i,
    /\bhide\b/i,
    /\bnext\b/i,
    /\bprevious\b/i,
    /\bprev\b/i,
    /\bcarousel\b/i,
    /\bslide\b/i
  ];

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
  const POST_PROCESS_CONCURRENCY = 4;

  const pendingPosts = new Set();
  const postIdCache = new WeakMap();
  const postSignatureCache = new WeakMap();
  const selectedPostLinkCache = new Map();
  const observedPostIds = new Map();
  const clickWarningState = {
    activeToken: 0,
    overlay: null,
    keydownHandler: null,
    focusTarget: null
  };
  const scanRuntimeState = {
    enabled: true,
    runtimeListenerBound: false,
    clickInterceptionBound: false,
    scrollListenerBound: false
  };
  let flushTimer = null;
  let rescanTimer = null;
  let observer = null;

  start().catch((error) => {
    console.warn("[DILI] Failed to initialize content script", error);
  });

  async function start() {
    if (!location.hostname.includes("facebook.com")) {
      return;
    }

    bindRuntimeListeners();
    scanRuntimeState.enabled = await getScanEnabledState();
    resetOwnedUiArtifacts();

    if (!scanRuntimeState.enabled) {
      console.debug("[DILI] Content script loaded with protection disabled.");
      stopScanning();
      return;
    }

    console.debug("[DILI] Content script initialized.");
    bindClickInterception();
    initialScan();
    observeFeed();
    bindScrollRescan();
  }

  function bindRuntimeListeners() {
    if (scanRuntimeState.runtimeListenerBound) {
      return;
    }

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.type !== MESSAGE_TYPES.RESCAN_NOW) {
        return false;
      }

      if (!scanRuntimeState.enabled) {
        sendResponse({ ok: true, skipped: true, reason: "Scanning disabled." });
        return false;
      }

      forceRescan()
        .then(() => sendResponse({ ok: true }))
        .catch((error) => sendResponse({ ok: false, error: error.message || "Re-scan failed." }));

      return true;
    });

    scanRuntimeState.runtimeListenerBound = true;
  }

  function bindClickInterception() {
    if (scanRuntimeState.clickInterceptionBound) {
      return;
    }

    document.addEventListener("click", handleDocumentClickCapture, true);
    scanRuntimeState.clickInterceptionBound = true;
  }

  function bindScrollRescan() {
    if (scanRuntimeState.scrollListenerBound) {
      return;
    }

    window.addEventListener("scroll", scheduleVisibleRescan, { passive: true });
    scanRuntimeState.scrollListenerBound = true;
  }

  async function handleDocumentClickCapture(event) {
    if (!scanRuntimeState.enabled || event.defaultPrevented) {
      return;
    }

    const clickContext = getInterceptedClickContext(event);
    if (!clickContext) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    const verificationToken = ++clickWarningState.activeToken;
    clickContext.intent.pendingWindow = preparePendingWindow(clickContext.intent);
    closeWarningModal({ restoreFocus: false });

    const analysis = await resolveClickAnalysis(clickContext);
    if (verificationToken !== clickWarningState.activeToken) {
      closePendingWindow(clickContext.intent.pendingWindow);
      return;
    }

    const destinationUrl = pickDestinationUrl(analysis, clickContext);
    if (!isUsableClickAnalysis(analysis)) {
      closePendingWindow(clickContext.intent.pendingWindow);
      clickContext.intent.pendingWindow = null;
      showVerificationUnavailableModal({
        clickContext,
        destinationUrl
      });
      return;
    }

    if (!shouldShowWarningModal(analysis)) {
      continueNavigation(destinationUrl, clickContext.intent);
      return;
    }

    closePendingWindow(clickContext.intent.pendingWindow);
    clickContext.intent.pendingWindow = null;
    showWarningModal({
      clickContext,
      analysis,
      destinationUrl,
      reasons: buildWarningReasons(analysis)
    });
  }

  function getInterceptedClickContext(event) {
    if (!(event.target instanceof Element) || event.button !== 0) {
      return null;
    }

    const anchor = event.target.closest("a[href]");
    if (!(anchor instanceof HTMLAnchorElement)) {
      return null;
    }

    if (anchor.closest(".dili-panel, .dili-warning-overlay")) {
      return null;
    }

    const post = findPostContainer(anchor);
    if (!post) {
      return null;
    }

    const rawUrl = anchor.href;
    if (!isEligibleLink(rawUrl)) {
      return null;
    }

    const normalizedTargetUrl = safelyNormalizeComparableUrl(rawUrl);
    return {
      anchor,
      post,
      postId: getStablePostId(post),
      postPermalink: findPermalink(post),
      rawUrl,
      normalizedTargetUrl,
      displayText: extractAnchorDisplayText(anchor),
      intent: deriveNavigationIntent(anchor, event)
    };
  }

  async function resolveClickAnalysis(clickContext) {
    const currentState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId: clickContext.postId
    });
    const baseline = currentState?.baseline || null;

    if (analysisMatchesTarget(baseline, clickContext.normalizedTargetUrl)) {
      return baseline;
    }

    const clickPostId = buildClickAnalysisPostId(clickContext.postId, clickContext.normalizedTargetUrl);
    const cachedClickState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId: clickPostId
    });
    const cachedClickAnalysis = cachedClickState?.baseline || null;

    if (analysisMatchesTarget(cachedClickAnalysis, clickContext.normalizedTargetUrl)) {
      return cachedClickAnalysis;
    }

    const messageType = cachedClickAnalysis?.urlHash ? MESSAGE_TYPES.REANALYZE_LINK : MESSAGE_TYPES.ANALYZE_LINK;
    const response = await sendRuntimeMessage({
      type: messageType,
      postId: clickPostId,
      url: clickContext.rawUrl,
      displayedText: clickContext.displayText
    });

    return response?.analysis || null;
  }

  function analysisMatchesTarget(analysis, normalizedTargetUrl) {
    if (!analysis || !normalizedTargetUrl) {
      return false;
    }

    return String(analysis.normalizedUrl || "").trim() === String(normalizedTargetUrl).trim();
  }

  function isUsableClickAnalysis(analysis) {
    if (!analysis || typeof analysis !== "object") {
      return false;
    }

    if (typeof analysis.classification === "string" && analysis.classification.trim()) {
      return true;
    }

    if (Number.isFinite(analysis.safetyScore)) {
      return true;
    }

    if (Array.isArray(analysis.providerResults)) {
      return true;
    }

    return false;
  }

  function buildClickAnalysisPostId(postId, normalizedTargetUrl) {
    return `${postId}::click::${hashString(normalizedTargetUrl || postId)}`;
  }

  function deriveNavigationIntent(anchor, event) {
    const target = String(anchor.getAttribute("target") || "").trim();
    const normalizedTarget = target.toLowerCase();
    const reservedTargets = new Set(["", "_self", "_top", "_parent"]);
    const targetName = reservedTargets.has(normalizedTarget) ? "" : target;
    const opensNewWindow = Boolean(event.shiftKey);
    const opensNewTab = Boolean(event.ctrlKey || event.metaKey || normalizedTarget === "_blank" || (targetName && !opensNewWindow));

    return {
      targetName: targetName || "_blank",
      opensNewWindow,
      opensNewTab,
      opensNewContext: opensNewWindow || opensNewTab,
      pendingWindow: null
    };
  }

  function preparePendingWindow(intent) {
    if (!intent?.opensNewContext) {
      return null;
    }

    try {
      const features = intent.opensNewWindow ? "popup=yes,width=1180,height=800" : "";
      const pendingWindow = window.open("about:blank", intent.targetName || "_blank", features);
      if (pendingWindow?.document) {
        pendingWindow.document.title = "DILI link check";
        pendingWindow.document.body.innerHTML = `
          <div style="font-family:Segoe UI,Tahoma,sans-serif;padding:24px;line-height:1.5;color:#1f2933;">
            <strong style="display:block;margin-bottom:8px;">DILI is checking this link.</strong>
            <span>Please wait while the destination is verified.</span>
          </div>
        `;
      }
      return pendingWindow || null;
    } catch {
      return null;
    }
  }

  function continueNavigation(destinationUrl, intent) {
    const safeDestination = destinationUrl || "about:blank";

    if (intent?.opensNewContext) {
      const pendingWindow = intent.pendingWindow && !intent.pendingWindow.closed ? intent.pendingWindow : null;

      if (pendingWindow) {
        try {
          pendingWindow.location.replace(safeDestination);
          pendingWindow.focus();
          return;
        } catch {
          closePendingWindow(pendingWindow);
        }
      }

      const features = intent.opensNewWindow ? "popup=yes,width=1180,height=800" : "";
      const openedWindow = window.open(safeDestination, intent.targetName || "_blank", features);
      if (openedWindow) {
        return;
      }
    }

    window.location.assign(safeDestination);
  }

  function closePendingWindow(pendingWindow) {
    if (!pendingWindow || pendingWindow.closed) {
      return;
    }

    try {
      pendingWindow.close();
    } catch {
      // Ignore close failures for windows not opened by this script.
    }
  }

  function shouldShowWarningModal(analysis) {
    const gsb = findProviderResult(analysis.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

    if (gsb?.flagged || urlhaus?.flagged) {
      return true;
    }

    const classification = String(analysis.classification || "").toLowerCase();
    if (classification.includes("suspicious") || classification.includes("risk") || classification.includes("danger") || classification.includes("unsafe") || classification.includes("malicious")) {
      return true;
    }

    return Number.isFinite(analysis.safetyScore) && analysis.safetyScore < 80;
  }

  function pickDestinationUrl(analysis, clickContext) {
    const candidates = [
      analysis?.redirectAnalysis?.resolvedUrl,
      analysis?.normalizedUrl,
      clickContext?.normalizedTargetUrl,
      unwrapFacebookRedirectUrl(clickContext?.rawUrl || ""),
      clickContext?.rawUrl
    ];

    for (const candidate of candidates) {
      if (isNavigableHttpUrl(candidate)) {
        return candidate;
      }
    }

    return clickContext?.rawUrl || "about:blank";
  }

  function buildWarningReasons(analysis) {
    const reasons = [];
    const features = analysis?.features || {};
    const gsb = findProviderResult(analysis?.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis?.providerResults, "urlhaus");
    const redirectCount = Number(analysis?.redirectAnalysis?.redirectCount ?? features.redirectCount ?? 0);

    if (gsb?.flagged) {
      reasons.push("Google Safe Browsing flagged this destination as unsafe.");
    }

    if (urlhaus?.flagged) {
      reasons.push("URLhaus flagged this destination as suspicious or malicious.");
    }

    if (features.domainPreviouslyFlagged) {
      reasons.push("This destination domain was flagged in an earlier local check.");
    }

    if (redirectCount > 0) {
      reasons.push(
        redirectCount === 1
          ? "The link appears to redirect before it reaches the final destination."
          : `The link appears to pass through ${redirectCount} redirects before reaching the final destination.`
      );
    }

    if (features.shortenedUrl) {
      reasons.push("The link uses a shortened URL that hides the full destination.");
    }

    if (features.obfuscatedUrl) {
      reasons.push("The destination contains encoding or obfuscation indicators.");
    }

    if (features.suspiciousTld) {
      reasons.push("The destination uses a top-level domain often abused in scams or phishing.");
    }

    if (features.textMismatch) {
      reasons.push("The visible link text does not match the destination domain.");
    }

    if (features.integrityHashMismatch) {
      reasons.push("The post link appears to have changed since it was first observed.");
    }

    if (reasons.length === 0) {
      for (const deduction of analysis?.deductions || []) {
        if (deduction?.triggered && deduction.label) {
          reasons.push(deduction.label);
        }
      }
    }

    return reasons.slice(0, 6);
  }

  function buildWarningExplanation(analysis) {
    const gsb = findProviderResult(analysis?.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis?.providerResults, "urlhaus");
    const classification = String(analysis?.classification || "").toLowerCase();

    if (gsb?.flagged || urlhaus?.flagged) {
      return "DILI paused navigation because this destination was flagged by a threat-intelligence provider and may expose you to phishing, malware, or other unsafe behavior.";
    }

    if (classification.includes("high risk") || classification.includes("danger") || classification.includes("unsafe")) {
      return "DILI paused navigation because this link shows several warning signs commonly seen in malicious redirects, scam campaigns, or deceptive destination changes.";
    }

    return "DILI paused navigation because this link appears suspicious and may not be safe to open without extra caution.";
  }

  function showVerificationUnavailableModal({ clickContext, destinationUrl }) {
    const reasons = ["DILI could not verify the link before navigation."];

    showWarningModal({
      clickContext,
      analysis: null,
      destinationUrl,
      reasons,
      modalConfig: {
        kicker: "Verification Unavailable",
        title: "Link verification could not be completed",
        explanation:
          "DILI paused navigation because it could not confidently verify the destination in time. You can proceed at your own risk or stay on Facebook.",
        classificationText: "Unverified",
        scoreText: "Unavailable",
        reportCopy:
          "If this post still looks suspicious, you can copy a structured report before deciding whether to proceed or stay on Facebook.",
        reportPayloadOverrides: {
          classification: "Unverified",
          safetyScore: null,
          providerFlags: {
            googleSafeBrowsing: false,
            urlhaus: false
          },
          integrityMismatch: false
        }
      }
    });
  }

  function showWarningModal({ clickContext, analysis, destinationUrl, reasons, modalConfig = {} }) {
    closeWarningModal({ restoreFocus: false });

    clickWarningState.focusTarget = clickContext.anchor instanceof HTMLElement ? clickContext.anchor : null;
    document.documentElement.classList.add("dili-warning-open");

    const overlay = document.createElement("div");
    overlay.className = "dili-warning-overlay";
    overlay.dataset.diliOwned = "true";

    const destinationDomain = safeHostname(destinationUrl) || "unknown-domain";
    const scoreText = modalConfig.scoreText || (Number.isFinite(analysis?.safetyScore) ? String(analysis.safetyScore) : "Unavailable");
    const classificationText = modalConfig.classificationText || analysis?.classification || "Unknown";
    const titleText = modalConfig.title || "Navigation paused for your safety";
    const explanationText = modalConfig.explanation || buildWarningExplanation(analysis);
    const kickerText = modalConfig.kicker || "DILI Link Warning";
    const reportCopyText =
      modalConfig.reportCopy ||
      "If this post looks malicious or deceptive, you can copy a structured report before deciding what to do next.";
    const reasonItems = (reasons || [])
      .map((reason) => `<li>${escapeHtml(reason)}</li>`)
      .join("");

    overlay.innerHTML = `
      <div class="dili-warning-modal" role="dialog" aria-modal="true" aria-labelledby="dili-warning-title">

        <div class="dili-warning-header">
          <div class="dili-warning-header-left">
            <span class="dili-warning-kicker">${escapeHtml(kickerText)}</span>
            <h2 id="dili-warning-title">${escapeHtml(titleText)}</h2>
            <p>${escapeHtml(explanationText)}</p>
          </div>
        </div>

        <div class="dili-warning-summary">
          <div class="dili-warning-summary-item">
            <span>Domain</span>
            <strong>${escapeHtml(destinationDomain)}</strong>
          </div>
          <div class="dili-warning-summary-item">
            <span>Classification</span>
            <strong>${escapeHtml(classificationText)}</strong>
          </div>
          <div class="dili-warning-summary-item">
            <span>Score</span>
            <strong>${escapeHtml(scoreText)}</strong>
          </div>
        </div>

        <div class="dili-warning-body">
          <div class="dili-warning-section">
            <h3>Why this link was stopped</h3>
            <ul class="dili-warning-reasons">${reasonItems || "<li>No detailed risk reasons were available for this check.</li>"}</ul>
          </div>

          <div class="dili-warning-section">
            <h3>Destination URL</h3>
            <p class="dili-warning-destination">${escapeHtml(destinationUrl)}</p>
          </div>

          <div class="dili-warning-section">
            <h3>Report this post</h3>
            <p class="dili-warning-report-copy">${escapeHtml(reportCopyText)}</p>
            <p class="dili-warning-report-status" data-role="report-status"></p>
            <textarea class="dili-warning-report-preview" data-role="report-preview" readonly hidden></textarea>
          </div>
        </div>

        <div class="dili-warning-actions">
          <button type="button" class="dili-warning-button dili-warning-button-secondary" data-action="stay">Stay on Facebook</button>
          <button type="button" class="dili-warning-button dili-warning-button-neutral" data-action="report">Copy report</button>
          <button type="button" class="dili-warning-button dili-warning-button-danger" data-action="proceed">Proceed anyway</button>
        </div>

      </div>
    `;

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        closeWarningModal();
      }
    });

    const statusNode = overlay.querySelector("[data-role='report-status']");
    const previewNode = overlay.querySelector("[data-role='report-preview']");
    const stayButton = overlay.querySelector("[data-action='stay']");
    const reportButton = overlay.querySelector("[data-action='report']");
    const proceedButton = overlay.querySelector("[data-action='proceed']");

    stayButton?.addEventListener("click", () => {
      closeWarningModal();
    });

    reportButton?.addEventListener("click", async () => {
      const reportPayload = buildReportPayload(clickContext, analysis, destinationUrl, reasons, modalConfig.reportPayloadOverrides);
      const reportText = formatReportText(reportPayload);

      if (previewNode instanceof HTMLTextAreaElement) {
        previewNode.hidden = false;
        previewNode.value = reportText;
      }

      const copied = await copyReportToClipboard(reportText);
      if (copied) {
        if (statusNode) {
          statusNode.textContent = "Report details copied. Paste them into your reporting workflow or share them with an admin.";
        }
        return;
      }

      downloadReportFile(reportText, reportPayload);
      if (statusNode) {
        statusNode.textContent = "Clipboard access was unavailable, so DILI downloaded the report as a text file instead.";
      }
    });

    proceedButton?.addEventListener("click", () => {
      closeWarningModal({ restoreFocus: false });
      continueNavigation(destinationUrl, clickContext.intent);
    });

    clickWarningState.keydownHandler = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeWarningModal();
      }
    };

    document.addEventListener("keydown", clickWarningState.keydownHandler, true);
    document.body.appendChild(overlay);
    clickWarningState.overlay = overlay;

    if (stayButton instanceof HTMLElement) {
      stayButton.focus();
    }
  }

  function closeWarningModal(options = {}) {
    const { restoreFocus = true } = options;

    if (clickWarningState.overlay) {
      clickWarningState.overlay.remove();
      clickWarningState.overlay = null;
    }

    if (clickWarningState.keydownHandler) {
      document.removeEventListener("keydown", clickWarningState.keydownHandler, true);
      clickWarningState.keydownHandler = null;
    }

    document.documentElement.classList.remove("dili-warning-open");

    if (restoreFocus && clickWarningState.focusTarget instanceof HTMLElement && document.contains(clickWarningState.focusTarget)) {
      clickWarningState.focusTarget.focus();
    }

    clickWarningState.focusTarget = null;
  }

  function buildReportPayload(clickContext, analysis, destinationUrl, reasons, overrides = {}) {
    const gsb = findProviderResult(analysis?.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis?.providerResults, "urlhaus");
    const features = analysis?.features || {};
    const providerFlags = overrides.providerFlags || {
      googleSafeBrowsing: Boolean(gsb?.flagged),
      urlhaus: Boolean(urlhaus?.flagged)
    };

    return {
      generatedAt: new Date().toISOString(),
      currentFacebookPageUrl: location.href,
      postId: clickContext.postId,
      postPermalink: clickContext.postPermalink || "",
      clickedText: clickContext.displayText || "",
      destinationUrl,
      destinationDomain: safeHostname(destinationUrl) || "",
      classification: overrides.classification || analysis?.classification || "Unverified",
      safetyScore: overrides.safetyScore !== undefined ? overrides.safetyScore : Number.isFinite(analysis?.safetyScore) ? analysis.safetyScore : null,
      mainReasons: reasons || [],
      providerFlags,
      integrityMismatch: overrides.integrityMismatch !== undefined ? Boolean(overrides.integrityMismatch) : Boolean(features.integrityHashMismatch),
      redirectCount: overrides.redirectCount !== undefined ? Number(overrides.redirectCount || 0) : Number(analysis?.redirectAnalysis?.redirectCount ?? features.redirectCount ?? 0),
      analysisState: overrides.analysisState || analysis?.state || "",
      timestamp: Date.now()
    };
  }

  function formatReportText(payload) {
    const reasonLines = (payload.mainReasons || []).length
      ? payload.mainReasons.map((reason) => `- ${reason}`).join("\n")
      : "- No additional reason text was available.";

    return [
      "DILI Suspicious Link Report",
      `Generated at: ${payload.generatedAt}`,
      `Facebook page URL: ${payload.currentFacebookPageUrl || ""}`,
      `Post ID: ${payload.postId || ""}`,
      `Post permalink: ${payload.postPermalink || ""}`,
      `Clicked text: ${payload.clickedText || ""}`,
      `Destination URL: ${payload.destinationUrl || ""}`,
      `Destination domain: ${payload.destinationDomain || ""}`,
      `Risk classification: ${payload.classification || ""}`,
      `Safety score: ${payload.safetyScore ?? "Unavailable"}`,
      "Main reasons:",
      reasonLines,
      `Google Safe Browsing flagged: ${payload.providerFlags?.googleSafeBrowsing ? "Yes" : "No"}`,
      `URLhaus flagged: ${payload.providerFlags?.urlhaus ? "Yes" : "No"}`,
      `Integrity mismatch detected: ${payload.integrityMismatch ? "Yes" : "No"}`,
      `Redirect count: ${payload.redirectCount ?? 0}`,
      `Analysis state: ${payload.analysisState || ""}`,
      `Timestamp: ${new Date(Number(payload.timestamp || Date.now())).toISOString()}`
    ].join("\n");
  }

  async function copyReportToClipboard(reportText) {
    if (!navigator.clipboard?.writeText) {
      return false;
    }

    try {
      await navigator.clipboard.writeText(reportText);
      return true;
    } catch {
      return false;
    }
  }

  function downloadReportFile(reportText, payload) {
    const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `dili-report-${sanitizeFileToken(payload.postId || "post")}-${timestampForFilename(new Date())}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function forceRescan() {
    if (!scanRuntimeState.enabled) {
      return;
    }

    for (const post of collectCandidatePosts(document)) {
      enqueuePost(post);
    }

    scheduleFlush();
    console.debug("[DILI] Manual re-scan requested from popup.");
  }

  function initialScan() {
    if (!scanRuntimeState.enabled) {
      return;
    }

    for (const post of collectCandidatePosts(document)) {
      enqueuePost(post);
    }

    scheduleFlush();
  }

  function scheduleVisibleRescan() {
    if (!scanRuntimeState.enabled) {
      return;
    }

    if (rescanTimer !== null) {
      return;
    }

    rescanTimer = window.setTimeout(() => {
      rescanTimer = null;
      for (const post of collectCandidatePosts(document)) {
        enqueuePost(post);
      }
      scheduleFlush();
    }, 300);
  }

  function observeFeed() {
    if (!scanRuntimeState.enabled) {
      return;
    }

    observer = new MutationObserver((mutations) => {
      const affectedPosts = new Set();

      for (const mutation of mutations) {
        if (shouldIgnoreMutation(mutation)) {
          continue;
        }

        const targets = [mutation.target, ...mutation.addedNodes];
        for (const target of targets) {
          if (!(target instanceof Element)) {
            continue;
          }

          const nearestPost = findPostContainer(target);
          if (nearestPost) {
            affectedPosts.add(nearestPost);
          }

          for (const nestedPost of collectCandidatePosts(target)) {
            affectedPosts.add(nestedPost);
          }
        }
      }

      for (const post of affectedPosts) {
        enqueuePost(post);
      }

      if (affectedPosts.size > 0) {
        scheduleFlush();
      }
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["href", "data-ft", "aria-label"]
    });
  }

  function shouldIgnoreMutation(mutation) {
    const target = mutation.target;
    if (!(target instanceof Element)) {
      return false;
    }

    return Boolean(target.closest(".dili-badge, .dili-panel, .dili-details, .dili-warning-overlay, .dili-warning-modal"));
  }

  function collectCandidatePosts(root) {
    const candidates = new Set();
    const searchRoot = root instanceof Document ? root : root;

    if (searchRoot instanceof Element) {
      const directContainer = findPostContainer(searchRoot);
      if (directContainer) {
        candidates.add(directContainer);
      }
    }

    if (!(searchRoot instanceof Document || searchRoot instanceof Element)) {
      return candidates;
    }

    for (const selector of POST_SELECTORS) {
      for (const element of searchRoot.querySelectorAll(selector)) {
        if (element instanceof Element && isProbablyVisible(element)) {
          candidates.add(element);
        }
      }
    }

    return candidates;
  }

  function enqueuePost(post) {
    if (!scanRuntimeState.enabled || !(post instanceof Element)) {
      return;
    }

    pendingPosts.add(post);
  }

  function scheduleFlush() {
    if (!scanRuntimeState.enabled) {
      return;
    }

    if (flushTimer !== null) {
      return;
    }

    flushTimer = window.setTimeout(async () => {
      const batch = [...pendingPosts];
      pendingPosts.clear();
      flushTimer = null;

      await processPostBatch(batch);
    }, 250);
  }

  async function processPostBatch(batch) {
    for (let index = 0; index < batch.length; index += POST_PROCESS_CONCURRENCY) {
      const slice = batch.slice(index, index + POST_PROCESS_CONCURRENCY);
      const results = await Promise.allSettled(slice.map((post) => processPost(post)));

      for (const result of results) {
        if (result.status === "rejected") {
          console.warn("[DILI] Post processing failed", result.reason);
        }
      }
    }
  }

  async function processPost(post) {
    if (!scanRuntimeState.enabled) {
      return;
    }

    if (!post.isConnected || !isProbablyVisible(post)) {
      return;
    }

    const postId = getStablePostId(post);
    const linkInfo = extractRelevantLink(post, postId);
    const signature = buildPostSignature(linkInfo);

    if (postSignatureCache.get(post) === signature) {
      return;
    }

    postSignatureCache.set(post, signature);
    observedPostIds.set(postId, {
      signature,
      lastSeen: Date.now()
    });

    if (!linkInfo) {
      await setNoLinkState(post, postId);
      return;
    }

    const currentState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId
    });
    const messageType = currentState?.baseline?.urlHash ? MESSAGE_TYPES.REANALYZE_LINK : MESSAGE_TYPES.ANALYZE_LINK;
    const response = await sendRuntimeMessage({
      type: messageType,
      postId,
      url: linkInfo.url,
      displayedText: linkInfo.displayText,
      candidateContext: linkInfo.candidateContext
    });

    if (!response?.analysis) {
      renderBadge(post, {
        label: "Analysis unavailable",
        safetyScore: null,
        state: "monitored",
        severityLevel: "unverified",
        summaryLine: "This link could not be verified in time.",
        detailsSummary: "Why this result was given",
        actionHint: "DILI may pause navigation until you decide whether to proceed.",
        details: [response?.error || "Background analysis did not return data."]
      });
      return;
    }

    renderBadge(post, mapAnalysisToViewModel(response.analysis));
  }

  async function setNoLinkState(post, postId) {
    await sendRuntimeMessage({
      type: MESSAGE_TYPES.SET_NO_LINK_STATE,
      postId
    });
    selectedPostLinkCache.delete(postId);
    removeOwnedPanel(post);
  }

  function extractRelevantLink(post, postId = getStablePostId(post)) {
    const rememberedSelection = selectedPostLinkCache.get(postId) || null;
    const candidateElements = [...post.querySelectorAll("a[href], [data-lynx-uri], [data-url]")].filter((element) => {
      return element instanceof Element && isUserFacingOutboundCandidate(element, post);
    });
    const candidates = candidateElements
      .map((element) => buildRelevantLinkCandidate(element, post))
      .filter(Boolean);
    const candidateSummary = summarizePostLinkCandidates(candidates, rememberedSelection);

    if (!candidateSummary?.dominantCandidate) {
      selectedPostLinkCache.delete(postId);
      return null;
    }

    const selectedCandidate = candidateSummary.dominantCandidate;
    selectedPostLinkCache.set(postId, {
      candidateMode: candidateSummary.candidateMode,
      dominantDomain: candidateSummary.dominantDomain,
      clusterKey: candidateSummary.dominantClusterKey,
      normalizedTargetUrl: selectedCandidate.normalizedTargetUrl
    });

    return {
      element: selectedCandidate.element,
      url: selectedCandidate.url,
      displayText: selectedCandidate.displayText,
      normalizedTargetUrl: selectedCandidate.normalizedTargetUrl,
      candidateContext: {
        candidateMode: candidateSummary.candidateMode,
        candidateCount: candidateSummary.candidateCount,
        candidateDomainCount: candidateSummary.candidateDomainCount,
        dominantDomain: candidateSummary.dominantDomain,
        selectedNormalizedTarget: candidateSummary.selectedNormalizedTarget,
        signature: candidateSummary.signature
      }
    };
  }

  function buildRelevantLinkCandidate(element, post) {
    const rawUrl = getCandidateRawUrl(element);
    if (!isEligibleLink(rawUrl)) {
      return null;
    }

    const displayText = extractAnchorDisplayText(element);
    const normalizedTargetUrl = safelyNormalizeComparableUrl(rawUrl);
    const domPath = buildDomPath(element);
    const hostname = safeHostname(normalizedTargetUrl || rawUrl);
    const registrableDomain = getRegistrableDomain(hostname);
    const rect = element.getBoundingClientRect();
    const visualArea = Math.round(Math.max(rect.width, 0) * Math.max(rect.height, 0));
    const hasMedia = Boolean(element.querySelector("img, picture, video, svg"));
    const meaningfulText = hasMeaningfulCandidateText(displayText);

    return {
      element,
      url: rawUrl,
      normalizedTargetUrl,
      displayText,
      hostname,
      registrableDomain,
      wrapperOutbound: isFacebookWrapperHref(rawUrl),
      meaningfulText,
      inMainContent: isElementInMainPostContent(element, post),
      inActionArea: isElementInActionArea(element, post),
      hasMedia,
      visualArea,
      textLength: displayText.length,
      urlLength: normalizedTargetUrl.length,
      domPath
    };
  }

  function getCandidateRawUrl(element) {
    if (!(element instanceof Element)) {
      return "";
    }

    const candidates = [
      element.getAttribute("data-lynx-uri"),
      element.getAttribute("data-url")
    ];

    if (element instanceof HTMLAnchorElement) {
      candidates.push(element.href || element.getAttribute("href") || "");
    }

    for (const candidate of candidates) {
      if (candidate && candidate.trim() && isEligibleLink(candidate.trim())) {
        return candidate.trim();
      }
    }

    for (const candidate of candidates) {
      if (candidate && candidate.trim()) {
        return candidate.trim();
      }
    }

    return "";
  }

  function summarizePostLinkCandidates(candidates, rememberedSelection) {
    if (!Array.isArray(candidates) || candidates.length === 0) {
      return null;
    }

    const sortedCandidates = [...candidates].sort(compareRelevantLinkCandidates);
    const uniqueDomains = [...new Set(sortedCandidates.map((candidate) => candidate.registrableDomain).filter(Boolean))];
    const uniqueTargets = [...new Set(sortedCandidates.map((candidate) => candidate.normalizedTargetUrl).filter(Boolean))];
    const domainGroups = buildCandidateGroups(sortedCandidates, (candidate) => {
      return candidate.registrableDomain || candidate.normalizedTargetUrl || candidate.url;
    });
    const domainGroupSummaries = domainGroups
      .map((group) => buildCandidateGroupSummary(group.key, group.candidates))
      .sort(compareCandidateGroupSummaries);
    const dominantDomainGroup = pickRememberedCandidateGroup(domainGroupSummaries, rememberedSelection) || domainGroupSummaries[0] || null;

    if (!dominantDomainGroup) {
      return null;
    }

    const targetGroups = buildCandidateGroups(dominantDomainGroup.candidates, (candidate) => {
      return candidate.normalizedTargetUrl || candidate.url;
    });
    const targetGroupSummaries = targetGroups
      .map((group) => buildCandidateGroupSummary(group.key, group.candidates))
      .sort(compareCandidateGroupSummaries);
    const dominantTargetGroup = pickRememberedTargetGroup(targetGroupSummaries, rememberedSelection) || targetGroupSummaries[0] || null;
    const dominantCandidate = dominantTargetGroup?.candidates?.[0] || null;

    if (!dominantCandidate) {
      return null;
    }

    const candidateMode = uniqueDomains.length <= 1
      ? uniqueTargets.length <= 1
        ? "single"
        : "multi-same-domain"
      : "multi-mixed";
    const dominantDomain = dominantDomainGroup.registrableDomain || dominantCandidate.registrableDomain || "";
    const selectedNormalizedTarget = dominantCandidate.normalizedTargetUrl || dominantCandidate.url;
    const signature = buildCandidateSummarySignature({
      candidateMode,
      dominantDomain,
      selectedNormalizedTarget,
      uniqueDomains
    });

    return {
      candidateCount: sortedCandidates.length,
      candidateDomainCount: uniqueDomains.length,
      candidateMode,
      dominantDomain,
      dominantCandidate,
      dominantClusterKey: candidateMode === "single" ? selectedNormalizedTarget : dominantDomain || dominantDomainGroup.key,
      selectedNormalizedTarget,
      uniqueDomains,
      signature
    };
  }

  function compareRelevantLinkCandidates(left, right) {
    const scoreDifference = buildRelevantLinkScore(right) - buildRelevantLinkScore(left);
    if (scoreDifference !== 0) {
      return scoreDifference;
    }

    const normalizedUrlOrder = left.normalizedTargetUrl.localeCompare(right.normalizedTargetUrl);
    if (normalizedUrlOrder !== 0) {
      return normalizedUrlOrder;
    }

    const rawUrlOrder = left.url.localeCompare(right.url);
    if (rawUrlOrder !== 0) {
      return rawUrlOrder;
    }

    return left.domPath.localeCompare(right.domPath);
  }

  function buildRelevantLinkScore(candidate) {
    let score = 0;

    if (candidate.inMainContent) {
      score += 45;
    }

    if (candidate.wrapperOutbound) {
      score += 20;
    }

    if (candidate.meaningfulText) {
      score += 18;
    }

    if (!candidate.inActionArea) {
      score += 10;
    }

    if (candidate.hasMedia) {
      score += 12;
    }

    score += Math.min(Math.round(candidate.visualArea / 450), 80);
    score += Math.min(candidate.textLength, 60);
    score += Math.min(candidate.urlLength, 30);

    return score;
  }

  function isUserFacingOutboundCandidate(element, post) {
    if (!(element instanceof Element) || !post.contains(element)) {
      return false;
    }

    if (element.closest(".dili-badge, .dili-panel, .dili-warning-overlay")) {
      return false;
    }

    if (element.hasAttribute("hidden") || element.getAttribute("aria-hidden") === "true") {
      return false;
    }

    if (!isRenderedCandidateElement(element)) {
      return false;
    }

    if (isElementInActionArea(element, post) || isElementInsideExcludedControlArea(element)) {
      return false;
    }

    return hasMeaningfulCandidateSurface(element);
  }

  function isRenderedCandidateElement(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);

    return style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      rect.width >= 8 &&
      rect.height >= 8 &&
      rect.width * rect.height >= 80;
  }

  function hasMeaningfulCandidateSurface(element) {
    const rect = element.getBoundingClientRect();
    const text = extractAnchorDisplayText(element);
    const hasMedia = Boolean(element.querySelector("img, picture, video, svg"));

    if (hasMeaningfulCandidateText(text)) {
      return true;
    }

    if (hasMedia) {
      return true;
    }

    return rect.width * rect.height >= 900;
  }

  function hasMeaningfulCandidateText(text) {
    return String(text || "").replace(/\s+/g, " ").trim().length >= 2;
  }

  function isElementInsideExcludedControlArea(element) {
    const utilityText = buildCandidateUtilityText(element);
    return EXCLUDED_CANDIDATE_CONTROL_PATTERNS.some((pattern) => pattern.test(utilityText));
  }

  function buildCandidateUtilityText(element) {
    const parts = [];
    let current = element;
    let depth = 0;

    while (current instanceof Element && depth < 4) {
      parts.push(
        current.getAttribute("aria-label") || "",
        current.getAttribute("title") || "",
        current.getAttribute("role") || "",
        current.id || "",
        typeof current.className === "string" ? current.className : ""
      );
      current = current.parentElement;
      depth += 1;
    }

    return parts.join(" ").toLowerCase();
  }

  function buildCandidateGroups(candidates, keySelector) {
    const groups = new Map();

    for (const candidate of candidates) {
      const key = String(keySelector(candidate) || candidate.normalizedTargetUrl || candidate.url || "").trim();
      if (!key) {
        continue;
      }

      if (!groups.has(key)) {
        groups.set(key, []);
      }

      groups.get(key).push(candidate);
    }

    return [...groups.entries()].map(([key, groupCandidates]) => ({
      key,
      candidates: [...groupCandidates].sort(compareRelevantLinkCandidates)
    }));
  }

  function buildCandidateGroupSummary(key, candidates) {
    const sortedCandidates = [...candidates].sort(compareRelevantLinkCandidates);
    const bestCandidate = sortedCandidates[0] || null;

    return {
      key,
      candidates: sortedCandidates,
      bestCandidate,
      bestScore: bestCandidate ? buildRelevantLinkScore(bestCandidate) : 0,
      totalScore: sortedCandidates.reduce((sum, candidate) => sum + buildRelevantLinkScore(candidate), 0),
      candidateCount: sortedCandidates.length,
      mainContentCount: sortedCandidates.filter((candidate) => candidate.inMainContent).length,
      registrableDomain: bestCandidate?.registrableDomain || ""
    };
  }

  function compareCandidateGroupSummaries(left, right) {
    if (right.bestScore !== left.bestScore) {
      return right.bestScore - left.bestScore;
    }

    if (right.mainContentCount !== left.mainContentCount) {
      return right.mainContentCount - left.mainContentCount;
    }

    if (right.candidateCount !== left.candidateCount) {
      return right.candidateCount - left.candidateCount;
    }

    if (right.totalScore !== left.totalScore) {
      return right.totalScore - left.totalScore;
    }

    return left.key.localeCompare(right.key);
  }

  function pickRememberedCandidateGroup(groups, rememberedSelection) {
    if (!rememberedSelection) {
      return null;
    }

    if (rememberedSelection.clusterKey) {
      const clusterMatch = groups.find((group) => group.key === rememberedSelection.clusterKey);
      if (clusterMatch) {
        return clusterMatch;
      }
    }

    if (rememberedSelection.dominantDomain) {
      const domainMatch = groups.find((group) => group.registrableDomain === rememberedSelection.dominantDomain);
      if (domainMatch) {
        return domainMatch;
      }
    }

    if (rememberedSelection.normalizedTargetUrl) {
      const targetMatch = groups.find((group) => {
        return group.candidates.some((candidate) => candidate.normalizedTargetUrl === rememberedSelection.normalizedTargetUrl);
      });
      if (targetMatch) {
        return targetMatch;
      }
    }

    return null;
  }

  function pickRememberedTargetGroup(groups, rememberedSelection) {
    if (!rememberedSelection?.normalizedTargetUrl) {
      return null;
    }

    return groups.find((group) => group.key === rememberedSelection.normalizedTargetUrl) || null;
  }

  function buildCandidateSummarySignature(summary) {
    if (!summary) {
      return "no-link";
    }

    if (summary.candidateMode === "single") {
      return `single|${summary.selectedNormalizedTarget || summary.dominantDomain || "unknown-target"}`;
    }

    const domainSignature = (summary.uniqueDomains || [])
      .filter(Boolean)
      .sort()
      .join("|");

    return `${summary.candidateMode}|${summary.dominantDomain || "unknown-domain"}|${domainSignature || "no-domain"}`;
  }

  function isElementInMainPostContent(anchor, post) {
    return MAIN_POST_CONTENT_SELECTORS.some((selector) => {
      const container = anchor.closest(selector);
      return container instanceof Element && post.contains(container);
    });
  }

  function isElementInActionArea(anchor, post) {
    const actionBar = findActionBar(post);
    return Boolean(actionBar && actionBar.contains(anchor));
  }

  function removeOwnedPanel(post) {
    const panel = post.querySelector(".dili-panel[data-dili-owned='true']");
    if (panel) {
      panel.remove();
    }
  }

  function removeAllOwnedPanels() {
    for (const panel of document.querySelectorAll(".dili-panel[data-dili-owned='true']")) {
      panel.remove();
    }
  }

  function removeOwnedWarningOverlays() {
    for (const overlay of document.querySelectorAll(".dili-warning-overlay[data-dili-owned='true']")) {
      overlay.remove();
    }
  }

  function resetOwnedUiArtifacts() {
    removeAllOwnedPanels();
    closeWarningModal({ restoreFocus: false });
    removeOwnedWarningOverlays();
  }

  function stopScanning() {
    pendingPosts.clear();
    selectedPostLinkCache.clear();
    observedPostIds.clear();

    if (flushTimer !== null) {
      window.clearTimeout(flushTimer);
      flushTimer = null;
    }

    if (rescanTimer !== null) {
      window.clearTimeout(rescanTimer);
      rescanTimer = null;
    }

    if (observer) {
      observer.disconnect();
      observer = null;
    }

    resetOwnedUiArtifacts();
  }

  function isFacebookWrapperHref(rawUrl) {
    try {
      return isFacebookOutboundWrapper(new URL(rawUrl, location.href));
    } catch {
      return false;
    }
  }

  function extractAnchorDisplayText(anchor) {
    return String(anchor?.textContent || anchor?.getAttribute("aria-label") || anchor?.getAttribute("title") || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function isEligibleLink(rawUrl) {
    try {
      const url = new URL(rawUrl, location.href);
      if (!["http:", "https:"].includes(url.protocol)) {
        return false;
      }

      if (url.hash && url.pathname === location.pathname && url.search === location.search) {
        return false;
      }

      if (/fb\.me$/i.test(url.hostname)) {
        return false;
      }

      if (/facebook\.com$/i.test(url.hostname)) {
        return isFacebookOutboundWrapper(url);
      }

      return true;
    } catch {
      return false;
    }
  }

  function renderBadge(post, viewModel) {
    const mountPoint = getBadgeMountPoint(post);
    let badge = post.querySelector(".dili-panel[data-dili-owned='true']");
    if (!badge) {
      badge = document.createElement("div");
      badge.className = "dili-panel";
      badge.dataset.diliOwned = "true";
    }

    if (badge.parentElement !== mountPoint) {
      if (shouldInsertBeforeActionBar(mountPoint, post)) {
        mountPoint.parentElement.insertBefore(badge, mountPoint);
      } else {
        mountPoint.appendChild(badge);
      }
    }

    const severityLevel = normalizeInlineSeverityLevel(viewModel);
    const severityClass = sanitizeClassToken(severityLevel);
    const scoreText = viewModel.scoreLabel || buildInlineScoreLabel(viewModel, severityLevel);
    const statusLabel = viewModel.label || getDefaultInlineLabel(severityLevel);
    const summaryLine = viewModel.summaryLine || buildInlineSummaryLine(viewModel, severityLevel);
    const actionHint = viewModel.actionHint !== undefined ? viewModel.actionHint : buildInlineActionHint(viewModel, severityLevel);
    const detailsSummary = viewModel.detailsSummary || buildInlineDetailsSummary(viewModel, severityLevel);
    const severityMarker = getInlineSeverityMarker(severityLevel);
    const safeState = sanitizeClassToken(viewModel.state || "monitored");
    const panelAriaLabel = `${statusLabel} | ${scoreText}`;
    const compactSummary = panelAriaLabel;
    const detailItems = (viewModel.details || [])
      .map((detail) => `<li>${escapeHtml(detail)}</li>`)
      .join("");

    badge.className = `dili-panel dili-panel-${severityClass} dili-state-${safeState}`;
    badge.innerHTML = `
      <div class="dili-badge" aria-label="${escapeHtml(compactSummary)}">
        <div class="dili-badge-top">
          <div class="dili-badge-status">
            <span class="dili-pill dili-pill-${severityClass}">${escapeHtml(severityMarker)}</span>
            <div class="dili-badge-copy">
              <strong class="dili-status-label">${escapeHtml(statusLabel)}</strong>
              <p class="dili-summary-line">${escapeHtml(summaryLine)}</p>
            </div>
          </div>
          <span class="dili-score-chip dili-score-chip-${severityClass}">${escapeHtml(scoreText)}</span>
        </div>
        ${actionHint ? `<p class="dili-action-hint">${escapeHtml(actionHint)}</p>` : ""}
      </div>
      <details class="dili-details">
        <summary>${escapeHtml(detailsSummary)}</summary>
        <ul class="dili-detail-list">${detailItems || "<li>No detailed indicators recorded.</li>"}</ul>
      </details>
    `;
  }

  function mapAnalysisToViewModel(analysis) {
    const details = [];
    const seenDetails = new Set();

    for (const item of analysis.deductions || []) {
      if (item.triggered) {
        pushUniqueAnalysisDetail(details, seenDetails, formatAnalysisDeductionDetail(item));
      }
    }

    for (const note of analysis.redirectAnalysis?.notes || []) {
      pushUniqueAnalysisDetail(details, seenDetails, note);
    }

    for (const note of analysis.analysisNotes || []) {
      pushUniqueAnalysisDetail(details, seenDetails, note);
    }

    const gsb = findProviderResult(analysis.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

    if (!gsb?.configured) {
      pushUniqueAnalysisDetail(details, seenDetails, "Google Safe Browsing lookup was not configured.");
    }

    if (!urlhaus?.checked) {
      pushUniqueAnalysisDetail(details, seenDetails, "URLhaus lookup could not be completed.");
    } else if (urlhaus?.details?.authKeyConfigured === false || urlhaus?.details?.authConfigured === false) {
      pushUniqueAnalysisDetail(details, seenDetails, "URLhaus was checked in public mode without an auth key.");
    }

    if (details.length === 0) {
      pushUniqueAnalysisDetail(details, seenDetails, "No score deductions were triggered by the current heuristic set.");
    }

    const severityLevel = normalizeInlineSeverityLevel({
      label: analysis.classification,
      state: analysis.state,
      safetyScore: analysis.safetyScore
    });

    return {
      label: analysis.classification || "Unknown",
      safetyScore: analysis.safetyScore,
      state: analysis.state,
      severityLevel,
      summaryLine: buildInlineSummaryLine(
        {
          label: analysis.classification || "Unknown",
          state: analysis.state,
          safetyScore: analysis.safetyScore
        },
        severityLevel
      ),
      scoreLabel: buildInlineScoreLabel(
        {
          safetyScore: analysis.safetyScore
        },
        severityLevel
      ),
      actionHint: buildInlineActionHint(
        {
          label: analysis.classification || "Unknown",
          state: analysis.state,
          safetyScore: analysis.safetyScore
        },
        severityLevel
      ),
      detailsSummary: buildInlineDetailsSummary(
        {
          label: analysis.classification || "Unknown",
          state: analysis.state
        },
        severityLevel
      ),
      details
    };
  }

  function formatAnalysisDeductionDetail(item) {
    const label = String(item?.label || "").trim();
    const deduction = Number(item?.deduction);

    if (!label || !Number.isFinite(deduction) || deduction === 0) {
      return label;
    }

    if (deduction < 0) {
      return `${label} (+${Math.abs(deduction)})`;
    }

    return `${label} (-${deduction})`;
  }

  function pushUniqueAnalysisDetail(details, seenDetails, detail) {
    const text = String(detail || "").trim();
    if (!text) {
      return;
    }

    const dedupeKey = buildAnalysisDetailDedupeKey(text);
    if (seenDetails.has(dedupeKey)) {
      return;
    }

    seenDetails.add(dedupeKey);
    details.push(text);
  }

  function buildAnalysisDetailDedupeKey(detail) {
    const normalized = String(detail || "")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .replace(/\s*\(([+-]?\d+)\)\s*$/g, "")
      .trim();

    if (
      normalized.includes("single redirect hop") ||
      normalized.includes("short redirect chain") ||
      normalized.includes("moderate redirect chain") ||
      normalized.includes("long redirect chain") ||
      normalized.includes("longer redirect chain than usual") ||
      normalized.includes("unusually long redirect chain") ||
      normalized.includes("passes through multiple redirects before reaching the final destination")
    ) {
      return "redirect-chain-length";
    }

    if (normalized.includes("network probing observed an additional redirect hop")) {
      return "redirect-network-hop";
    }

    if (normalized.includes("redirect chain hands the user across different domains")) {
      return "redirect-cross-domain";
    }

    if (normalized.includes("pattern commonly seen in deceptive links")) {
      return "redirect-suspicious-pattern";
    }

    return normalized;
  }

  function normalizeInlineSeverityLevel(viewModel = {}) {
    const explicit = String(viewModel.severityLevel || "").toLowerCase();
    if (["safe", "suspicious", "high-risk", "unverified", "no-link"].includes(explicit)) {
      return explicit;
    }

    if (String(viewModel.state || "").toLowerCase() === "no_link") {
      return "no-link";
    }

    if (String(viewModel.state || "").toLowerCase() === "changed") {
      return "high-risk";
    }

    const score = Number(viewModel.safetyScore);
    if (Number.isFinite(score)) {
      if (score >= 80) {
        return "safe";
      }

      if (score >= 50) {
        return "suspicious";
      }

      return "high-risk";
    }

    const sourceText = [
      viewModel.label,
      viewModel.badgeTone,
      viewModel.state,
      viewModel.summaryLine
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    if (sourceText.includes("no hyperlink") || sourceText.includes("no_link") || sourceText.includes("monitoring")) {
      return "no-link";
    }

    if (sourceText.includes("high risk") || sourceText.includes("danger") || sourceText.includes("unsafe") || sourceText.includes("malicious")) {
      return "high-risk";
    }

    if (sourceText.includes("suspicious") || sourceText.includes("warning")) {
      return "suspicious";
    }

    if (sourceText.includes("safe")) {
      return "safe";
    }

    return "unverified";
  }

  function getDefaultInlineLabel(severityLevel) {
    switch (severityLevel) {
      case "safe":
        return "Safe";
      case "suspicious":
        return "Suspicious";
      case "high-risk":
        return "High Risk";
      case "no-link":
        return "No hyperlink detected";
      default:
        return "Unverified";
    }
  }

  function getInlineSeverityMarker(severityLevel) {
    switch (severityLevel) {
      case "safe":
        return "SAFE";
      case "suspicious":
        return "CAUTION";
      case "high-risk":
        return "HIGH RISK";
      case "no-link":
        return "MONITORING";
      default:
        return "UNVERIFIED";
    }
  }

  function buildInlineSummaryLine(viewModel = {}, severityLevel = normalizeInlineSeverityLevel(viewModel)) {
    switch (severityLevel) {
      case "safe":
        return "No major warning signs were detected for this destination.";
      case "suspicious":
        return "This link shows warning signs and should be opened carefully.";
      case "high-risk":
        return "This link may be unsafe and could lead to phishing or malware.";
      case "no-link":
        return "This post is still being monitored for future link insertions.";
      default:
        return "This link could not be verified in time.";
    }
  }

  function buildInlineScoreLabel(viewModel = {}, severityLevel = normalizeInlineSeverityLevel(viewModel)) {
    if (Number.isFinite(viewModel.safetyScore)) {
      return `Score ${viewModel.safetyScore}`;
    }

    if (severityLevel === "no-link") {
      return "Monitoring";
    }

    if (severityLevel === "unverified") {
      return "Unverified";
    }

    return "No score";
  }

  function buildInlineActionHint(viewModel = {}, severityLevel = normalizeInlineSeverityLevel(viewModel)) {
    switch (severityLevel) {
      case "suspicious":
        return "Clicking this link may trigger a warning before navigation.";
      case "high-risk":
        return "DILI will pause navigation before opening this link.";
      case "unverified":
        return "DILI may pause navigation until you decide whether to proceed.";
      default:
        return "";
    }
  }

  function buildInlineDetailsSummary(viewModel = {}, severityLevel = normalizeInlineSeverityLevel(viewModel)) {
    if (severityLevel === "high-risk" || severityLevel === "suspicious" || severityLevel === "unverified") {
      return "Why this result was given";
    }

    if (severityLevel === "no-link") {
      return "Why DILI is monitoring this post";
    }

    return "View scan details";
  }

  function findProviderResult(results, providerName) {
    if (!Array.isArray(results)) {
      return null;
    }

    return results.find((item) => item.provider === providerName) || null;
  }

  function getStablePostId(post) {
    const cached = postIdCache.get(post);
    if (cached) {
      return cached;
    }

    const permalink = findPermalink(post);
    const dataFt = post.getAttribute("data-ft") || post.dataset?.ft || "";
    const aria = [post.getAttribute("aria-label"), post.getAttribute("aria-labelledby"), post.getAttribute("aria-posinset")]
      .filter(Boolean)
      .join("|");
    const domPath = buildDomPath(post);
    const source = [permalink, dataFt, aria, domPath].filter(Boolean).join("::") || domPath;
    const postId = `post-${hashString(source)}`;

    postIdCache.set(post, postId);
    return postId;
  }

  function findPermalink(post) {
    const anchors = [...post.querySelectorAll('a[href*="/posts/"], a[href*="/permalink/"], a[href*="story_fbid"], a[href*="fbid="]')];
    const match = anchors.find((anchor) => anchor.href);
    return match ? match.href : "";
  }

  function buildDomPath(element) {
    const parts = [];
    let current = element;

    while (current && current !== document.body && parts.length < 6) {
      if (!(current instanceof Element)) {
        break;
      }

      const parent = current.parentElement;
      const index = parent ? [...parent.children].indexOf(current) : 0;
      parts.unshift(`${current.tagName.toLowerCase()}:${index}`);
      current = parent;
    }

    return parts.join(">");
  }

  function buildPostSignature(linkInfo) {
    if (!linkInfo) {
      return "no-link";
    }

    if (linkInfo.candidateContext?.signature) {
      return linkInfo.candidateContext.signature;
    }

    return linkInfo.normalizedTargetUrl || linkInfo.url || "unknown-link";
  }

  function findPostContainer(node) {
    if (!(node instanceof Element)) {
      return null;
    }

    return node.closest(POST_SELECTORS.join(","));
  }

  function getBadgeMountPoint(post) {
    for (const selector of MAIN_POST_CONTENT_SELECTORS) {
      const matches = [...post.querySelectorAll(selector)].filter((element) => {
        return element instanceof Element && !element.closest(".dili-panel");
      });

      const bestMatch = matches.find((element) => isUsefulMountNode(element, post));
      if (bestMatch) {
        return bestMatch;
      }
    }

    const actionBar = findActionBar(post);
    if (actionBar) {
      return actionBar;
    }

    const firstBlock = [...post.children].find((child) => child instanceof Element && !child.classList.contains("dili-panel"));
    return firstBlock || post;
  }

  function findActionBar(post) {
    const actionSelectors = [
      '[role="group"]',
      '[aria-label*="Like"]',
      '[aria-label*="Comment"]',
      '[aria-label*="Share"]'
    ];

    for (const selector of actionSelectors) {
      const match = post.querySelector(selector);
      if (match instanceof Element && !match.closest(".dili-panel")) {
        return match;
      }
    }

    return null;
  }

  function shouldInsertBeforeActionBar(mountPoint, post) {
    return mountPoint instanceof Element && mountPoint === findActionBar(post) && mountPoint.parentElement instanceof Element;
  }

  function isUsefulMountNode(element, post) {
    if (!(element instanceof Element) || !post.contains(element)) {
      return false;
    }

    const text = (element.textContent || "").trim();
    return text.length > 0 && text.length < 4000;
  }

  function isProbablyVisible(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);

    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0 && rect.bottom >= -300 && rect.top <= window.innerHeight * 2;
  }

  function isFacebookOutboundWrapper(url) {
    return ["l.facebook.com", "lm.facebook.com"].includes(url.hostname.toLowerCase()) && Boolean(url.searchParams.get("u") || url.searchParams.get("url"));
  }

  function safelyNormalizeComparableUrl(rawUrl) {
    try {
      return normalizeComparableUrl(rawUrl);
    } catch {
      return unwrapFacebookRedirectUrl(rawUrl);
    }
  }

  function normalizeComparableUrl(rawUrl) {
    if (!rawUrl) {
      throw new Error("Missing URL.");
    }

    const firstPass = new URL(rawUrl, location.origin);
    const unwrapped = unwrapFacebookRedirectUrl(firstPass.toString());
    const url = new URL(unwrapped, location.origin);

    url.hash = "";
    url.protocol = url.protocol.toLowerCase();
    url.hostname = url.hostname.toLowerCase();

    if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
      url.port = "";
    }

    for (const key of [...url.searchParams.keys()]) {
      if (TRACKING_PARAMS.has(key.toLowerCase())) {
        url.searchParams.delete(key);
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

  function unwrapFacebookRedirectUrl(rawUrl) {
    try {
      const inputUrl = new URL(rawUrl, location.origin);
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
    } catch {
      return String(rawUrl || "");
    }
  }

  function isNavigableHttpUrl(rawUrl) {
    try {
      const url = new URL(rawUrl, location.origin);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  }

  function safeHostname(rawUrl) {
    try {
      return new URL(rawUrl, location.origin).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function getRegistrableDomain(hostname) {
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

  async function sendRuntimeMessage(message) {
    try {
      const response = await chrome.runtime.sendMessage(message);
      if (!response?.ok) {
        console.warn("[DILI] Background returned an error", response?.error);
      }
      return response;
    } catch (error) {
      console.warn("[DILI] Message dispatch failed", error);
      return {
        ok: false,
        error: error.message || "Runtime messaging failed."
      };
    }
  }

  async function getScanEnabledState() {
    const response = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_SCAN_STATE
    });

    return response?.scanEnabled !== false;
  }

  function hashString(value) {
    let hash = 2166136261;

    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }

    return Math.abs(hash >>> 0).toString(16);
  }

  function sanitizeFileToken(value) {
    return String(value || "report")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "report";
  }

  function sanitizeClassToken(value) {
    return String(value || "monitored")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-");
  }

  function timestampForFilename(date) {
    const parts = [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, "0"),
      String(date.getDate()).padStart(2, "0"),
      String(date.getHours()).padStart(2, "0"),
      String(date.getMinutes()).padStart(2, "0"),
      String(date.getSeconds()).padStart(2, "0")
    ];

    return `${parts[0]}-${parts[1]}-${parts[2]}-${parts[3]}-${parts[4]}-${parts[5]}`;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
