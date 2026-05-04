(function initializeDili() {
  if (window.__DILI_CONTENT_ACTIVE__ && !window.__DILI_FORCE_REINIT__) {
    return;
  }

  if (window.__DILI_FORCE_REINIT__ && typeof window.__DILI_STOP__ === "function") {
    window.__DILI_STOP__();
  }

  window.__DILI_CONTENT_ACTIVE__ = true;
  window.__DILI_FORCE_REINIT__ = false;

  const MESSAGE_TYPES = {
    ANALYZE_LINK: "DILI_ANALYZE_LINK",
    REANALYZE_LINK: "DILI_REANALYZE_LINK",
    GET_POST_STATE: "DILI_GET_POST_STATE",
    SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
    GET_SCAN_STATE: "DILI_GET_SCAN_STATE",
    SET_SCAN_STATE: "DILI_SET_SCAN_STATE",
    RESCAN_NOW: "DILI_RESCAN_NOW",
    GET_SCAN_STATUS: "DILI_GET_SCAN_STATUS"
  };

  const FEED_ROOT_SELECTORS = [
    '[role="main"]',
    '[role="feed"]',
    '[data-pagelet*="MainFeed"]',
    '[data-pagelet*="FeedUnit"]',
    '[data-pagelet*="ProfileTimeline"]'
  ];
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
    /\bhide\b/i
  ];
  const DOMAIN_TEXT_PATTERN = /\b[a-z0-9.-]+\.(?:ai|app|biz|click|com|dev|info|io|net|org|ph|shop|site|store|xyz)\b/i;
  const CTA_TEXT_PATTERNS = [
    /\bsign up\b/i,
    /\bclaim now\b/i,
    /\bdownload\b/i,
    /\bshop now\b/i,
    /\blearn more\b/i,
    /\bapply now\b/i,
    /\binstall\b/i,
    /\bwatch more\b/i,
    /\bbook now\b/i,
    /\bget offer\b/i,
    /\bsubscribe\b/i,
    /\bcontact us\b/i,
    /\bsend message\b/i,
    /\buse app\b/i,
    /\bopen app\b/i,
    /\border now\b/i
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

  const FACEBOOK_REDIRECT_HOSTS = new Set([
    "l.facebook.com",
    "lm.facebook.com",
    "m.facebook.com",
    "facebook.com",
    "www.facebook.com"
  ]);
  const FACEBOOK_REDIRECT_PARAMS = new Set([
  "u",
  "url",
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
]);  
  const POST_PROCESS_CONCURRENCY = 4;
  const MAX_LINKS_PER_POST = 8;

  const pendingPosts = new Set();
  const postIdCache = new WeakMap();
  let postSignatureCache = new WeakMap();
  const selectedPostLinkCache = new Map();
  const observedPostIds = new Map();
  const latestRequestByPostId = new Map();
  const cachedPanelByPostId = new Map();
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
    scrollListenerBound: false,
    extensionContextInvalidated: false
  };
  const scanStatus = {
    enabled: true,
    route: location.href,
    lastScanAt: null,
    feedRootsFound: 0,
    candidatePostsFound: 0,
    eligibleLinkPostsFound: 0,
    analyzedPosts: 0,
    renderedPanels: 0,
    visiblePanels: 0,
    queuedPosts: 0,
    skippedSidebar: 0,
    skippedInvisible: 0,
    skippedNoLinks: 0,
    skippedActionArea: 0,
    staleResponsesDiscarded: 0,
    duplicatePanelsRemoved: 0,
    sponsoredFallbackAttempts: 0,
    sponsoredFallbackAccepted: 0,
    lastError: "",
    lastRenderedDomain: ""
  };
  let flushTimer = null;
  let rescanTimer = null;
  let observer = null;

  start().catch((error) => {
    console.warn("[DILI] Failed to initialize content script", error);
  });

  async function start() {
    if (isRuntimeInvalidated()) {
      invalidateRuntimeContext();
      return;
    }

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
      if (message?.type === MESSAGE_TYPES.GET_SCAN_STATUS) {
        sendResponse({ ok: true, status: buildScanStatusSnapshot() });
        return false;
      }

      if (message?.type === MESSAGE_TYPES.SET_SCAN_STATE) {
        applyScanState(message.enabled !== false);
        sendResponse({ ok: true, enabled: scanRuntimeState.enabled });
        return false;
      }

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

  function applyScanState(enabled) {
    scanRuntimeState.enabled = Boolean(enabled) && !scanRuntimeState.extensionContextInvalidated;
    scanStatus.enabled = scanRuntimeState.enabled;

    if (!scanRuntimeState.enabled) {
      stopScanning();
      return;
    }

    bindClickInterception();
    observeFeed();
    bindScrollRescan();
    initialScan();
  }

  async function handleDocumentClickCapture(event) {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated || event.defaultPrevented) {
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

    const targetElement = event.target.closest("a[href], [data-lynx-uri], [data-url]");
    if (!(targetElement instanceof Element)) {
      return null;
    }

    if (targetElement.closest(".dili-panel, .dili-warning-overlay")) {
      return null;
    }

    const post = getOwningPostContainer(targetElement);
    if (!post) {
      return null;
    }

    const rawUrl = getCandidateRawUrl(targetElement);
    if (!isEligibleLink(rawUrl)) {
      return null;
    }

    const normalizedTargetUrl = safelyNormalizeComparableUrl(rawUrl);
    return {
      anchor: targetElement,
      post,
      postId: getStablePostId(post),
      postPermalink: findPermalink(post),
      rawUrl,
      normalizedTargetUrl,
      displayText: extractAnchorDisplayText(targetElement),
      intent: deriveNavigationIntent(targetElement, event)
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
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    scanAndQueueVisiblePosts(document);
    console.debug("[DILI] Manual re-scan requested from popup.");
  }

  function initialScan() {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    scanAndQueueVisiblePosts();
    scheduleDelayedScan(300);
    scheduleDelayedScan(1000);
    scheduleDelayedScan(2500);
  }

  function scheduleVisibleRescan() {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    if (rescanTimer !== null) {
      return;
    }

    rescanTimer = window.setTimeout(() => {
      rescanTimer = null;
      scanAndQueueVisiblePosts();
    }, 1000);
  }

  function scheduleDelayedScan(delayMs) {
    window.setTimeout(() => {
      if (scanRuntimeState.enabled && !scanRuntimeState.extensionContextInvalidated) {
        scanAndQueueVisiblePosts();
      }
    }, delayMs);
  }

  function scanAndQueueVisiblePosts(root = document) {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    scanStatus.lastScanAt = Date.now();
    scanStatus.route = location.href;

    for (const post of collectCandidatePosts(root)) {
      enqueuePost(post);
    }

    scheduleFlush();
  }

  function observeFeed() {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    if (observer) {
      return;
    }

    observer = new MutationObserver((mutations) => {
      if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
        return;
      }

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

    return Boolean(target.closest(".dili-badge, .dili-panel, .dili-panel-slot, .dili-details, .dili-warning-overlay, .dili-warning-modal"));
  }

  function collectCandidatePosts(root) {
    const candidates = new Set();
    const searchRoots = getScanRoots(root);

    for (const searchRoot of searchRoots) {
      if (searchRoot instanceof Element) {
        const directContainer = getOwningPostContainer(searchRoot);
        if (directContainer && isScannablePostContainer(directContainer)) {
          candidates.add(directContainer);
        }
      }

      if (!(searchRoot instanceof Document || searchRoot instanceof Element)) {
        continue;
      }

      for (const selector of POST_SELECTORS) {
        for (const element of searchRoot.querySelectorAll(selector)) {
          const owningPost = getOwningPostContainer(element);
          if (owningPost && isScannablePostContainer(owningPost)) {
            candidates.add(owningPost);
          }
        }
      }

      for (const element of searchRoot.querySelectorAll('a[href], [data-lynx-uri], [data-url], [role="link"], [role="button"]')) {
        if (!(element instanceof Element)) {
          continue;
        }

        const owningPost = getOwningPostContainer(element);
        if (owningPost && isScannablePostContainer(owningPost)) {
          candidates.add(owningPost);
        }
      }
    }

    scanStatus.candidatePostsFound = candidates.size;
    return candidates;
  }

  function getScanRoots(root) {
    if (root instanceof Element && isExcludedSurface(root)) {
      scanStatus.skippedSidebar += 1;
      return [];
    }

    if (root instanceof Element && getOwningPostContainer(root)) {
      return [root];
    }

    const base = root instanceof Document ? root : root instanceof Element ? root : document;
    const roots = [];

    for (const selector of FEED_ROOT_SELECTORS) {
      for (const element of base.querySelectorAll(selector)) {
        if (element instanceof Element && !isExcludedSurface(element)) {
          roots.push(element);
        }
      }
    }

    const uniqueRoots = [...new Set(roots)];
    scanStatus.feedRootsFound = uniqueRoots.length;

    if (uniqueRoots.length > 0) {
      return uniqueRoots;
    }

    return [base];
  }

  function isScannablePostContainer(post) {
    if (!(post instanceof Element)) {
      return false;
    }

    if (isExcludedSurface(post)) {
      scanStatus.skippedSidebar += 1;
      return false;
    }

    if (!isProbablyVisible(post)) {
      scanStatus.skippedInvisible += 1;
      return false;
    }

    return isNearViewport(post);
  }

  function getOwningPostContainer(element) {
    if (!(element instanceof Element)) {
      return null;
    }

    return getCanonicalPost(element);
  }

  function isExcludedSurface(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    if (element.closest('[role="complementary"], aside')) {
      return true;
    }

    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.width < 380 && rect.left > window.innerWidth * 0.62;
  }

  function isNearViewport(element) {
    const rect = element.getBoundingClientRect();
    const buffer = window.innerHeight || 800;
    return rect.bottom >= -buffer && rect.top <= (window.innerHeight || 800) + buffer;
  }

  function enqueuePost(post) {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated || !(post instanceof Element)) {
      return;
    }

    const owningPost = getOwningPostContainer(post) || post;
    if (!isScannablePostContainer(owningPost)) {
      return;
    }

    pendingPosts.add(owningPost);
    scanStatus.queuedPosts = pendingPosts.size;
  }

  function scheduleFlush() {
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
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
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

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
    if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    const owningPost = getOwningPostContainer(post) || post;
    if (!owningPost.isConnected || !isScannablePostContainer(owningPost)) {
      return;
    }

    const postIdentity = getStablePostIdentity(owningPost);
    const postId = postIdentity.id;
    const postTextSnapshot = await buildVisiblePostTextSnapshot(owningPost);
    const linkInfo = extractRelevantLinks(owningPost, postId);
    const signature = buildPostSignature(linkInfo);

    if (postSignatureCache.get(owningPost) === signature) {
      const cachedPanel = cachedPanelByPostId.get(postId);
      if (linkInfo && cachedPanel && !owningPost.querySelector(".dili-panel[data-dili-owned='true']")) {
        renderBadge(owningPost, cachedPanel);
        return;
      }

      if (!linkInfo) {
        const currentState = await sendRuntimeMessage({
          type: MESSAGE_TYPES.GET_POST_STATE,
          postId
        });
        const storedBaseline = currentState?.baseline || null;
        const hasOwnedArtifacts = Boolean(
          owningPost.querySelector(".dili-panel[data-dili-owned='true'], .dili-panel-slot[data-dili-owned='true']") ||
          cachedPanel
        );

        if (
          !storedBaseline ||
          storedBaseline.baselineState !== "no_link" ||
          storedBaseline.postTextHash !== postTextSnapshot.postTextHash ||
          hasOwnedArtifacts
        ) {
          await setNoLinkState(owningPost, postId, postTextSnapshot);
        }
      }

      return;
    }

    postSignatureCache.set(owningPost, signature);
    observedPostIds.set(postId, {
      signature,
      lastSeen: Date.now()
    });

    if (!linkInfo) {
      scanStatus.skippedNoLinks += 1;
      await setNoLinkState(owningPost, postId, postTextSnapshot);
      return;
    }

    scanStatus.eligibleLinkPostsFound += 1;
    const currentState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId
    });

    const baseline = currentState?.baseline || null;

    const hasPriorBaseline = Boolean(
      baseline?.urlHash ||
      baseline?.baselineState === "no_link" ||
      baseline?.hadLinkAtBaseline === false ||
      baseline?.postTextHash
    );

    const messageType = hasPriorBaseline
      ? MESSAGE_TYPES.REANALYZE_LINK
      : MESSAGE_TYPES.ANALYZE_LINK;

    const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const linkFingerprint = linkInfo.linkFingerprint;
    latestRequestByPostId.set(postId, {
      requestId,
      signature,
      linkFingerprint,
      postTextHash: postTextSnapshot.postTextHash
    });
    renderBadge(owningPost, {
      label: "Analyzing",
      safetyScore: null,
      state: "monitored",
      severityLevel: "unverified",
      summaryLine: "DILI is resolving this post's external link destination.",
      detailsSummary: "Scan details",
      details: [`Checking ${linkInfo.links.length} link${linkInfo.links.length === 1 ? "" : "s"}.`]
    });

    const response = await sendRuntimeMessage({
      type: messageType,
      postId,
      url: linkInfo.links[0]?.url,
      links: linkInfo.links,
      displayedText: linkInfo.displayText,
      postTextHash: postTextSnapshot.postTextHash,
      normalizedVisiblePostText: postTextSnapshot.normalizedVisiblePostText,
      candidateContext: {
        ...linkInfo.candidateContext,
        postIdentityStable: postIdentity.stable
      },
      requestId,
      postSignature: signature,
      linkFingerprint
    });

    const latestRequest = latestRequestByPostId.get(postId);
    if (
      !latestRequest ||
      latestRequest.requestId !== requestId ||
      latestRequest.signature !== signature ||
      latestRequest.linkFingerprint !== linkFingerprint ||
      latestRequest.postTextHash !== postTextSnapshot.postTextHash ||
      buildPostSignature(extractRelevantLinks(owningPost, postId)) !== signature
    ) {
      scanStatus.staleResponsesDiscarded += 1;
      return;
    }

    if (!response?.analysis) {
      renderBadge(owningPost, {
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

    scanStatus.analyzedPosts += 1;
    renderBadge(owningPost, mapAnalysisToViewModel(response.analysis));
  }

  async function setNoLinkState(post, postId, postTextSnapshot = null) {
    await sendRuntimeMessage({
      type: MESSAGE_TYPES.SET_NO_LINK_STATE,
      postId,
      postTextHash: postTextSnapshot?.postTextHash || "",
      normalizedVisiblePostText: postTextSnapshot?.normalizedVisiblePostText || ""
    });
    selectedPostLinkCache.delete(postId);
    cachedPanelByPostId.delete(postId);
    removeOwnedPanel(post);
  }

  function extractRelevantLinks(post, postId = getStablePostId(post)) {
    const rememberedSelection = selectedPostLinkCache.get(postId) || null;
    let candidateElements = [...post.querySelectorAll('a[href], [data-lynx-uri], [data-url], [role="link"], [role="button"]')].filter((element) => {
      return element instanceof Element && isUserFacingOutboundCandidate(element, post);
    });
    candidateElements = includeAncestorAnchors(candidateElements, post);
    const candidates = candidateElements
      .map((element) => buildRelevantLinkCandidate(element, post))
      .filter(Boolean);
    const withSponsoredFallback = candidates.length > 0 ? candidates : findSponsoredFallbackCandidates(post);
    const candidateSummary = summarizePostLinkCandidates(candidates, rememberedSelection);

    if (!candidateSummary?.dominantCandidate && withSponsoredFallback.length === 0) {
      selectedPostLinkCache.delete(postId);
      return null;
    }

    const sortedCandidates = [...(withSponsoredFallback.length ? withSponsoredFallback : candidates)].sort(compareRelevantLinkCandidates);
    const uniqueCandidates = dedupeLinkCandidates(sortedCandidates).slice(0, MAX_LINKS_PER_POST);
    const selectedCandidate = candidateSummary?.dominantCandidate || uniqueCandidates[0];
    const uniqueDomains = [...new Set(uniqueCandidates.map((candidate) => candidate.registrableDomain).filter(Boolean))];
    const uniqueTargets = [...new Set(uniqueCandidates.map((candidate) => candidate.normalizedTargetUrl).filter(Boolean))];
    const candidateMode = uniqueDomains.length <= 1
      ? uniqueTargets.length <= 1
        ? "single"
        : "multi-same-domain"
      : "multi-mixed";
    const selectedNormalizedTarget = selectedCandidate.normalizedTargetUrl || selectedCandidate.url;
    const signature = buildCandidateSummarySignature({
      candidateMode,
      dominantDomain: selectedCandidate.registrableDomain || "",
      selectedNormalizedTarget,
      uniqueDomains
    });

    selectedPostLinkCache.set(postId, {
      candidateMode,
      dominantDomain: selectedCandidate.registrableDomain || "",
      clusterKey: selectedNormalizedTarget,
      normalizedTargetUrl: selectedCandidate.normalizedTargetUrl
    });

    return {
      element: selectedCandidate.element,
      url: selectedCandidate.url,
      displayText: selectedCandidate.displayText,
      normalizedTargetUrl: selectedCandidate.normalizedTargetUrl,
      links: uniqueCandidates.map((candidate) => ({
        url: candidate.url,
        displayText: candidate.displayText,
        normalizedTargetUrl: candidate.normalizedTargetUrl,
        candidateContext: {
          candidateMode,
          candidateCount: uniqueCandidates.length,
          candidateDomainCount: uniqueDomains.length,
          dominantDomain: candidate.registrableDomain || "",
          selectedNormalizedTarget: candidate.normalizedTargetUrl,
          signature
        }
      })),
      linkFingerprint: uniqueTargets.sort().join("|"),
      candidateContext: {
        candidateMode,
        candidateCount: uniqueCandidates.length,
        candidateDomainCount: uniqueDomains.length,
        dominantDomain: selectedCandidate.registrableDomain || "",
        selectedNormalizedTarget,
        signature
      }
    };
  }

  function includeAncestorAnchors(elements, post) {
    const result = new Set(elements);
    for (const element of elements) {
      const anchor = element.closest("a[href]");
      if (anchor instanceof Element && post.contains(anchor)) {
        result.add(anchor);
      }
    }
    return [...result];
  }

  function dedupeLinkCandidates(candidates) {
    const seen = new Set();
    const unique = [];
    for (const candidate of candidates) {
      const key = candidate.normalizedTargetUrl || candidate.url;
      if (!key || seen.has(key)) {
        continue;
      }
      seen.add(key);
      unique.push(candidate);
    }
    return unique;
  }

  function findSponsoredFallbackCandidates(post) {
    if (!hasSponsoredFallbackSignals(post)) {
      return [];
    }

    scanStatus.sponsoredFallbackAttempts += 1;
    const candidates = [];
    const searchContainers = [
      post,
      ...post.querySelectorAll('[role="button"], [role="link"], a[href], [data-url], [data-lynx-uri]')
    ];

    for (const container of searchContainers) {
      if (!(container instanceof Element)) {
        continue;
      }

      const elements = [
        container,
        ...Array.from(container.querySelectorAll?.('a[href], [data-lynx-uri], [data-url]') || [])
      ];

      for (const element of elements) {
        if (!(element instanceof Element)) {
          continue;
        }

        const candidate = buildRelevantLinkCandidate(element, post);
        if (candidate) {
          candidates.push(candidate);
        }
      }
    }

    const unique = dedupeLinkCandidates(candidates);
    if (unique.length > 0) {
      scanStatus.sponsoredFallbackAccepted += 1;
    }

    return unique;
  }

  function hasSponsoredFallbackSignals(post) {
    const text = String(post.textContent || "").replace(/\s+/g, " ").trim();
    const hasSponsored = /\bsponsored\b/i.test(text);
    const hasCta = CTA_TEXT_PATTERNS.some((pattern) => pattern.test(text));
    const hasPreviewDomain = DOMAIN_TEXT_PATTERN.test(text);
    return hasSponsored && hasCta && hasPreviewDomain;
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

    if (isFacebookInAppFormElement(element) || isInternalFacebookMediaOrActionUrl(getCandidateRawUrl(element))) {
      return false;
    }

    if (element.hasAttribute("hidden") || element.getAttribute("aria-hidden") === "true") {
      return false;
    }

    if (!isRenderedCandidateElement(element)) {
      return false;
    }

    if (isElementInActionArea(element, post) || isElementInsideExcludedControlArea(element)) {
      scanStatus.skippedActionArea += 1;
      return false;
    }

    return hasMeaningfulCandidateSurface(element);
  }

  function isFacebookInAppFormElement(element) {
    const text = buildCandidateUtilityText(element);
    return /lead form|instant form|in-app form|registration form|register on facebook|open form|native form/i.test(text);
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
    return isCarouselNavigationControl(element) || EXCLUDED_CANDIDATE_CONTROL_PATTERNS.some((pattern) => pattern.test(utilityText));
  }

  function isCarouselNavigationControl(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const utilityText = buildCandidateUtilityText(element);
    return /\b(next|previous|prev)\b/i.test(utilityText) && /\b(carousel|slide)\b/i.test(utilityText);
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
    const postId = getStablePostId(post);
    cachedPanelByPostId.delete(postId);

    for (const artifact of post.querySelectorAll(".dili-panel[data-dili-owned='true'], .dili-panel-slot[data-dili-owned='true']")) {
      artifact.remove();
    }

    for (const badge of post.querySelectorAll(".dili-badge")) {
      if (!badge.closest(".dili-panel[data-dili-owned='true']")) {
        badge.remove();
      }
    }
  }

  function removeAllOwnedPanels() {
    for (const artifact of document.querySelectorAll(".dili-panel[data-dili-owned='true'], .dili-panel-slot[data-dili-owned='true']")) {
      artifact.remove();
    }

    for (const badge of document.querySelectorAll(".dili-badge")) {
      if (!badge.closest(".dili-panel[data-dili-owned='true']")) {
        badge.remove();
      }
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
    cachedPanelByPostId.clear();
    postSignatureCache = new WeakMap(); 
}

  function stopScanning() {
    pendingPosts.clear();
    selectedPostLinkCache.clear();
    observedPostIds.clear();
    latestRequestByPostId.clear();

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

    if (scanRuntimeState.scrollListenerBound) {
      window.removeEventListener("scroll", scheduleVisibleRescan, { passive: true });
      scanRuntimeState.scrollListenerBound = false;
    }

    if (scanRuntimeState.clickInterceptionBound) {
      document.removeEventListener("click", handleDocumentClickCapture, true);
      scanRuntimeState.clickInterceptionBound = false;
    }

    resetOwnedUiArtifacts();
  }

  window.__DILI_STOP__ = stopScanning;

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
      if (!String(rawUrl || "").trim()) {
        return false;
      }

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

      if (isFacebookHost(url.hostname)) {
        if (!isFacebookOutboundWrapper(url)) {
          return false;
        }

        if (isInternalFacebookMediaOrActionUrl(url.toString())) {
          return false;
        }

        const unwrapped = unwrapFacebookRedirectUrl(url.toString());
        if (isFacebookInAppFormUrl(unwrapped)) {
          return false;
        }

        const targetHost = safeHostname(unwrapped);
        return Boolean(targetHost) && !isFacebookHost(targetHost);
      }

      if (isFacebookInAppFormUrl(url.toString())) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  function renderBadge(post, viewModel) {
    const owningPost = getOwningPostContainer(post) || post;
    const mountPoint = getBadgeMountPoint(owningPost);
    const panels = [...owningPost.querySelectorAll(".dili-panel[data-dili-owned='true']")];
    if (panels.length > 1) {
      for (const extraPanel of panels.slice(1)) {
        extraPanel.remove();
        scanStatus.duplicatePanelsRemoved += 1;
      }
    }

    let badge = owningPost.querySelector(".dili-panel[data-dili-owned='true']");
    if (!badge) {
      badge = document.createElement("div");
      badge.className = "dili-panel";
      badge.dataset.diliOwned = "true";
    }

    if (badge.parentElement !== mountPoint) {
      mountPoint.appendChild(badge);
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

    cachedPanelByPostId.set(getStablePostId(owningPost), viewModel);
    scanStatus.renderedPanels += 1;
    scanStatus.visiblePanels = document.querySelectorAll(".dili-panel[data-dili-owned='true']").length;
    scanStatus.lastRenderedDomain = viewModel.finalDomain || viewModel.domain || "";
  }

  function mapAnalysisToViewModel(analysis) {
    const severityLevel = normalizeInlineSeverityLevel({
      label: analysis.classification,
      state: analysis.state,
      safetyScore: analysis.safetyScore
    });
    const details = buildPanelDetails(analysis);

    return {
      label: analysis.classification || "Unknown",
      safetyScore: analysis.safetyScore,
      state: analysis.state,
      severityLevel,
      finalDomain: analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || "",
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

  function buildPanelDetails(analysis = {}) {
    const details = [];
    const seenDetails = new Set();
    const finalDomain = analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || safeHostname(analysis.analysisUrl) || "unknown site";
    const originalDomain = safeHostname(analysis.rawUrl || analysis.normalizedUrl) || analysis.endpointResult?.effectiveDomain || "unknown link";
    const linkType = describeLinkType(analysis);
    const scoreLabel = Number.isFinite(analysis.safetyScore) ? `score ${analysis.safetyScore}` : "no score";

    pushUniqueAnalysisDetail(details, seenDetails, `Summary: Final site: ${finalDomain}.`);
    pushUniqueAnalysisDetail(details, seenDetails, `Summary: Original link: ${originalDomain}.`);
    pushUniqueAnalysisDetail(details, seenDetails, `Summary: Link type: ${linkType}.`);
    pushUniqueAnalysisDetail(details, seenDetails, `Summary: Risk level: ${analysis.classification || "Unknown"} (${scoreLabel}).`);

    const mainReasons = buildMainRiskReasons(analysis).slice(0, 5);
    if (mainReasons.length > 0) {
      for (const reason of mainReasons) {
        pushUniqueAnalysisDetail(details, seenDetails, `Reason: ${reason}`);
      }
    } else {
      pushUniqueAnalysisDetail(details, seenDetails, "Reason: No major risk reasons were found.");
    }

    for (const limitation of buildLimitations(analysis).slice(0, 5)) {
      pushUniqueAnalysisDetail(details, seenDetails, `Limitation: ${limitation}`);
    }

    for (const detail of buildTechnicalDetails(analysis).slice(0, 6)) {
      pushUniqueAnalysisDetail(details, seenDetails, `Technical: ${detail}`);
    }

    return details;
  }

  function buildMainRiskReasons(analysis = {}) {
    const reasons = [];
    for (const item of analysis.deductions || []) {
      if (!item?.triggered || Number(item.deduction || 0) <= 0 || !item.label) {
        continue;
      }

      if (isProviderErrorText(item.label) || isNormalWrapperText(item.label)) {
        continue;
      }

      reasons.push(formatAnalysisDeductionDetail(item));
    }

    return reasons;
  }

  function buildLimitations(analysis = {}) {
    const limitations = [];
    for (const limitation of analysis.limitations || []) {
      if (!limitation || isNormalWrapperText(limitation)) {
        continue;
      }
      limitations.push(limitation);
    }

    const gsb = findProviderResult(analysis.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

    if (!gsb?.configured) {
      limitations.push("Google Safe Browsing is not configured.");
    } else if (gsb?.details?.status === "error") {
      limitations.push("Google Safe Browsing lookup returned an error.");
    }

    if (urlhaus?.details?.status === "error") {
      limitations.push("URLhaus public lookup was unavailable.");
    }

    return [...new Set(limitations)];
  }

  function buildTechnicalDetails(analysis = {}) {
    const details = [];
    const endpoint = analysis.endpointResult || {};
    const finalDomain = endpoint.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || safeHostname(analysis.analysisUrl) || "";
    const chain = endpoint.resolutionChain || analysis.redirectAnalysis?.redirectChain || [];
    const chainDomains = [...new Set(chain.map((url) => safeHostname(url)).filter(Boolean))];

    for (const detail of analysis.technicalDetails || []) {
      if (detail && !isNormalWrapperText(detail)) {
        details.push(detail);
      }
    }

    if (endpoint.isFacebookWrapper && finalDomain) {
      details.push(`Facebook wrapper unwrapped to ${finalDomain}.`);
    }

    if (chainDomains.length > 1) {
      details.push(`Redirect chain: ${chainDomains.join(" -> ")}.`);
    }

    if (analysis.urlFeatureAnalysis?.sourceNormalizedUrl && analysis.urlFeatureAnalysis?.sourceRawComparableUrl && analysis.urlFeatureAnalysis.sourceNormalizedUrl !== analysis.urlFeatureAnalysis.sourceRawComparableUrl) {
      details.push("Tracking parameters were stripped for comparison.");
    }

    if (endpoint.endpointConfidence || analysis.endpointConfidence) {
      details.push(`Endpoint confidence: ${endpoint.endpointConfidence || analysis.endpointConfidence}.`);
    }

    if (analysis.postIntegrityEvent) {
      details.push(`Post integrity event: ${formatIntegrityEventLabel(analysis.postIntegrityEvent)}.`);
    }

    if (analysis.linkInsertedAfterBaseline) {
      details.push("A link was inserted after a stored no-link baseline.");
    }

    if (analysis.baselineFirstSeenAt) {
      details.push(`Baseline first seen: ${new Date(Number(analysis.baselineFirstSeenAt)).toISOString()}.`);
    }

    if (analysis.previousPostTextHash) {
      details.push(`Previous post text hash: ${analysis.previousPostTextHash}.`);
    }

    if (analysis.currentPostTextHash) {
      details.push(`Current post text hash: ${analysis.currentPostTextHash}.`);
    }

    for (const note of analysis.redirectAnalysis?.notes || []) {
      if (!isNormalWrapperText(note)) {
        details.push(note);
      }
    }

    return [...new Set(details)];
  }

  function describeLinkType(analysis = {}) {
    if (analysis.endpointResult?.isShortener || analysis.features?.shortenedUrl) {
      return "Shortened external link";
    }

    if (analysis.endpointResult?.isFacebookWrapper) {
      return "Facebook outbound wrapper";
    }

    return "External link";
  }

  function isProviderErrorText(text) {
    return /not configured|lookup returned an error|lookup could not be completed|public lookup was unavailable|public mode/i.test(String(text || ""));
  }

  function isNormalWrapperText(text) {
    return /facebook wrapper concealed|wrapper concealed an external destination|facebook wrapper unwrapped|facebook or tracking wrapper concealed/i.test(String(text || ""));
  }

  function formatIntegrityEventLabel(value) {
    return String(value || "")
      .replace(/_/g, " ")
      .replace(/\b([a-z])/g, (match) => match.toUpperCase());
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
    if (["safe", "caution", "suspicious", "high-risk", "unverified", "no-link"].includes(explicit)) {
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

      if (score >= 60) {
        return "caution";
      }

      if (score >= 40) {
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

    if (sourceText.includes("caution")) {
      return "caution";
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
      case "caution":
        return "Caution";
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
      case "caution":
        return "CAUTION";
      case "suspicious":
        return "SUSPICIOUS";
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
      case "caution":
        return "This link has minor warning signs or limited verification.";
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
      case "caution":
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
    if (severityLevel === "high-risk" || severityLevel === "suspicious" || severityLevel === "caution" || severityLevel === "unverified") {
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
    return getStablePostIdentity(post).id;
  }

  function getStablePostIdentity(post) {
    const cached = postIdCache.get(post);
    if (cached) {
      return typeof cached === "string"
        ? { id: cached, stable: false, reason: "Legacy cached post id." }
        : cached;
    }

    const permalink = findPermalink(post);
    const dataFt = post.getAttribute("data-ft") || post.dataset?.ft || "";
    const stableSource = extractStableFacebookPostToken(permalink) || extractStableFacebookPostToken(dataFt);
    if (stableSource) {
      const identity = {
        id: `fb-${hashString(stableSource)}`,
        stable: true,
        reason: "Stable Facebook post identifier or permalink."
      };
      postIdCache.set(post, identity);
      return identity;
    }

    const authorText = extractAuthorText(post);
    const previewDomainText = extractPreviewDomainText(post);
    const ctaText = extractCtaText(post);
    const sponsoredMarker = /\bsponsored\b/i.test(post.textContent || "") ? "sponsored" : "";
    const cleanedPostText = String(post.textContent || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 160);
    const timestampText = extractTimestampText(post);
    const source = [authorText, sponsoredMarker, cleanedPostText, timestampText, previewDomainText, ctaText]
      .filter(Boolean)
      .join("|");
    const identity = {
      id: `session-${sponsoredMarker || "post"}-${hashString(source || cleanedPostText || "unknown-post")}`,
      stable: false,
      reason: "Session-only deterministic post fingerprint."
    };

    postIdCache.set(post, identity);
    return identity;
  }

  function extractStableFacebookPostToken(value) {
    const source = String(value || "");
    const patterns = [
      /story_fbid[=:]([0-9]+)/i,
      /\/posts\/([0-9]+)/i,
      /\/videos\/([0-9]+)/i,
      /\/reel\/([0-9]+)/i,
      /fbid[=:]([0-9]+)/i,
      /\/permalink\/([0-9]+)/i
    ];

    for (const pattern of patterns) {
      const match = source.match(pattern);
      if (match?.[1]) {
        return match[0].toLowerCase();
      }
    }

    return "";
  }

  function extractAuthorText(post) {
    const heading = post.querySelector('h2, h3, strong, [role="heading"]');
    return String(heading?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 80);
  }

  function extractTimestampText(post) {
    const time = post.querySelector("time, abbr, a[href*='/posts/'], a[href*='story_fbid']");
    return String(time?.textContent || time?.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim().slice(0, 80);
  }

  function extractPreviewDomainText(post) {
    const text = String(post.textContent || "");
    const match = text.match(DOMAIN_TEXT_PATTERN);
    return match ? match[0].toLowerCase() : "";
  }

  function extractCtaText(post) {
    const text = String(post.textContent || "").replace(/\s+/g, " ");
    const pattern = CTA_TEXT_PATTERNS.find((item) => item.test(text));
    return pattern ? String(pattern).replace(/[\\/bi^$]/g, "").slice(0, 40) : "";
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
      return `${linkInfo.candidateContext.signature}|${linkInfo.linkFingerprint || ""}`;
    }

    return linkInfo.normalizedTargetUrl || linkInfo.url || "unknown-link";
  }

  function findPostContainer(node) {
    return getCanonicalPost(node);
  }

  function getBadgeMountPoint(post) {
    return ensurePanelSlot(post);
  }

  function getArticleAncestors(element) {
    const ancestors = [];
    let current = element instanceof Element ? element : null;

    while (current instanceof Element) {
      if (isPostContainerCandidate(current)) {
        ancestors.push(current);
      }

      current = current.parentElement;
    }

    return ancestors.reverse();
  }

  function isPostContainerCandidate(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    return POST_SELECTORS.some((selector) => element.matches(selector));
  }

  function isLikelyFeedPost(element) {
    if (!(element instanceof Element) || !element.isConnected || !isProbablyVisible(element) || isExcludedSurface(element)) {
      return false;
    }

if (
  isLikelyCommentOrReplyContainer(element) ||
  isLikelyEmbeddedPreviewContainer(element) ||
  isLikelyActionBarOrControlContainer(element)
) {
  return false;
}

    const rect = element.getBoundingClientRect();
    if (rect.width < 180 || rect.height < 120) {
      return false;
    }

    return hasPostAuthorHeader(element) && hasPostBodyOrAttachment(element);
  }

  function hasPostAuthorHeader(post) {
    return Boolean(findPostHeader(post) || extractAuthorText(post));
  }

  function hasPostBodyOrAttachment(post) {
    return Boolean(findPostCaption(post) || findPostAttachmentOrPreview(post) || extractVisiblePostText(post).length >= 24);
  }

  function isLikelyCommentOrReplyContainer(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const utilityText = buildCandidateUtilityText(element);
    return /\b(comment|reply|replies|responses|thread)\b/i.test(utilityText);
  }

  function isLikelyEmbeddedPreviewContainer(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const utilityText = buildCandidateUtilityText(element);
    if (/\b(carousel|preview|attachment|embedded card|link preview|shared link|promo card)\b/i.test(utilityText)) {
      return true;
    }

    return Boolean(element.matches('[data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"])'));
  }

  function isLikelyActionBarOrControlContainer(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    return EXCLUDED_CANDIDATE_CONTROL_PATTERNS.some((pattern) => pattern.test(buildCandidateUtilityText(element)));
  }

  function getCanonicalPost(element) {
    const ancestors = getArticleAncestors(element);
    if (ancestors.length === 0) {
      return null;
    }

    const rankedCandidates = ancestors
      .map((candidate, index) => ({
        candidate,
        index,
        score: scoreCanonicalPostCandidate(candidate)
      }))
      .filter((item) => item.score >= 0);

    if (rankedCandidates.length === 0) {
      return null;
    }

    const strongestScore = Math.max(...rankedCandidates.map((item) => item.score));
    const acceptableCandidates = rankedCandidates.filter((item) => item.score >= strongestScore - 8);

    return acceptableCandidates.sort((left, right) => left.index - right.index)[0]?.candidate || null;
  }

  function scoreCanonicalPostCandidate(candidate) {
    if (!(candidate instanceof Element) || !candidate.isConnected || !isProbablyVisible(candidate) || isExcludedSurface(candidate)) {
      return -1;
    }

    if (isLikelyCommentOrReplyContainer(candidate) || isLikelyEmbeddedPreviewContainer(candidate) || isLikelyActionBarOrControlContainer(candidate)) {
      return -1;
    }

    const rect = candidate.getBoundingClientRect();
    const textLength = extractVisiblePostText(candidate).length;
    let score = 0;

    if (candidate.matches('div[role="article"]')) {
      score += 25;
    }

    if (candidate.matches('article')) {
      score += 18;
    }

    if (candidate.matches('[data-pagelet*="FeedUnit"]')) {
      score += 14;
    }

    if (candidate.matches('[aria-posinset]')) {
      score += 8;
    }

    if (hasPostAuthorHeader(candidate)) {
      score += 28;
    }

    if (hasPostBodyOrAttachment(candidate)) {
      score += 24;
    }

    if (candidate.closest('[role="feed"], [role="main"]')) {
      score += 8;
    }

    if (textLength > 60) {
      score += 8;
    } else if (textLength > 20) {
      score += 4;
    }

    if (rect.width > 300 && rect.height > 180) {
      score += 6;
    }

    if (candidate.querySelector('time, abbr, a[href*="/posts/"], a[href*="/permalink/"], a[href*="story_fbid"], a[href*="fbid="]')) {
      score += 10;
    }

    return score;
  }

  function findPostHeader(post) {
    if (!(post instanceof Element)) {
      return null;
    }

    const selectors = [
      "header",
      '[role="heading"]',
      "h1",
      "h2",
      "h3",
      "time",
      "abbr",
      'a[href*="/posts/"]',
      'a[href*="/permalink/"]',
      'a[href*="story_fbid"]',
      'a[href*="fbid="]'
    ];
    const bodySelectors = [
      '[data-ad-preview="message"]',
      '[data-ad-comet-preview="message"]',
      '[data-testid="post_message"]'
    ].join(",");

    for (const selector of selectors) {
      const match = [...post.querySelectorAll(selector)].find((element) => {
        if (!(element instanceof Element) || !post.contains(element) || !isProbablyVisible(element)) {
          return false;
        }

        if (element.closest(bodySelectors) || isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
          return false;
        }

        return extractAnchorDisplayText(element).length > 0 || element.tagName === "TIME" || element.tagName === "ABBR" || Boolean(element.querySelector('img, svg, picture'));
      });

      if (match) {
        return match;
      }
    }

    return null;
  }

  function findPostCaption(post) {
    if (!(post instanceof Element)) {
      return null;
    }

    for (const selector of MAIN_POST_CONTENT_SELECTORS) {
      const match = [...post.querySelectorAll(selector)].find((element) => {
        if (!(element instanceof Element) || !post.contains(element) || !isProbablyVisible(element)) {
          return false;
        }

        if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
          return false;
        }

        return extractVisiblePostText(element).length >= 2;
      });

      if (match) {
        return match;
      }
    }

    return null;
  }

  function findPostAttachmentOrPreview(post) {
    if (!(post instanceof Element)) {
      return null;
    }

    const selectors = [
      '[data-ad-preview]',
      '[data-ad-comet-preview]',
      'img',
      'video',
      'picture',
      '[aria-label*="carousel"]',
      '[aria-label*="preview"]',
      '[role="link"]'
    ];

    for (const selector of selectors) {
      const match = [...post.querySelectorAll(selector)].find((element) => {
        if (!(element instanceof Element) || !post.contains(element) || !isProbablyVisible(element)) {
          return false;
        }

        if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
          return false;
        }

        if (selector === '[role="link"]' && extractVisiblePostText(element).length < 2 && !element.querySelector('img, video, picture, svg')) {
          return false;
        }

        return true;
      });

      if (match) {
        return match;
      }
    }

    return null;
  }

  function findPanelInsertionPoint(post) {
    const headerBlock = findPostHeaderBlock(post);
    if (headerBlock?.parentElement instanceof Element) {
      return {
        parent: headerBlock.parentElement,
        beforeNode: headerBlock.nextSibling || null
      };
    }

    const caption = findPostCaption(post);
    if (caption?.parentElement instanceof Element) {
      return {
        parent: caption.parentElement,
        beforeNode: caption
      };
    }

    const attachment = findPostAttachmentOrPreview(post);
    if (attachment?.parentElement instanceof Element) {
      return {
        parent: attachment.parentElement,
        beforeNode: attachment
      };
    }

    return {
      parent: post,
      beforeNode: post.firstElementChild || null
    };
  }

  function findPostHeaderBlock(post) {
    const header = findPostHeader(post);
    if (!(header instanceof Element) || !post.contains(header)) {
      return null;
    }

    let block = header;
    while (block.parentElement instanceof Element && block.parentElement !== post) {
      const parent = block.parentElement;
      if (parent.querySelector('[data-ad-preview="message"], [data-ad-comet-preview="message"], [data-testid="post_message"]')) {
        break;
      }

      const parentText = extractVisiblePostText(parent);
      if (parentText.length > 260) {
        break;
      }

      block = parent;
    }

    return block;
  }

  function ensurePanelSlot(post) {
    const ownedSlots = [...post.querySelectorAll(".dili-panel-slot[data-dili-owned='true']")];
    let slot = ownedSlots[0] || null;

    for (const extraSlot of ownedSlots.slice(1)) {
      extraSlot.remove();
      scanStatus.duplicatePanelsRemoved += 1;
    }

    if (!slot) {
      slot = document.createElement("div");
      slot.className = "dili-panel-slot";
      slot.dataset.diliOwned = "true";
    }

    const insertionPoint = findPanelInsertionPoint(post);
    if (slot.parentElement !== insertionPoint.parent || slot.nextSibling !== insertionPoint.beforeNode) {
      if (insertionPoint.beforeNode instanceof Node) {
        insertionPoint.parent.insertBefore(slot, insertionPoint.beforeNode);
      } else {
        insertionPoint.parent.appendChild(slot);
      }
    }

    cleanupDuplicatePanelArtifacts(post, slot);
    return slot;
  }

  function cleanupDuplicatePanelArtifacts(post, activeSlot) {
    const activePanel = activeSlot?.querySelector(".dili-panel[data-dili-owned='true']") || null;

    for (const panel of [...post.querySelectorAll(".dili-panel[data-dili-owned='true']")]) {
      if (panel !== activePanel) {
        panel.remove();
        scanStatus.duplicatePanelsRemoved += 1;
      }
    }

    for (const badge of [...post.querySelectorAll(".dili-badge")]) {
      if (!badge.closest(".dili-panel[data-dili-owned='true']")) {
        badge.remove();
        scanStatus.duplicatePanelsRemoved += 1;
      }
    }
  }

  function extractVisiblePostText(post) {
    if (!(post instanceof Element)) {
      return "";
    }

    const clone = post.cloneNode(true);
    for (const selector of [".dili-panel", ".dili-panel-slot", ".dili-badge", ".dili-details", ".dili-warning-overlay", ".dili-warning-modal", "script", "style", "noscript"]) {
      for (const element of clone.querySelectorAll(selector)) {
        element.remove();
      }
    }

    return String(clone.textContent || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  async function buildVisiblePostTextSnapshot(post) {
    const normalizedVisiblePostText = extractVisiblePostText(post);
    const postTextHash = await hashTextFingerprint(normalizedVisiblePostText);

    return {
      normalizedVisiblePostText,
      postTextHash
    };
  }

  async function hashTextFingerprint(value) {
    const text = String(value || "");

    try {
      if (crypto?.subtle?.digest) {
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
      }
    } catch {
      // Fall back to the lightweight local hash below.
    }

    return `fnv-${hashString(text)}`;
  }

  function formatIntegrityEventLabel(value) {
    return String(value || "")
      .replace(/_/g, " ")
      .replace(/\b([a-z])/g, (match) => match.toUpperCase());
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
    if (!FACEBOOK_REDIRECT_HOSTS.has(url.hostname.toLowerCase())) {
      return false;
    }

    const targetUrl = getFacebookRedirectTarget(url.toString());
    if (!targetUrl) {
      return false;
    }

    const targetHost = safeHostname(targetUrl);
    return Boolean(targetHost) && !isFacebookHost(targetHost);
  }

  function isFacebookHost(hostname) {
    return /(^|\.)facebook\.com$/i.test(String(hostname || ""));
  }

  function isFacebookInAppFormUrl(rawUrl) {
    try {
      if (!String(rawUrl || "").trim()) {
        return false;
      }

      const url = new URL(rawUrl, location.href);
      const host = url.hostname.toLowerCase();
      const path = url.pathname.toLowerCase();
      const source = `${host}${path}?${url.searchParams.toString()}`.toLowerCase();

      if (!isFacebookHost(host)) {
        return false;
      }

      return (
        path.includes("/lead_gen") ||
        path.includes("/leadgen") ||
        path.includes("/ads/lead") ||
        path.includes("/instant_form") ||
        path.includes("/instantforms") ||
        path.includes("/forms/") ||
        path.includes("/event_register") ||
        path.includes("/events/register") ||
        source.includes("lead_gen") ||
        source.includes("leadgen") ||
        source.includes("instant_form") ||
        source.includes("registration_form") ||
        source.includes("event_registration")
      );
    } catch {
      return false;
    }
  }

  function isInternalFacebookMediaOrActionUrl(rawUrl) {
    try {
      if (!String(rawUrl || "").trim()) {
        return false;
      }

      const url = new URL(rawUrl, location.href);
      if (!isFacebookHost(url.hostname)) {
        return false;
      }

      const path = url.pathname.toLowerCase();
      const source = `${path}?${url.searchParams.toString()}`.toLowerCase();
      return (
        path.startsWith("/watch") ||
        path.startsWith("/reel") ||
        path.includes("/reel/") ||
        path.includes("/videos/") ||
        path.includes("/photo") ||
        path.includes("/photos/") ||
        path.includes("/profile.php") ||
        path.includes("/share/") ||
        path.includes("/shares/") ||
        path.includes("/comment") ||
        path.includes("/plugins/") ||
        path.includes("/ufi/") ||
        source.includes("comment_id=") ||
        source.includes("reply_comment_id=") ||
        source.includes("reaction_type=")
      );
    } catch {
      return false;
    }
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

      const nested = getFacebookRedirectTarget(inputUrl.toString());
      if (!nested) {
        return inputUrl.toString();
      }

      return nested;
    } catch {
      return String(rawUrl || "");
    }
  }

  function getFacebookRedirectTarget(rawUrl) {
    try {
      const inputUrl = new URL(rawUrl, location.origin);
      if (!FACEBOOK_REDIRECT_HOSTS.has(inputUrl.hostname.toLowerCase())) {
        return "";
      }

      for (const paramName of FACEBOOK_REDIRECT_PARAMS) {
        const nested = inputUrl.searchParams.get(paramName);
        if (!nested) {
          continue;
        }

        const decoded = decodeRedirectTarget(nested);
        const targetHost = safeHostname(decoded);
        if (targetHost && !isFacebookHost(targetHost)) {
          return decoded;
        }
      }

      return "";
    } catch {
      return "";
    }
  }

  function decodeRedirectTarget(value) {
    try {
      return decodeURIComponent(String(value || ""));
    } catch {
      return String(value || "");
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
    if (scanRuntimeState.extensionContextInvalidated || isRuntimeInvalidated()) {
      invalidateRuntimeContext();
      return {
        ok: false,
        runtimeInvalidated: true,
        error: "Extension context invalidated."
      };
    }

    try {
      const response = await chrome.runtime.sendMessage(message);
      if (!response?.ok) {
        console.warn("[DILI] Background returned an error", response?.error);
      }
      return response;
    } catch (error) {
      if (isRuntimeInvalidationError(error)) {
        invalidateRuntimeContext();
        return {
          ok: false,
          runtimeInvalidated: true,
          error: "Extension context invalidated."
        };
      }

      console.warn("[DILI] Message dispatch failed", error);
      return {
        ok: false,
        error: error.message || "Runtime messaging failed."
      };
    }
  }

  function isRuntimeInvalidated() {
    return typeof chrome === "undefined" || !chrome.runtime?.id;
  }

  function isRuntimeInvalidationError(error) {
    const message = String(error?.message || error || "");
    return /Extension context invalidated|context invalidated|Invalid extension context/i.test(message);
  }

  function invalidateRuntimeContext() {
    if (scanRuntimeState.extensionContextInvalidated) {
      return;
    }

    scanRuntimeState.extensionContextInvalidated = true;
    scanRuntimeState.enabled = false;
    scanStatus.enabled = false;
    scanStatus.lastError = "Extension context invalidated.";
    console.debug("[DILI] Extension context invalidated; stopping old content script instance.");
    stopScanning();
  }

  function buildScanStatusSnapshot() {
    scanStatus.enabled = scanRuntimeState.enabled && !scanRuntimeState.extensionContextInvalidated;
    scanStatus.visiblePanels = document.querySelectorAll(".dili-panel[data-dili-owned='true']").length;
    scanStatus.queuedPosts = pendingPosts.size;
    scanStatus.route = location.href;
    return { ...scanStatus };
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
