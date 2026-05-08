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
const DOMAIN_TEXT_PATTERN =
  /\b(?:www\.)?[a-z0-9][a-z0-9.-]*\.(?:academy|agency|ai|app|biz|click|cloud|co|com|dev|edu|finance|gov|info|io|me|net|online|org|ph|shop|site|store|xyz)\b/i;
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
const DILI_UI_SELECTOR =
  ".dili-panel, .dili-panel-slot, .dili-badge, .dili-details, .dili-warning-overlay, .dili-warning-modal";

const OUTBOUND_CLICK_TARGET_SELECTOR =
  'a[href], [data-lynx-uri], [data-url], [role="link"], [role="button"]';

const UNSAFE_PANEL_ANCESTOR_SELECTOR =
  'a[href], [data-lynx-uri], [data-url], [role="link"], [role="button"]';
  const pendingPosts = new Set();
  const postIdCache = new WeakMap();
  let postSignatureCache = new WeakMap();
  const selectedPostLinkCache = new Map();
  const observedPostIds = new Map();
  const latestRequestByPostId = new Map();
  const cachedPanelByPostId = new Map();
  const noLinkRescanCountsByPostId = new Map();
const NO_LINK_PANEL_REMOVAL_CONFIRMATION_COUNT = 3;
  const clickAnalysisCache = new Map();
const CLICK_ANALYSIS_CACHE_TTL_MS = 10 * 60 * 1000;
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

  // Post discovery
  feedRootsFound: 0,
  candidatePostsFound: 0,
  lastCandidatePostsFound: 0,
  eligibleLinkPostsFound: 0,
  analyzedPosts: 0,
  renderedPanels: 0,
  visiblePanels: 0,
  queuedPosts: 0,

  // Existing skip counters
  skippedSidebar: 0,
  skippedInvisible: 0,
  skippedNoLinks: 0,
  skippedActionArea: 0,
  staleResponsesDiscarded: 0,
  duplicatePanelsRemoved: 0,

  // P1-C diagnostics: analysis pipeline tracking
  analysisRequestsSent: 0,
  analysisResponsesReceived: 0,
  analysisResponsesMissing: 0,
  analysisRenderedPanels: 0,
  analysisStaleDiscardedByMissingRequest: 0,
  analysisStaleDiscardedByRequestId: 0,
  analysisStaleDiscardedBySignature: 0,
  analysisStaleDiscardedByFingerprint: 0,
  analysisStaleDiscardedByTextHash: 0,
  analysisStaleDiscardedByCurrentRescan: 0,
  panelRemovedNoLinkState: 0,
  panelRemovedCollapsedDeferred: 0,
  cachedPanelRestored: 0,
  panelPreservedNoLinkRescan: 0,
  panelPreservedCollapsedRescan: 0,
  hiddenDomainFallbackSkipped: 0,
  lastPanelPreservationReason: "",
  skippedMalformedCandidate: 0,
  lastAnalysisPipelineState: null,
  // P3-A diagnostics: timing/performance
  perfLastCollectMs: 0,
  perfLastQueueSize: 0,
  perfLastBatchSize: 0,
  perfLastBatchMs: 0,
  perfLastPostMs: 0,
  perfLastExtractMs: 0,
  perfLastBackgroundRoundTripMs: 0,
  perfLastRenderMs: 0,
  perfMaxPostMs: 0,
  perfMaxBackgroundRoundTripMs: 0,
  perfMaxRenderMs: 0,
  // P1 diagnostics: why candidates/posts are skipped
  skippedImageSource: 0,
  skippedGenericDomain: 0,
  skippedHeaderDomain: 0,
  skippedNoUrl: 0,
  skippedHidden: 0,
  skippedNoOwningPost: 0,
  skippedInternalFacebook: 0,
  skippedNestedSharedStory: 0,
  skippedDiliUi: 0,

  // P1 diagnostics: candidate source counts
  directCandidatesFound: 0,
  embeddedCandidatesFound: 0,
  fallbackCandidatesFound: 0,
  visibleDomainCandidatesFound: 0,
  sponsoredFallbackCandidatesFound: 0,
  hiddenFullUrlCandidatesFound: 0,

  // P1 diagnostics: panel mount behavior
  panelMountFallbackUsed: 0,
  panelUnsafeRelocated: 0,
  panelSlotReused: 0,

  // Existing fallback counters
  sponsoredFallbackAttempts: 0,
  sponsoredFallbackAccepted: 0,

  // Last known diagnostic snapshot
  lastCandidateBreakdown: null,
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

  const cachedAnalysis = getCachedClickAnalysisSync(clickContext);
  const forceFullUrlReanalysis = shouldForceFullUrlClickReanalysis(cachedAnalysis, clickContext);

  // Important:
  // If this exact clicked link was already analyzed and does not require a warning,
  // do not intercept at all. Let Facebook/browser navigation proceed normally.
  // This prevents the repeated "DILI link check" tab/window.
  if (cachedAnalysis && !forceFullUrlReanalysis && !shouldShowWarningModal(cachedAnalysis)) {
    scanStatus.lastAnalysisPipelineState = {
      stage: "click-allowed-from-cache",
      postId: clickContext.postId,
      timestamp: Date.now()
    };
    return;
  }

  event.preventDefault();
  event.stopPropagation();
  if (typeof event.stopImmediatePropagation === "function") {
    event.stopImmediatePropagation();
  }

  const verificationToken = ++clickWarningState.activeToken;
  closeWarningModal({ restoreFocus: false });

  try {
    const analysis = forceFullUrlReanalysis
      ? await resolveClickAnalysis(clickContext, { forceReanalysis: true })
      : cachedAnalysis || await resolveClickAnalysis(clickContext);

    if (verificationToken !== clickWarningState.activeToken) {
      closePendingWindow(clickContext.intent.pendingWindow);
      return;
    }

    if (analysis) {
      rememberClickAnalysis(clickContext, analysis);
      if (forceFullUrlReanalysis && clickContext.post instanceof Element) {
        renderBadge(getTopLevelPanelOwner(clickContext.post), mapAnalysisToViewModel(analysis));
      }
    }

    const destinationUrl = pickDestinationUrl(analysis, clickContext);

    if (!isUsableClickAnalysis(analysis)) {
      showVerificationUnavailableModal({
        clickContext,
        destinationUrl
      });
      return;
    }

    if (!shouldShowWarningModal(analysis)) {
      const continued = continueNavigation(destinationUrl, clickContext.intent);

      if (!continued) {
        showVerificationUnavailableModal({
          clickContext,
          destinationUrl
        });
      }

      return;
    }

    showWarningModal({
      clickContext,
      analysis,
      destinationUrl,
      reasons: buildWarningReasons(analysis)
    });
  } catch (error) {
    console.warn("[DILI] Click link verification failed", error);

    showVerificationUnavailableModal({
      clickContext,
      destinationUrl: normalizeNavigationCandidate(clickContext.normalizedTargetUrl || clickContext.rawUrl)
    });
  }
}

function getInterceptedClickContext(event) {
  if (!(event.target instanceof Element) || event.button !== 0) {
    return null;
  }

  // Critical: ignore DILI UI before looking for Facebook clickable ancestors.
  // This prevents a DILI panel placed inside/near a clickable card from being
  // treated as a Facebook link click.
  if (event.target.closest(DILI_UI_SELECTOR)) {
    return null;
  }

  const targetElement = findClickableUrlElement(event.target);
  if (!(targetElement instanceof Element)) {
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

function findClickableUrlElement(startElement) {
  if (!(startElement instanceof Element)) {
    return null;
  }

  const primary = startElement.closest(OUTBOUND_CLICK_TARGET_SELECTOR);
  if (!(primary instanceof Element)) {
    return null;
  }

  if (getCandidateRawUrl(primary)) {
    return primary;
  }

  // Facebook CTA cards often place the URL on a nested anchor/data-url node.
  const descendantWithUrl = [...primary.querySelectorAll('a[href], [data-lynx-uri], [data-url]')]
    .find((element) => getCandidateRawUrl(element));

  if (descendantWithUrl instanceof Element) {
    return descendantWithUrl;
  }

  const ancestorWithUrl = primary.closest('a[href], [data-lynx-uri], [data-url]');
  if (ancestorWithUrl instanceof Element && getCandidateRawUrl(ancestorWithUrl)) {
    return ancestorWithUrl;
  }

  return primary;
}

  async function resolveClickAnalysis(clickContext, options = {}) {
    const forceReanalysis = options?.forceReanalysis === true;
    const currentState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId: clickContext.postId
    });
    const baseline = currentState?.baseline || null;

if (!forceReanalysis && analysisMatchesTarget(baseline, clickContext.normalizedTargetUrl)) {
  rememberClickAnalysis(clickContext, baseline);
  return baseline;
}

    const clickPostId = buildClickAnalysisPostId(clickContext.postId, clickContext.normalizedTargetUrl);
    const cachedClickState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId: clickPostId
    });
    const cachedClickAnalysis = cachedClickState?.baseline || null;

if (!forceReanalysis && analysisMatchesTarget(cachedClickAnalysis, clickContext.normalizedTargetUrl)) {
  rememberClickAnalysis(clickContext, cachedClickAnalysis);
  return cachedClickAnalysis;
}

    const messageType = !forceReanalysis && cachedClickAnalysis?.urlHash ? MESSAGE_TYPES.REANALYZE_LINK : MESSAGE_TYPES.ANALYZE_LINK;
    const response = await sendRuntimeMessage({
      type: messageType,
      postId: clickPostId,
      url: clickContext.rawUrl,
      displayedText: clickContext.displayText,
      candidateContext: buildClickCandidateContext(clickContext)
    });

const analysis = response?.analysis || null;

if (analysis) {
  rememberClickAnalysis(clickContext, analysis);
}

return analysis;
  }

function shouldForceFullUrlClickReanalysis(cachedAnalysis, clickContext) {
  if (!cachedAnalysis || !clickContext) {
    return false;
  }

  const fallbackOnly = Boolean(
    cachedAnalysis.candidateIsDomainOnlyFallback === true ||
    cachedAnalysis.candidateContext?.candidateIsDomainOnlyFallback === true ||
    cachedAnalysis.candidateUrlCompleteness === "domain-only-fallback"
  );

  if (!fallbackOnly) {
    return false;
  }

  return hasPathOrQueryUrl(clickContext.rawUrl) ||
    hasPathOrQueryUrl(clickContext.normalizedTargetUrl) ||
    hasPathOrQueryUrl(unwrapFacebookRedirectUrl(clickContext.rawUrl || ""));
}

function hasPathOrQueryUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""), location.href);
    return ["http:", "https:"].includes(url.protocol) && Boolean((url.pathname && url.pathname !== "/") || url.search);
  } catch {
    return false;
  }
}

function buildClickCandidateContext(clickContext = {}) {
  const rawUrl = String(clickContext.rawUrl || "").trim();
  const unwrappedCandidateUrl = unwrapFacebookRedirectUrl(rawUrl);
  const normalizedTargetUrl = clickContext.normalizedTargetUrl || safelyNormalizeComparableUrl(rawUrl);

  return {
    candidateMode: "single",
    candidateCount: 1,
    candidateDomainCount: safeHostname(normalizedTargetUrl || unwrappedCandidateUrl || rawUrl) ? 1 : 0,
    dominantDomain: getRegistrableDomain(safeHostname(normalizedTargetUrl || unwrappedCandidateUrl || rawUrl)),
    selectedNormalizedTarget: normalizedTargetUrl || unwrappedCandidateUrl || rawUrl,
    displayText: clickContext.displayText || "",
    visibleText: clickContext.displayText || "",
    rawHref: rawUrl,
    facebookWrapperUrl: isFacebookWrapperHref(rawUrl) ? rawUrl : "",
    unwrappedCandidateUrl,
    candidateSource: "direct",
    candidateUrlCompleteness: getUrlCompletenessForValue(normalizedTargetUrl || unwrappedCandidateUrl || rawUrl),
    candidateIsDomainOnlyFallback: false
  };
}

function getUrlCompletenessForValue(rawUrl) {
  try {
    const url = new URL(rawUrl, location.href);
    const hasPath = url.pathname && url.pathname !== "/";
    const hasQuery = Boolean(url.search);
    return hasPath || hasQuery ? "full-url" : "domain-root-url";
  } catch {
    return "unknown";
  }
}

function analysisMatchesTarget(analysis, normalizedTargetUrl) {
  if (!analysis || !normalizedTargetUrl) {
    return false;
  }

  const target = String(normalizedTargetUrl || "").trim();

  const candidates = [
    analysis.normalizedUrl,
    analysis.rawUrl,
    analysis.analysisUrl,
    analysis.redirectAnalysis?.resolvedUrl,
    analysis.endpointResult?.effectiveEndpoint
  ];

  for (const item of analysis.linkAnalyses || []) {
    candidates.push(
      item.normalizedUrl,
      item.analysisUrl,
      item.redirectAnalysis?.resolvedUrl
    );
  }

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    const normalizedCandidate = safelyNormalizeComparableUrl(candidate);
    if (normalizedCandidate && normalizedCandidate === target) {
      return true;
    }
  }

  return false;
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
function getClickAnalysisCacheKey(postId, normalizedTargetUrl) {
  return `${postId || "unknown-post"}::${String(normalizedTargetUrl || "").trim()}`;
}

function getCachedClickAnalysisSync(clickContext) {
  const key = getClickAnalysisCacheKey(clickContext.postId, clickContext.normalizedTargetUrl);
  const entry = clickAnalysisCache.get(key);

  if (!entry) {
    return null;
  }

  if (Number(entry.expiresAt || 0) <= Date.now()) {
    clickAnalysisCache.delete(key);
    return null;
  }

  if (!analysisMatchesTarget(entry.analysis, clickContext.normalizedTargetUrl)) {
    clickAnalysisCache.delete(key);
    return null;
  }

  return entry.analysis;
}

function setClickAnalysisCacheEntry(postId, normalizedTargetUrl, analysis) {
  if (!postId || !normalizedTargetUrl || !analysis) {
    return;
  }

  clickAnalysisCache.set(getClickAnalysisCacheKey(postId, normalizedTargetUrl), {
    analysis,
    expiresAt: Date.now() + CLICK_ANALYSIS_CACHE_TTL_MS
  });
}

function rememberClickAnalysis(clickContext, analysis) {
  if (!clickContext || !analysis) {
    return;
  }

  setClickAnalysisCacheEntry(clickContext.postId, clickContext.normalizedTargetUrl, analysis);
}

function rememberAnalysisForLinkInfo(postId, linkInfo, analysis) {
  if (!postId || !linkInfo || !analysis) {
    return;
  }

  for (const link of linkInfo.links || []) {
    const normalizedTargetUrl =
      link.normalizedTargetUrl ||
      safelyNormalizeComparableUrl(link.url || "");

    if (normalizedTargetUrl) {
      setClickAnalysisCacheEntry(postId, normalizedTargetUrl, analysis);
    }
  }

  if (linkInfo.normalizedTargetUrl) {
    setClickAnalysisCacheEntry(postId, linkInfo.normalizedTargetUrl, analysis);
  }
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
  const safeDestination = normalizeNavigationCandidate(destinationUrl);

  if (!safeDestination) {
    console.warn("[DILI] Navigation blocked because no valid HTTP/HTTPS destination was available.", {
      destinationUrl
    });
    return false;
  }

    if (intent?.opensNewContext) {
      const pendingWindow = intent.pendingWindow && !intent.pendingWindow.closed ? intent.pendingWindow : null;

if (pendingWindow) {
  try {
    pendingWindow.location.replace(safeDestination);
    pendingWindow.focus();
    return true;
  } catch {
    closePendingWindow(pendingWindow);
  }
}

      const features = intent.opensNewWindow ? "popup=yes,width=1180,height=800" : "";
      const openedWindow = window.open(safeDestination, intent.targetName || "_blank", features);
if (openedWindow) {
  return true;
}
    }

    window.location.assign(safeDestination);
    return true;
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
  if (!analysis || typeof analysis !== "object") {
    return true;
  }

  const gsb = findProviderResult(analysis.providerResults, "gsb");
  const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

  if (gsb?.flagged || urlhaus?.flagged) {
    return true;
  }

  const score = Number(analysis.safetyScore);
  const classification = String(analysis.classification || "").toLowerCase();
  const features = analysis.features || {};
  const verificationState = String(analysis.verificationState || "").toLowerCase();

  if (
    classification.includes("high risk") ||
    classification.includes("danger") ||
    classification.includes("unsafe") ||
    classification.includes("malicious")
  ) {
    return true;
  }

  if (classification.includes("suspicious")) {
    return true;
  }

  if (Number.isFinite(score) && score < 60) {
    return true;
  }

  if (features.integrityHashMismatch && Number.isFinite(score) && score < 75) {
    return true;
  }

  if (
    verificationState === "unverified" &&
    (
      features.shortenedUrl ||
      features.textMismatch ||
      features.obfuscatedUrl ||
      features.suspiciousRedirectPattern ||
      features.usernamePasswordTrick
    )
  ) {
    return true;
  }

  return false;
}
function resolveModalDestinationUrl(destinationUrl, clickContext, analysis = null) {
  const candidates = [
    analysis?.endpointResult?.effectiveEndpoint,
    analysis?.analysisUrl,
    analysis?.endpointResult?.resolvedUrl,
    analysis?.redirectAnalysis?.resolvedUrl,
    analysis?.endpointResult?.unwrappedUrl,
    unwrapFacebookRedirectUrl(clickContext?.rawUrl || ""),
    clickContext?.normalizedTargetUrl,
    destinationUrl,
    clickContext?.rawUrl
  ];

  for (const candidate of candidates) {
    const resolved = normalizeNavigationCandidate(candidate);
    if (resolved) {
      return resolved;
    }
  }

  return "";
}

function normalizeNavigationCandidate(candidate) {
  const value = String(candidate || "").trim();

  if (!value || value === "about:blank") {
    return "";
  }

  try {
    const url = new URL(value, location.href);

    if (url.protocol === "http:" || url.protocol === "https:") {
      return url.toString();
    }
  } catch {
    return "";
  }

  return "";
}
  function pickDestinationUrl(analysis, clickContext) {
    const candidates = [
      analysis?.endpointResult?.effectiveEndpoint,
      analysis?.analysisUrl,
      analysis?.endpointResult?.resolvedUrl,
      analysis?.redirectAnalysis?.resolvedUrl,
      analysis?.endpointResult?.unwrappedUrl,
      unwrapFacebookRedirectUrl(clickContext?.rawUrl || ""),
      clickContext?.normalizedTargetUrl,
      clickContext?.rawUrl
    ];

    for (const candidate of candidates) {
      if (isNavigableHttpUrl(candidate)) {
        return candidate;
      }
    }

return normalizeNavigationCandidate(clickContext?.rawUrl) || "";
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
    const score = Number(analysis?.safetyScore);

    if (gsb?.flagged || urlhaus?.flagged) {
      return "DILI paused navigation because this destination was flagged by a threat-intelligence provider and may expose you to phishing, malware, or other unsafe behavior.";
    }

    if (classification.includes("high risk") || classification.includes("danger") || classification.includes("unsafe")) {
      return "DILI paused navigation because this link shows several warning signs commonly seen in malicious redirects, scam campaigns, or deceptive destination changes.";
    }

    if (classification.includes("suspicious") || (Number.isFinite(score) && score < 60)) {
      return "DILI paused navigation because this link has enough warning signs that you should review it before opening.";
    }

    return "DILI paused navigation because this link could not be verified together with other warning signs.";
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

const safeDestinationUrl = resolveModalDestinationUrl(destinationUrl, clickContext, analysis);
const displayDestinationUrl = safeDestinationUrl || "Unresolved destination";
const navigationDestinationUrl = safeDestinationUrl;

const destinationDomain = safeHostname(safeDestinationUrl) || "unknown-domain";    const scoreText = modalConfig.scoreText || (Number.isFinite(analysis?.safetyScore) ? String(analysis.safetyScore) : "Unavailable");
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
            <span>Safety Score</span>
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
            <p class="dili-warning-destination">${escapeHtml(displayDestinationUrl)}</p>          
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
    const reportPayload = buildReportPayload(
    clickContext,
    analysis,
    safeDestinationUrl,
    reasons,
    modalConfig.reportPayloadOverrides
  );      
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
  if (!navigationDestinationUrl) {
    if (statusNode) {
      statusNode.textContent =
        "DILI could not find a valid destination URL to open. Stay on Facebook or copy the report instead.";
    }
    return;
  }

  closeWarningModal({ restoreFocus: false });
  continueNavigation(navigationDestinationUrl, clickContext.intent);
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
      providerEvidence: overrides.providerEvidence || {
        gsb: buildProviderReportEvidence(gsb),
        urlhaus: buildProviderReportEvidence(urlhaus)
      },
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

    const providerEvidence = payload.providerEvidence || {};
    const gsbEvidence = providerEvidence.gsb || {};
    const urlhausEvidence = providerEvidence.urlhaus || {};

    return [
      "DILI Suspicious Link Report",
      `Generated at: ${payload.generatedAt}`,
      `Facebook page URL: ${payload.currentFacebookPageUrl || ""}`,
      `Post ID: ${payload.postId || ""}`,
      `Post permalink: ${payload.postPermalink || ""}`,
      `Clicked text: ${payload.clickedText || ""}`,
      `Destination URL: ${payload.destinationUrl || ""}`,
      `Destination domain: ${payload.destinationDomain || ""}`,
      `Safety Classification: ${payload.classification || ""}`,
      `Safety score: ${payload.safetyScore ?? "Unavailable"}`,
      "Main reasons:",
      reasonLines,
      `Google Safe Browsing flagged: ${payload.providerFlags?.googleSafeBrowsing ? "Yes" : "No"}`,
      `Google Safe Browsing checked URL: ${gsbEvidence.checkedUrl || "Unavailable"}`,
      `Google Safe Browsing result: ${gsbEvidence.resultSummary || "Unavailable"}`,
      `Google Safe Browsing checked at: ${gsbEvidence.checkedAt || "Unavailable"}`,
      `Google Safe Browsing response time: ${Number.isFinite(Number(gsbEvidence.durationMs)) ? `${Number(gsbEvidence.durationMs)} ms` : "Unavailable"}`,
      `URLhaus flagged: ${payload.providerFlags?.urlhaus ? "Yes" : "No"}`,
      `URLhaus checked URL: ${urlhausEvidence.checkedUrl || "Unavailable"}`,
      `URLhaus result: ${urlhausEvidence.resultSummary || "Unavailable"}`,
      `URLhaus checked at: ${urlhausEvidence.checkedAt || "Unavailable"}`,
      `URLhaus response time: ${Number.isFinite(Number(urlhausEvidence.durationMs)) ? `${Number(urlhausEvidence.durationMs)} ms` : "Unavailable"}`,
      `Integrity mismatch detected: ${payload.integrityMismatch ? "Yes" : "No"}`,
      `Redirect count: ${payload.redirectCount ?? 0}`,
      `Analysis state: ${payload.analysisState || ""}`,
      `Timestamp: ${new Date(Number(payload.timestamp || Date.now())).toISOString()}`
    ].join("\n");
  }

  function buildProviderReportEvidence(provider) {
    if (!provider || typeof provider !== "object") {
      return {
        checkedUrl: "",
        checkedAt: "",
        durationMs: null,
        resultSummary: "Provider not configured."
      };
    }

    return {
      checkedUrl: provider.checkedUrl || "",
      checkedAt: provider.checkedAt || "",
      durationMs: Number.isFinite(Number(provider.durationMs)) ? Number(provider.durationMs) : null,
      resultSummary: provider.resultSummary || getProviderOutcomeSummary(provider)
    };
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

  const startedAt = nowMs();

  scanStatus.lastScanAt = Date.now();
  scanStatus.route = location.href;

  const posts = collectCandidatePosts(root);

  for (const post of posts) {
    enqueuePost(post);
  }

  scanStatus.perfLastCollectMs = elapsedMs(startedAt);
  scanStatus.perfLastQueueSize = pendingPosts.size;

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
attributeFilter: [
  "href",
  "data-ft",
  "aria-label",
  "aria-expanded",
  "data-url",
  "data-lynx-uri",
  "role",
  "target"
] 
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

  if (!owningPost) {
    scanStatus.skippedNoOwningPost += 1;
    continue;
  }

  if (isScannablePostContainer(owningPost)) {
    candidates.add(owningPost);
  }
}
    }

scanStatus.lastCandidatePostsFound = candidates.size;
scanStatus.candidatePostsFound = Math.max(
  Number(scanStatus.candidatePostsFound || 0),
  candidates.size
);    
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

  function getTopLevelPanelOwner(element) {
    const base = getOwningPostContainer(element) || element;

    if (!(base instanceof Element)) {
      return base;
    }

    const ancestors = getArticleAncestors(base)
      .filter((candidate) => candidate instanceof Element && isScannablePostContainer(candidate));

    return ancestors[0] || base;
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

  const batchStartedAt = nowMs();
  scanStatus.perfLastBatchSize = Array.isArray(batch) ? batch.length : 0;

  for (let index = 0; index < batch.length; index += POST_PROCESS_CONCURRENCY) {
    const slice = batch.slice(index, index + POST_PROCESS_CONCURRENCY);
    const results = await Promise.allSettled(slice.map((post) => processPost(post)));

    for (const result of results) {
      if (result.status === "rejected") {
        console.warn("[DILI] Post processing failed", result.reason);
      }
    }
  }

  scanStatus.perfLastBatchMs = elapsedMs(batchStartedAt);
}

async function processPost(post) {
  if (!scanRuntimeState.enabled || scanRuntimeState.extensionContextInvalidated) {
    return;
  }

  const postStartedAt = nowMs();
  const owningPost = getTopLevelPanelOwner(post);

  if (!owningPost?.isConnected || !isScannablePostContainer(owningPost)) {
    return;
  }

  const postIdentity = getStablePostIdentity(owningPost);
  const postId = postIdentity.id;

  console.debug("[DILI] Post identity", {
    postId,
    stable: postIdentity.stable,
    reason: postIdentity.reason
  });

  const extractStartedAt = nowMs();
  const postTextSnapshot = await buildVisiblePostTextSnapshot(owningPost);
  const linkInfo = extractRelevantLinks(owningPost, postId);
  scanStatus.perfLastExtractMs = elapsedMs(extractStartedAt);

  const signature = buildPostSignature(linkInfo);

  if (linkInfo) {
    resetNoLinkRescanCount(postId);
  }

  if (postSignatureCache.get(owningPost) === signature) {
    const cachedPanel = cachedPanelByPostId.get(postId);

    if (linkInfo && cachedPanel && !owningPost.querySelector(".dili-panel[data-dili-owned='true']")) {
      scanStatus.cachedPanelRestored += 1;
      scanStatus.lastAnalysisPipelineState = {
        stage: "cached-panel-restored",
        postId,
        timestamp: Date.now()
      };

      renderBadge(owningPost, cachedPanel);
      return;
    }

    if (!linkInfo) {
      if (isPostCaptionProbablyCollapsed(owningPost)) {
        if (shouldDelayNoLinkPanelRemoval(owningPost, postId, "collapsed-no-link-awaiting-confirmation")) {
          scanStatus.panelPreservedCollapsedRescan += 1;
          return;
        }

        await deferCollapsedNoLinkPost(owningPost, postId, postTextSnapshot);
        return;
      }

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
        if (shouldDelayNoLinkPanelRemoval(owningPost, postId, "no-link-awaiting-confirmation")) {
          return;
        }

        await setNoLinkState(owningPost, postId, postTextSnapshot, postIdentity);
      }

      return;
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

    if (isPostCaptionProbablyCollapsed(owningPost)) {
      if (shouldDelayNoLinkPanelRemoval(owningPost, postId, "collapsed-no-link-awaiting-confirmation")) {
        scanStatus.panelPreservedCollapsedRescan += 1;
        return;
      }

      await deferCollapsedNoLinkPost(owningPost, postId, postTextSnapshot);
      return;
    }

    if (shouldDelayNoLinkPanelRemoval(owningPost, postId, "no-link-awaiting-confirmation")) {
      return;
    }

    await setNoLinkState(owningPost, postId, postTextSnapshot, postIdentity);
    return;
  }

  scanStatus.lastPanelPreservationReason = "";
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

  scanStatus.analysisRequestsSent += 1;
  scanStatus.lastAnalysisPipelineState = {
    stage: "request-sent",
    postId,
    requestId,
    messageType,
    signature,
    linkFingerprint,
    linkCount: linkInfo.links.length,
    timestamp: Date.now()
  };

  renderBadge(owningPost, {
    label: "Analyzing",
    safetyScore: null,
    state: "monitored",
    severityLevel: "unverified",
    summaryLine: "DILI is resolving this post's external link destination.",
    detailsSummary: "Scan details",
    details: [`Checking ${linkInfo.links.length} link${linkInfo.links.length === 1 ? "" : "s"}.`]
  });

  const backgroundStartedAt = nowMs();

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

  const backgroundRoundTripMs = elapsedMs(backgroundStartedAt);
  scanStatus.perfLastBackgroundRoundTripMs = backgroundRoundTripMs;
  recordMaxScanStatusValue("perfMaxBackgroundRoundTripMs", backgroundRoundTripMs);

  if (response?.analysis) {
    scanStatus.analysisResponsesReceived += 1;
    scanStatus.lastAnalysisPipelineState = {
      stage: "response-received",
      postId,
      requestId,
      hasAnalysis: true,
      timestamp: Date.now()
    };
  } else {
    scanStatus.analysisResponsesMissing += 1;
    scanStatus.lastAnalysisPipelineState = {
      stage: "response-missing",
      postId,
      requestId,
      error: response?.error || "",
      timestamp: Date.now()
    };
  }

  const latestRequest = latestRequestByPostId.get(postId);
  const currentLinkInfoForStaleCheck = extractRelevantLinks(owningPost, postId, {
    suppressDiagnostics: true
  });
  const currentSignatureForStaleCheck = buildPostSignature(currentLinkInfoForStaleCheck);

  let staleReason = "";

  if (!latestRequest) {
    staleReason = "missing-request";
    scanStatus.analysisStaleDiscardedByMissingRequest += 1;
  } else if (latestRequest.requestId !== requestId) {
    staleReason = "request-id";
    scanStatus.analysisStaleDiscardedByRequestId += 1;
  } else if (latestRequest.signature !== signature) {
    staleReason = "signature";
    scanStatus.analysisStaleDiscardedBySignature += 1;
  } else if (latestRequest.linkFingerprint !== linkFingerprint) {
    staleReason = "fingerprint";
    scanStatus.analysisStaleDiscardedByFingerprint += 1;
  } else if (latestRequest.postTextHash !== postTextSnapshot.postTextHash) {
    staleReason = "text-hash";
    scanStatus.analysisStaleDiscardedByTextHash += 1;
  } else if (currentSignatureForStaleCheck !== signature) {
    staleReason = "current-rescan";
    scanStatus.analysisStaleDiscardedByCurrentRescan += 1;
  }

  if (staleReason) {
    scanStatus.staleResponsesDiscarded += 1;
    scanStatus.lastAnalysisPipelineState = {
      stage: "stale-discarded",
      reason: staleReason,
      postId,
      requestId,
      expectedSignature: signature,
      currentSignature: currentSignatureForStaleCheck,
      expectedFingerprint: linkFingerprint,
      currentFingerprint: currentLinkInfoForStaleCheck?.linkFingerprint || "",
      timestamp: Date.now()
    };

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
  scanStatus.lastAnalysisPipelineState = {
    stage: "rendering-analysis-panel",
    postId,
    requestId,
    timestamp: Date.now()
  };

  const renderStartedAt = nowMs();

  renderBadge(owningPost, mapAnalysisToViewModel(response.analysis));
  rememberAnalysisForLinkInfo(postId, linkInfo, response.analysis);

  const renderMs = elapsedMs(renderStartedAt);
  scanStatus.perfLastRenderMs = renderMs;
  recordMaxScanStatusValue("perfMaxRenderMs", renderMs);
  scanStatus.analysisRenderedPanels += 1;

  scanStatus.lastAnalysisPipelineState = {
    stage: "analysis-panel-rendered",
    postId,
    requestId,
    visiblePanels: document.querySelectorAll(".dili-panel[data-dili-owned='true']").length,
    timestamp: Date.now()
  };

  const postMs = elapsedMs(postStartedAt);
  scanStatus.perfLastPostMs = postMs;
  recordMaxScanStatusValue("perfMaxPostMs", postMs);
}
function isPostCaptionProbablyCollapsed(post) {
  if (!(post instanceof Element)) {
    return false;
  }

  const candidates = [...post.querySelectorAll('[role="button"], span, div')];

  return candidates.some((element) => {
    if (!(element instanceof Element) || !isProbablyVisible(element)) {
      return false;
    }

    if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
      return false;
    }

    const text = extractVisiblePostText(element)
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();

    const aria = String(element.getAttribute("aria-label") || "").toLowerCase();

    return (
      text === "see more" ||
      text === "show more" ||
      text === "more" ||
      /\bsee more\b/.test(aria) ||
      /\bshow more\b/.test(aria)
    );
  });
}
async function deferCollapsedNoLinkPost(post, postId, postTextSnapshot = null) {
  await sendRuntimeMessage({
    type: MESSAGE_TYPES.SET_NO_LINK_STATE,
    postId,
    baselineState: "truncated_unexpanded",
    postTextHash: postTextSnapshot?.postTextHash || "",
    normalizedVisiblePostText: postTextSnapshot?.normalizedVisiblePostText || ""
  });

  selectedPostLinkCache.delete(postId);
  cachedPanelByPostId.delete(postId);

  scanStatus.panelRemovedCollapsedDeferred += 1;
  scanStatus.lastAnalysisPipelineState = {
    stage: "panel-removed-collapsed-deferred",
    postId,
    timestamp: Date.now()
  };

  // Important:
  // Do not render a panel here. A collapsed caption is not proof that a link exists.
  // The post will be rescanned when "See more" mutates the DOM.
  removeOwnedPanel(post);
}
async function setNoLinkState(post, postId, postTextSnapshot = null, postIdentity = null) {
  const stable = postIdentity?.stable === true;

  await sendRuntimeMessage({
    type: MESSAGE_TYPES.SET_NO_LINK_STATE,
    postId,
    baselineState: stable ? "no_link" : "observed_no_link_unstable",
    postTextHash: postTextSnapshot?.postTextHash || "",
    normalizedVisiblePostText: postTextSnapshot?.normalizedVisiblePostText || ""
  });

  selectedPostLinkCache.delete(postId);
  cachedPanelByPostId.delete(postId);

  scanStatus.panelRemovedNoLinkState += 1;
  scanStatus.lastAnalysisPipelineState = {
    stage: "panel-removed-no-link-state",
    postId,
    baselineState: stable ? "no_link" : "observed_no_link_unstable",
    timestamp: Date.now()
  };
  removeOwnedPanel(post);
}
function extractRelevantLinks(post, postId = getStablePostId(post), options = {}) {
  const suppressDiagnostics = options?.suppressDiagnostics === true;
  const rememberedSelection = selectedPostLinkCache.get(postId) || null;

  let candidateElements = [...post.querySelectorAll(
    'a[href], [data-lynx-uri], [data-url], [role="link"], [role="button"]'
  )].filter((element) => {
    return element instanceof Element && isUserFacingOutboundCandidate(element, post);
  });

  candidateElements = includeAncestorAnchors(candidateElements, post);

const directCandidates = candidateElements
  .map((element) => buildRelevantLinkCandidate(element, post))
  .filter(Boolean);

const embeddedCardCandidates = findEmbeddedCardCandidates(post);
const sponsoredFallbackCandidates = findSponsoredFallbackCandidates(post);
const hiddenFullUrlCandidates = findHiddenFullUrlCandidates(post);
const visibleDomainFallbackCandidates = findVisibleDomainFallbackCandidates(post);

const fallbackCandidates = [
  ...sponsoredFallbackCandidates,
  ...hiddenFullUrlCandidates,
  ...visibleDomainFallbackCandidates
];

const candidates = filterFallbackCandidatesWhenFullUrlsExist(dedupeLinkCandidates([
  ...directCandidates,
  ...embeddedCardCandidates,
  ...fallbackCandidates
]));

if (!suppressDiagnostics) {
  scanStatus.directCandidatesFound += directCandidates.length;
  scanStatus.embeddedCandidatesFound += embeddedCardCandidates.length;
  scanStatus.sponsoredFallbackCandidatesFound += sponsoredFallbackCandidates.length;
  scanStatus.hiddenFullUrlCandidatesFound += hiddenFullUrlCandidates.length;
  scanStatus.visibleDomainCandidatesFound += visibleDomainFallbackCandidates.length;
  scanStatus.fallbackCandidatesFound += fallbackCandidates.length;

  scanStatus.lastCandidateBreakdown = {
    direct: directCandidates.length,
    embedded: embeddedCardCandidates.length,
    sponsoredFallback: sponsoredFallbackCandidates.length,
    hiddenFullUrl: hiddenFullUrlCandidates.length,
    visibleDomainFallback: visibleDomainFallbackCandidates.length,
    fallback: fallbackCandidates.length,
    total: candidates.length
  };

  console.debug("[DILI] Candidate summary", scanStatus.lastCandidateBreakdown);
}

  const candidateSummary = summarizePostLinkCandidates(candidates, rememberedSelection);

  if (!candidateSummary?.dominantCandidate || candidates.length === 0) {
    selectedPostLinkCache.delete(postId);
    return null;
  }

  const sortedCandidates = [...candidates].sort(compareRelevantLinkCandidates);
  const uniqueCandidates = dedupeLinkCandidates(sortedCandidates).slice(0, MAX_LINKS_PER_POST);
  const selectedCandidate = candidateSummary.dominantCandidate || uniqueCandidates[0];

  const uniqueDomains = [...new Set(
    uniqueCandidates.map((candidate) => candidate.registrableDomain).filter(Boolean)
  )];

  const uniqueTargets = [...new Set(
    uniqueCandidates.map((candidate) => candidate.normalizedTargetUrl).filter(Boolean)
  )];

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

  const selectedCandidateDetails = buildCandidateContextDetails(selectedCandidate);

  return {
    element: selectedCandidate.element,
    url: selectedCandidate.url,
    displayText: selectedCandidate.displayText,
    visibleText: selectedCandidate.visibleText || selectedCandidate.displayText || "",
    rawHref: selectedCandidate.rawHref || selectedCandidate.url || "",
    normalizedTargetUrl: selectedCandidate.normalizedTargetUrl,
    links: uniqueCandidates.map((candidate) => ({
      url: candidate.url,
      displayText: candidate.displayText,
      visibleText: candidate.visibleText || candidate.displayText || "",
      rawHref: candidate.rawHref || candidate.url || "",
      facebookWrapperUrl: candidate.facebookWrapperUrl || "",
      unwrappedCandidateUrl: candidate.unwrappedCandidateUrl || candidate.normalizedTargetUrl || candidate.url || "",
      normalizedTargetUrl: candidate.normalizedTargetUrl,
      candidateSource: getCandidateSource(candidate),
      candidateUrlCompleteness: getCandidateUrlCompleteness(candidate),
      candidateIsDomainOnlyFallback: isDomainOnlyFallbackCandidate(candidate),
      candidateContext: {
        candidateMode,
        candidateCount: uniqueCandidates.length,
        candidateDomainCount: uniqueDomains.length,
        dominantDomain: candidate.registrableDomain || "",
        selectedNormalizedTarget: candidate.normalizedTargetUrl,
        signature,
        ...buildCandidateContextDetails(candidate)
      }
    })),
    linkFingerprint: uniqueTargets.sort().join("|"),
    candidateContext: {
      candidateMode,
      candidateCount: uniqueCandidates.length,
      candidateDomainCount: uniqueDomains.length,
      dominantDomain: selectedCandidate.registrableDomain || "",
      selectedNormalizedTarget,
      signature,
      ...selectedCandidateDetails
    }
  };
}
function findVisibleDomainFallbackCandidates(post) {
  if (!(post instanceof Element)) {
    return [];
  }

  const renderedText = extractRenderedVisibleText(post);
  const text = removeHeaderTextFromRenderedText(post, renderedText);
  const hasCta = CTA_TEXT_PATTERNS.some((pattern) => pattern.test(text));
  const hasSponsored = /\bsponsored\b/i.test(text);
  const hasEmbedOrAttachment = Boolean(
    post.querySelector(
      '[data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"]), [role="link"], [role="button"]'
    )
  );

  if (!text) {
    scanStatus.hiddenDomainFallbackSkipped += 1;
    return [];
  }

  const domainMatches = [...text.matchAll(new RegExp(DOMAIN_TEXT_PATTERN.source, "gi"))]
    .map((match) => String(match[0] || "").toLowerCase())
    .filter(Boolean);

  const postHasClearDestinationIntent = hasClearDestinationIntent(post, text);

  const uniqueDomains = [...new Set(domainMatches)]
    .filter((domain) => !isIgnoredVisibleDomain(domain))
    .filter((domain) => {
      if (!isLikelyImageAttributionDomain(domain)) {
        return true;
      }

      // Do not scan image-generator attribution domains unless the post clearly
      // presents them as a CTA/sponsored destination.
      return postHasClearDestinationIntent;
    });
  if (uniqueDomains.length === 0) {
    return [];
  }

  // Avoid treating random organic text as a link.
  // But allow ads/cards with visible domains even if the href is hidden.
  if (!hasSponsored && !hasCta && !hasEmbedOrAttachment) {
    return [];
  }

  if (!hasSponsored && !hasCta && uniqueDomains.length > 0) {
    const attachment = findPostAttachmentOrPreview(post);
    const hasRenderedDomainInAttachment = attachment instanceof Element &&
      DOMAIN_TEXT_PATTERN.test(extractRenderedVisibleText(attachment));

    if (!hasRenderedDomainInAttachment) {
      scanStatus.hiddenDomainFallbackSkipped += 1;
      return [];
    }
  }

  const filteredDomains = uniqueDomains.filter((domain) => {
    if (!domainAppearsOnlyInHeader(domain, post, renderedText)) {
      return true;
    }

    scanStatus.skippedHeaderDomain += 1;
    return false;
  });

  if (filteredDomains.length === 0) {
    return [];
  }

  return filteredDomains
    .map((domain) => {
      const normalizedDomain = domain.replace(/^www\./i, "");
      const url = `https://${domain}`;

      if (!isEligibleLink(url)) {
        return null;
      }

      const hostname = safeHostname(url);
      const registrableDomain = getRegistrableDomain(hostname);

      return {
        element: post,
        url,
        normalizedTargetUrl: safelyNormalizeComparableUrl(url),
        displayText: domain,
        visibleText: domain,
        rawHref: url,
        facebookWrapperUrl: "",
        unwrappedCandidateUrl: url,
        hostname,
        registrableDomain,
        wrapperOutbound: false,
        meaningfulText: true,
        inMainContent: false,
        inActionArea: false,
        hasMedia: Boolean(post.querySelector("img, picture, video, svg")),
        visualArea: 900,
        textLength: domain.length,
        urlLength: url.length,
        domPath: `visible-domain:${normalizedDomain}`,
        candidateSource: "visible-domain-fallback"
      };
    })
    .filter(Boolean);
}

function findEmbeddedCardCandidates(post) {
  if (!(post instanceof Element)) {
    return [];
  }

  const cardSelectors = [
    '[data-ad-preview]:not([data-ad-preview="message"])',
    '[data-ad-comet-preview]:not([data-ad-comet-preview="message"])',
    '[role="link"]',
    '[role="button"]',
    'a[href]',
    '[data-url]',
    '[data-lynx-uri]'
  ];

  const cards = [];

  for (const selector of cardSelectors) {
    for (const element of post.querySelectorAll(selector)) {
      if (!(element instanceof Element) || !post.contains(element)) {
        continue;
      }

      if (element.closest(".dili-panel, .dili-panel-slot, .dili-badge, .dili-warning-overlay")) {
        continue;
      }
if (isInsidePostHeaderArea(element, post)) {
  scanStatus.skippedHeaderDomain += 1;
  continue;
}
      if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
        continue;
      }

      if (!isProbablyVisible(element)) {
        continue;
      }

      cards.push(element);
    }
  }

  const candidates = [];

  for (const card of [...new Set(cards)]) {
    const directCandidate = buildRelevantLinkCandidate(card, post);
    if (directCandidate) {
      candidates.push({
        ...directCandidate,
        candidateSource: "embedded-card-direct"
      });
      continue;
    }

    const renderedCardText = extractRenderedVisibleText(card);
    const cardText = [
      renderedCardText,
      card.getAttribute("aria-label") || "",
      card.getAttribute("title") || ""
    ]
      .join(" ")
      .replace(/\s+/g, " ")
      .trim();

    if (!renderedCardText && !hasClearDestinationIntent(card, cardText)) {
      scanStatus.hiddenDomainFallbackSkipped += 1;
      continue;
    }

    const cardHasClearDestinationIntent = hasClearDestinationIntent(card, cardText);

    const domainMatches = [...cardText.matchAll(new RegExp(DOMAIN_TEXT_PATTERN.source, "gi"))]
      .map((match) => String(match[0] || "").toLowerCase())
      .filter((domain) => domain && !isIgnoredVisibleDomain(domain))
      .filter((domain) => {
        if (!isLikelyImageAttributionDomain(domain)) {
          return true;
        }

        // Do not convert image/meme attribution domains into embedded-card links
        // unless the card/post has clear destination intent.
        return cardHasClearDestinationIntent;
      });

    const filteredCardDomains = [...new Set(domainMatches)].filter((domain) => {
      if (!domainAppearsOnlyInHeader(domain, post, cardText)) {
        return true;
      }

      scanStatus.skippedHeaderDomain += 1;
      return false;
    });

    for (const domain of filteredCardDomains) {
      const url = `https://${domain}`;

      if (!isEligibleLink(url)) {
        continue;
      }

      const hostname = safeHostname(url);
      const registrableDomain = getRegistrableDomain(hostname);

      candidates.push({
        element: card,
        url,
        normalizedTargetUrl: safelyNormalizeComparableUrl(url),
        displayText: domain,
        visibleText: domain,
        rawHref: url,
        facebookWrapperUrl: "",
        unwrappedCandidateUrl: url,
        hostname,
        registrableDomain,
        wrapperOutbound: false,
        meaningfulText: true,
        inMainContent: false,
        inActionArea: false,
        hasMedia: Boolean(card.querySelector("img, picture, video, svg")),
        visualArea: 1200,
        textLength: domain.length,
        urlLength: url.length,
        domPath: `embedded-card-domain:${domain.replace(/^www\./i, "")}`,
        candidateSource: "embedded-card-visible-domain"
      });
    }
  }

  return dedupeLinkCandidates(candidates);
}

function findHiddenFullUrlCandidates(post) {
  if (!(post instanceof Element)) {
    return [];
  }

  const visibleDomains = collectVisibleDomains(post);
  const candidates = [];
  const seen = new Set();

  for (const { element, value, sourceLabel } of collectAttributeUrlStrings(post)) {
    for (const rawUrl of extractUrlCandidatesFromRawString(value)) {
      if (!isUsefulFullEndpointCandidate(rawUrl, post)) {
        continue;
      }

      const candidate = buildHiddenFullUrlCandidate(rawUrl, element, sourceLabel, post);
      if (!candidate) {
        continue;
      }

      candidate.visibleDomainMatch = candidateMatchesVisibleDomains(candidate, visibleDomains);
      const key = candidate.normalizedTargetUrl || candidate.url;
      if (!key || seen.has(key)) {
        continue;
      }

      seen.add(key);
      candidates.push(candidate);
    }
  }

  const uniqueCandidates = dedupeLinkCandidates(candidates);
  if (uniqueCandidates.length > 0) {
    console.debug(`[DILI] Hidden full URL candidates found: ${uniqueCandidates.length}`);
  }

  return uniqueCandidates;
}

function collectAttributeUrlStrings(root) {
  if (!(root instanceof Element)) {
    return [];
  }

  const interestingAttributes = new Set([
    "href",
    "data-url",
    "data-lynx-uri",
    "ajaxify",
    "data-store",
    "data-ft",
    "data-hovercard",
    "data-hovercard-prefer-more-content-show",
    "aria-label",
    "title",
    "onclick",
    "role",
    "target"
  ]);
  const urlishPattern =
  /https?:\/\/|https?:\\\/\\\/|https?\\u003a\\u002f\\u002f|https?%3a%2f%2f|l\.facebook\.com\/l\.php|l\.facebook\.com\\\/l\.php|(?:^|[?&"'\s])(url|u|redirect|destination|target)=|(?:url|u|redirect|destination|target)\\u003d/i;
  const result = [];
  const elements = [root, ...root.querySelectorAll("*")];

  for (const element of elements) {
    if (!(element instanceof Element) || element.closest(".dili-panel, .dili-panel-slot, .dili-badge, .dili-warning-overlay")) {
      continue;
    }

    for (const attribute of [...element.attributes]) {
      const name = String(attribute.name || "").toLowerCase();
      const value = String(attribute.value || "").trim();
      if (!value) {
        continue;
      }

      if (interestingAttributes.has(name) || urlishPattern.test(value)) {
        result.push({ element, value, sourceLabel: name });
      }
    }
  }

  return result;
}

function extractUrlCandidatesFromRawString(rawValue) {
  const values = [];
  const seenValues = new Set();
  const pushValue = (value) => {
    const text = String(value || "").trim();
    if (text && !seenValues.has(text)) {
      seenValues.add(text);
      values.push(text);
    }
  };

  pushValue(rawValue);
  pushValue(decodeHtmlEntities(rawValue));
  pushValue(normalizeEscapedUrlString(rawValue));

  for (let index = 0; index < values.length && index < 12; index += 1) {
    const decoded = decodePossibleUrlString(values[index]);
    if (decoded && decoded !== values[index]) {
      pushValue(decoded);
    }
  }

  const found = [];
  const seenUrls = new Set();
  const pushUrl = (url) => {
    const text = String(url || "").trim();
    if (!/^https?:\/\//i.test(text) || seenUrls.has(text)) {
      return;
    }

    seenUrls.add(text);
    found.push(text);
  };

  for (const value of values) {
    for (const match of value.matchAll(/https?:\/\/[^\s"'<>\\)\\]}]+/gi)) {
      pushUrl(cleanExtractedUrl(match[0]));
    }

    for (const match of value.matchAll(/https?%3a%2f%2f[^\s"'<>\\)\\]}]+/gi)) {
      pushUrl(cleanExtractedUrl(decodePossibleUrlString(match[0])));
    }

    for (const nested of extractRedirectParamUrls(value)) {
      pushUrl(nested);
    }
  }

  return found;
}

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">");
}

function normalizeEscapedUrlString(value) {
  return decodeHtmlEntities(value)
    .replace(/\\u0026/gi, "&")
    .replace(/\\u003d/gi, "=")
    .replace(/\\u003f/gi, "?")
    .replace(/\\u002f/gi, "/")
    .replace(/\\u003a/gi, ":")
    .replace(/\\\//g, "/")
    .replace(/&amp;/gi, "&");
}

function decodePossibleUrlString(value) {
  let current = normalizeEscapedUrlString(value);
  for (let depth = 0; depth < 2; depth += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) {
        break;
      }
      current = normalizeEscapedUrlString(decoded);
    } catch {
      break;
    }
  }

  return current;
}

function extractRedirectParamUrls(rawUrl) {
  const result = [];
  const queue = extractUrlCandidatesFromPlainText(decodePossibleUrlString(rawUrl)).slice(0, 8);
  const seen = new Set();

  for (let index = 0; index < queue.length && index < 12; index += 1) {
    const value = queue[index];
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);

    try {
      const parsed = new URL(value, location.href);
      for (const paramName of FACEBOOK_REDIRECT_PARAMS) {
        const nested = parsed.searchParams.get(paramName);
        if (!nested) {
          continue;
        }

        const decoded = decodePossibleUrlString(nested);
        if (/^https?:\/\//i.test(decoded)) {
          result.push(decoded);
          queue.push(decoded);
        }
      }

      const unwrapped = unwrapFacebookRedirectUrl(parsed.toString());
      if (unwrapped && unwrapped !== parsed.toString()) {
        result.push(unwrapped);
        queue.push(unwrapped);
      }
    } catch {
      continue;
    }
  }

  return [...new Set(result)];
}

function extractUrlCandidatesFromPlainText(value) {
  const text = String(value || "");
  const urls = [];
  for (const match of text.matchAll(/https?:\/\/[^\s"'<>\\)\\]}]+/gi)) {
    urls.push(cleanExtractedUrl(match[0]));
  }
  return urls;
}

function cleanExtractedUrl(value) {
  return normalizeEscapedUrlString(value)
    .replace(/[),.;\]}]+$/g, "")
    .trim();
}

function isUsefulFullEndpointCandidate(rawUrl, post) {
  if (!isEligibleLink(rawUrl)) {
    return false;
  }

  const unwrapped = unwrapFacebookRedirectUrl(rawUrl);

  try {
    const url = new URL(unwrapped, location.href);
    const hostname = url.hostname.toLowerCase();
    const hasPathOrQuery = Boolean((url.pathname && url.pathname !== "/") || url.search);

    if (!["http:", "https:"].includes(url.protocol) || !hasPathOrQuery) {
      return false;
    }

    if (isFacebookHost(hostname) || isFacebookMediaCdnOrViewerUrl(url.toString()) || isInternalFacebookMediaOrActionUrl(url.toString())) {
      return false;
    }

    if (isProviderApiUrl(url.toString()) || isFacebookInAppFormUrl(url.toString()) || isLikelyMediaAssetUrl(url.toString())) {
      return false;
    }

    return post instanceof Element;
  } catch {
    return false;
  }
}

function buildHiddenFullUrlCandidate(rawUrl, sourceElement, sourceLabel, post) {
  const unwrappedCandidateUrl = unwrapFacebookRedirectUrl(rawUrl);
  const normalizedTargetUrl = safelyNormalizeComparableUrl(unwrappedCandidateUrl || rawUrl);
  const hostname = safeHostname(normalizedTargetUrl || unwrappedCandidateUrl || rawUrl);
  const registrableDomain = getRegistrableDomain(hostname);

  if (!hostname || !registrableDomain) {
    return null;
  }

  const rect = sourceElement instanceof Element ? sourceElement.getBoundingClientRect() : { width: 0, height: 0 };
  const displayText = sourceElement instanceof Element ? extractAnchorDisplayText(sourceElement) : "";
  const facebookWrapperUrl = isFacebookWrapperHref(rawUrl) ? rawUrl : "";

  return {
    element: sourceElement instanceof Element ? sourceElement : post,
    url: rawUrl,
    rawHref: rawUrl,
    normalizedTargetUrl,
    displayText,
    visibleText: displayText,
    facebookWrapperUrl,
    unwrappedCandidateUrl,
    hostname,
    registrableDomain,
    wrapperOutbound: Boolean(facebookWrapperUrl),
    meaningfulText: hasMeaningfulCandidateText(displayText),
    inMainContent: sourceElement instanceof Element ? isElementInMainPostContent(sourceElement, post) : false,
    inActionArea: sourceElement instanceof Element ? isElementInActionArea(sourceElement, post) : false,
    hasMedia: sourceElement instanceof Element ? Boolean(sourceElement.querySelector?.("img, picture, video, svg")) : false,
    visualArea: Math.round(Math.max(rect.width || 0, 0) * Math.max(rect.height || 0, 0)),
    textLength: displayText.length,
    urlLength: normalizedTargetUrl.length,
    domPath: `hidden-url:${String(sourceLabel || "attribute")}:${hostname}`,
    candidateSource: facebookWrapperUrl ? "hidden-facebook-wrapper-full-url" : "hidden-attribute-full-url"
  };
}

function collectVisibleDomains(post) {
  const text = removeHeaderTextFromRenderedText(post, extractRenderedVisibleText(post));
  return new Set(
    [...text.matchAll(new RegExp(DOMAIN_TEXT_PATTERN.source, "gi"))]
      .map((match) => getRegistrableDomain(String(match[0] || "").toLowerCase()))
      .filter(Boolean)
  );
}

function candidateMatchesVisibleDomains(candidate, visibleDomains) {
  return Boolean(candidate?.registrableDomain && visibleDomains instanceof Set && visibleDomains.has(candidate.registrableDomain));
}

function isProviderApiUrl(rawUrl) {
  const hostname = safeHostname(rawUrl);
  return (
    hostname === "safebrowsing.googleapis.com" ||
    hostname.endsWith(".safebrowsing.googleapis.com") ||
    hostname === "urlhaus-api.abuse.ch" ||
    hostname.endsWith(".urlhaus-api.abuse.ch")
  );
}

function isLikelyMediaAssetUrl(rawUrl) {
  try {
    const url = new URL(rawUrl, location.href);
    return /\.(?:png|jpe?g|gif|webp|svg|mp4|webm|mov|avi)(?:$|[?#])/i.test(url.pathname);
  } catch {
    return false;
  }
}

function isBarePublicSuffixLikeDomain(domain) {
  const normalized = String(domain || "")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");

  const parts = normalized.split(".").filter(Boolean);

  if (parts.length < 2) {
    return true;
  }

  // Common Philippine second-level category domains.
  // These are not specific user-facing destinations by themselves.
  const phSecondLevelCategories = new Set([
    "com.ph",
    "net.ph",
    "org.ph",
    "edu.ph",
    "gov.ph",
    "mil.ph"
  ]);

  if (phSecondLevelCategories.has(normalized)) {
    return true;
  }

  // Keep this explicit for readability and future maintenance.
  if (normalized === "edu.ph" || normalized === "gov.ph") {
    return true;
  }

  return false;
}

function isRepeatedTokenDomainLikeValue(value, token) {
  const normalized = String(value || "")
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[^a-z0-9.]+/g, "")
    .replace(/\.+/g, ".");

  const hostLike = normalized.split(/[/?#]/)[0] || normalized;
  const compact = hostLike.replace(/\./g, "");

  if (!compact || !token) {
    return false;
  }

  const repeatedPattern = new RegExp(`^(?:${token}){2,}(?:com|net|org)?$`, "i");
  return repeatedPattern.test(compact);
}

function isMalformedRepeatedFacebookCandidate(value) {
  const source = String(value || "").toLowerCase();

  if (!source) {
    return false;
  }

  if (isRepeatedTokenDomainLikeValue(source, "facebook")) {
    return true;
  }

  try {
    const url = new URL(source, location.href);
    const host = url.hostname.toLowerCase();
    const compactHost = host.replace(/^www\./, "").replace(/\./g, "");

    return /^(?:facebook){2,}(?:com)?$/i.test(compactHost);
  } catch {
    return /(?:facebook){3,}/i.test(source.replace(/[^a-z]/g, ""));
  }
}

function isIgnoredVisibleDomain(domain) {
  const normalized = String(domain || "")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");

  if (isMalformedRepeatedFacebookCandidate(normalized)) {
    scanStatus.skippedMalformedCandidate += 1;
    return true;
  }

  if (isBarePublicSuffixLikeDomain(normalized)) {
    scanStatus.skippedGenericDomain += 1;
    return true;
  }

  return (
    normalized === "facebook.com" ||
    normalized === "fb.com" ||
    normalized === "fbcdn.net" ||
    normalized.endsWith(".fbcdn.net") ||
    normalized === "messenger.com"
  );
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

    const byDomain = new Map();
    for (const candidate of unique) {
      const domain = getComparableCandidateDomain(candidate);
      if (!domain) {
        continue;
      }

      if (!byDomain.has(domain)) {
        byDomain.set(domain, []);
      }

      byDomain.get(domain).push(candidate);
    }

    const result = [];
    const processedKeys = new Set();

    for (const candidate of unique) {
      const key = candidate.normalizedTargetUrl || candidate.url;
      if (processedKeys.has(key)) {
        continue;
      }

      const domain = getComparableCandidateDomain(candidate);
      if (!domain) {
        result.push(candidate);
        processedKeys.add(key);
        continue;
      }

      const group = byDomain.get(domain) || [];
      const isDomainOnlyFallback = isDomainOnlyFallbackCandidate(candidate);

      if (isDomainOnlyFallback && group.length > 1) {
        const hasFullerUrl = group.some((c) => !isDomainOnlyFallbackCandidate(c) && isFullerCandidateThan(c, candidate));
        if (hasFullerUrl) {
          processedKeys.add(key);
          continue;
        }
      }

      result.push(candidate);
      processedKeys.add(key);
    }

    return result;
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

  if (!isUserFacingOutboundCandidate(element, post)) {
    continue;
  }

  const candidate = buildRelevantLinkCandidate(element, post);
  if (candidate) {
    candidates.push({
      ...candidate,
      candidateSource: "sponsored-fallback-direct"
    });
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
  const text = extractRenderedVisibleText(post).replace(/\s+/g, " ").trim();
  const hasSponsored = /\bsponsored\b/i.test(text);
  const hasCta = CTA_TEXT_PATTERNS.some((pattern) => pattern.test(text));
  const hasPreviewDomain = DOMAIN_TEXT_PATTERN.test(text);
  return hasSponsored && hasCta && hasPreviewDomain;
}

function buildRelevantLinkCandidate(element, post) {
  if (isInsidePostHeaderArea(element, post)) {
    scanStatus.skippedHeaderDomain += 1;
    return null;
  }

  const rawUrl = getCandidateRawUrl(element);

  if (isMalformedRepeatedFacebookCandidate(rawUrl)) {
    scanStatus.skippedMalformedCandidate += 1;
    return null;
  }

  if (!isEligibleLink(rawUrl)) {
    return null;
  }

  if (isLikelyImageSourceCandidate(element, rawUrl)) {
    scanStatus.skippedImageSource += 1;
    return null;
  }

    const displayText = extractAnchorDisplayText(element);
    const unwrappedCandidateUrl = unwrapFacebookRedirectUrl(rawUrl);
    const facebookWrapperUrl = isFacebookWrapperHref(rawUrl) ? rawUrl : "";
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
      rawHref: rawUrl,
      normalizedTargetUrl,
      displayText,
      visibleText: displayText,
      facebookWrapperUrl,
      unwrappedCandidateUrl,
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
      domPath,
      candidateSource: "direct"
    };
  }

function getCandidateRawUrl(element) {
  if (!(element instanceof Element)) {
    return "";
  }

  const direct = readCandidateRawUrlFromElement(element);
  if (direct) {
    return direct;
  }

  const nested = element.querySelector?.('a[href], [data-lynx-uri], [data-url]');
  if (nested instanceof Element) {
    const nestedUrl = readCandidateRawUrlFromElement(nested);
    if (nestedUrl) {
      return nestedUrl;
    }
  }

  const ancestor = element.closest?.('a[href], [data-lynx-uri], [data-url]');
  if (ancestor instanceof Element && ancestor !== element) {
    const ancestorUrl = readCandidateRawUrlFromElement(ancestor);
    if (ancestorUrl) {
      return ancestorUrl;
    }
  }

  return "";
}

function readCandidateRawUrlFromElement(element) {
  if (!(element instanceof Element)) {
    return "";
  }

  const candidates = [
    element.getAttribute("data-lynx-uri"),
    element.getAttribute("data-url")
  ];

  if (element instanceof HTMLAnchorElement) {
    candidates.push(element.href || element.getAttribute("href") || "");
  } else {
    candidates.push(element.getAttribute("href") || "");
  }

  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value && isEligibleLink(value)) {
      return value;
    }
  }

  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value) {
      return value;
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

  function getCandidateSource(candidate = {}) {
    return String(candidate.candidateSource || "direct").trim() || "direct";
  }

  function buildCandidateContextDetails(candidate = {}) {
    return {
      displayText: candidate.displayText || "",
      visibleText: candidate.visibleText || candidate.displayText || "",
      rawHref: candidate.rawHref || candidate.url || "",
      facebookWrapperUrl: candidate.facebookWrapperUrl || "",
      unwrappedCandidateUrl: candidate.unwrappedCandidateUrl || candidate.normalizedTargetUrl || candidate.url || "",
      candidateSource: getCandidateSource(candidate),
      candidateUrlCompleteness: getCandidateUrlCompleteness(candidate),
      candidateIsDomainOnlyFallback: isDomainOnlyFallbackCandidate(candidate)
    };
  }

  function filterFallbackCandidatesWhenFullUrlsExist(candidates = []) {
    const values = Array.isArray(candidates) ? candidates : [];
    const hasUsableFullCandidate = values.some((candidate) => {
      const source = getCandidateSource(candidate);
      return (
        !isVisibleDomainFallbackSource(source) &&
        getCandidateUrlCompleteness(candidate) === "full-url"
      );
    });

    if (!hasUsableFullCandidate) {
      return values;
    }

    return values.filter((candidate) => {
      return !isVisibleDomainFallbackSource(getCandidateSource(candidate));
    });
  }

  function isVisibleDomainFallbackSource(source) {
    return /visible-domain/i.test(String(source || ""));
  }

  function isDomainOnlyFallbackCandidate(candidate = {}) {
    const source = getCandidateSource(candidate);

    if (!isVisibleDomainFallbackSource(source)) {
      return false;
    }

    try {
      const url = new URL(candidate.normalizedTargetUrl || candidate.url || "", location.href);
      const pathname = url.pathname || "/";
      return (pathname === "/" || pathname === "") && !url.search && !url.hash;
    } catch {
      return true;
    }
  }

  function getCandidateUrlCompleteness(candidate = {}) {
    if (isDomainOnlyFallbackCandidate(candidate)) {
      return "domain-only-fallback";
    }

    try {
      const url = new URL(candidate.normalizedTargetUrl || candidate.url || "", location.href);
      const hasPath = url.pathname && url.pathname !== "/";
      const hasQuery = Boolean(url.search);
      return hasPath || hasQuery ? "full-url" : "domain-root-url";
    } catch {
      return "unknown";
    }
  }

  function getCandidateSourcePriority(candidate = {}) {
    const source = getCandidateSource(candidate);

    if (source === "hidden-facebook-wrapper-full-url") {
      return 95;
    }

    if (source === "hidden-attribute-full-url") {
      return 92;
    }

    if (source === "embedded-card-direct") {
      return 90;
    }

    if (source === "sponsored-fallback-direct") {
      return 85;
    }

    if (source === "direct") {
      return 80;
    }

    if (source === "embedded-card-visible-domain") {
      return 45;
    }

    if (source === "visible-domain-fallback") {
      return 35;
    }

    if (source.includes("visible-domain")) {
      return 35;
    }

    return 60;
  }

  function getComparableCandidateDomain(candidate = {}) {
    return candidate.registrableDomain || safeHostname(candidate.normalizedTargetUrl || candidate.url) || "";
  }

  function isFullerCandidateThan(left = {}, right = {}) {
    const leftCompleteness = getCandidateUrlCompleteness(left);
    const rightCompleteness = getCandidateUrlCompleteness(right);
    const rank = {
      "full-url": 3,
      "domain-root-url": 2,
      "unknown": 1,
      "domain-only-fallback": 0
    };

    const leftRank = rank[leftCompleteness] ?? 1;
    const rightRank = rank[rightCompleteness] ?? 1;

    if (leftRank !== rightRank) {
      return leftRank > rightRank;
    }

    return buildRelevantLinkScore(left) > buildRelevantLinkScore(right);
  }

  function buildRelevantLinkScore(candidate) {
    let score = 0;

    score += getCandidateSourcePriority(candidate);

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

    if (candidate.visibleDomainMatch) {
      score += 18;
    }

    const completeness = getCandidateUrlCompleteness(candidate);
    if (completeness === "full-url") {
      score += 120;
    } else if (completeness === "domain-root-url") {
      score += 20;
    } else if (completeness === "domain-only-fallback") {
      score -= 120;
    }

    score += Math.min(Math.round(candidate.visualArea / 800), 30);
    score += Math.min(candidate.textLength, 60);
    score += Math.min(candidate.urlLength, 30);

    return score;
  }

function isUserFacingOutboundCandidate(element, post) {
  if (!(element instanceof Element) || !post.contains(element)) {
    scanStatus.skippedNoOwningPost += 1;
    return false;
  }

  if (element.closest(".dili-badge, .dili-panel, .dili-warning-overlay")) {
    scanStatus.skippedDiliUi += 1;
    return false;
  }

  if (isInsidePostHeaderArea(element, post)) {
    scanStatus.skippedHeaderDomain += 1;
    return false;
  }

  if (isInsideNestedSharedStory(element, post)) {
    scanStatus.skippedNestedSharedStory += 1;
    console.debug("[DILI] Skipping nested shared-story candidate.");
    return false;
  }

  const rawUrl = getCandidateRawUrl(element);

  if (!rawUrl) {
    scanStatus.skippedNoUrl += 1;
    return false;
  }

  if (
    isFacebookInAppFormElement(element) ||
    isInternalFacebookMediaOrActionUrl(rawUrl) ||
    isFacebookMediaCdnOrViewerUrl(rawUrl)
  ) {
    scanStatus.skippedInternalFacebook += 1;
    return false;
  }

  if (element.hasAttribute("hidden") || element.getAttribute("aria-hidden") === "true") {
    scanStatus.skippedHidden += 1;
    return false;
  }

  if (!isRenderedCandidateElement(element)) {
    scanStatus.skippedHidden += 1;
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

  function hasRenderedOrCachedPanel(post, postId) {
    if (!(post instanceof Element)) {
      return false;
    }

    return Boolean(
      post.querySelector(".dili-panel[data-dili-owned='true']") ||
      post.querySelector(".dili-panel-slot[data-dili-owned='true']") ||
      cachedPanelByPostId.has(postId)
    );
  }
function shouldRemovePanelAfterNoLinkRescan(postId) {
  const currentCount = Number(noLinkRescanCountsByPostId.get(postId) || 0) + 1;
  noLinkRescanCountsByPostId.set(postId, currentCount);

  return currentCount >= NO_LINK_PANEL_REMOVAL_CONFIRMATION_COUNT;
}

function resetNoLinkRescanCount(postId) {
  if (postId) {
    noLinkRescanCountsByPostId.delete(postId);
  }
}
function shouldDelayNoLinkPanelRemoval(post, postId, reason) {
  if (!hasRenderedOrCachedPanel(post, postId)) {
    return false;
  }

  if (shouldRemovePanelAfterNoLinkRescan(postId)) {
    return false;
  }

  scanStatus.panelPreservedNoLinkRescan += 1;
  scanStatus.lastPanelPreservationReason = reason || "no-link-rescan-awaiting-confirmation";
  scanStatus.lastAnalysisPipelineState = {
    stage: "panel-preserved-no-link-rescan",
    reason: reason || "awaiting-confirmation",
    postId,
    timestamp: Date.now()
  };

  return true;
}
  function preserveExistingPanelDuringNoLinkRescan(post, postId, reason) {
    if (!hasRenderedOrCachedPanel(post, postId)) {
      return false;
    }

    scanStatus.panelPreservedNoLinkRescan += 1;
    scanStatus.lastPanelPreservationReason = reason || "no-link-rescan";
    scanStatus.lastAnalysisPipelineState = {
      stage: "panel-preserved-no-link-rescan",
      reason: reason || "no-link-rescan",
      postId,
      timestamp: Date.now()
    };

    return true;
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
    clickAnalysisCache.clear();
    observedPostIds.clear();
    latestRequestByPostId.clear();
noLinkRescanCountsByPostId.clear();

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

      if (isMalformedRepeatedFacebookCandidate(rawUrl) || isMalformedRepeatedFacebookCandidate(url.hostname)) {
        return false;
      }

      if (isFacebookMediaCdnOrViewerUrl(url.toString())) {
        return false;
      }

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
  const owningPost = getTopLevelPanelOwner(post);
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

  badge.style.width = "100%";
  badge.style.maxWidth = "100%";
  badge.style.boxSizing = "border-box";
  badge.style.alignSelf = "stretch";

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
    const reportHtml = viewModel.reportSections
  ? renderPanelReportSections(viewModel.reportSections)
  : `<ul class="dili-detail-list">${detailItems || "<li>No detailed indicators recorded.</li>"}</ul>`;
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
  ${reportHtml}
</details>
    `;

    cachedPanelByPostId.set(getStablePostId(owningPost), viewModel);
    scanStatus.renderedPanels += 1;
    scanStatus.visiblePanels = document.querySelectorAll(".dili-panel[data-dili-owned='true']").length;
    scanStatus.lastRenderedDomain = viewModel.finalDomain || viewModel.domain || "";
  }
function renderPanelReportSections(report = {}) {
  const reasonItems = (report.reasons || [])
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join("");

  const verificationItems = (report.verificationNotes || [])
    .map((note) => `<li>${escapeHtml(note)}</li>`)
    .join("");

  const technicalItems = (report.technicalDetails || [])
    .map((detail) => `<li>${escapeHtml(detail)}</li>`)
    .join("");

  const technicalSectionHtml =
    verificationItems || technicalItems
      ? `
        <details class="dili-technical-details">
          <summary>Show technical details</summary>

          ${
            verificationItems
              ? `
                <p><strong>Verification notes:</strong></p>
                <ul class="dili-detail-list">${verificationItems}</ul>
              `
              : ""
          }

          ${
            technicalItems
              ? `
                <p><strong>Technical details:</strong></p>
                <ul class="dili-detail-list">${technicalItems}</ul>
              `
              : ""
          }
        </details>
      `
      : "";

  return `
    <div class="dili-report-simple">
      <p><strong>Result:</strong> ${escapeHtml(report.resultLine || "DILI completed the scan.")}</p>

      <p><strong>What DILI checked:</strong> ${escapeHtml(
        report.checkedLine || "DILI checked the link and its final destination."
      )}</p>

      <p><strong>Why DILI gave this result:</strong></p>
      <ul class="dili-detail-list">
        ${reasonItems || "<li>No major warning signs were found.</li>"}
      </ul>

      <p><strong>What you should do:</strong> ${escapeHtml(
        report.recommendation || "Continue only if the link and website make sense."
      )}</p>

      ${technicalSectionHtml}
    </div>
  `;
}
function buildPlainResultLine(classification, score, finalDomain) {
  const scoreText = Number.isFinite(score) ? ` with a safety score of ${score}` : "";
  return `${classification}${scoreText} for ${finalDomain}.`;
}

  function mapAnalysisToViewModel(analysis) {
    const reportSections = buildPanelReportSections(analysis);
    const severityLevel = normalizeInlineSeverityLevel({
      label: analysis.classification,
      state: analysis.state,
      safetyScore: analysis.safetyScore
    });
    const details = buildPanelDetails(analysis);

    return {
      label: analysis.classification || "Unknown",
      reportSections,
      details,
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
)
    };
  }

  function buildEndUserRecommendation(analysis = {}, severityLevel = "unverified") {
    if (severityLevel === "safe") {
      return "You can open this link normally, but still avoid entering passwords or payment information unless you trust the site.";
    }

    if (severityLevel === "caution") {
      return "Open with care. Check the final website address before entering personal information.";
    }

    if (severityLevel === "suspicious") {
      return "Avoid entering passwords, payment details, or personal information unless you can independently verify the site.";
    }

    if (severityLevel === "high-risk") {
      return "Do not continue unless you are certain this destination is legitimate.";
    }

    return "Treat this as not fully verified. Continue only if the source and destination make sense.";
  }

  function buildPanelDetails(analysis = {}) {
    const details = [];
    const seenDetails = new Set();
    const finalDomain = analysis.endpointResult?.effectiveDomain || analysis.urlFeatureAnalysis?.finalDomain || safeHostname(analysis.analysisUrl) || "unknown site";
    const originalDomain = getUserFacingStartDomain(analysis);
    const scoreLabel = Number.isFinite(analysis.safetyScore) ? `safety score ${analysis.safetyScore}` : "no score";
    const classification = analysis.classification || "Unverified";
    const severityLevel = normalizeInlineSeverityLevel({
      label: classification,
      state: analysis.state,
      safetyScore: analysis.safetyScore
    });

    pushUniqueAnalysisDetail(details, seenDetails, `Result: ${classification} (${scoreLabel}) for ${finalDomain}.`);
    pushUniqueAnalysisDetail(details, seenDetails, `What DILI checked: The clicked/visible link was ${originalDomain}, and the final site appears to be ${finalDomain}.`);

    const mainReasons = buildMainRiskReasons(analysis).slice(0, 4);
    if (mainReasons.length > 0) {
      for (const reason of mainReasons) {
        pushUniqueAnalysisDetail(details, seenDetails, `Why this result was given: ${reason}`);
      }
    } else if (severityLevel === "safe") {
      pushUniqueAnalysisDetail(details, seenDetails, "Why this result was given: DILI did not find major warning signs from the link structure or configured threat checks.");
    } else if (severityLevel === "unverified") {
      pushUniqueAnalysisDetail(details, seenDetails, "Why this result was given: DILI could not fully verify the destination, but it did not find enough evidence to mark it suspicious.");
    } else {
      pushUniqueAnalysisDetail(details, seenDetails, "Why this result was given: DILI found minor uncertainty but no confirmed threat provider flag.");
    }

    pushUniqueAnalysisDetail(details, seenDetails, `What you should do: ${buildEndUserRecommendation(analysis, severityLevel)}`);

    for (const limitation of buildLimitations(analysis).slice(0, 3)) {
      pushUniqueAnalysisDetail(details, seenDetails, `Verification note: ${limitation}`);
    }

    for (const detail of buildTechnicalDetails(analysis).slice(0, 4)) {
      pushUniqueAnalysisDetail(details, seenDetails, `Technical: ${detail}`);
    }

    return details;
  }
function buildPanelReportSections(analysis = {}) {
  const finalDomain =
    analysis.endpointResult?.effectiveDomain ||
    analysis.urlFeatureAnalysis?.finalDomain ||
    safeHostname(analysis.analysisUrl) ||
    "unknown site";

  const originalDomain = getUserFacingStartDomain(analysis);

  const classification = analysis.classification || "Unverified";
  const severityLevel = normalizeInlineSeverityLevel({
    label: classification,
    state: analysis.state,
    safetyScore: analysis.safetyScore
  });

  const reasons = buildEndUserRiskReasons(analysis, severityLevel);
  const verificationNotes = buildEndUserVerificationNotes(analysis);
  const technicalDetails = buildTechnicalDetails(analysis);

  return {
    resultLine: buildPlainResultLine(classification, analysis.safetyScore, finalDomain),
    checkedLine: `DILI checked where the link starts and where it finally leads. The clicked/visible link appears to be ${originalDomain}, and the final site appears to be ${finalDomain}.`,
    reasons,
    recommendation: buildEndUserRecommendation(analysis, severityLevel),
    verificationNotes,
    technicalDetails
  };
}

function getUserFacingStartUrlOrText(analysis = {}) {
  const context = analysis.candidateContext || {};
  const endpoint = analysis.endpointResult || {};
  const candidates = [
    context.unwrappedCandidateUrl,
    context.selectedNormalizedTarget,
    endpoint.unwrappedUrl,
    analysis.normalizedUrl,
    looksLikeUsefulVisibleDestinationText(context.visibleText) ? context.visibleText : "",
    looksLikeUsefulVisibleDestinationText(context.displayText) ? context.displayText : "",
    isFacebookClickWrapperLikeText(analysis.rawUrl) ? "" : analysis.rawUrl
  ];

  for (const candidate of candidates) {
    const value = String(candidate || "").replace(/\s+/g, " ").trim();
    if (!value) {
      continue;
    }

    if (isFacebookClickWrapperLikeText(value)) {
      continue;
    }

    return value;
  }

  return String(endpoint.unwrappedUrl || analysis.normalizedUrl || analysis.rawUrl || "unknown link").trim();
}

function getUserFacingStartDomain(analysis = {}) {
  const value = getUserFacingStartUrlOrText(analysis);
  return normalizeVisibleDestinationLabel(value) || "unknown link";
}

function isFacebookClickWrapperLikeText(value) {
  try {
    const url = new URL(String(value || ""), location.href);
    return /(^|\.)facebook\.com$/i.test(url.hostname) && /\/l\.php(?:$|[/?#])/i.test(url.pathname);
  } catch {
    return /^https?:\/\/l\.facebook\.com\/l\.php/i.test(String(value || ""));
  }
}

function looksLikeUsefulVisibleDestinationText(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();

  if (!text) {
    return false;
  }

  if (isFacebookClickWrapperLikeText(text)) {
    return false;
  }

  if (/^facebook\.com$/i.test(text) || /^www\.facebook\.com$/i.test(text)) {
    return false;
  }

  if (/^[a-z0-9_-]{20,}$/i.test(text) && !/[./:]/.test(text)) {
    return false;
  }

  if (getHostnameFromUrlOrDomainText(text)) {
    return true;
  }

  return /\b(?:https?:\/\/|www\.)?[a-z0-9][a-z0-9.-]*\.(?:com|net|org|ph|app|ai|edu|gov|io|me|page|shop|site|store|xyz)\b/i.test(text);
}

function normalizeVisibleDestinationLabel(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  const host = getHostnameFromUrlOrDomainText(text);

  if (host) {
    return host.replace(/^www\./i, "");
  }

  const domainMatch = text.match(/\b(?:https?:\/\/|www\.)?([a-z0-9][a-z0-9.-]*\.(?:com|net|org|ph|app|ai|edu|gov|io|me|page|shop|site|store|xyz))\b/i);
  if (domainMatch?.[1]) {
    return domainMatch[1].replace(/^www\./i, "");
  }

  return text;
}

function getHostnameFromUrlOrDomainText(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }

  try {
    if (/^https?:\/\//i.test(text)) {
      return new URL(text).hostname.toLowerCase();
    }

    if (/^(?:www\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[/?#].*)?$/i.test(text)) {
      return new URL(`https://${text.replace(/^\/+/, "")}`).hostname.toLowerCase();
    }
  } catch {
    return "";
  }

  return "";
}
function buildEndUserRiskReasons(analysis = {}, severityLevel = "unverified") {
  const features = analysis.features || {};
  const reasons = [];

  const gsb = findProviderResult(analysis.providerResults, "gsb");
  const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

  if (gsb?.flagged) {
    reasons.push("Google Safe Browsing flagged this destination as unsafe.");
  }

  if (urlhaus?.flagged) {
    reasons.push("URLhaus flagged this destination as suspicious or malicious.");
  }

  if (features.integrityHashMismatch || analysis.linkInsertedAfterBaseline) {
    reasons.push("The link appears to have changed after DILI first observed the post.");
  }

  if (features.shortenedUrl) {
    reasons.push("The link uses a shortened URL, so the final website is hidden at first.");
  }

  if (features.shortenerToUnrelatedDomain || features.crossDomainRedirectChain) {
    reasons.push("The link redirects to a different website before reaching the final destination.");
  }

  if (features.textMismatch) {
    reasons.push("The visible link text does not match the final website.");
  }

  if (features.obfuscatedUrl) {
    reasons.push("The URL contains encoded or unusual text that can make the destination harder to read.");
  }

  if (features.suspiciousTld || features.suspiciousPath || features.usernamePasswordTrick) {
    reasons.push("The destination contains patterns often seen in suspicious links.");
  }

  if (features.domainPreviouslyFlagged) {
    reasons.push("This website was previously marked during an earlier DILI scan.");
  }

  if (reasons.length === 0) {
    if (severityLevel === "safe") {
      reasons.push("DILI did not find major warning signs in the link structure or configured threat checks.");
    } else if (severityLevel === "unverified") {
      reasons.push("DILI could not fully verify the destination, but it did not find enough evidence to mark it suspicious.");
    } else {
      reasons.push("DILI found minor uncertainty, but no configured threat provider confirmed this link as malicious.");
    }
  }

  return [...new Set(reasons)].slice(0, 4);
}

function getProviderOutcomeSummary(provider = {}) {
  const providerName = String(provider.provider || "").toLowerCase();
  const status = String(provider.details?.status || "").toLowerCase();

  if (!provider.configured || status === "not-configured") {
    return "Provider not configured.";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return "Request failed.";
  }

  if (!provider.checked || status === "skipped") {
    return "Provider not configured.";
  }

  if (providerName === "gsb") {
    return provider.flagged ? "Unsafe URL reported." : "No unsafe matches reported.";
  }

  if (providerName === "urlhaus") {
    return provider.flagged ? "Known malware record found." : "No known malware record found.";
  }

  return provider.flagged ? "Provider reported a match." : "No provider match reported.";
}

function getProviderAuditStatus(provider = {}) {
  const status = String(provider.details?.status || "").toLowerCase();

  if (!provider.configured || status === "not-configured" || status === "skipped" || !provider.checked) {
    return "skipped";
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    return "failed";
  }

  return "completed";
}

function pushProviderVerificationNote(notes, provider, providerName) {
  if (!provider || typeof provider !== "object") {
    return;
  }

  const providerKey = String(provider.provider || "").toLowerCase();
  const status = String(provider.details?.status || "").toLowerCase();

  if (!provider.configured || status === "not-configured" || status === "skipped") {
    return;
  }

  if (status === "error" || status === "rate-limited" || status === "parse-error") {
    notes.push(`${providerName} verification could not be completed during this scan.`);
    return;
  }

  if (provider.flagged) {
    if (providerKey === "gsb") {
      notes.push("Google Safe Browsing reported this link as unsafe.");
      return;
    }

    notes.push("URLhaus reported known malware activity for this link.");
    return;
  }

  if (provider.checked) {
    if (providerKey === "gsb") {
      notes.push("Google Safe Browsing completed its endpoint check and did not report this link as unsafe.");
      return;
    }

    notes.push("URLhaus did not report known malware activity for this link.");
  }
}

function buildEndUserVerificationNotes(analysis = {}) {
  const notes = [];
  const gsb = findProviderResult(analysis.providerResults, "gsb");
  const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

  pushProviderVerificationNote(notes, gsb, "Google Safe Browsing");
  pushProviderVerificationNote(notes, urlhaus, "URLhaus");

  for (const limitation of analysis.limitations || []) {
    const text = String(limitation || "");

    if (/did not expose a full clickable URL|visible domain only|domain-only fallback/i.test(text)) {
      notes.push("Facebook only exposed the visible domain for this card, so DILI checked that domain instead of a full page path.");
      continue;
    }

    if (/google safe browsing completed its endpoint check and did not report/i.test(text)) {
      notes.push("Google Safe Browsing completed its endpoint check and did not report this link as unsafe.");
      continue;
    }

    if (/urlhaus/i.test(text)) {
      notes.push("URLhaus verification could not be completed during this scan.");
      continue;
    }

    if (/google safe browsing/i.test(text) && !/completed/i.test(text)) {
      notes.push("Google Safe Browsing could not complete its check for this link.");
      continue;
    }

    if (/could not confidently resolve|endpoint/i.test(text)) {
      notes.push("DILI could not fully confirm the final destination.");
      continue;
    }
  }

  return [...new Set(notes)].slice(0, 3);
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

function pushUniqueTechnicalDetail(details, text) {
  const normalized = String(text || "")
    .replace(/\s+/g, " ")
    .replace(/\.$/, "")
    .trim()
    .toLowerCase();

  if (!normalized) {
    return;
  }

  const alreadyExists = details.some((item) => {
    return String(item || "")
      .replace(/\s+/g, " ")
      .replace(/\.$/, "")
      .trim()
      .toLowerCase() === normalized;
  });

  if (!alreadyExists) {
    details.push(text);
  }
}

function shouldSkipAutoGeneratedTechnicalDetail(detail) {
  const text = String(detail || "").trim();

  return (
    /^Original URL:/i.test(text) ||
    /^Clicked\/visible URL:/i.test(text) ||
    /^Visible post URL\/text:/i.test(text) ||
    /^Facebook click wrapper URL:/i.test(text) ||
    /^Unwrapped URL:/i.test(text) ||
    /^Full endpoint URL:/i.test(text) ||
    /^Redirect chain:/i.test(text) ||
    /^Observed redirect chain:/i.test(text) ||
    /^Risk-relevant redirect chain:/i.test(text) ||
    /^Redirect chain domains:/i.test(text) ||
    /^Endpoint confidence:/i.test(text) ||
    /^Provider scan scope:/i.test(text) ||
    /^Full endpoint extraction status:/i.test(text) ||
    /^Click-time note:/i.test(text) ||
    /^Resolution method:/i.test(text) ||
    /^GSB checked URL:/i.test(text) ||
    /^URLHAUS checked URL:/i.test(text) ||
    /^Google Safe Browsing checked URL:/i.test(text) ||
    /^Google Safe Browsing attempted URL check:/i.test(text) ||
    /^URLhaus checked URL:/i.test(text) ||
    /^URLhaus attempted URL check:/i.test(text)
  );
}
function formatCompactRedirectChainDetail(chain = []) {
  const urls = Array.isArray(chain)
    ? chain.map((url) => String(url || "").trim()).filter(Boolean)
    : [];

  if (urls.length === 0) {
    return "";
  }

  const domains = urls
    .map((url) => safeHostname(url).replace(/^www\./i, ""))
    .filter(Boolean);

  if (domains.length === 0) {
    return "";
  }

  const compactDomains = [];
  for (const domain of domains) {
    if (compactDomains[compactDomains.length - 1] !== domain) {
      compactDomains.push(domain);
    }
  }

  const hopCount = Math.max(urls.length - 1, 0);
  const hopText = hopCount === 1 ? "1 redirect hop" : `${hopCount} redirect hops`;

  if (compactDomains.length === 1) {
    return hopCount > 0
      ? `Redirect chain: ${compactDomains[0]} only (${hopText}; same-domain redirect or tracking cleanup).`
      : `Redirect chain: ${compactDomains[0]} only (no redirect hop observed).`;
  }

  return `Redirect chain: ${compactDomains.join(" -> ")} (${hopText}).`;
}

function isFacebookPlatformWrapperUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    return /(^|\.)facebook\.com$/i.test(url.hostname) && /\/l\.php(?:$|[/?#])/i.test(url.pathname);
  } catch {
    return false;
  }
}

function buildRiskRelevantRedirectChain(chain = []) {
  return (Array.isArray(chain) ? chain : []).filter((url) => !isFacebookPlatformWrapperUrl(url));
}

function prependKnownFacebookWrapperForDisplay(chain = [], facebookWrapperUrl = "") {
  const values = Array.isArray(chain) ? chain.filter(Boolean) : [];
  if (!facebookWrapperUrl || values.some((url) => String(url || "") === String(facebookWrapperUrl))) {
    return values;
  }

  return [facebookWrapperUrl, ...values];
}

function buildTechnicalDetails(analysis = {}) {
  const details = [];
  const endpoint = analysis.endpointResult || {};
  const finalDomain =
    endpoint.effectiveDomain ||
    analysis.urlFeatureAnalysis?.finalDomain ||
    safeHostname(analysis.analysisUrl) ||
    "";

  const chain = Array.isArray(endpoint.resolutionChain) && endpoint.resolutionChain.length > 0
    ? endpoint.resolutionChain
    : Array.isArray(analysis.redirectAnalysis?.redirectChain)
      ? analysis.redirectAnalysis.redirectChain
      : [];

  const chainDomains = [...new Set(chain.map((url) => safeHostname(url)).filter(Boolean))];

  for (const detail of analysis.technicalDetails || []) {
    if (!detail || isNormalWrapperText(detail) || shouldSkipAutoGeneratedTechnicalDetail(detail)) {
      continue;
    }

    pushUniqueTechnicalDetail(details, detail);
  }

  const candidateContext = analysis.candidateContext || {};
  const visiblePostValue =
    candidateContext.unwrappedCandidateUrl ||
    candidateContext.selectedNormalizedTarget ||
    endpoint.unwrappedUrl ||
    (looksLikeUsefulVisibleDestinationText(candidateContext.visibleText) ? candidateContext.visibleText : "") ||
    (looksLikeUsefulVisibleDestinationText(candidateContext.displayText) ? candidateContext.displayText : "") ||
    "";

  if (visiblePostValue && !isFacebookClickWrapperLikeText(visiblePostValue)) {
    pushUniqueTechnicalDetail(details, `Visible post URL/text: ${visiblePostValue}.`);
  }

  const facebookWrapperUrl = candidateContext.facebookWrapperUrl || (endpoint.isFacebookWrapper ? endpoint.rawUrl || analysis.rawUrl : "");
  if (facebookWrapperUrl) {
    pushUniqueTechnicalDetail(details, `Facebook click wrapper URL: ${facebookWrapperUrl}.`);
  }

  if (
    endpoint.unwrappedUrl &&
    endpoint.unwrappedUrl !== analysis.rawUrl &&
    endpoint.unwrappedUrl !== endpoint.effectiveEndpoint
  ) {
    pushUniqueTechnicalDetail(details, `Unwrapped URL: ${endpoint.unwrappedUrl}`);
  }

  if (endpoint.effectiveEndpoint) {
    pushUniqueTechnicalDetail(details, `Full endpoint URL: ${endpoint.effectiveEndpoint}`);
  }

  const observedRedirectChain = prependKnownFacebookWrapperForDisplay(chain, facebookWrapperUrl);
  const observedRedirectChainDetail = formatCompactRedirectChainDetail(observedRedirectChain);
  if (observedRedirectChainDetail) {
    pushUniqueTechnicalDetail(details, observedRedirectChainDetail.replace(/^Redirect chain:/, "Observed redirect chain:"));
  }

  const riskRelevantRedirectChain = buildRiskRelevantRedirectChain(observedRedirectChain);
  const riskRelevantRedirectChainDetail = formatCompactRedirectChainDetail(riskRelevantRedirectChain);
  if (
    riskRelevantRedirectChainDetail &&
    riskRelevantRedirectChain.length > 0 &&
    riskRelevantRedirectChain.length !== observedRedirectChain.length
  ) {
    pushUniqueTechnicalDetail(details, riskRelevantRedirectChainDetail.replace(/^Redirect chain:/, "Risk-relevant redirect chain:"));
  }

  if (endpoint.isFacebookWrapper && finalDomain) {
    pushUniqueTechnicalDetail(details, `Facebook wrapper unwrapped to ${finalDomain}.`);
  }

  if (chainDomains.length > 1) {
    pushUniqueTechnicalDetail(details, `Redirect chain domains: ${chainDomains.join(" -> ")}.`);
  }

  if (
    analysis.urlFeatureAnalysis?.sourceNormalizedUrl &&
    analysis.urlFeatureAnalysis?.sourceRawComparableUrl &&
    analysis.urlFeatureAnalysis.sourceNormalizedUrl !== analysis.urlFeatureAnalysis.sourceRawComparableUrl
  ) {
    pushUniqueTechnicalDetail(details, "Tracking parameters were stripped for comparison.");
  }

  if (endpoint.endpointConfidence || analysis.endpointConfidence) {
    pushUniqueTechnicalDetail(
      details,
      `Endpoint confidence: ${endpoint.endpointConfidence || analysis.endpointConfidence}.`
    );
  }

  if (endpoint.resolutionMethod) {
    pushUniqueTechnicalDetail(details, `Resolution method: ${endpoint.resolutionMethod}.`);
  }

  if (
    candidateContext?.candidateIsDomainOnlyFallback === true ||
    candidateContext?.candidateUrlCompleteness === "domain-only-fallback"
  ) {
    pushUniqueTechnicalDetail(details, "Candidate source: visible-domain-fallback.");
    pushUniqueTechnicalDetail(details, "Endpoint source note: Facebook did not expose a full clickable URL for this card, so DILI checked the visible domain only.");
    pushUniqueTechnicalDetail(details, "Provider scan scope: limited to visible-domain fallback because no full endpoint was exposed during passive scan.");
    pushUniqueTechnicalDetail(details, "Full endpoint extraction status: No full path/query URL was exposed during passive scan.");
    pushUniqueTechnicalDetail(details, "Click-time note: If the user clicks this card, DILI will re-check the actual clicked destination before navigation.");
  }

  const providerLabels = {
    gsb: "Google Safe Browsing",
    urlhaus: "URLhaus"
  };

  for (const provider of analysis.providerResults || []) {
    if (!provider?.checkedUrl) {
      continue;
    }

    const providerName = String(provider.provider || "").toLowerCase();
    if (providerName !== "gsb" && providerName !== "urlhaus") {
      continue;
    }

    const label = providerLabels[providerName] || provider.provider || "Provider";
    const auditStatus = getProviderAuditStatus(provider);
    const outcomeSummary = provider.resultSummary || getProviderOutcomeSummary(provider);
    const durationMs = Number(provider.durationMs);

    pushUniqueTechnicalDetail(details, `${label} checked URL: ${provider.checkedUrl}.`);
    pushUniqueTechnicalDetail(details, `${label} result: ${outcomeSummary}`);
    pushUniqueTechnicalDetail(details, `${label} status: ${auditStatus}.`);

    if (provider.checkedAt) {
      pushUniqueTechnicalDetail(details, `${label} checked at: ${provider.checkedAt}.`);
    }

    if (Number.isFinite(durationMs)) {
      pushUniqueTechnicalDetail(details, `${label} response time: ${durationMs} ms`);
    }
  }

  if (analysis.postIntegrityEvent) {
    pushUniqueTechnicalDetail(
      details,
      `Post integrity event: ${formatIntegrityEventLabel(analysis.postIntegrityEvent)}.`
    );
  }

  if (analysis.linkInsertedAfterBaseline) {
    pushUniqueTechnicalDetail(details, "A link was inserted after a stored no-link baseline.");
  }

  if (analysis.baselineFirstSeenAt) {
    pushUniqueTechnicalDetail(
      details,
      `Baseline first seen: ${new Date(Number(analysis.baselineFirstSeenAt)).toISOString()}.`
    );
  }

  if (analysis.previousPostTextHash) {
    pushUniqueTechnicalDetail(details, `Previous post text hash: ${analysis.previousPostTextHash}.`);
  }

  if (analysis.currentPostTextHash) {
    pushUniqueTechnicalDetail(details, `Current post text hash: ${analysis.currentPostTextHash}.`);
  }

  for (const note of analysis.redirectAnalysis?.notes || []) {
    if (!isNormalWrapperText(note)) {
      pushUniqueTechnicalDetail(details, note);
    }
  }

  return details;
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
    if (["safe", "caution", "suspicious", "high-risk", "unverified", "no-link", "low-caution"].includes(explicit)) {
      if (explicit === "low-caution") {
        return "caution";
      }

      return explicit;
    }

    if (String(viewModel.state || "").toLowerCase() === "no_link") {
      return "no-link";
    }

if (String(viewModel.state || "").toLowerCase() === "changed") {
  return Number(viewModel.safetyScore) < 40 ? "high-risk" : "suspicious";
}

    const score = Number(viewModel.safetyScore);
    if (Number.isFinite(score)) {
      if (score >= 90) {
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

    if (sourceText.includes("low caution")) {
      return "caution";
    }

    if (sourceText.includes("caution")) {
      return "caution";
    }

    if (sourceText.includes("unverified")) {
      return "unverified";
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
      return `Safety Score ${viewModel.safetyScore}`;
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
    const score = Number(viewModel.safetyScore);
    const label = String(viewModel.label || "").toLowerCase();

    if (severityLevel === "high-risk" || severityLevel === "suspicious") {
      return "DILI will pause navigation before opening this link.";
    }

    if (severityLevel === "caution") {
      if (Number.isFinite(score) && score >= 60) {
        return "DILI will show this warning in the post, but will not block navigation by default.";
      }

      return "Clicking this link may trigger a warning before navigation.";
    }

    if (severityLevel === "unverified" || label.includes("unverified")) {
      return "DILI could not fully verify this link. It will only pause navigation if other risk signs are present.";
    }

    return "";
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

  function isNestedSharedStoryContainer(candidate, owningPost) {
    if (!(candidate instanceof Element) || !(owningPost instanceof Element)) {
      return false;
    }

    if (candidate === owningPost || !owningPost.contains(candidate)) {
      return false;
    }

    if (!isPostContainerCandidate(candidate)) {
      return false;
    }

    const rect = candidate.getBoundingClientRect();
    const postRect = owningPost.getBoundingClientRect();

    return (
      rect.top > postRect.top + 80 &&
      hasPostAuthorHeader(candidate) &&
      hasPostBodyOrAttachment(candidate)
    );
  }

  function isInsideNestedSharedStory(element, owningPost) {
    if (!(element instanceof Element) || !(owningPost instanceof Element)) {
      return false;
    }

    const nestedPost = element.closest('div[role="article"], article, [aria-posinset]');

    return Boolean(
      nestedPost &&
      nestedPost !== owningPost &&
      owningPost.contains(nestedPost) &&
      isNestedSharedStoryContainer(nestedPost, owningPost)
    );
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

  function isInsidePostHeaderArea(element, post) {
    if (!(element instanceof Element) || !(post instanceof Element) || !post.contains(element)) {
      return false;
    }

    const header = findPostHeader(post);
    if (header instanceof Element && header.contains(element)) {
      return true;
    }

    const headerBlock = findPostHeaderBlock(post);
    if (headerBlock instanceof Element && headerBlock.contains(element)) {
      return true;
    }

    const utilityText = buildCandidateUtilityText(element);
    const rect = element.getBoundingClientRect();
    const postRect = post.getBoundingClientRect();

    const appearsNearTop = rect.top <= postRect.top + Math.max(90, postRect.height * 0.12);

    const looksLikeIdentityOrMetadata =
      /\b(profile|page|author|posted|sponsored|follow|verified|timestamp|public|friends)\b/i.test(utilityText) ||
      Boolean(element.closest('h1, h2, h3, strong, time, abbr, [role="heading"]'));

    return appearsNearTop && looksLikeIdentityOrMetadata;
  }

  function removeHeaderTextFromRenderedText(post, renderedText) {
    if (!(post instanceof Element)) {
      return String(renderedText || "").replace(/\s+/g, " ").trim();
    }

    const headerTexts = [];

    const header = findPostHeader(post);
    if (header instanceof Element) {
      headerTexts.push(extractRenderedVisibleText(header));
    }

    const headerBlock = findPostHeaderBlock(post);
    if (headerBlock instanceof Element) {
      headerTexts.push(extractRenderedVisibleText(headerBlock));
    }

    let text = String(renderedText || "").replace(/\s+/g, " ").trim();

    for (const headerText of headerTexts) {
      const normalizedHeader = String(headerText || "").replace(/\s+/g, " ").trim();
      if (!normalizedHeader) {
        continue;
      }

      if (text.startsWith(normalizedHeader)) {
        text = text.slice(normalizedHeader.length).replace(/\s+/g, " ").trim();
        continue;
      }

      text = text.replace(normalizedHeader, " ").replace(/\s+/g, " ").trim();
    }

    return text;
  }

  function domainAppearsOnlyInHeader(domain, post, candidateText = "") {
    const normalizedDomain = String(domain || "")
      .toLowerCase()
      .replace(/^www\./, "")
      .replace(/\.$/, "");

    if (!normalizedDomain || !(post instanceof Element)) {
      return false;
    }

    const fullText = String(candidateText || extractRenderedVisibleText(post))
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();

    const bodyText = removeHeaderTextFromRenderedText(post, fullText)
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();

    const header = findPostHeader(post);
    const headerBlock = findPostHeaderBlock(post);

    const headerText = [
      header instanceof Element ? extractRenderedVisibleText(header) : "",
      headerBlock instanceof Element ? extractRenderedVisibleText(headerBlock) : ""
    ]
      .join(" ")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();

    return (
      headerText.includes(normalizedDomain) &&
      !bodyText.includes(normalizedDomain)
    );
  }

function findPostCaption(post) {
  if (!(post instanceof Element)) {
    return null;
  }

  // Prefer real Facebook caption/message containers only.
  const primarySelectors = [
    '[data-ad-preview="message"]',
    '[data-ad-comet-preview="message"]',
    '[data-testid="post_message"]'
  ];

  for (const selector of primarySelectors) {
    const match = [...post.querySelectorAll(selector)].find((element) => {
      return isValidCaptionCandidate(element, post);
    });

    if (match) {
      return match;
    }
  }

  // Fallback for organic posts where Facebook only exposes caption text as dir="auto".
  // This fallback must not select text inside embeds, previews, CTAs, or media cards.
  const fallbackCandidates = [...post.querySelectorAll('[dir="auto"]')]
    .filter((element) => isValidCaptionCandidate(element, post))
    .sort((left, right) => {
      const leftRect = left.getBoundingClientRect();
      const rightRect = right.getBoundingClientRect();
      return leftRect.top - rightRect.top;
    });

  return fallbackCandidates[0] || null;
}
function isForbiddenPanelMountSurface(element, owningPost) {
  if (!(element instanceof Element) || !(owningPost instanceof Element)) {
    return true;
  }

  if (!owningPost.contains(element)) {
    return true;
  }

  if (isElementInsideUnsafeClickableSurface(element, owningPost)) {
    return true;
  }

  const forbiddenAncestor = element.closest(
    'a[href], [data-url], [data-lynx-uri], [role="link"], [role="button"], [data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"])'
  );

  return Boolean(
    forbiddenAncestor &&
    forbiddenAncestor !== owningPost &&
    owningPost.contains(forbiddenAncestor)
  );
}
function isValidCaptionCandidate(element, post) {
  if (!(element instanceof Element) || !post.contains(element) || !isProbablyVisible(element)) {
    return false;
  }

  if (element.closest(".dili-panel, .dili-panel-slot, .dili-badge, .dili-warning-overlay")) {
    return false;
  }

  if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
    return false;
  }

  // Critical: do not treat embed/card text as the caption.
  if (element.closest('[role="link"], a[href], [data-url], [data-lynx-uri]')) {
    return false;
  }

  if (element.closest('[data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"])')) {
    return false;
  }

  const text = extractVisiblePostText(element);
  if (text.length < 2) {
    return false;
  }

  // Captions are usually above the media/attachment. Reject text that is clearly
  // inside or below the first media/card block.
  const attachment = findPostAttachmentOrPreview(post);
  if (attachment instanceof Element && attachment !== element) {
    const elementRect = element.getBoundingClientRect();
    const attachmentRect = attachment.getBoundingClientRect();

    if (elementRect.top >= attachmentRect.top - 4 && attachment.contains(element)) {
      return false;
    }
  }

  return true;
}
function findPostAttachmentOrPreview(post) {
  if (!(post instanceof Element)) {
    return null;
  }

  const selectors = [
    '[data-ad-preview]:not([data-ad-preview="message"])',
    '[data-ad-comet-preview]:not([data-ad-comet-preview="message"])',
    '[role="link"]:has(img), [role="link"]:has(video), [role="link"]:has(picture)',
    '[role="button"]:has(img), [role="button"]:has(video), [role="button"]:has(picture)',
    'a[href]:has(img), a[href]:has(video), a[href]:has(picture)',
    '[aria-label*="carousel"]',
    '[aria-label*="preview"]',
    'video',
    'picture',
    'img'
  ];

  for (const selector of selectors) {
    let matches = [];

    try {
      matches = [...post.querySelectorAll(selector)];
    } catch {
      continue;
    }

    const match = matches.find((element) => {
      if (!(element instanceof Element) || !post.contains(element) || !isProbablyVisible(element)) {
        return false;
      }

      if (element.closest(".dili-panel, .dili-panel-slot, .dili-badge")) {
        return false;
      }

      if (isLikelyActionBarOrControlContainer(element) || isLikelyCommentOrReplyContainer(element)) {
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
  const fallbackPoint = getSafePanelFallbackPoint(post);

  // Desired layout:
  // Header
  // DILI panel
  // Caption
  // Media / embedded card
  const caption = findPostCaption(post);
  if (caption instanceof Element) {
    const captionPoint = buildSafeInsertionBeforeElement(post, caption);
    if (captionPoint) {
      return captionPoint;
    }
  }

  const attachment = findPostAttachmentOrPreview(post);
  if (attachment instanceof Element) {
    const attachmentPoint = buildSafeInsertionBeforeElement(post, attachment);
    if (attachmentPoint) {
      return attachmentPoint;
    }
  }

  const headerBlock = findPostHeaderBlock(post);
  if (headerBlock instanceof Element) {
    const headerPoint = buildSafeInsertionAfterElement(post, headerBlock);
    if (headerPoint) {
      return headerPoint;
    }
  }

  return fallbackPoint;
}
function isFacebookMediaCdnOrViewerUrl(rawUrl) {
  try {
    const url = new URL(rawUrl, location.href);
    const host = url.hostname.toLowerCase();
    const path = url.pathname.toLowerCase();

    if (
      host.endsWith("fbcdn.net") ||
      host.includes("scontent.") ||
      host.includes("fbsbx.com")
    ) {
      return true;
    }

    if (isFacebookHost(host)) {
      return (
        path.startsWith("/photo") ||
        path.includes("/photo/") ||
        path.includes("/photos/") ||
        path.startsWith("/watch") ||
        path.includes("/videos/") ||
        path.startsWith("/reel") ||
        path.includes("/reel/")
      );
    }

    return false;
  } catch {
    return false;
  }
}
function isLikelyImageAssetUrl(rawUrl) {
  try {
    const url = new URL(rawUrl, location.href);
    const host = url.hostname.toLowerCase();
    const path = url.pathname.toLowerCase();

    if (/\.(?:png|jpe?g|gif|webp|avif|bmp|svg)(?:$|[?#])/.test(path)) {
      return true;
    }

    return (
      host.startsWith("i.") ||
      host.startsWith("img.") ||
      host.startsWith("image.") ||
      host.startsWith("images.") ||
      host.includes("cdn") && /\.(?:png|jpe?g|gif|webp|avif|bmp|svg)(?:$|[?#])/.test(rawUrl)
    );
  } catch {
    return false;
  }
}

function isLikelyImageAttributionDomain(domain) {
  const normalized = String(domain || "")
    .toLowerCase()
    .replace(/^www\./, "");

  return (
    normalized === "imgflip.com" ||
    normalized === "i.imgflip.com" ||
    normalized === "memegenerator.net" ||
    normalized === "makeameme.org" ||
    normalized === "kapwing.com"
  );
}

function hasClearDestinationIntent(element, text = "") {
  const utilityText = element instanceof Element ? buildCandidateUtilityText(element) : "";
  const anchorText = element instanceof Element ? extractAnchorDisplayText(element) : "";
  const combinedText = `${text} ${anchorText} ${utilityText}`.replace(/\s+/g, " ").trim();

  const hasCta = CTA_TEXT_PATTERNS.some((pattern) => pattern.test(combinedText));
  const hasSponsored = /\bsponsored\b/i.test(combinedText);
  const hasExplicitCardMetadata = Boolean(
    element instanceof Element &&
    (
      element.matches('[data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"])') ||
      element.closest('[data-ad-preview]:not([data-ad-preview="message"]), [data-ad-comet-preview]:not([data-ad-comet-preview="message"])')
    )
  );

  return hasCta || hasSponsored || hasExplicitCardMetadata;
}

function isLikelyImageSourceCandidate(element, rawUrl) {
  if (!(element instanceof Element)) {
    return false;
  }

  const text = extractAnchorDisplayText(element);
  const utilityText = buildCandidateUtilityText(element);
  const combinedText = `${text} ${utilityText}`.replace(/\s+/g, " ").trim();

  const hasMedia = Boolean(
    element.matches("img, picture, video, svg") ||
    element.querySelector("img, picture, video, svg")
  );

  if (!hasMedia) {
    return false;
  }

  // Real ad/link cards should still be scanned.
  if (hasClearDestinationIntent(element, combinedText)) {
    return false;
  }

  const host = safeHostname(rawUrl);
  const registrableDomain = getRegistrableDomain(host);

  return (
    isLikelyImageAssetUrl(rawUrl) ||
    isLikelyImageAttributionDomain(host) ||
    isLikelyImageAttributionDomain(registrableDomain)
  );
}
function getSafePanelFallbackPoint(post) {
  if (!(post instanceof Element)) {
    return {
      parent: document.body,
      beforeNode: null
    };
  }

  const headerBlock = findPostHeaderBlock(post);
  if (headerBlock instanceof Element && headerBlock.parentElement instanceof Element) {
    return {
      parent: headerBlock.parentElement,
      beforeNode: headerBlock.nextSibling || null
    };
  }

  return {
    parent: post,
    beforeNode: post.firstElementChild || null
  };
}
function buildSafeInsertionBeforeElement(post, target) {
  if (!(post instanceof Element) || !(target instanceof Element) || !post.contains(target)) {
    return null;
  }

  let node = target;

  while (node.parentElement instanceof Element && node.parentElement !== post) {
    const parent = node.parentElement;

    if (isUnsafePanelMountParent(parent, post)) {
      node = parent;
      continue;
    }

    if (isLikelyActionBarOrControlContainer(parent) || isLikelyCommentOrReplyContainer(parent)) {
      node = parent;
      continue;
    }

    if (isPanelMountGeometrySafe(parent, post)) {
      return {
        parent,
        beforeNode: node
      };
    }

    node = parent;
  }

  if (node instanceof Element && node.parentElement === post) {
    return {
      parent: post,
      beforeNode: node
    };
  }

  return null;
}

function buildSafeInsertionAfterElement(post, target) {
  if (!(post instanceof Element) || !(target instanceof Element) || !post.contains(target)) {
    return null;
  }

  let node = target;

  while (node.parentElement instanceof Element && node.parentElement !== post) {
    const parent = node.parentElement;

    if (isUnsafePanelMountParent(parent, post)) {
      node = parent;
      continue;
    }

    if (isLikelyActionBarOrControlContainer(parent) || isLikelyCommentOrReplyContainer(parent)) {
      node = parent;
      continue;
    }

    if (isPanelMountGeometrySafe(parent, post)) {
      return {
        parent,
        beforeNode: node.nextSibling || null
      };
    }

    node = parent;
  }

  if (node instanceof Element && node.parentElement === post) {
    return {
      parent: post,
      beforeNode: node.nextSibling || null
    };
  }

  return null;
}

function isPanelMountGeometrySafe(parent, post) {
  if (!(parent instanceof Element) || !(post instanceof Element)) {
    return false;
  }

  const parentRect = parent.getBoundingClientRect();
  const postRect = post.getBoundingClientRect();

  if (parentRect.width <= 0 || postRect.width <= 0) {
    return false;
  }

  if (parentRect.width < postRect.width * 0.72) {
    return false;
  }

  if (parentRect.left < postRect.left - 12 || parentRect.right > postRect.right + 12) {
    return false;
  }

  return true;
}

function normalizePanelInsertionPoint(post, preferredPoint, fallbackPoint) {
  if (
    !preferredPoint?.parent ||
    !(preferredPoint.parent instanceof Element) ||
    !post.contains(preferredPoint.parent)
  ) {
    return fallbackPoint;
  }

  if (isUnsafePanelMountParent(preferredPoint.parent, post)) {
    return fallbackPoint;
  }

  if (!isPanelMountGeometrySafe(preferredPoint.parent, post)) {
    return fallbackPoint;
  }

  return preferredPoint;
}

function isUnsafePanelMountParent(parent, owningPost) {
  if (!(parent instanceof Element)) {
    return true;
  }

  const clickableAncestor = parent.closest(UNSAFE_PANEL_ANCESTOR_SELECTOR);

  return Boolean(
    clickableAncestor &&
    clickableAncestor !== owningPost &&
    owningPost.contains(clickableAncestor)
  );
}

function isElementInsideUnsafeClickableSurface(element, owningPost) {
  if (!(element instanceof Element)) {
    return false;
  }

  const clickableAncestor = element.closest(UNSAFE_PANEL_ANCESTOR_SELECTOR);

  return Boolean(
    clickableAncestor &&
    clickableAncestor !== owningPost &&
    owningPost.contains(clickableAncestor)
  );
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

if (slot && isExistingPanelSlotStillSafe(slot, post)) {
  scanStatus.panelSlotReused += 1;
  cleanupDuplicatePanelArtifacts(post, slot);
  return slot;
}

  if (!slot) {
    slot = document.createElement("div");
    slot.className = "dili-panel-slot";
    slot.dataset.diliOwned = "true";
  }

  slot.style.width = "100%";
  slot.style.maxWidth = "100%";
  slot.style.boxSizing = "border-box";
  slot.style.alignSelf = "stretch";

  let insertionPoint = findPanelInsertionPoint(post);

if (
  !insertionPoint?.parent ||
  !(insertionPoint.parent instanceof Element) ||
  isForbiddenPanelMountSurface(insertionPoint.parent, post)
) {
  scanStatus.panelMountFallbackUsed += 1;
  insertionPoint = getSafePanelFallbackPoint(post);
}
  if (slot.parentElement !== insertionPoint.parent || slot.nextSibling !== insertionPoint.beforeNode) {
    if (insertionPoint.beforeNode instanceof Node) {
      insertionPoint.parent.insertBefore(slot, insertionPoint.beforeNode);
    } else {
      insertionPoint.parent.appendChild(slot);
    }
  }

  // Final assertion: if Facebook DOM still placed this inside a clickable/card
  // surface, force the slot to the top-level post container.
if (isForbiddenPanelMountSurface(slot, post)) {
  scanStatus.panelUnsafeRelocated += 1;

  const fallbackPoint = {
    parent: post,
    beforeNode: post.firstElementChild || null
  };

  if (fallbackPoint.beforeNode instanceof Node) {
    fallbackPoint.parent.insertBefore(slot, fallbackPoint.beforeNode);
  } else {
    fallbackPoint.parent.appendChild(slot);
  }
}

  cleanupDuplicatePanelArtifacts(post, slot);
  return slot;
}

function isExistingPanelSlotStillSafe(slot, post) {
  if (!(slot instanceof Element) || !(post instanceof Element)) {
    return false;
  }

  if (!post.contains(slot)) {
    return false;
  }

  if (isForbiddenPanelMountSurface(slot, post)) {
    return false;
  }

  const rect = slot.getBoundingClientRect();
  const postRect = post.getBoundingClientRect();

  if (rect.width <= 0 || postRect.width <= 0) {
    return false;
  }

  return rect.width >= postRect.width * 0.72;
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
    for (const nested of [...clone.querySelectorAll('div[role="article"], article, [aria-posinset]')]) {
      if (nested !== clone) {
        nested.remove();
      }
    }

    for (const selector of [".dili-panel", ".dili-panel-slot", ".dili-badge", ".dili-details", ".dili-warning-overlay", ".dili-warning-modal", "script", "style", "noscript"]) {
      for (const element of clone.querySelectorAll(selector)) {
        element.remove();
      }
    }

    return String(clone.textContent || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function extractRenderedVisibleText(element) {
    if (!(element instanceof Element)) {
      return "";
    }

    const parts = [];
    const walker = document.createTreeWalker(
      element,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const text = String(node.nodeValue || "").replace(/\s+/g, " ").trim();
          if (!text) {
            return NodeFilter.FILTER_REJECT;
          }

          const parent = node.parentElement;
          if (!(parent instanceof Element)) {
            return NodeFilter.FILTER_REJECT;
          }

          if (!element.contains(parent)) {
            return NodeFilter.FILTER_REJECT;
          }

          if (parent.closest(DILI_UI_SELECTOR)) {
            return NodeFilter.FILTER_REJECT;
          }

          if (parent.closest("script, style, noscript")) {
            return NodeFilter.FILTER_REJECT;
          }

          if (parent.hasAttribute("hidden") || parent.getAttribute("aria-hidden") === "true") {
            return NodeFilter.FILTER_REJECT;
          }

          if (!isProbablyVisible(parent)) {
            return NodeFilter.FILTER_REJECT;
          }

          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    while (walker.nextNode()) {
      parts.push(String(walker.currentNode.nodeValue || "").replace(/\s+/g, " ").trim());
    }

    return parts.join(" ").replace(/\s+/g, " ").trim();
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
  if (!(post instanceof Element)) {
    return null;
  }

  const groups = [...post.querySelectorAll('[role="group"], [aria-label]')]
    .filter((element) => element instanceof Element && !element.closest(".dili-panel"));

  const postRect = post.getBoundingClientRect();

  for (const group of groups) {
    const text = buildCandidateUtilityText(group);
    const visibleText = extractVisiblePostText(group).toLowerCase();
    const combined = `${text} ${visibleText}`;

    const looksLikeReactionBar =
      /\blike\b/i.test(combined) &&
      /\bcomment\b/i.test(combined) &&
      /\bshare\b/i.test(combined);

    if (!looksLikeReactionBar) {
      continue;
    }

    const rect = group.getBoundingClientRect();

    // Reaction bars are normally near the lower part of the post.
    // This avoids classifying CTA cards or link previews as the action bar.
    if (rect.top < postRect.top + postRect.height * 0.45) {
      continue;
    }

    return group;
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
function nowMs() {
  return typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

function elapsedMs(startMs) {
  return Math.max(0, Math.round(nowMs() - Number(startMs || nowMs())));
}

function recordMaxScanStatusValue(key, value) {
  const numeric = Number(value || 0);
  scanStatus[key] = Math.max(Number(scanStatus[key] || 0), numeric);
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
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
})();
