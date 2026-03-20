(function initializeDili() {
  const DEBUG_SHOW_NO_LINK_UI = false;

  const MESSAGE_TYPES = {
    ANALYZE_LINK: "DILI_ANALYZE_LINK",
    REANALYZE_LINK: "DILI_REANALYZE_LINK",
    GET_POST_STATE: "DILI_GET_POST_STATE",
    SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
    RESCAN_NOW: "DILI_RESCAN_NOW",
    POST_ANALYSIS_UPDATE: "DILI_POST_ANALYSIS_UPDATE"
  };

  const POST_SELECTORS = [
    'div[role="article"]',
    "article",
    '[data-pagelet*="FeedUnit"]',
    "[aria-posinset]"
  ];

  const visibleQueue = new Set();
  const deferredQueue = new Set();
  const postIdCache = new WeakMap();
  const postSignatureCache = new WeakMap();
  const postRenderSignature = new WeakMap();
  const postIdToElement = new Map();
  const postRiskMeta = new Map();
  const observedAnchors = new WeakSet();

  let observer = null;
  let intersectionObserver = null;
  let flushTimer = null;
  let mutationDebounceTimer = null;
  let runtimeBound = false;
  let globalUiBound = false;

  start().catch((error) => {
    console.warn("[DILI] Failed to initialize content script", error);
  });

  async function start() {
    if (!location.hostname.includes("facebook.com")) {
      return;
    }

    bindRuntimeListeners();
    bindGlobalUiActions();
    setupIntersectionObserver();
    initialScan();
    observeFeed();
    window.addEventListener("scroll", scheduleVisibleRescan, { passive: true });
    window.addEventListener("resize", scheduleVisibleRescan, { passive: true });
    console.debug("[DILI] Content script initialized.");
  }

  function bindRuntimeListeners() {
    if (runtimeBound) {
      return;
    }

    runtimeBound = true;
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.type === MESSAGE_TYPES.RESCAN_NOW) {
        forceRescan()
          .then(() => sendResponse({ ok: true }))
          .catch(() => sendResponse({ ok: false, error: "Re-scan failed." }));
        return true;
      }

      if (message?.type === MESSAGE_TYPES.POST_ANALYSIS_UPDATE && message.postId && message.analysis) {
        applyAnalysisUpdate(message.postId, message.analysis);
        sendResponse({ ok: true });
        return false;
      }

      return false;
    });
  }

  function bindGlobalUiActions() {
    if (globalUiBound) {
      return;
    }

    globalUiBound = true;

    document.addEventListener("click", handleInterceptedLinkClick, true);
    document.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) {
        return;
      }

      const detailsButton = target.closest("[data-dili-action='details']");
      if (detailsButton instanceof HTMLElement) {
        event.preventDefault();
        openDetailsModal(detailsButton.dataset.postId || "");
        return;
      }

      const reportButton = target.closest("[data-dili-action='report']");
      if (reportButton instanceof HTMLElement) {
        event.preventDefault();
        openReportModal(reportButton.dataset.postId || "");
      }
    });
  }

  async function forceRescan() {
    for (const post of collectCandidatePosts(document)) {
      enqueuePost(post);
    }

    scheduleFlush();
    console.debug("[DILI] Manual re-scan requested from popup.");
  }

  function initialScan() {
    for (const post of collectCandidatePosts(document)) {
      enqueuePost(post);
    }

    scheduleFlush();
  }

  function setupIntersectionObserver() {
    if (!("IntersectionObserver" in window)) {
      return;
    }

    intersectionObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting || !(entry.target instanceof Element)) {
            continue;
          }

          if (deferredQueue.has(entry.target)) {
            deferredQueue.delete(entry.target);
            visibleQueue.add(entry.target);
            scheduleFlush();
          }
        }
      },
      {
        root: null,
        rootMargin: "350px 0px 350px 0px",
        threshold: [0, 0.01]
      }
    );
  }

  function scheduleVisibleRescan() {
    if (mutationDebounceTimer !== null) {
      return;
    }

    mutationDebounceTimer = window.setTimeout(() => {
      mutationDebounceTimer = null;
      for (const post of collectCandidatePosts(document)) {
        if (isNearViewport(post)) {
          enqueuePost(post, "visible");
        }
      }
      scheduleFlush();
    }, 220);
  }

  function observeFeed() {
    observer = new MutationObserver((mutations) => {
      const affectedPosts = new Set();

      for (const mutation of mutations) {
        if (shouldIgnoreMutation(mutation)) {
          continue;
        }

        const candidates = [mutation.target, ...mutation.addedNodes];
        for (const node of candidates) {
          if (!(node instanceof Element)) {
            continue;
          }

          const nearest = findPostContainer(node);
          if (nearest) {
            affectedPosts.add(nearest);
          }

          for (const nested of collectCandidatePosts(node)) {
            affectedPosts.add(nested);
          }
        }
      }

      if (affectedPosts.size === 0) {
        return;
      }

      for (const post of affectedPosts) {
        enqueuePost(post);
      }

      if (mutationDebounceTimer !== null) {
        return;
      }

      mutationDebounceTimer = window.setTimeout(() => {
        mutationDebounceTimer = null;
        scheduleFlush();
      }, 180);
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["href", "data-ft", "aria-label", "aria-labelledby"]
    });
  }

  function shouldIgnoreMutation(mutation) {
    const target = mutation.target;
    if (!(target instanceof Element)) {
      return false;
    }

    return Boolean(target.closest(".dili-panel, .dili-modal, .dili-backdrop"));
  }

  function collectCandidatePosts(root) {
    const candidates = new Set();
    const searchRoot = root instanceof Document || root instanceof Element ? root : null;

    if (!searchRoot) {
      return candidates;
    }

    if (searchRoot instanceof Element) {
      const direct = findPostContainer(searchRoot);
      if (direct) {
        candidates.add(direct);
      }
    }

    for (const selector of POST_SELECTORS) {
      for (const element of searchRoot.querySelectorAll(selector)) {
        if (element instanceof Element) {
          candidates.add(element);
        }
      }
    }

    return candidates;
  }

  function enqueuePost(post, priority = "auto") {
    if (!(post instanceof Element) || !post.isConnected) {
      return;
    }

    if (intersectionObserver) {
      intersectionObserver.observe(post);
    }

    if (priority === "visible" || (priority === "auto" && isNearViewport(post))) {
      deferredQueue.delete(post);
      visibleQueue.add(post);
      return;
    }

    if (!visibleQueue.has(post)) {
      deferredQueue.add(post);
    }
  }

  function scheduleFlush() {
    if (flushTimer !== null) {
      return;
    }

    flushTimer = window.setTimeout(async () => {
      flushTimer = null;
      await flushQueue();
    }, 90);
  }

  async function flushQueue() {
    const visibleBatch = popBatch(visibleQueue, 12);
    const deferredBatch = visibleBatch.length === 0 ? popBatch(deferredQueue, 4) : [];
    const batch = visibleBatch.length > 0 ? visibleBatch : deferredBatch;

    if (batch.length === 0) {
      return;
    }

    console.debug(`[DILI] Processing visible=${visibleBatch.length} deferred=${deferredBatch.length}`);

    for (const post of batch) {
      await processPost(post);
    }

    if (visibleQueue.size > 0 || deferredQueue.size > 0) {
      scheduleFlush();
    }
  }

  function popBatch(queue, limit) {
    const items = [];
    for (const item of queue) {
      queue.delete(item);
      items.push(item);
      if (items.length >= limit) {
        break;
      }
    }

    return items;
  }

  async function processPost(post) {
    if (!post.isConnected) {
      return;
    }

    const postId = getStablePostId(post);
    postIdToElement.set(postId, post);

    const linkInfo = extractRelevantLink(post);
    const signature = buildPostSignature(linkInfo);

    if (postSignatureCache.get(post) === signature) {
      return;
    }

    postSignatureCache.set(post, signature);

    if (!linkInfo) {
      await setNoLinkState(post, postId);
      return;
    }

    bindAnchorHints(linkInfo.element, postId);
    renderBadge(post, {
      postId,
      label: "Scanning",
      safetyScore: null,
      state: "scanning",
      sentence: "Checking this link now.",
      reasons: []
    });

    const currentState = await sendRuntimeMessage({
      type: MESSAGE_TYPES.GET_POST_STATE,
      postId
    });

    const messageType = currentState?.baseline?.urlHash ? MESSAGE_TYPES.REANALYZE_LINK : MESSAGE_TYPES.ANALYZE_LINK;
    const response = await sendRuntimeMessage({
      type: messageType,
      postId,
      url: linkInfo.url,
      displayedText: linkInfo.displayText
    });

    if (!response?.analysis) {
      renderBadge(post, {
        postId,
        label: "Analysis Unavailable",
        safetyScore: null,
        state: "analysis_failed",
        sentence: "This link could not be fully checked.",
        reasons: ["Some checks could not be completed."]
      });
      return;
    }

    applyAnalysisUpdate(postId, response.analysis);
  }

  async function setNoLinkState(post, postId) {
    await sendRuntimeMessage({
      type: MESSAGE_TYPES.SET_NO_LINK_STATE,
      postId
    });

    postRiskMeta.delete(postId);

    if (!DEBUG_SHOW_NO_LINK_UI) {
      removeBadge(post);
      return;
    }

    renderBadge(post, {
      postId,
      label: "No Link",
      safetyScore: null,
      state: "no_link",
      sentence: "No external HTTP or HTTPS link detected.",
      reasons: []
    });
  }

  function applyAnalysisUpdate(postId, analysis) {
    const post = postIdToElement.get(postId);
    if (!post || !post.isConnected) {
      return;
    }

    const viewModel = mapAnalysisToViewModel(analysis);
    const stateChanged = postRiskMeta.get(postId)?.state !== viewModel.state;
    postRiskMeta.set(postId, {
      postId,
      normalizedUrl: analysis.normalizedUrl || "",
      domain: safeHostname(analysis.normalizedUrl),
      state: viewModel.state,
      classification: analysis.classification || "Unknown",
      score: analysis.safetyScore,
      reasons: viewModel.reasons,
      sentence: viewModel.sentence
    });

    if (stateChanged) {
      console.debug(`[DILI] state transition ${postId}: ${viewModel.state}`);
    }

    renderBadge(post, {
      postId,
      label: viewModel.label,
      safetyScore: viewModel.safetyScore,
      state: viewModel.state,
      sentence: viewModel.sentence,
      reasons: viewModel.reasons,
      showActions: viewModel.state === "suspicious" || viewModel.state === "high_risk"
    });
  }

  function extractRelevantLink(post) {
    const anchors = [...post.querySelectorAll("a[href]")].filter((anchor) => !anchor.closest(".dili-panel, .dili-modal"));

    for (const anchor of anchors) {
      const rawHref = anchor.getAttribute("href");
      const parsed = safeParseUrl(rawHref, location.href);
      if (!parsed) {
        if (rawHref) {
          console.debug("[DILI] rejected invalid href", rawHref);
        }
        continue;
      }

      const unwrapped = unwrapFacebookOutbound(parsed);
      if (!unwrapped) {
        continue;
      }

      if (isInternalFacebookLink(unwrapped)) {
        continue;
      }

      return {
        element: anchor,
        url: unwrapped.toString(),
        displayText: (anchor.textContent || anchor.getAttribute("aria-label") || "").trim()
      };
    }

    return null;
  }

  function safeParseUrl(rawHref, baseUrl) {
    const raw = String(rawHref || "").trim();
    if (!raw || raw === "#") {
      return null;
    }

    const lowered = raw.toLowerCase();
    if (lowered.startsWith("javascript:") || lowered.startsWith("mailto:") || lowered.startsWith("tel:")) {
      return null;
    }

    try {
      const parsed = new URL(raw, baseUrl || location.href);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        return null;
      }

      return parsed;
    } catch {
      return null;
    }
  }

  function unwrapFacebookOutbound(url) {
    const host = url.hostname.toLowerCase();
    if (!["l.facebook.com", "lm.facebook.com", "m.facebook.com"].includes(host)) {
      return url;
    }

    const nested = url.searchParams.get("u") || url.searchParams.get("url");
    if (!nested) {
      return url;
    }

    try {
      const decoded = decodeURIComponent(nested);
      const parsed = safeParseUrl(decoded, url.toString());
      return parsed || url;
    } catch {
      return url;
    }
  }

  function isInternalFacebookLink(url) {
    const host = String(url.hostname || "").toLowerCase();
    return host.endsWith("facebook.com") || host.endsWith("fb.me");
  }

  function bindAnchorHints(anchor, postId) {
    if (!(anchor instanceof Element) || observedAnchors.has(anchor)) {
      return;
    }

    observedAnchors.add(anchor);
    anchor.dataset.diliPostId = postId;
  }

  function renderBadge(post, viewModel) {
    const safeState = sanitizeClassToken(viewModel.state || "safe");
    const scoreText = Number.isFinite(viewModel.safetyScore) ? String(viewModel.safetyScore) : "--";
    const compactSummary = viewModel.safetyScore === null ? viewModel.label : `${viewModel.label} • ${scoreText}`;
    const renderSignature = [
      safeState,
      viewModel.label,
      scoreText,
      viewModel.sentence || "",
      (viewModel.reasons || []).join("|"),
      String(Boolean(viewModel.showActions))
    ].join("::");

    if (postRenderSignature.get(post) === renderSignature) {
      console.debug("[DILI] UI update skipped because state unchanged.");
      return;
    }

    postRenderSignature.set(post, renderSignature);

    const mountPoint = getBadgeMountPoint(post);
    if (!mountPoint) {
      return;
    }

    let panel = post.querySelector(".dili-panel[data-dili-owned='true']");
    if (!panel) {
      panel = document.createElement("div");
      panel.className = "dili-panel";
      panel.dataset.diliOwned = "true";
    }

    if (panel.parentElement !== mountPoint) {
      mountPoint.prepend(panel);
    }

    const reasonLabel = escapeHtml((viewModel.reasons || [])[0] || "No strong risk indicators were found.");
    const actionsHtml = viewModel.showActions
      ? `
        <div class="dili-actions">
          <button type="button" data-dili-action="report" data-post-id="${escapeHtml(viewModel.postId || "")}">Report Post</button>
          <button type="button" data-dili-action="details" data-post-id="${escapeHtml(viewModel.postId || "")}" title="Why this link was flagged">Details</button>
        </div>
      `
      : "";

    panel.className = `dili-panel dili-state-${safeState}`;
    panel.innerHTML = `
      <div class="dili-row">
        <span class="dili-pill">${escapeHtml(compactSummary)}</span>
      </div>
      <p class="dili-sentence">${escapeHtml(viewModel.sentence || "")}</p>
      <p class="dili-reason" hidden>${reasonLabel}</p>
      ${actionsHtml}
    `;
  }

  function removeBadge(post) {
    const panel = post.querySelector(".dili-panel[data-dili-owned='true']");
    if (panel) {
      panel.remove();
    }
  }

  function mapAnalysisToViewModel(analysis) {
    const score = Number.isFinite(analysis?.safetyScore) ? analysis.safetyScore : null;
    const normalizedState = normalizeState(analysis?.state, analysis?.classification, score);
    const reasons = sanitizeReasons(analysis?.reasons);

    let label = "Safe";
    let sentence = "No strong risk indicators were detected.";

    if (normalizedState === "scanning") {
      label = "Scanning";
      sentence = "Checking this link now.";
    } else if (normalizedState === "analysis_partial") {
      label = analysis?.classification || "Partial Check";
      sentence = "Some checks could not be completed, but available signals were reviewed.";
    } else if (normalizedState === "analysis_failed") {
      label = "Check Limited";
      sentence = "This link could not be fully checked.";
    } else if (normalizedState === "suspicious") {
      label = "Suspicious";
      sentence = "This link may redirect through a shortened or suspicious destination.";
    } else if (normalizedState === "high_risk") {
      label = "High Risk";
      sentence = "This link appears to have changed or may be unsafe.";
    }

    return {
      postId: analysis?.postId || "",
      label,
      safetyScore: score,
      state: normalizedState,
      reasons,
      sentence
    };
  }

  function normalizeState(state, classification, score) {
    const source = String(state || "").toLowerCase();
    if (["no_link", "scanning", "safe", "suspicious", "high_risk", "analysis_partial", "analysis_failed"].includes(source)) {
      return source;
    }

    if (classification === "High Risk") {
      return "high_risk";
    }

    if (classification === "Suspicious") {
      return "suspicious";
    }

    if (Number.isFinite(score)) {
      if (score < 50) {
        return "high_risk";
      }

      if (score < 80) {
        return "suspicious";
      }

      return "safe";
    }

    return "analysis_partial";
  }

  function sanitizeReasons(reasons) {
    if (!Array.isArray(reasons) || reasons.length === 0) {
      return ["Some checks could not be completed."];
    }

    return reasons
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .slice(0, 4);
  }

  function openDetailsModal(postId) {
    const meta = postRiskMeta.get(postId);
    if (!meta) {
      return;
    }

    const body = `
      <h3>Why this link was flagged</h3>
      <ul>
        ${(meta.reasons || []).slice(0, 4).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
      <div class="dili-modal-actions">
        <button type="button" data-dili-close-modal="true">Close</button>
      </div>
    `;

    showModal({
      mode: "details",
      body
    });
  }

  function openReportModal(postId) {
    const meta = postRiskMeta.get(postId);
    if (!meta) {
      return;
    }

    const body = `
      <h3>Report this post</h3>
      <p>If this post appears suspicious, you may report it through Facebook.</p>
      <ol>
        <li>Click the three dots (⋯) on the post</li>
        <li>Select Report post</li>
        <li>Choose Scam or Fraud or False Information</li>
        <li>Submit the report</li>
      </ol>
      <div class="dili-modal-actions">
        <button type="button" data-dili-copy-evidence="${escapeHtml(postId)}">Copy Evidence</button>
        <button type="button" data-dili-close-modal="true">Close</button>
      </div>
      <p class="dili-copy-feedback" aria-live="polite"></p>
    `;

    showModal({
      mode: "report",
      body,
      onAfterRender(modalRoot) {
        const copyButton = modalRoot.querySelector("[data-dili-copy-evidence]");
        const feedback = modalRoot.querySelector(".dili-copy-feedback");
        if (!(copyButton instanceof HTMLButtonElement) || !(feedback instanceof HTMLElement)) {
          return;
        }

        copyButton.addEventListener("click", async () => {
          const summary = buildEvidenceSummary(meta);
          try {
            await navigator.clipboard.writeText(summary);
            feedback.textContent = "Evidence copied.";
          } catch {
            feedback.textContent = "Could not copy evidence in this browser context.";
          }
        });
      }
    });
  }

  function buildEvidenceSummary(meta) {
    const stamp = new Date().toISOString();
    return [
      "DILI Report Summary",
      `Safety Score: ${Number.isFinite(meta.score) ? meta.score : "--"}`,
      `Classification: ${meta.classification || "Unknown"}`,
      `URL: ${meta.normalizedUrl || "Unknown"}`,
      `Reason(s): ${(meta.reasons || []).join("; ")}`,
      `Timestamp: ${stamp}`
    ].join("\n");
  }

  function handleInterceptedLinkClick(event) {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }

    const anchor = target.closest("a[href]");
    if (!(anchor instanceof HTMLAnchorElement)) {
      return;
    }

    if (anchor.closest(".dili-modal, .dili-panel")) {
      return;
    }

    const post = findPostContainer(anchor);
    if (!post) {
      return;
    }

    const postId = getStablePostId(post);
    const meta = postRiskMeta.get(postId);
    if (!meta || !["suspicious", "high_risk"].includes(meta.state)) {
      return;
    }

    const parsed = safeParseUrl(anchor.getAttribute("href"), location.href);
    if (!parsed) {
      return;
    }

    const destination = unwrapFacebookOutbound(parsed);
    if (!destination || isInternalFacebookLink(destination)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();

    const toneClass = meta.state === "high_risk" ? "danger" : "warning";
    const heading = meta.state === "high_risk" ? "⚠ High Risk Link Detected" : "Suspicious Link Detected";
    const warning = meta.state === "high_risk"
      ? "This link may redirect to an unsafe or misleading website."
      : "This link may lead to a misleading destination.";

    const body = `
      <h3>${escapeHtml(heading)}</h3>
      <p><strong>Destination:</strong> ${escapeHtml(destination.hostname)}</p>
      <p><strong>Safety Score:</strong> ${Number.isFinite(meta.score) ? meta.score : "--"}</p>
      <p>${escapeHtml(warning)}</p>
      <ul>
        ${(meta.reasons || []).slice(0, 3).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
      <div class="dili-modal-actions">
        <button type="button" data-dili-close-modal="true" class="primary">Go Back</button>
        <button type="button" data-dili-proceed-url="${escapeHtml(destination.toString())}">Proceed Anyway</button>
        <button type="button" data-dili-action="report" data-post-id="${escapeHtml(postId)}">Report Post</button>
      </div>
    `;

    showModal({
      mode: "warning",
      toneClass,
      body,
      onAfterRender(modalRoot) {
        const proceed = modalRoot.querySelector("[data-dili-proceed-url]");
        if (proceed instanceof HTMLButtonElement) {
          proceed.addEventListener("click", () => {
            const nextUrl = proceed.dataset.diliProceedUrl || "";
            if (nextUrl) {
              closeModal();
              location.assign(nextUrl);
            }
          });
        }

        const report = modalRoot.querySelector("[data-dili-action='report']");
        if (report instanceof HTMLButtonElement) {
          report.addEventListener("click", () => {
            const nextPostId = report.dataset.postId || postId;
            openReportModal(nextPostId);
          });
        }
      }
    });
  }

  function showModal({ mode, toneClass = "", body, onAfterRender }) {
    closeModal();

    const backdrop = document.createElement("div");
    backdrop.className = "dili-backdrop";
    backdrop.dataset.diliModal = mode;

    const modal = document.createElement("div");
    modal.className = `dili-modal ${toneClass}`.trim();
    modal.innerHTML = body;
    backdrop.appendChild(modal);

    backdrop.addEventListener("click", (event) => {
      if (event.target === backdrop) {
        closeModal();
      }
    });

    modal.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) {
        return;
      }

      const closeButton = target.closest("[data-dili-close-modal='true']");
      if (closeButton) {
        event.preventDefault();
        closeModal();
      }
    });

    document.body.appendChild(backdrop);
    if (typeof onAfterRender === "function") {
      onAfterRender(modal);
    }
  }

  function closeModal() {
    const existing = document.querySelector(".dili-backdrop");
    if (existing) {
      existing.remove();
    }
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

    return `${linkInfo.url}|${linkInfo.displayText}`;
  }

  function findPostContainer(node) {
    if (!(node instanceof Element)) {
      return null;
    }

    return node.closest(POST_SELECTORS.join(","));
  }

  function getBadgeMountPoint(post) {
    const contentSelectors = [
      '[data-ad-preview="message"]',
      '[data-ad-comet-preview="message"]',
      '[data-testid="post_message"]',
      '[dir="auto"]'
    ];

    for (const selector of contentSelectors) {
      const matches = [...post.querySelectorAll(selector)].filter((element) => element instanceof Element && !element.closest(".dili-panel"));
      const bestMatch = matches.find((element) => isUsefulMountNode(element, post));
      if (bestMatch) {
        return bestMatch;
      }
    }

    const actionBar = findActionBar(post);
    if (actionBar) {
      return actionBar.parentElement || actionBar;
    }

    return post;
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

  function isUsefulMountNode(element, post) {
    if (!(element instanceof Element) || !post.contains(element)) {
      return false;
    }

    const text = (element.textContent || "").trim();
    return text.length > 0 && text.length < 4000;
  }

  function isNearViewport(element) {
    if (!(element instanceof Element)) {
      return false;
    }

    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      rect.width > 0 &&
      rect.height > 0 &&
      rect.bottom >= -400 &&
      rect.top <= window.innerHeight + 600
    );
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
        error: "Background communication failed."
      };
    }
  }

  function safeHostname(rawUrl) {
    try {
      return new URL(rawUrl).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function hashString(value) {
    let hash = 2166136261;

    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }

    return Math.abs(hash >>> 0).toString(16);
  }

  function sanitizeClassToken(value) {
    return String(value || "safe")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-");
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
