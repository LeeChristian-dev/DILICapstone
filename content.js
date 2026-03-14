(function initializeDili() {
  const MESSAGE_TYPES = {
    ANALYZE_LINK: "DILI_ANALYZE_LINK",
    REANALYZE_LINK: "DILI_REANALYZE_LINK",
    GET_POST_STATE: "DILI_GET_POST_STATE",
    SET_NO_LINK_STATE: "DILI_SET_NO_LINK_STATE",
    RESCAN_NOW: "DILI_RESCAN_NOW"
  };

  const POST_SELECTORS = [
    'div[role="article"]',
    'article',
    '[data-pagelet*="FeedUnit"]',
    '[aria-posinset]'
  ];

  const pendingPosts = new Set();
  const postIdCache = new WeakMap();
  const postSignatureCache = new WeakMap();
  const observedPostIds = new Map();
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

    console.debug("[DILI] Content script initialized.");
    bindRuntimeListeners();
    initialScan();
    observeFeed();
    window.addEventListener("scroll", scheduleVisibleRescan, { passive: true });
  }

  function bindRuntimeListeners() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.type !== MESSAGE_TYPES.RESCAN_NOW) {
        return false;
      }

      forceRescan()
        .then(() => sendResponse({ ok: true }))
        .catch((error) => sendResponse({ ok: false, error: error.message || "Re-scan failed." }));

      return true;
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

  function scheduleVisibleRescan() {
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

    return Boolean(target.closest(".dili-badge, .dili-panel, .dili-details"));
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
    if (!(post instanceof Element)) {
      return;
    }

    pendingPosts.add(post);
  }

  function scheduleFlush() {
    if (flushTimer !== null) {
      return;
    }

    flushTimer = window.setTimeout(async () => {
      const batch = [...pendingPosts];
      pendingPosts.clear();
      flushTimer = null;

      for (const post of batch) {
        await processPost(post);
      }
    }, 250);
  }

  async function processPost(post) {
    if (!post.isConnected || !isProbablyVisible(post)) {
      return;
    }

    const postId = getStablePostId(post);
    const linkInfo = extractRelevantLink(post);
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
      displayedText: linkInfo.displayText
    });

    if (!response?.analysis) {
      renderBadge(post, {
        label: "Analysis unavailable",
        safetyScore: null,
        state: "monitored",
        details: [response?.error || "Background analysis did not return data."]
      });
      return;
    }

    renderBadge(post, mapAnalysisToViewModel(response.analysis));
  }

  async function setNoLinkState(post, postId) {
    const response = await sendRuntimeMessage({
      type: MESSAGE_TYPES.SET_NO_LINK_STATE,
      postId
    });

    renderBadge(post, {
      label: "No hyperlink detected",
      safetyScore: null,
      state: response?.baseline?.state || "no_link",
      badgeTone: "no-link-detected",
      details: ["This post is being monitored for future HTTP or HTTPS link insertions."]
    });
  }

  function extractRelevantLink(post) {
    const anchors = [...post.querySelectorAll("a[href]")].filter((anchor) => !anchor.closest(".dili-badge, .dili-panel"));
    const candidates = anchors
      .map((anchor) => ({
        element: anchor,
        url: anchor.href,
        displayText: (anchor.textContent || anchor.getAttribute("aria-label") || "").trim()
      }))
      .filter((anchor) => isEligibleLink(anchor.url));

    return candidates[0] || null;
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

    const scoreText = Number.isFinite(viewModel.safetyScore) ? String(viewModel.safetyScore) : "--";
    const safeState = sanitizeClassToken(viewModel.state || "monitored");
    const badgeTone = sanitizeClassToken(viewModel.badgeTone || safeState);
    const summaryText = `${viewModel.label} | Safety Score ${scoreText}`;
    const compactSummary = viewModel.safetyScore === null ? viewModel.label : `${viewModel.label} • ${scoreText}`;
    const detailItems = (viewModel.details || [])
      .map((detail) => `<li>${escapeHtml(detail)}</li>`)
      .join("");

    badge.className = `dili-panel dili-state-${safeState}`;
    badge.innerHTML = `
      <div class="dili-badge">
        <span class="dili-pill dili-pill-${badgeTone}">${escapeHtml(compactSummary)}</span>
        <span class="dili-score" aria-hidden="true">DILI</span>
      </div>
      <details class="dili-details">
        <summary>${escapeHtml(summaryText)}</summary>
        <ul class="dili-detail-list">${detailItems || "<li>No detailed indicators recorded.</li>"}</ul>
      </details>
    `;
  }

  function mapAnalysisToViewModel(analysis) {
    const details = [];

    for (const item of analysis.deductions || []) {
      if (item.triggered) {
        details.push(`${item.label} (-${item.deduction})`);
      }
    }

    for (const note of analysis.redirectAnalysis?.notes || []) {
      details.push(note);
    }

    const gsb = findProviderResult(analysis.providerResults, "gsb");
    const urlhaus = findProviderResult(analysis.providerResults, "urlhaus");

    if (!gsb?.configured) {
      details.push("Google Safe Browsing lookup was not configured.");
    }

    if (!urlhaus?.checked) {
      details.push("URLhaus lookup could not be completed.");
    } else if (urlhaus?.details?.authConfigured === false) {
      details.push("URLhaus was checked in public mode without auth token.");
    }

    if (details.length === 0) {
      details.push("No score deductions were triggered by the current heuristic set.");
    }

    return {
      label: analysis.classification || "Unknown",
      safetyScore: analysis.safetyScore,
      state: analysis.state,
      badgeTone: analysis.classification || analysis.state,
      details
    };
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

  function hashString(value) {
    let hash = 2166136261;

    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }

    return Math.abs(hash >>> 0).toString(16);
  }

  function sanitizeClassToken(value) {
    return String(value || "monitored")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-");
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