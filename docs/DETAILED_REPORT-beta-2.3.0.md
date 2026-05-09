# Detailed branch report — DILI `beta-2.3.0`

**Product:** DILI (Detecting Illegal Link Injections) — Chrome extension, Manifest V3  
**Branch:** `beta-2.3.0`  
**Repository:** [LeeChristian-dev/DILICapstone](https://github.com/LeeChristian-dev/DILICapstone) (branch `beta-2.3.0`)  
**Related docs:** [Release notes](RELEASE_NOTES-beta-2.3.0.md), [Process-flow appendix](PROCESS_FLOW_APPENDIX-beta-2.3.0.md), root [`README.md`](../README.md)

---

## Executive summary

`beta-2.3.0` implements a **Facebook-focused link integrity monitor** as a Manifest V3 extension. The system:

- Continuously scans Facebook feed posts for user-facing outbound links.
- Normalizes and fingerprints the selected link per post (baseline).
- Detects later **link edits/insertions** by comparing against the baseline.
- Performs layered security analysis:
  - Local heuristics (shorteners, wrappers, mismatch indicators, redirect signals).
  - Optional provider checks (Google Safe Browsing and URLhaus).
- Computes a **Safety Score** (0–100) and classification (Safe / Suspicious / High risk).
- Presents results in:
  - Inline post badge UI.
  - Click-time navigation interception with a warning modal.
  - Popup dashboard with provider status, recent activity, and CSV export.

This branch is “demo-ready” for the capstone story: it has a full pipeline from **post discovery → baseline persistence → integrity detection → re-analysis → user decision & logging**.

---

## Goals and threat model (what this branch is designed to catch)

### Primary problem
Facebook posts can contain links that are:

- Edited after initial posting (“link swapped” / illegal injection).
- Wrapped (Facebook redirect wrappers, tracking parameters) to conceal destinations.
- Shortened or obfuscated to reduce user ability to verify the destination.
- Redirecting through multiple domains to increase deception.

### The project’s detection strategy
- Establish a **per-post baseline** of the dominant outbound link and its stable fingerprint.
- Re-scan and compare on feed mutations and user actions.
- Use **multiple weak signals** (heuristics + providers) to decide whether to warn.
- Log and expose structured evidence for analysis (history + CSV export).

---

## System architecture (high level)

### Runtime components
- **Content script (`content.js`)**
  - Runs on `https://*.facebook.com/*`.
  - Finds posts, extracts link candidates, requests analysis from background.
  - Renders badges and owns the warning modal overlay.
  - Intercepts clicks on outbound links to run click-time verification before navigation.

- **Background service worker (`background.js`)**
  - Central “analysis engine coordinator.”
  - Receives link analysis requests, normalizes URLs, computes hashes, runs redirect + feature analysis, optionally queries providers, calculates score/classification, persists baselines and logs, and returns structured results.

- **Popup UI (`popup.html`, `popup.js`, `popup.css`)**
  - Presents session counts, provider health/configuration status, recent records, and actions (CSV export, clear logs, re-scan current tab, enable/disable scanning).

- **Utility modules (`utils/*.js`)**
  - Hashing, storage access, URL and redirect analysis helpers.

### Permissions and scope (`manifest.json`)
- **Host permissions**
  - Facebook pages for scanning.
  - Provider endpoints for external checks (when configured).
- **Extension permissions**
  - `storage` for baselines/logs.
  - `activeTab` + `scripting` for tab-related operations.
  - `webNavigation` for navigation-related behavior in the extension.

---

## Data flow (end-to-end)

### 1) Initialization and scanning
1. User opens Facebook.
2. `content.js` initializes, binds runtime listeners, binds click interception, runs an initial scan, and starts observing feed mutations.
3. Candidate post containers are identified using multiple selectors to tolerate Facebook DOM variation.

### 2) Link selection and baseline establishment
1. For each post, `content.js` extracts candidate outbound links.
2. The content script chooses a “dominant” candidate using a candidate summarization strategy.
3. The selected URL + visible text + candidate context is sent to `background.js`.
4. `background.js` normalizes URL inputs and computes a stable fingerprint (hash).
5. The analysis output is persisted as a post baseline in `chrome.storage`.

### 3) Security analysis and scoring
The background analysis pipeline combines:

- **Redirect analysis**
  - Attempts to resolve wrappers and identify redirect count/patterns.
- **URL feature analysis**
  - Shorteners, wrapper detection, obfuscation indicators, suspicious TLD/path, query complexity, subdomain depth, and mismatch checks between visible text and destination.
- **Threat intelligence providers (optional)**
  - **Google Safe Browsing**: real request flow when API key present.
  - **URLhaus**: public lookup with optional auth.
- **Risk model**
  - Score starts at 100 and deducts weighted points for triggered deductions + combination rules.
  - Classification derived from score bands:
    - 80–100: Safe
    - 50–79: Suspicious
    - 0–49: High risk

### 4) Continuous monitoring and re-analysis
1. `MutationObserver` and scroll-rescan schedule post re-processing when DOM changes.
2. If the post signature changes, the content script requests a **re-analysis**.
3. The background compares compatibility with an existing baseline and computes **integrity mismatch** when a meaningful destination change is detected.
4. The UI badge is updated to reflect integrity state and score changes.

### 5) Click-time verification and user decision
1. `content.js` intercepts clicks (capture-phase) on outbound candidates.
2. Navigation is paused while click-time analysis is resolved:
   - If analysis indicates safe enough: navigation proceeds.
   - If analysis is suspicious/high risk or provider-flagged: warning modal is shown.
3. The warning modal provides:
   - Destination domain, score, classification.
   - Top reasons (provider flags, redirect behavior, mismatch, integrity changes).
   - Clear actions to proceed or stay.

### 6) Logging and export
1. `background.js` appends structured analysis records (bounded + TTL-based).
2. Popup provides CSV export for demo sessions and reporting.

---

## Key behaviors mapped to your process flow

See [Process-flow appendix](PROCESS_FLOW_APPENDIX-beta-2.3.0.md) for the stage-by-stage coverage table and weighted alignment estimate (~87%).

---

## Module-by-module responsibilities

### `content.js` (Facebook page logic)
- **Post discovery**
  - Uses multiple selectors (`role="article"`, `FeedUnit`, etc.) to collect candidates.
  - Filters candidates with visibility and UI-control exclusion heuristics.
- **Link extraction**
  - Collects `a[href]` and related URL attributes, filters to user-facing outbound candidates.
  - Chooses a dominant candidate and stores a selection cache keyed by post ID.
- **Monitoring**
  - `MutationObserver` watches changes that may alter link destinations.
  - Scroll-triggered rescans to handle lazy-loaded feed content.
- **UI**
  - Renders inline badges/panels on posts.
  - Owns a warning overlay modal for click-time decisions.
- **Navigation interception**
  - Prevents default click behavior, resolves analysis, then either navigates or warns.

### `background.js` (analysis coordinator)
- **Message routing**
  - Handles analysis requests and popup requests (summary, records, provider health, toggles).
- **Analysis pipeline**
  - Normalization → hashing → redirects → URL features → provider checks → scoring → classification.
- **Baseline + integrity**
  - Stores baseline per post; on re-analysis determines integrity mismatch state.
- **Persistence**
  - Writes baselines, domain-flag history, scan toggle state, and analysis record log.

### `riskEngine.js` (risk model)
- **Deduction rules**
  - Weighted point deductions for triggered feature flags.
- **Combination rules**
  - Additional deductions for specific feature combinations (e.g., shortener + suspicious redirect).
- **Classification**
  - Converts final score to discrete bands for UI and click-time decisions.

### `utils/storage.js` (persistence layer)
- Provides keying conventions for:
  - per-post baselines
  - per-domain flagged history
  - analysis record log (bounded list + TTL)
  - scan enabled/disabled toggle

### `popup.*` (user-facing dashboard)
- Displays:
  - Supported-tab status (Facebook vs not supported)
  - analyzed/flagged counts
  - provider configuration/health state
  - recent analysis activity
- Actions:
  - export CSV
  - clear session logs
  - re-scan current tab
  - enable/disable scanning

---

## Storage and record schema (conceptual)

### Per-post baseline (stored under a `dili:post:*` key)
Common fields used by the pipeline/UI include:

- `postId`
- `url`, `normalizedUrl`, `domain`
- `urlHash` (stable fingerprint)
- `classification`
- `safetyScore`
- `features` (boolean + numeric feature flags, including integrity mismatch)
- `providerResults` (GSB/URLhaus results when configured)
- `redirectAnalysis` (resolved URL, redirect counts/patterns)
- `state` (e.g., monitored/changed/no_link, depending on pipeline state)

### Analysis records log
Append-only (bounded) records capturing:

- timestamp
- postId
- destination URL/domain/hash
- score + classification
- provider flags/config state
- feature flags (redirect count, shortener, mismatch, integrity mismatch, etc.)

This enables the popup “recent activity” and CSV export.

---

## UX: what a demo looks like (recommended walkthrough)

1. Load unpacked extension in Chrome.
2. Visit Facebook feed; observe badges appearing on posts with outbound links.
3. Click the extension icon to open the popup:
   - verify provider config status
   - show analyzed/flagged counts
   - export CSV after a few detections
4. Demonstrate integrity detection:
   - trigger a link destination change scenario (or simulate by navigating to different posts/links).
5. Demonstrate click interception:
   - click a suspicious link (shortener/wrapper/redirecting) and show warning modal.
   - proceed vs stay behavior.

---

## Security and privacy notes

### What is collected / stored
- Baseline and analysis metadata are stored in `chrome.storage` (post IDs as local identifiers plus URL/domain info).
- Analysis log records are stored for demo/history and can be exported to CSV.

### External requests
- Provider requests are made only when configured and permitted by manifest host permissions.
- Redirect checks are best-effort and subject to network/CORS and provider policy constraints.

### Secrets management
- API keys belong in `config.local.js` and should be gitignored (template should contain placeholders only).

---

## Known limitations and edge cases

- **Facebook DOM volatility**: selectors and heuristics may require tuning over time.
- **MVP link coverage**: analysis emphasizes one dominant/primary outbound link per post in typical flows.
- **Redirect observability**: some redirect chains are not fully observable from extension context.
- **Service worker lifecycle**: popup “session” counters can drift when the background worker restarts; durable records persist where implemented.
- **False positives/negatives**: heuristic weighting mitigates but cannot eliminate misclassifications; provider availability/config strongly affects confidence.

---

## Suggested next steps (if extending beyond capstone)

- Expand from “dominant link per post” to multi-link scoring with per-link badges.
- Add a dedicated “warning page” option (instead of modal-only) for stronger user clarity.
- Add automated tests for URL normalization, redirect analysis, and risk scoring rules.
- Add structured telemetry toggles and privacy controls for demo environments.
- Improve resilience to Facebook UI changes with a selector diagnostics panel in popup.

---

## Revision

| Field | Value |
|-------|--------|
| Document version | 1.0 |
| Branch | `beta-2.3.0` |
| Last updated | 2026-04-26 |

