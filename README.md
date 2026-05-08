# DILI - Detecting Illegal Link Injections

DILI is a Manifest V3 Chrome extension for Facebook link monitoring. It fingerprints URLs, stores per-post baselines, detects link edits and insertions, runs external threat-intelligence checks, computes a Safety Score, and renders inline post badges.

## Release documentation

- **Branch `beta-2.3.0`:** [Release notes and capstone appendix](docs/RELEASE_NOTES-beta-2.3.0.md) — feature list, changelog-style summary, setup, limitations, and security notes.
- **Process-flow coverage (capstone):** [Process-flow appendix & rubric](docs/PROCESS_FLOW_APPENDIX-beta-2.3.0.md) — stage-by-stage mapping to the DILI flow diagram, weighted **~87%** alignment, PDF export notes.
- **Detailed branch report:** [Detailed report — `beta-2.3.0`](docs/DETAILED_REPORT-beta-2.3.0.md) — architecture, data flow, modules, persistence, UX, limitations, and next steps.

## What Is New In This Revision

- Google Safe Browsing integration (real request flow when key is configured)
- URLhaus integration (public lookup endpoint with optional auth token support)
- Popup dashboard (`popup.html`, `popup.js`, `popup.css`)
- CSV export for analysis log records
- Compact storage-backed analysis history for demo sessions
- Multi-link Facebook post analysis with one DILI panel per owning post
- Endpoint resolution for Facebook wrappers, shorteners, and final redirect destinations

### Endpoint stages

DILI displays endpoint stages as:

- Visible post URL/text — the visible URL or link text shown in the Facebook post.
- Facebook click wrapper URL — the full `l.facebook.com` wrapper when Facebook exposes one.
- Unwrapped URL — the URL obtained after removing known wrappers when possible.
- Full endpoint URL — the final destination DILI uses for provider checks and Safety Score analysis.

This clarifies that shortened links are resolved to their final endpoint before provider checks whenever resolution succeeds.

DILI prefers full clickable or embedded URLs over visible-domain fallbacks. A visible-domain fallback is used only when Facebook does not expose a usable full destination in the same post/card.

Facebook wrappers are shown in Technical Details for auditability, but normal user-facing summaries prefer the visible post URL/text or unwrapped target.

When Facebook only exposes a visible domain for a sponsored card and does not expose the full href/data-url/data-lynx-uri to the extension, DILI labels the scan as a visible-domain fallback. When a full clickable URL is available, DILI prefers that full URL over the visible-domain fallback.

### Full endpoint extraction limitation

DILI attempts three levels of endpoint discovery:

1. Passive full URL extraction from `href`, `data-url`, `data-lynx-uri`, and hidden encoded attributes.
2. Redirect resolution in the background service worker.
3. Click-time reanalysis when Facebook only exposed a root-domain fallback during passive scanning.

Passive visible-domain fallback is a limited check. It can still receive a normal Safety Score classification based on the exposed domain and configured checks, but Technical Details must clearly state that only the visible domain was checked. DILI re-checks the actual clicked destination when click-time data exposes a fuller URL.

## File Structure

```text
manifest.json
content.js
background.js
riskEngine.js
styles.css
popup.html
popup.js
popup.css
config.example.js
config.local.js
.gitignore
README.md
utils/
  hash.js
  redirectAnalyzer.js
  storage.js
  urlAnalyzer.js
icons/
storage/
```

## Setup Configuration (GSB + URLhaus)

**Active Providers:** Google Safe Browsing (GSB) and URLhaus.

1. Open `config.example.js` for the key template.
2. Copy `config.example.js` to `config.local.js` and add your own values.
3. For local development, save provider keys through `chrome.storage.local` using these keys:

- `dili:config:gsbApiKey`
- `dili:config:urlhausAuthKey`
- `dili:config:urlhausApiKey`

Notes:

- Never commit real provider credentials.
- If no key is configured, extension fallback behavior is safe:
- GSB returns `configured: false`, `checked: false`, `flagged: false`
- URLhaus still attempts public-mode lookup when available

## Host Permissions

DILI requests broad `http://*/*` and `https://*/*` host permissions so the MV3 service worker can resolve shortened URLs that may redirect to any domain. Google Safe Browsing and URLhaus are covered by these host permissions for API requests.

## Safety Score Model

DILI computes a **Safety Score** using a subtractive model:

- **Starting point:** 100 (neutral/safe baseline)
- **Deduction:** Points are deducted for suspicious indicators
- **Final range:** `0..100` (clamped)
- **Interpretation:**
  - **Higher score = Safer** (e.g., 95 is safer than 50)
  - **Lower score = More concerning** (e.g., 20 indicates more risk signs)

### Safety Score Classifications

- `90-100`: **Safe** — no major warning signs detected
- `75-89`: **Low Caution** — minor uncertainty; DILI does not pause navigation by default
- `60-74`: **Caution** — review the destination; no hard pause unless combined with strong risk signs
- `40-59`: **Suspicious** — navigation pause/interception recommended
- `0-39`: **High Risk** — strong warning/interception recommended
- `Unverified`: DILI could not fully verify the destination; this is independent of suspicious unless other risk signs are also present

**Provider-flagged results:** URLs flagged by Google Safe Browsing or URLhaus are classified as High Risk. Provider errors and rate limits do not directly deduct score points.

### Local domain memory

DILI only stores a local flagged-domain memory when an external provider, such as Google Safe Browsing or URLhaus, flags the destination. Heuristic-only High Risk results do not permanently flag a domain.

Clearing session logs also clears local flagged-domain records so test runs are not contaminated by earlier false positives.

### Shortened marketing links

Shortened links are treated as caution signals, not automatic malicious signals. A shortened link is escalated more strongly only when combined with stronger warning signs such as provider flags, suspicious paths, suspicious TLDs, visible-domain mismatch, post-integrity changes, or very long redirect chains.

### Interception Policy

DILI only pauses navigation by default when:

- a provider flags the URL,
- classification is Suspicious or High Risk,
- score is below `60`,
- a post-integrity change is combined with a score below `75`,
- or an unverified destination also has other risk indicators.

## Popup Dashboard

Click the extension toolbar icon to open the popup.

The popup shows:

- **Current tab context** (Facebook vs unsupported / non-scannable URLs)
- **Session stats:** current page candidates, current page analyses, visible panels, total compact analyses in storage
- **Session started** timestamp (when the background session began)
- **Provider chips:** config readiness, Google Safe Browsing, and URLhaus compact status
- **Recent activity** list (latest stored analyses)
- Action buttons:
- Export CSV
- Clear Session Logs
- Re-scan Current Tab

The popup reads available stored or session data only; it does not force full page analysis unless you click re-scan.

## CSV Export

Export runs from the popup and downloads a file named like:

`dili-analysis-export-YYYY-MM-DD-HH-mm-ss.csv`

Each row includes:

- `timestamp`
- `postId`
- `url`
- `domain`
- `urlHash`
- `safetyScore`
- `classification`
- `gsbStatus`
- `urlhausStatus`
- `gsbConfigured`
- `gsbFlagged`
- `gsbCheckedUrl`
- `gsbCheckedAt`
- `gsbDurationMs`
- `gsbResultSummary`
- `urlhausConfigured` (URLhaus auth-key configured; public mode can still run when this is false)
- `urlhausFlagged`
- `urlhausCheckedUrl`
- `urlhausCheckedAt`
- `urlhausDurationMs`
- `urlhausResultSummary`
- `redirectCount`
- `usedShortener`
- `suspiciousTld`
- `obfuscationDetected`
- `displayedDomainMismatch`
- `integrityMismatch`
- `state`
- `verificationState`
- `interceptionRecommended`
- `manualVerdict`
- `expectedClassification`
- `isCorrect`
- `accuracyNotes`

## Provider Verification Evidence

DILI records compact verification evidence for Google Safe Browsing and URLhaus:

- checked URL
- provider outcome
- scan timestamp
- provider response duration

This evidence is shown in Technical Details and included in CSV/report exports to improve auditability, demonstrate that provider scans ran, and support cybersecurity awareness and transparency during evaluation.

Provider telemetry is informational only. It does not directly affect Safety Score deductions, classification thresholds, or warning/interception decisions.

## Provider Caveats

- Google Safe Browsing requires an API key and is subject to quota and provider policies.
- Google Safe Browsing remains DILI's primary phishing and social-engineering threat provider.
- URLhaus is malware-oriented telemetry, not a complete phishing verdict.
- URLhaus may run in authenticated or public mode. If authenticated mode fails, DILI attempts a public lookup fallback.
- URLhaus lookup failures do not automatically reduce the Safety Score.
- External lookups can fail due to network, CORS, quota, authentication, or endpoint changes. DILI logs failures and continues with local heuristics.
- PhishTank was deprecated from active checks because its API behavior is unreliable for direct browser-extension use.

## Loading Unpacked Extension

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click Load unpacked
4. Select this folder
5. Open Facebook to trigger content scanning

## Current Limitations

- Facebook DOM changes frequently. Selectors in `content.js` may require periodic tuning.
- DILI analyzes up to eight meaningful external hyperlinks per post and uses the lowest-scoring successful link as the post result.
- Redirect analysis remains best-effort and cannot guarantee complete redirect-chain visibility in all cases.
- Service worker lifecycle affects session counters in popup; historical logs remain in storage.

## Manual Follow-Up Required

- Add real PNG icon files:
- `icons/icon16.png`
- `icons/icon48.png`
- `icons/icon128.png`
- Configure real provider credentials in `chrome.storage.local`, not in committed files.
