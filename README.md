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

## Setup Configuration (GSB + PhishTank + URLhaus)

1. Open `config.example.js` for the key template.
2. Copy `config.example.js` to `config.local.js` and add your own values.
3. For local development, save provider keys through `chrome.storage.local` using these keys:

- `dili:config:gsbApiKey`
- `dili:config:phishtankAppKey`
- `dili:config:urlhausAuthKey`
- `dili:config:urlhausApiKey`

Notes:

- Never commit real provider credentials.
- If no key is configured, extension fallback behavior is safe:
- GSB returns `configured: false`, `checked: false`, `flagged: false`
- PhishTank can still attempt a public lookup when enabled, but an app key improves rate limits.
- URLhaus still attempts public-mode lookup when available

## Host Permissions

DILI requests broad `http://*/*` and `https://*/*` host permissions so the MV3 service worker can resolve shortened URLs that may redirect to any domain. Google Safe Browsing and URLhaus still appear as explicit provider entries, and PhishTank is covered by the broad HTTPS/HTTP permissions.

## Safety Score Model

DILI now computes a Safety Score instead of additive risk:

- Start at `100`
- Deduct weighted points for suspicious indicators
- Clamp final score to `0..100`

Classification:

- `90-100`: Safe - no major warning signs
- `75-89`: Low Caution - minor uncertainty, no hard navigation pause by default
- `60-74`: Caution - review the destination, no hard navigation pause by default unless combined with strong risk signs
- `40-59`: Suspicious - navigation pause/interception recommended
- `0-39`: High Risk - strong warning/interception recommended
- `Unverified`: DILI could not fully verify the destination; this is separate from suspicious unless other risk signs are present
- Provider-flagged URLs from Google Safe Browsing, PhishTank, or URLhaus should become High Risk.
- Provider errors and rate limits do not deduct score by themselves.

### Local domain memory

DILI only stores a local flagged-domain memory when an external provider, such as Google Safe Browsing, PhishTank, or URLhaus, flags the destination. Heuristic-only High Risk results do not permanently flag a domain.

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
- **Provider chips:** config readiness, Google Safe Browsing, PhishTank, and URLhaus compact status
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
- `gsbConfigured`
- `gsbFlagged`
- `phishtankConfigured`
- `phishtankFlagged`
- `urlhausConfigured`
- `urlhausFlagged`
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

## Provider Caveats

- Google Safe Browsing requires an API key and is subject to quota and provider policies.
- PhishTank is phishing-specific and works best with an app key; the app key is optional but improves rate limits.
- PhishTank requires a descriptive User-Agent, but direct Chrome extension fetch calls may not reliably set a custom User-Agent header. If lookups are rate-limited or blocked, a backend proxy or local database approach may be needed.
- URLhaus is malware-oriented telemetry, not purely phishing classification.
- URLhaus remains a malware-oriented supplement and may be skipped when Google Safe Browsing and PhishTank complete cleanly, depending on lookup policy.
- External lookups can fail due to network, CORS, quota, or endpoint changes. DILI logs failures and continues with local heuristics.

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
