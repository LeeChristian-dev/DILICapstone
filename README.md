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

## Setup Configuration (GSB + URLhaus)

1. Open `config.example.js` for the key template.
2. `config.local.js` is a committed empty placeholder and must stay empty.
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

DILI requests broad `http://*/*` and `https://*/*` host permissions so the MV3 service worker can resolve shortened URLs that may redirect to any domain. Provider-specific permissions for Google Safe Browsing and URLhaus are kept as explicit entries.

## Safety Score Model

DILI now computes a Safety Score instead of additive risk:

- Start at `100`
- Deduct weighted points for suspicious indicators
- Clamp final score to `0..100`

Classification:

- `80-100`: Safe
- `60-79`: Caution
- `40-59`: Suspicious
- `0-39`: High Risk

## Popup Dashboard

Click the extension toolbar icon to open the popup.

The popup shows:

- **Current tab context** (Facebook vs unsupported / non-scannable URLs)
- **Session stats:** current page candidates, current page analyses, visible panels, total compact analyses in storage
- **Session started** timestamp (when the background session began)
- **Provider chips:** config readiness, Google Safe Browsing, URLhaus compact status
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
- `urlhausConfigured`
- `urlhausFlagged`
- `redirectCount`
- `usedShortener`
- `suspiciousTld`
- `obfuscationDetected`
- `displayedDomainMismatch`
- `integrityMismatch`
- `state`

## Provider Caveats

- Google Safe Browsing requires an API key and is subject to quota and provider policies.
- URLhaus is malware-oriented telemetry, not purely phishing classification.
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
