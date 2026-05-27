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

DILI prefers full clickable, embedded, hidden-attribute, and wrapper-unwrapped URLs over visible-domain fallbacks. A visible-domain fallback is used only when Facebook does not expose a usable full or clickable root destination in the same post/card.

Facebook wrappers are shown in Technical Details for auditability, but normal user-facing summaries prefer the visible post URL/text or unwrapped target.

When a post exposes a full endpoint through an anchor href, Facebook `l.php` wrapper target, `data-lynx-uri`, `data-url`, `ajaxify`, visible caption text, or embedded card URL, DILI uses that full endpoint for provider checks. The provider checked URL preserves available path and query parameters, including product IDs, `utm_*`, `fbclid`, campaign IDs, and ad IDs. Tracking parameters may still be stripped separately for comparison normalization, duplicate detection, and cleaner display.

When Facebook only exposes a visible domain for a sponsored card and does not expose the full href/data-url/data-lynx-uri to the extension, DILI labels the scan as a visible-domain fallback. When a full clickable URL is available, DILI prefers that full URL over the visible-domain fallback.

### Full endpoint extraction limitation

DILI attempts three levels of endpoint discovery:

1. Passive full URL extraction from `href`, `data-url`, `data-lynx-uri`, and hidden encoded attributes.
2. Redirect resolution in the background service worker.
3. Click-time reanalysis when Facebook only exposed a root-domain fallback during passive scanning.

Passive visible-domain fallback is not a full endpoint verification. It is a limited root-domain check used only when Facebook does not expose a usable full URL during passive scanning. It can still receive a normal Safety Score classification based on the exposed domain and configured checks, but Technical Details must clearly state that only the visible domain was checked. DILI re-checks the actual clicked destination when click-time data exposes a fuller URL.

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

- `80-100`: **Safe** — no major warning signs detected
- `50-79`: **Suspicious** — warning signs detected; navigation pause/interception recommended
- `0-49`: **High Risk** — strong warning signs or provider flag; navigation pause/interception recommended
- `Unverified`: DILI could not fully verify the destination

**Evidence-weighted scoring:** DILI treats provider-confirmed detections as primary evidence and local heuristics as supporting evidence. Google Safe Browsing and URLhaus flags can immediately produce a High Risk result without waiting for VirusTotal. VirusTotal is treated as a multi-engine corroboration provider: strong malicious consensus can force High Risk, while single weak detections are warning/caution evidence rather than automatic maliciousness.

Heuristic deductions are category-capped. Post-baseline and link-change events are post-integrity warnings, not direct proof of phishing or malware. Provider errors, limits, pending checks, and unavailable checks do not directly deduct score points.

When configured providers complete clean and the endpoint resolves to a high-confidence HTTPS final destination, DILI may recover explainable Facebook wrapper, tracking, shortener, branded alias, or campaign-redirect penalties to a minimum score of 80. This recovery is a floor, not a raw bonus. Clean provider results never override provider flags, strong VirusTotal consensus, suspicious TLDs, credential tricks, obfuscation, unresolved shorteners, low-confidence endpoints, true unrelated visible-domain mismatches, or verified link changes combined with suspicious/unrelated redirects. Based on the documented use cases of the configured providers, this keeps provider-confirmed threats primary while reducing false positives from normal marketing links.

DILI does not display a final Safety Score while a configured or active provider check is still pending. In that state, the inline panel shows a pending scan result with provider status details instead of Safe, Suspicious, High Risk, or a numeric score. The computed score is retained internally for audit/debug, but it is withheld from the UI until provider verification reaches a terminal state.

Pending VirusTotal checks use controlled delayed follow-ups to update the same in-page panel when the provider result completes. DILI does not use continuous interval polling. Terminal limited provider states such as rate-limited, timeout, not-configured, skipped, and error do not block forever; DILI reports them as verification limitations and then allows the scan display to finalize.

Pending-provider panels use a dedicated caution theme and show a visible countdown for the next scheduled provider follow-up. VirusTotal pending follow-ups use a fixed delayed retry budget; if VirusTotal does not return a terminal result within that retry window, DILI finalizes the panel using available provider results and records VirusTotal as a provider limitation.

Pending scans show no numeric score in the panel or popup. If provider exhaustion or timeout prevents verification from finishing, DILI finalizes the result as Verification Incomplete / Unverified instead of leaving it in Scan Pending forever.

Completed, unchanged post scans are reused during the same browsing session. If the stable post ID, post signature, link fingerprint, visible text hash, and terminal provider state are unchanged, DILI restores the existing panel instead of sending another analysis request. Manual rescans and actual link/text changes still bypass this reuse.

For multi-link posts, hidden computed scores from pending child links are retained only as internal audit data. They do not drive the visible post-level classification. The post remains **Scan Pending** until every participating provider check for every analyzed link reaches a terminal state, unless a completed provider check already flags one link. Pending VirusTotal refreshes target the actual pending child link rather than a completed sibling or the parent summary.

DILI uses score bands for display and navigation decisions. Suspicious results, High Risk results, provider-flagged results, and final scores below 80 trigger a navigation pause before opening the destination.

### Local domain memory

DILI only stores a local flagged-domain memory when an external provider, such as Google Safe Browsing, URLhaus, or optional VirusTotal, flags the destination. Heuristic-only High Risk results do not permanently flag a domain.

Clearing session logs also clears local flagged-domain records so test runs are not contaminated by earlier false positives.

### Shortened marketing links

Shortened links are treated as caution signals, not automatic malicious signals. A shortened link is escalated more strongly only when combined with stronger warning signs such as provider flags, suspicious paths, suspicious TLDs, visible-domain mismatch, post-integrity changes, or very long redirect chains.

Single weak indicators, such as an ordinary shortener, are treated mildly to reduce false positives. Combined indicators, such as a shortener plus cross-domain redirect, mismatch, obfuscation, or link-injection evidence, receive stronger deductions.

Visible-domain fallback is not treated as proof of danger by itself. It is a limited verification mode used when Facebook does not expose the full endpoint during passive scanning.

DILI unwraps Facebook outbound wrappers before resolving common shorteners when the destination is available. Provider checks prefer the resolved final endpoint. If the shortener cannot be resolved with enough confidence, DILI reports that limitation instead of claiming the shortener service itself is the final website.

Clean provider results with a high-confidence resolved HTTPS endpoint can mitigate false positives from normal marketing mechanics such as Facebook wrappers, UTM/fbclid tracking parameters, branded shortlinks, and campaign redirects. Configured branded alias relationships, such as a known short brand domain resolving to its official destination, reduce mismatch penalties but never suppress provider flags or clearly malicious URL features.

Post-integrity deductions are limited to verified, stable post baselines. When post identity is unstable, collapsed, provisional, too recent, or endpoint-equivalent after normalization, DILI still scans the URL but skips post-baseline integrity scoring.

Advanced audit output separates active deductions, mitigations, provider overrides, and incomplete category-level audit details so a scan does not claim that no warning signs were triggered when a category deduction was actually applied.

### Redirect trace visibility

DILI separates redirect evidence into two views:

- **Full observed redirect trace** — every redirect stage DILI could observe through wrapper parameters and allowed network probing.
- **Risk-relevant redirect chain** — the simplified chain used for scoring and user-facing risk explanation.

Some redirects may still be invisible when a service uses JavaScript redirects, meta refresh, anti-bot behavior, or browser-only navigation. In those cases, DILI reports the endpoint it could verify and the observed trace it could collect.

### Interception Policy

DILI only pauses navigation by default when:

- a provider flags the URL,
- classification is Suspicious or High Risk,
- or the final score is below `80`.

## Popup Dashboard

Click the extension toolbar icon to open the popup.

The popup shows:

- **Current tab context** (Facebook vs unsupported / non-scannable URLs)
- **Session stats:** current page candidates, current page analyses, visible panels, total compact analyses in storage
- **Session started** timestamp (when the background session began)
- **Provider chips:** config readiness, Google Safe Browsing, URLhaus, and optional VirusTotal compact status
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
- `vtStatus`
- `vtConfigured`
- `vtFlagged`
- `vtCheckedUrl`
- `vtCheckedAt`
- `vtResultSummary`
- `vtMaliciousCount`
- `vtSuspiciousCount`
- `vtAnalysisId`
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

DILI records compact verification evidence for Google Safe Browsing, URLhaus, and optional VirusTotal:

- checked URL
- provider outcome
- scan timestamp
- provider response duration

This evidence is shown in Technical Details and included in CSV/report exports to improve auditability, demonstrate that provider scans ran, and support cybersecurity awareness and transparency during evaluation.

Provider operational telemetry, such as timeout, error, pending, and rate-limit states, is informational only. It does not directly affect Safety Score deductions, classification thresholds, or warning/interception decisions.

## Provider Result Cache

DILI caches Google Safe Browsing, URLhaus, and optional VirusTotal results per checked endpoint for a short time during a session. This reduces duplicate provider calls, improves panel speed, and lowers quota pressure when multiple posts resolve to the same URL.

Facebook can lazy-load or mutate posts after they first appear, so DILI performs short delayed rescans to catch newly exposed destinations. Once an unchanged post already has a completed panel, DILI protects that panel from unnecessary visible re-rendering to avoid repeated "Analyzing" flicker.

Cached provider results preserve their original `checkedAt` timestamp and do not change Safety Score rules. The provider cache is cleared when session logs are cleared, the session is restarted, or provider keys change.

DILI stores a no-link baseline for posts where no external destination is detected. DILI treats post-publication link insertion conservatively: a newly observed link is only treated as link injection when it appears after a mature, confirmed no-link baseline for the same stable post. Provisional baselines caused by collapsed captions, unstable post identity, or Facebook lazy-loading are not enough by themselves to trigger post-integrity scoring. Text-only edits without a new external link are not penalized.

For existing-link edits, DILI compares the current link target against the stored baseline for the same observed post. When Facebook does not expose a stable post identifier, DILI uses a session fallback identity that intentionally avoids mutable URL/domain/CTA text so post-publication link replacement can still be detected during the same session.

DILI may apply conservative false-positive mitigation for explicitly mapped branded campaign redirectors when providers are clean and the final destination matches the expected brand family. Current examples include `cnn.it` to `cnn.com`/`edition.cnn.com`, known `hoyo.link` campaign redirects to approved HoYoverse/Twitch/YouTube destinations, DITO internal redirects, and same-domain Coca-Cola campaign redirects. This does not apply to unknown shorteners or provider-flagged links.

Sensitive article-topic words in legitimate news URLs, such as crime, abuse, assault, investigation, violence, or porn, are not treated as phishing terms by themselves. DILI only treats those topic words as suspicious when they appear together with phishing or scam intent such as login, verify, claim, reward, wallet, password, payment, account, free, or urgent.

DILI also applies a narrow trusted redirect destination mitigation for clean redirects to selected productivity and content platforms such as `docs.google.com`, `forms.google.com`, `drive.google.com`, `youtube.com`, `twitch.tv`, `discord.com`, `github.com`, `notion.so`, and `canva.com`. Known campaign or tracking redirects to those destinations are treated as expected redirect behavior when providers are clean. Unknown shorteners to those destinations remain Suspicious rather than Safe. Unknown redirects to unknown destinations, provider-flagged URLs, and phishing-pattern destinations remain strict.

## Provider Caveats

- Google Safe Browsing requires an API key and is subject to quota and provider policies.
- Google Safe Browsing remains DILI's primary phishing and social-engineering threat provider.
- Google Safe Browsing and URLhaus requests use short timeouts so provider delays do not block the rest of the analysis.
- URLhaus is malware-oriented telemetry, not a complete phishing verdict.
- URLhaus may run in authenticated or public mode. If authenticated mode fails, DILI attempts a public lookup fallback.
- URLhaus lookup failures do not automatically reduce the Safety Score.
- VirusTotal is an optional enrichment provider. It is disabled by default, quota-sensitive, cached/rate-limited, and does not reduce Safety Score when unavailable, pending, or rate-limited. Strong VirusTotal malicious consensus can escalate a URL to High Risk; weak one-off detections are treated as warning/caution evidence.
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
- DILI analyzes up to eight meaningful external links per post. For safety, the post-level result follows the lowest-scoring successful link rather than an average, so one risky link cannot be hidden by several safe links. When multiple links are analyzed, the panel shows how many links were found and which link determined the post result.
- Redirect analysis remains best-effort and cannot guarantee complete redirect-chain visibility in all cases.
- Known owner shortlinks such as `youtu.be` -> `youtube.com` are treated as lower-risk when providers are clean and the resolved endpoint matches the expected owner domain, but they are not exempt from provider flags or stronger warning signs.
- Technical Details are grouped into readable sections. Long provider, wrapper, and redirect URLs wrap inside the panel instead of forcing horizontal overflow. Provider checked URLs and final endpoint evidence remain visible, while optimization/debug telemetry is kept out of the normal user-facing panel and advanced audit data is kept in an expanded subsection to reduce clutter.
- DILI checks URL structure, redirect behavior, and provider reputation. It does not verify the legitimacy of claims inside external messaging groups, community channels, or pages that require joining or logging in, such as Telegram or Discord invites.
- Messaging/community invite links may receive a normal Safe classification when provider checks are clean, but DILI may softly cap perfect scores because it cannot verify group/channel content, future messages, members, or claims inside the platform. This soft cap is not a provider flag and does not mean the URL is malicious. If a provider flags the URL or the result is High Risk, DILI uses High Risk wording and does not show safe/open-normal guidance.
- DILI pauses navigation for Suspicious or High Risk links. Clicking Proceed anyway opens a second confirmation dialog before the destination is opened. DILI does not automatically report posts to Facebook; it provides instructions for using Facebook's built-in report menu and choosing the closest available report reason.
- Facebook's report flow varies between normal posts and ads. Users may see options such as Report post, Find support or report post, Report ad, Scam/Fraud/Impersonation, Spam, False information, or related subcategories; choose the closest available reason shown by Facebook.
- Plain email addresses are not treated as destination links unless Facebook exposes them as actual clickable links.
- Known Google Forms redirects, including generic shorteners that resolve to `docs.google.com/forms`, may be reduced from High Risk when providers are clean, but users should still verify the form owner before submitting information.
- Service worker lifecycle affects session counters in popup; historical logs remain in storage.

## Manual Follow-Up Required

- Add real PNG icon files:
- `icons/icon16.png`
- `icons/icon48.png`
- `icons/icon128.png`
- Configure real provider credentials in `chrome.storage.local`, not in committed files.

## Optional VirusTotal Enrichment

VirusTotal is off unless an API key is configured. It supplements Google Safe Browsing and URLhaus; it does not replace them. It is quota-sensitive and rate-limited, so it may initially show as pending. DILI first checks for an existing VirusTotal URL report when possible. If no report exists, DILI may submit the URL for analysis. DILI stores the returned VirusTotal analysis ID in memory and may follow up on later rescans instead of repeatedly submitting the same URL.

When VirusTotal initially returns pending, DILI may perform a small number of delayed follow-up checks and update the visible panel if the result completes. This follow-up is quota-safe and does not reduce Safety Score while pending, rate-limited, timed out, or failed.

Clearing session logs does not necessarily clear pending VirusTotal analysis IDs unless provider configuration changes or the session is fully reset. Pending, timeout, error, and rate-limited VirusTotal states do not reduce Safety Score. Strong VirusTotal malicious consensus can escalate a URL to High Risk. Do not use demo score bias during real provider accuracy testing.

Enable VirusTotal:

```js
chrome.storage.local.set({
  "dili:config:virustotalApiKey": "YOUR_VIRUSTOTAL_API_KEY",
});
```

Disable VirusTotal:

```js
chrome.storage.local.remove(["dili:config:virustotalApiKey"]);
```

## Debug/Test Mode

Temporary demo score bias is disabled by default and should only be used for warning-modal testing. Adjusted results are labeled as DEMO MODE and keep the original score visible.

Enable demo score bias:

```js
chrome.storage.local.set({
  "dili:debug:scoreBiasEnabled": true,
  "dili:debug:scoreBiasAmount": 60,
});
```

Disable demo score bias:

```js
chrome.storage.local.set({
  "dili:debug:scoreBiasEnabled": false,
});
```

Clear debug settings:

```js
chrome.storage.local.remove([
  "dili:debug:scoreBiasEnabled",
  "dili:debug:scoreBiasAmount",
]);
```
