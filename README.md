# DILI - Detecting Illegal Link Injections

DILI is a Manifest V3 Chrome extension for Facebook link monitoring. It fingerprints detected URLs, stores per-post baselines, detects post-link changes after edits, runs local and external checks, computes a Safety Score, and displays compact inline classifications.

## Stable Update Focus

This revision keeps the existing architecture and working integrations while improving startup speed, scan consistency, and end-user clarity.

## Staged Analysis Pipeline

DILI now uses a staged pipeline for faster first feedback:

1. Stage 1 (Immediate detection)

- Detect Facebook post containers
- Extract first significant external link safely
- Skip invalid/internal/non-HTTP(S) links

2. Stage 2 (Fast local analysis)

- Normalize URL
- Generate URL hash baseline
- Detect URL shorteners
- Detect suspicious TLD and obfuscation indicators
- Apply local safety scoring
- Return quick preliminary state

3. Stage 3 (Deferred external checks)

- Google Safe Browsing
- URLhaus
- Optional redirect probing (best effort)
- UI updates asynchronously when final checks complete

## Startup and Scan Performance

Performance behavior is optimized for feed responsiveness:

- Visible-post prioritization (IntersectionObserver + near-viewport queue)
- Deferred queue for offscreen posts
- Debounced MutationObserver processing
- Batched post processing instead of full-feed rescans
- Duplicate-work avoidance with signature checks
- Session TTL caching for finalized URL analysis

## User-Facing State Model

Internal states:

- no_link
- scanning
- safe
- suspicious
- high_risk
- analysis_partial
- analysis_failed

Behavior:

- no_link: hidden by default (unless debug mode is enabled)
- safe: subtle compact UI
- suspicious/high_risk: visible compact warning card with action row
- analysis_partial: gentle message that some checks were limited
- analysis_failed: rare, soft failure wording

Raw technical errors are kept in console logs only.

## Inline UI and Actions

For suspicious/high-risk posts:

- left accent border
- compact badge format (for example: Suspicious • 61)
- one short explanation line
- action row:
  - Report Post
  - Details

Tooltip/details now focus only on why the link was flagged (human-readable reasons).

## Middleman Warning Popup

Click interception applies only to suspicious/high-risk links.

- Safe links navigate normally.
- Suspicious/high-risk links show a warning modal before navigation.
- High-risk links show stronger visual urgency.

Warning modal includes:

- destination domain
- Safety Score
- short warning text
- 1-3 human-readable reasons
- actions: Go Back, Proceed Anyway, Report Post

## Reporting UX

Report Post opens a dedicated guidance modal:

- how to report suspicious posts on Facebook
- Copy Evidence button using navigator.clipboard.writeText()
- short copied summary:
  - score
  - classification
  - URL
  - reasons
  - timestamp

## Provider and Config Behavior

Background service worker remains the source of truth for provider status.

- GSB uses GSB_API_KEY when available
- URLhaus supports optional credentials
- Missing config.local.js or missing keys degrades gracefully
- External provider and redirect checks are best effort

Optional URLhaus keys supported in config.local.js:

- URLHAUS_AUTH_KEY
- URLHAUS_AUTH_TOKEN
- URLHAUS_API_KEY

## CSV Export and Popup

Popup remains available and keeps:

- status summary
- recent activity
- re-scan action
- CSV export
- log clearing

CSV export format is preserved for existing reporting flow.

## Loading the Extension

1. Open chrome://extensions
2. Enable Developer mode
3. Click Load unpacked
4. Select this project folder
5. Open Facebook to start monitoring

## Known Limitations

- Facebook DOM structure changes frequently; selectors in content.js may still require manual tuning.
- Redirect analysis is environment-limited in browsers and may be partial.
- DILI currently evaluates the first significant external link per post.

## Configuration Template

Use config.example.js as a template for config.local.js and keep local secrets out of version control.
