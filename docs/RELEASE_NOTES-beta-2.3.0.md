# Release notes — DILI `beta-2.3.0`

**Product:** DILI (Detecting Illegal Link Injections) — Chrome extension, Manifest V3  
**Branch:** `beta-2.3.0`  
**Purpose:** Capstone appendix — features, changes since initial drop, and how to run the build.

---

## Executive summary

DILI monitors **Facebook** posts for suspicious or altered outbound links. It fingerprints URLs, stores per-post baselines, analyzes redirects and URL structure, optionally queries **Google Safe Browsing** and **URLhaus**, computes a **Safety Score** (0–100), and shows **inline feedback** plus a **toolbar popup dashboard** (stats, provider status, CSV export, session controls, protection on/off).

---

## Feature set (this branch)

| Area | Description |
|------|-------------|
| **On-page monitoring** | Content script on `https://*.facebook.com/*` observes posts and coordinates with the background service worker. |
| **Baseline and integrity** | Per-post URL hashing and storage so **link edits and insertions** can be detected against an earlier baseline. |
| **Heuristic analysis** | Shorteners, wrappers, visible-text vs destination mismatch, suspicious TLD/path patterns, query complexity, redirect-chain signals, and related combinations (see `riskEngine.js`). |
| **External intelligence** | Optional **Google Safe Browsing** and **URLhaus** lookups when API configuration is present (`manifest.json` host permissions). |
| **Safety score** | Score starts at 100; weighted deductions and combination rules; classification bands: Safe (80–100), Suspicious (50–79), High risk (0–49). |
| **Trusted endpoints** | Mitigation logic for known trusted destination patterns when strong contradictory signals are absent (`utils/urlAnalyzer.js`, `riskEngine.js`, `background.js`). |
| **Popup dashboard** | Session statistics, provider health-style status, recent activity, settings menu (**Export CSV**, **Restart session**, **Clear session logs**, **How it works**). |
| **Protection toggle** | User can enable or disable scanning; state is **persisted** (`utils/storage.js`, background messages). |
| **Re-scan** | User-triggered re-analysis of the current tab / links via background message handlers. |
| **Persistence** | `chrome.storage` for baselines, analysis history, scan state, and related session data. |

---

## Changes since initial extension drop (`v1.1` baseline)

1. **Redirect and URL pipeline** — Stronger redirect-chain handling, URL normalization, expanded URL feature detection, and alignment with the risk engine. Large updates to `utils/redirectAnalyzer.js`, `utils/urlAnalyzer.js`, `content.js`, and `background.js`.
2. **Popup and UX** — Dashboard-style layout, settings menu, power toggle with clear on/off feedback, improved statistics and messaging. Updates to `popup.html`, `popup.js`, `popup.css`.
3. **Platform** — `webNavigation` permission added where needed for navigation-related behavior (see commit history on `beta-2.3.0`).
4. **Risk model** — Additional rules and **trusted-endpoint mitigation** to reduce false positives for well-known safe destinations.
5. **Configuration** — Project expects local secrets in **`config.local.js`** (gitignored). Use a template with **placeholder** keys only; do not commit real API keys.

---

## Operational setup

1. **Chrome:** open `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the **repository root** (the folder that contains `manifest.json`).
2. **Edge:** `edge://extensions` → **Developer mode** → **Load unpacked** → same folder.
3. Open **Facebook** in a tab so the content script can run.
4. Click the **DILI** toolbar icon to open the popup dashboard.

**Optional:** Copy the project’s key template to `config.local.js` and set `GSB_API_KEY` and URLhaus-related values as described in the main `README.md`. If keys are missing, the extension still loads; providers report as not fully configured and local heuristics continue.

---

## Security and configuration hygiene

- Keep **all secrets** in `config.local.js` only; verify `config.local.js` is listed in `.gitignore`.
- If any API-like strings were ever committed to the repository, **rotate those keys** in the provider consoles and replace them locally.
- Prefer a single clearly named template file (for example `config.example.js`) containing **only placeholders**, for team onboarding.

---

## Known limitations

- Facebook’s DOM changes frequently; selectors in `content.js` may need periodic updates.
- The MVP may emphasize the **first significant external link** per post in some paths.
- Full redirect chains cannot always be observed from the extension context; analysis is **best-effort**.
- Service worker lifecycle can affect **session counters** in the popup; durable history remains in storage where implemented.

---

## Repository reference

- **Remote:** `https://github.com/LeeChristian-dev/DILICapstone.git`  
- **Branch:** `beta-2.3.0` (tracks `origin/beta-2.3.0` when configured)

For file-level structure and CSV column details, see the main **`README.md`** in the repository root.
