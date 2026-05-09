# Process-flow coverage appendix — DILI `beta-2.3.0`

**Product:** DILI (Detecting Illegal Link Injections) — Chrome extension, Manifest V3  
**Branch:** `beta-2.3.0`  
**Repository:** [LeeChristian-dev/DILICapstone](https://github.com/LeeChristian-dev/DILICapstone) (branch `beta-2.3.0`)  
**Purpose:** Capstone appendix — map the implemented system to the **DILI process flow** (initialization → scanning → baseline & analysis → continuous monitoring → click-time verification → logging), with **quantitative coverage estimates**.

**Related:** [Release notes — `beta-2.3.0`](RELEASE_NOTES-beta-2.3.0.md), root [`README.md`](../README.md).

---

## How to export this document to PDF

- **Chrome / Edge:** Open this file in a Markdown preview (or paste into a Google Doc / Word after export), then **Print** → **Save as PDF**.
- **VS Code:** Use a Markdown PDF extension if installed, or preview and print to PDF.
- **Pandoc (optional):** `pandoc PROCESS_FLOW_APPENDIX-beta-2.3.0.md -o PROCESS_FLOW_APPENDIX-beta-2.3.0.pdf`

For a **one-page rubric**, print only **Section 3** (tables) or reduce margins in the print dialog.

---

## 1. Executive summary (this branch)

DILI targets **Facebook** (`https://*.facebook.com/*`). The content script discovers posts, extracts outbound link candidates, and coordinates with a **service worker** that normalizes URLs, computes a **SHA-256** fingerprint, stores a **per-post baseline** in `chrome.storage`, runs **heuristic features** and optional **Google Safe Browsing** and **URLhaus** checks, and derives a **Safety Score** (0–100) with classifications **Safe / Suspicious / High risk**. The UI shows **inline badges** on posts, a **popup dashboard** (stats, CSV export, session controls), and **capture-phase click handling** that can **pause navigation** and show a **warning modal** before proceeding.

**Terminology vs. generic flowcharts:** Many diagrams use “Risk Score” and labels like **Dangerous**. This build uses an inverse **Safety Score** and **High risk** for the lowest band — same architectural role (classify link safety), different naming.

---

## 2. Process-flow stage mapping

| Stage | Description (process flow) | Implementation in `beta-2.3.0` | Est. coverage |
|------|------------------------------|--------------------------------|---------------|
| **A** | User opens Facebook; extension initializes; feed/posts scanned | `content.js` init, `initialScan`, post selectors, scroll-based rescan | **~95%** |
| **B** | Post contains hyperlinks → extract URL → hash → store baseline → initial analysis → score → on-post label | `background.js` analysis pipeline, `utils/hash.js`, `utils/storage.js`, `renderBadge`; MVP focuses on **primary / first significant** external link per post | **~82%** |
| **C** | Continuous monitoring → detect edits → compare to baseline → integrity issue → re-analyze → update label | `MutationObserver` in `content.js`, `REANALYZE_LINK`, `integrityHashMismatch` in `riskEngine.js` / `background.js` | **~88%** |
| **D** | User clicks link → click-time verification → block + warning vs. allow navigation | Capture listener, `resolveClickAnalysis`, `shouldShowWarningModal`, `continueNavigation`; warning as **in-page modal**, not a separate extension page | **~85%** |
| **E** | Log incidents / results | `appendAnalysisRecord` / storage log, CSV export from popup | **~90%** |

**Main gaps vs. an idealized flow:** (1) **Not every hyperlink** in a post is independently scored (see README limitation). (2) Click-time UI is a **modal overlay**; blocking logic may also pause on **suspicious** or **score &lt; 80**, not only on a strict “dangerous” tier. (3) Facebook DOM changes can require selector updates over time.

---

## 3. One-page rubric — weighted overall score

Weights reflect emphasis on the core monitoring loop (scan + baseline + integrity + click-time).

| Weight | Process area | Midpoint % | Weighted contribution |
|--------|----------------|------------|------------------------|
| 20% | **A** — Init & scan | 95 | 19.0 |
| 25% | **B** — Baseline, hash, initial analysis, badges | 82 | 20.5 |
| 25% | **C** — Continuous monitoring & integrity | 88 | 22.0 |
| 20% | **D** — Click-time verify & block/allow | 85 | 17.0 |
| 10% | **E** — Logging & export | 90 | 9.0 |
| | **Weighted total** | | **87.5%** |

**Reported overall process-flow alignment:** **~87%** (rounded **85–90%** if treating estimates as a band).

*Interpretation:* Percentages are **engineering judgments** against the capstone process diagram, not formal test coverage. They summarize how completely each stage is realized in code versus an ideal end-to-end flow.

---

## 4. Primary code references

| Concern | Location |
|---------|----------|
| Post scan, observer, click interception | `content.js` |
| Analysis, baseline, integrity, providers | `background.js` |
| Safety score rules | `riskEngine.js` |
| URL / redirect features | `utils/urlAnalyzer.js`, `utils/redirectAnalyzer.js` |
| Hashing | `utils/hash.js` |
| Persistence | `utils/storage.js` |
| Popup & CSV | `popup.js`, `popup.html`, `popup.css` |
| Extension manifest | `manifest.json` |

---

## 5. Revision

| Field | Value |
|-------|--------|
| Document version | 1.0 |
| Branch | `beta-2.3.0` |
| Last updated | 2026-04-18 |
