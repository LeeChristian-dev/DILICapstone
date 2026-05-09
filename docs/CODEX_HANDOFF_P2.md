# DILI Codex Handoff — P2 Scoring and Explanation Improvements

Current state:

- P0 was completed: canonical post ownership, panel slot handling, no-link baseline storage, no-link-to-link reanalysis, stale panel cleanup, duplicate panel prevention.
- P1 was completed enough to proceed: sponsored domain regex is case-insensitive, Facebook redirect wrapper detection is broader than /l.php, carousel card links are not broadly excluded, endpoint confidence now caps score, and endpoint redirect analysis is reused to avoid duplicate probing.
- Do not redo P0/P1 unless a direct regression is found.
- Keep changes conservative.

Important current behavior:

- content.js scans Facebook posts and sends ANALYZE_LINK or REANALYZE_LINK.
- background.js performs endpoint resolution, redirect analysis reuse, GSB and URLhaus checks, scoring, and persistence.
- riskEngine.js calculates safety score from features and category caps.
- utils/endpointResolver.js resolves effective endpoints and carries redirectAnalysis.
- utils/urlAnalyzer.js handles URL parsing, wrappers, and feature detection.
- utils/redirectAnalyzer.js performs redirect-chain analysis.
- config.local.js may exist only as a placeholder. Do not commit real API keys.

Do not:

- Rewrite the whole extension.
- Change Manifest V3 architecture.
- Add a framework or build step.
- Break P0/P1 behavior.
- Expose API keys.
- Make broad DOM selector changes unless absolutely necessary.
- Change popup/export behavior unless needed to display P2 explanation fields.

P2 target:

1. Raise redirect-risk weight/cap.
2. Add explicit linkInsertedAfterBaseline scoring if not already separate enough.
3. Distinguish “Safe” from “Limited Verification.”
4. Show exactly which URL was checked by GSB and URLhaus.
5. Improve URLhaus active/historical interpretation.

Validation required:

- node --check content.js
- node --check background.js
- node --check riskEngine.js
- node --check utils/endpointResolver.js
- node --check utils/redirectAnalyzer.js
- node --check utils/urlAnalyzer.js
- Manual smoke test on Facebook feed.
