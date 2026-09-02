---
status: resolved
trigger: "Production main dashboard is healthy after Migration 8, but opening Advanced diagnosis returns Flask's Internal Server Error page."
created: 2026-08-14
updated: 2026-08-14
---

# Debug Session: Advanced page returns 500 in production

## Symptoms

**Expected:** `/advanced` loads the implemented Phase 3 diagnosis workspace with its JavaScript and stylesheet from the production Docker image.

**Actual:** The healthy production web service returns Flask's generic Internal Server Error document for `/advanced`; the main dashboard remains healthy and fresh.

**Errors:** HTTP 500 screenshot. Repository inspection shows `send_file('advanced.html')`, while the Dockerfile copies only `index.html`, `app.js`, and `style.css`; it omits all three advanced assets. The `/advanced.css` route also returns an empty placeholder instead of the implemented stylesheet.

**Timeline:** First production validation after deploying completed Phase 3 and Migration 8.

**Reproduction:** Build the production image from the current Dockerfile, start web, and request `/advanced`.

## Current Focus

hypothesis: confirmed — the production image omitted advanced.html, advanced.js, and advanced.css, so send_file could not load /advanced; the stale /advanced.css placeholder would also suppress the implemented stylesheet.
test: deployment manifest coverage plus route-byte delivery coverage, followed by a production Docker image build and live Gunicorn requests.
expecting: met — all Advanced assets are packaged, and Flask returns the implemented HTML, JavaScript, and CSS.
next_action: resolved; deploy commit 1ab5db7.
reasoning_checkpoint: the main dashboard's fresh data ruled out worker or Migration 8 failures; the failure was confined to the Advanced asset delivery boundary.
tdd_checkpoint: RED confirmed before the fix; GREEN confirmed after the fix.

## Evidence

- timestamp: 2026-08-14; source: production screenshots; observation: main dashboard is fresh and healthy while `/advanced` returns Flask's generic HTTP 500 page; action: isolate the advanced static route and image contents
- timestamp: 2026-08-14; source: dashboard/Dockerfile; observation: the production COPY instruction omits advanced.html, advanced.js, and advanced.css; action: reproduce at the image/package boundary
- timestamp: 2026-08-14; source: dashboard/app.py; observation: `/advanced` and `/advanced.js` use send_file but `/advanced.css` returns an empty placeholder; action: serve the implemented stylesheet from the same immutable image
- timestamp: 2026-08-14; source: existing tests; observation: Flask route tests run against checkout files and browser tests use a local SimpleHTTPRequestHandler, so neither proves production-image inclusion; action: add a container/deployment regression
- timestamp: 2026-08-14; source: RED regression run; observation: the production-image manifest test failed because the Dockerfile copied none of advanced.html, advanced.js, or advanced.css, and the route-byte test failed because GET /advanced.css returned b'' instead of the implemented stylesheet; action: add all three assets to Docker COPY and return advanced.css with send_file
- timestamp: 2026-08-14; source: commit 1ab5db7 fix(advanced): package production assets; observation: Docker COPY now includes the complete Advanced bundle and /advanced.css serves the file body; action: verify the checkout, image contents, and live Gunicorn delivery
- timestamp: 2026-08-14; source: GREEN verification; observation: focused regressions passed, the complete suite passed (245 tests, 269 subtests; one unrelated SystemTimeWarning), built image beacon-advanced-assets-test contained all three non-empty assets, and live Gunicorn returned HTTP 200 for /advanced (7757 bytes) and /advanced.css (6268 bytes); action: resolve session

## Eliminated

- Worker or Migration 8 failure: the main page shows fresh sampling, recent discovery, and no safety warnings.
- Future-phase placeholder: the complete advanced HTML, JS, and CSS assets already exist in the Phase 3 checkout.

## Resolution

root_cause: The production Dockerfile omitted advanced.html, advanced.js, and advanced.css even though Flask routes served them with send_file; this made /advanced raise an internal error in production. Separately, /advanced.css returned an intentionally empty placeholder rather than the implemented stylesheet.
fix: Commit 1ab5db7 adds all three Advanced assets to the production COPY instruction and changes /advanced.css to send_file('advanced.css', mimetype='text/css').
verification: RED — Docker manifest regression and stylesheet-byte route regression both failed before the fix. GREEN — focused regressions passed; complete pytest suite passed (245 tests, 269 subtests; one unrelated SystemTimeWarning); built production image contained all three non-empty assets; live Gunicorn returned 200 non-empty responses for /advanced and /advanced.css.
files_changed: dashboard/Dockerfile; dashboard/app.py; tests/test_module_boundaries.py; tests/test_advanced_diagnosis_api.py; commit 1ab5db7.
