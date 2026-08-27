---
phase: 5
slug: theme-parity-analytics-experience
kind: debt-and-dispositions
created: 2026-08-27
---

# Phase 5 — Tracked Debt & Revision Dispositions

> Two ledgers a later verifier must read before re-litigating anything in this phase:
> what was deliberately **not** done and why, and how every planning-review finding was disposed of.

---

## 1. Deferred — awaiting a human decision

### D-DEBT-01 — light-mode `--green` fails WCAG AA for `.freshness-fresh`

| Field | Value |
|---|---|
| **Raised by** | Plan-review iteration 2, against `05-02-PLAN.md` |
| **Status** | **Deferred — awaiting a human decision.** Not fixed in Phase 5. |
| **Recorded in the plan** | `05-02-PLAN.md` assumption **A-34**, the deferral paragraph in Task 1's `<action>`, and an explicit Task 3 acceptance criterion naming the exemption |

**The fact.** `05-02-PLAN.md` Task 1 states the governing rule for the freshness badges: *"These
badges carry state meaning at the body font size (12px), so WCAG AA requires 4.5:1."* Three of the
four badges are asserted against that rule in Task 3. The fourth, `.freshness-fresh`, resolves
`var(--green)`, and light-mode `--green` is `#16a34a` (`dashboard/style.css:36`):

| Foreground | Surface | Ratio | AA 4.5:1 |
|---|---|---|---|
| `#16a34a` | light body surface `--bg` `#ffffff` | **3.30:1** | ✗ fails |
| `#16a34a` | `--bg3` `#f7f7f7` | 3.08:1 | ✗ fails |
| `#00ff88` | dark body surface `--bg` `#010a14` | 14.85:1 | ✓ passes |

The body surface is the one that matters: nothing between `body` and the freshness `<td>` sets a
background, and the Task 3 assertion reads `getComputedStyle(document.body).backgroundColor`. A
previously circulated figure of 3.08 was measured against `--bg3`; against the surface the cascade
argument identifies it is **3.30**. Dark mode is not affected.

**Why it is deferred rather than fixed.** `--green` is an app-wide token, not a badge-local colour.
Retuning it re-colours every success reading in the light theme:

| Consumer | Location | How it uses `--green` |
|---|---|---|
| `.svc-online` | `dashboard/style.css:498` | text colour at `font-size: 10px` (no AA large-text relief applies) |
| `html.light .svc-online` | `dashboard/style.css:507` | text colour |
| `.evt-up .evt-title` | `dashboard/style.css:1128` | text colour |
| `.scan-pip.ready` | `dashboard/style.css:153` | fill |
| `.svc-online .status-pip` | `dashboard/style.css:512` | fill |
| `.us.up` | `dashboard/style.css:565` | uptime-strip segment fill |
| `.hist-band-online` | `dashboard/advanced.css:213` | state-band fill |

That is a whole-light-theme token decision — it trades the token's current chroma against AA for two
text surfaces at two sizes, and it changes five non-text fills that AA text rules do not govern. It
is not a targeted edit inside a phase scoped to freshness vocabulary, and no source artifact
(`05-CONTEXT.md`, `05-UI-SPEC.md`, `05-RESEARCH.md`) decides it.

**What a human must decide.** Whether to (a) darken light-mode `--green` to clear 4.5:1 on `#ffffff`
across every text consumer, (b) introduce a separate text-only success token leaving the fills alone,
or (c) accept 3.30:1 for success text and record the exception. Until then:

- Executing Phase 5 must **not** change `--green`.
- Task 3 asserts contrast for `.freshness-stale`, `.freshness-unknown` and `.freshness-degraded`
  only. The absence of a fourth assertion is deliberate and recorded here — it is not an oversight,
  and a verifier should not read `05-02-PLAN.md:199`'s 4.5:1 rule as enforced for `fresh`.

---

## 2. Planning-review warning dispositions

### Root cause this ledger exists

The iteration-1 plan-review report was never written to disk. Its findings survived only in the
subject and body of commit `c28706b`, which is why re-check iteration 2 could not determine whether
every warning had been disposed of. **Convention from here on: every planning-review finding gets a
row in this table, with its resolution location, at the same commit that resolves it.** A commit
message is not a durable disposition record.

### Iteration 1 → resolved in `c28706b`

The report numbered its findings in one sequence. The two **blockers** occupied the first two slots;
the **ten warnings** were W-3 … W-12. Each row below was re-verified against `git show c28706b`.

| ID | Target | Disposition | Where resolved |
|---|---|---|---|
| (blocker 1) | `05-UI-SPEC.md`, `05-06-PLAN.md` T3 | **fixed** | Filter-group "collapses to one column" claim was false; replaced with measured wrapping facts (`05-UI-SPEC.md:353-366`, `05-06-PLAN.md:23,254`) |
| (blocker 2) | `05-06-PLAN.md` T3 | **fixed** | "Not a strict subset" proved nothing (T-05-25); replaced with a `collections.Counter` superset assertion, both collections asserted non-empty |
| W-3 | `05-03-PLAN.md` | **fixed** | A-17 rewritten plus two assertion sites: wave-2 reads `title`, since `aria-label` arrives in 05-04 (wave 3) |
| W-4 | `05-02-PLAN.md` | **fixed** | `--muted` fails AA for stale/unknown badges; switched to `--text`, with a per-theme contrast assertion and a non-vacuity self-check |
| W-5 | `05-06-PLAN.md` | **fixed** | Descriptor rule inlined rather than cross-referenced — 05-05 is a same-wave sibling |
| W-6 | `05-01-PLAN.md` | **fixed** | A-04 corrected: the J1 heartbeat cadence is the literal `('seconds', 5)`; only `WORKER_READY_SECONDS` is configurable, so the overlap is one-sided |
| W-7 | `05-02-PLAN.md` | **fixed** | Ill-formed selector-count grep gate repaired (`^`-anchored count → `grep -oE … \| sort -u`) |
| W-8 | `05-02-PLAN.md` | **fixed** | Ill-formed custom-property gate repaired (two-file `grep -c` prints `file:count` lines; now concatenated, with `\|\| true`) |
| W-9 | `05-03-PLAN.md` | **fixed** | Injected-regression criteria given exact probe rule text plus a `shasum -a 256` restore check |
| W-10 | `05-05-PLAN.md` | **fixed** | Control descriptor gains a parent-child index and becomes a `Counter` (its supplementary criterion was itself a tautology — see iteration 2 below) |
| W-11 | `05-03-PLAN.md` | **fixed** | Task 2's fixture must seed `preview_status` on one service, or Task 3's `.svc-preview-status` locator is empty |
| W-12 | `05-01-PLAN.md` | **fixed** | Degraded-banner truth reworded to what `style.css` actually shows across the `.safety-warning` cluster |

**On the count discrepancy.** Commit `c28706b`'s subject reads "2 blockers, 8 warnings" while its
body lists nine bullets covering ten warning IDs — W-7 and W-8 share a bullet. The subject
undercounts; it is not evidence of dropped findings. Every ID W-3 … W-12 has a diff hunk in that
commit, verified above.

**On `05-04-PLAN.md` being untouched.** No iteration-1 warning targeted it. The only warning that
*mentions* 05-04 is W-3, whose subject is 05-03's wave-2 assertion and whose fix therefore lands
entirely in `05-03-PLAN.md`. Stated as inference from the surviving evidence, not as a quotation
from the report — the report itself is unrecoverable, which is precisely the gap §2's convention
closes.

### Iteration 2 → resolved in this commit

| ID | Target | Disposition | Where resolved |
|---|---|---|---|
| Blocker | `05-05-PLAN.md` | **fixed** | The Task 2 criterion `sum(counter.values()) == len(elements)` is true for every input (it is the invariant a `Counter` guarantees, and it passes on the collapsed descriptors it was meant to catch). Replaced with `len(counter) == len(elements)` — distinct descriptors — in both the `<action>` and the criterion |
| W-1 | `05-02-PLAN.md` | **fixed** | Degraded-badge ratios were `--accent2` on `--bg3` while the assertion reads `document.body`; corrected to **5.02** light / **10.50** dark at both quotation sites. Swept: `--muted` figures now also quoted body-surface-first (2.17 light, 4.18 dark), `--text` figures were already body-surface |
| W-2 | `05-02-PLAN.md`, this file | **deferred, recorded** | Light-mode `--green` — see §1 D-DEBT-01. Deliberately not fixed; A-34, a Task 1 deferral paragraph and a Task 3 criterion make the exemption visible in the plan itself |
| W-3 | `05-UI-SPEC.md:408` | **fixed** | "filter collapse" → "filter wrapping" in the E10 resolution row; swept — no other instance of the disproven claim survives in the UI-SPEC |
| W-4 | this file | **fixed** | This ledger, and the convention in §2 that makes commit-message-only dispositions non-conforming going forward |
| W-5 | `05-02-PLAN.md` | **fixed** | BSD `wc -l` on darwin pads to `       0`, breaking string-equality gate runners; appended `\| tr -d ' '` and pinned the reason. Swept all six plans — this was the only `wc` gate in the set |
| W-5b (self-initiated) | `05-06-PLAN.md:345` | **fixed** | Found while sweeping for W-5's failure class: `grep -c 'to_have_screenshot\|page.screenshot' tests/` recurses the directory and prints one `file:count` line per test module (25 today), so the criterion "returns 0" was unsatisfiable as a scalar — the same defect W-8 repaired in 05-02. Repaired to `grep -rho … \| grep -c ''`, verified to print a clean `0` against the live tree. Recorded here rather than only in a hand-off message, per W-2's lesson |
