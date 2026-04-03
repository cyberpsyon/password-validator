---
title: Result Animations & Color-Coded Rows
date: 2026-04-02
status: approved
---

# Result Animations & Color-Coded Rows

## Overview

Add three visual enhancements to the validation results in `app.py`. All changes are additive — the existing rendering pipeline and button-click trigger are unchanged. No new dependencies required.

## Features

### 1. Color-Coded Result Rows

**What:** Each rule in the Rule Analysis section gets a background tint and left border based on its outcome.

| Row type | Background | Left border |
|----------|-----------|-------------|
| Passed (✓) | `rgba(0, 230, 118, 0.06)` | `--green` |
| Failed (✗ / CRITICAL) | `rgba(255, 23, 68, 0.06)` | `--red` |
| Warning (⚠) | `rgba(245, 166, 35, 0.08)` | `--amber` |

**How:** In `render_validation_results()`, inspect the first character of each result string to determine its type (✓, ✗, ⚠), then apply a CSS class (`pv-row-pass`, `pv-row-fail`, `pv-row-warn`) to the row wrapper div. Add those three classes to `inject_global_styles()`.

**Scope:** `app.py` only — the result row HTML and global CSS.

---

### 2. Animated Score Count-Up

**What:** When results render, the score number counts up from 0 to its final value over ~800ms with an ease-out curve. The progress bar animates in sync.

**How:**
- Add `id="pv-score"` and `data-target="{score}"` to the score element in the score card HTML.
- Add `id="pv-bar"` and `data-target-width="{pct}%"` to the progress bar element.
- At the end of `render_validation_results()`, inject a single 0-height `st.components.v1.html()` block. The JS inside:
  - Accesses `window.parent.document` (same-origin; already used by the copy button component)
  - Reads `data-target` from `#pv-score`
  - Uses `requestAnimationFrame` with an ease-out easing function to count from 0 → target over 800ms
  - Updates `#pv-bar` width in sync on each frame

**Scope:** `app.py` — score card HTML, progress bar HTML, one new `components.html()` call at end of `render_validation_results()`.

---

### 3. Typewriter Rating Effect

**What:** The rating label (WEAK / FAIR / GOOD / STRONG / EXCELLENT) types in character by character after the score count-up begins, at ~80ms per character.

**How:**
- Add `id="pv-rating"` to the rating element. Set its initial text content to empty. Store the full rating string in `data-rating="{rating}"`.
- The existing color (red for WEAK, green for EXCELLENT, etc.) is set via inline style upfront so it renders correctly as letters appear.
- The same JS block from feature 2 handles this: after a short initial delay (~100ms), reveal one character every 80ms using `setInterval` until the full string is displayed.

**Scope:** `app.py` — rating HTML in score card, same JS block as feature 2.

---

## Implementation Boundaries

- **`inject_global_styles()`** — add `pv-row-pass`, `pv-row-fail`, `pv-row-warn` CSS classes
- **`render_validation_results()`** — update score card HTML (add IDs/data attrs), update result row HTML (add CSS classes), add one `components.html()` JS block at the end
- **`password_validator.py`** — no changes
- **No new dependencies**

## JS Block Structure (pseudo-code)

```javascript
// Score count-up
const scoreEl = window.parent.document.getElementById('pv-score');
const target = parseInt(scoreEl.dataset.target);
const bar = window.parent.document.getElementById('pv-bar');
const targetWidth = bar.dataset.targetWidth;
const duration = 800;
const start = performance.now();

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function tick(now) {
  const t = Math.min((now - start) / duration, 1);
  const eased = easeOut(t);
  scoreEl.textContent = Math.round(eased * target);
  bar.style.width = (eased * parseFloat(targetWidth)) + '%';
  if (t < 1) requestAnimationFrame(tick);
}
requestAnimationFrame(tick);

// Typewriter rating
const ratingEl = window.parent.document.getElementById('pv-rating');
const ratingText = ratingEl.dataset.rating;
let i = 0;
setTimeout(() => {
  const interval = setInterval(() => {
    ratingEl.textContent += ratingText[i++];
    if (i >= ratingText.length) clearInterval(interval);
  }, 80);
}, 100);
```

## Notes

- `window.parent.document` access works same-origin (localhost and Streamlit Cloud both serve components from the same domain).
- The copy button component in `_render_copy_output()` confirms this pattern already works in this app.
- The existing `t-reveal` fade-in animation on result sections fires independently and is unaffected.
- If JS fails silently (e.g. element not found), results are still fully visible — animations are pure enhancement.
