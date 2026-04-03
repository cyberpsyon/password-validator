# Result Animations & Color-Coded Rows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add color-coded result rows, an animated score count-up, and a typewriter rating effect to the validation results in `app.py`.

**Architecture:** All changes are in `app.py` only. Color-coded rows use CSS classes added to `inject_global_styles()` and applied in the row-building loop. The score and rating animations use `id` and `data-*` attributes added to the score card HTML, driven by a 0-height `st.components.v1.html()` JS block injected at the end of `render_validation_results()`. This follows the same pattern as the existing copy button component (`_render_copy_output`).

**Tech Stack:** Python, Streamlit, vanilla JS (`requestAnimationFrame`, `setInterval`), CSS

> **Note:** This project has no test suite (confirmed in CLAUDE.md). Test steps are replaced with manual verification via `streamlit run app.py`.

---

### Task 1: Color-Coded Result Rows

**Files:**
- Modify: `app.py` — `inject_global_styles()` (add CSS classes) and `render_validation_results()` (apply classes to row divs)

- [ ] **Step 1: Add CSS classes to `inject_global_styles()`**

Find this block in `inject_global_styles()` (just after the `pvRight` animation block, around line 403):

```python
        .pv-left  { animation: pvLeft  10s linear infinite; }
        .pv-right { animation: pvRight 10s linear infinite; }
```

Add immediately after:

```python
        /* ── Result row color coding ── */
        .pv-row-pass {
            background: rgba(0, 230, 118, 0.06);
            border-left: 2px solid var(--green);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }
        .pv-row-fail {
            background: rgba(255, 23, 68, 0.06);
            border-left: 2px solid var(--red);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }
        .pv-row-warn {
            background: rgba(245, 166, 35, 0.08);
            border-left: 2px solid var(--amber);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }
```

- [ ] **Step 2: Apply classes to result rows in `render_validation_results()`**

Find the row-building loop in `render_validation_results()` (around line 758). Replace the entire `rows_html` block (both `for` loops) with:

```python
    rows_html = ""
    for rule in passed:
        rows_html += (
            f'<div class="pv-row-pass" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'<span style="color:#00E676; font-size:0.62rem; font-weight:700; '
            f'letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; '
            f'padding-top:2px;">[ OK ]</span>'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
            f'</div>'
        )
    for rule in failed:
        row_class = "pv-row-warn" if rule.startswith("\u26a0") else "pv-row-fail"
        rows_html += (
            f'<div class="{row_class}" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'<span style="color:#FF1744; font-size:0.62rem; font-weight:700; '
            f'letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; '
            f'padding-top:2px;">[FAIL]</span>'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
            f'</div>'
        )
```

- [ ] **Step 3: Manual verification**

Run: `streamlit run app.py`

Enter a weak password (e.g. `password`) and click Run Analysis. Expected:
- Failed rows have a faint red background and red left border
- Warning rows (⚠) have a faint amber background and amber left border
- Passed rows have a faint green background and green left border

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "feat: color-coded result rows (pass/fail/warn)"
```

---

### Task 2: Score Card HTML — Add IDs and Data Attributes

**Files:**
- Modify: `app.py` — score card HTML inside `render_validation_results()` (around line 724)

- [ ] **Step 1: Update the score number element**

Find this line in the score card f-string (around line 729):

```python
                <div style="font-size:3rem; font-weight:800; color:{color}; line-height:1; font-family:'JetBrains Mono',monospace; letter-spacing:-0.02em;">{score}<span style="font-size:1rem; color:#46466A; font-weight:400;"> / {max_score}</span></div>
```

Replace with:

```python
                <div style="font-size:3rem; font-weight:800; color:{color}; line-height:1; font-family:'JetBrains Mono',monospace; letter-spacing:-0.02em;"><span id="pv-score" data-target="{score}">0</span><span style="font-size:1rem; color:#46466A; font-weight:400;"> / {max_score}</span></div>
```

- [ ] **Step 2: Update the progress bar element**

Find this line (around line 731):

```python
                    <div style="width:{score_pct:.1f}%; height:100%; background:{color};"></div>
```

Replace with:

```python
                    <div id="pv-bar" data-target-width="{score_pct:.1f}" style="width:0%; height:100%; background:{color}; transition:none;"></div>
```

Note: `width` starts at `0%` and `transition:none` overrides the CSS transition so JS controls the animation exclusively.

- [ ] **Step 3: Update the rating element**

Find this line (around line 736):

```python
                <div style="color:{color}; font-size:1.1rem; font-weight:800; letter-spacing:0.12em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; border:1px solid {color}; padding:0.4rem 0.9rem; box-shadow:{shadow};">{html.escape(rating)}</div>
```

Replace with:

```python
                <div id="pv-rating" data-rating="{html.escape(rating)}" style="color:{color}; font-size:1.1rem; font-weight:800; letter-spacing:0.12em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; border:1px solid {color}; padding:0.4rem 0.9rem; box-shadow:{shadow};"></div>
```

Note: initial text content is empty — JS will type it in.

- [ ] **Step 4: Manual verification (pre-JS)**

Run: `streamlit run app.py`

Enter any password and click Run Analysis. Expected:
- Score shows `0` (static, no animation yet — JS not added yet)
- Rating box is empty
- Progress bar is invisible (width 0%)
- Everything else renders normally

This confirms the HTML changes are correct before adding JS.

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "feat: add IDs and data attrs to score card for animation"
```

---

### Task 3: JS Animation Block

**Files:**
- Modify: `app.py` — add `st.components.v1.html()` call at the end of `render_validation_results()`, just before the closing of the function (after the recommendations block)

- [ ] **Step 1: Add the JS animation block**

At the very end of `render_validation_results()`, after the recommendations `if recs:` block (around line 833), add:

```python
    # ── Animations ─────────────────────────────────────────────────────────
    st.components.v1.html(
        f"""
        <script>
        (function() {{
            var scoreEl = window.parent.document.getElementById('pv-score');
            var barEl   = window.parent.document.getElementById('pv-bar');
            var ratingEl = window.parent.document.getElementById('pv-rating');
            if (!scoreEl || !barEl || !ratingEl) return;

            var targetScore = parseInt(scoreEl.dataset.target);
            var targetWidth = parseFloat(barEl.dataset.targetWidth);
            var ratingText  = ratingEl.dataset.rating;
            var duration    = 800;
            var start       = performance.now();

            function easeOut(t) {{ return 1 - Math.pow(1 - t, 3); }}

            function tick(now) {{
                var t = Math.min((now - start) / duration, 1);
                var eased = easeOut(t);
                scoreEl.textContent = Math.round(eased * targetScore);
                barEl.style.width = (eased * targetWidth) + '%';
                if (t < 1) requestAnimationFrame(tick);
            }}
            requestAnimationFrame(tick);

            var i = 0;
            setTimeout(function() {{
                var interval = setInterval(function() {{
                    ratingEl.textContent += ratingText[i++];
                    if (i >= ratingText.length) clearInterval(interval);
                }}, 80);
            }}, 100);
        }})();
        </script>
        """,
        height=0,
    )
```

Note: double braces `{{` / `}}` are required because this is inside an f-string.

- [ ] **Step 2: Manual verification — score count-up**

Run: `streamlit run app.py`

Enter a password and click Run Analysis. Expected:
- Score counts up from `0` to its final value over ~800ms
- Progress bar fills from left to right in sync with the score
- Animation uses ease-out (fast start, slows near the end)

- [ ] **Step 3: Manual verification — typewriter rating**

Same run as above. Expected:
- Rating box starts empty
- ~100ms after results appear, letters type in one by one (~80ms each)
- For `EXCELLENT` (9 chars): full reveal takes ~820ms after the initial delay
- Color of the rating is correct from the first character (color is set via inline style, not JS)

- [ ] **Step 4: Manual verification — edge cases**

Test these specific cases:
- Score of `0` (e.g. enter `password`): count-up stays at 0, rating types `WEAK` in red
- Score of `100` (strong password): counts up to 100, rating types `EXCELLENT`
- Hard fail password in rockyou (e.g. `dragon`): bar stays near 0, `WEAK` types in

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "feat: animated score count-up and typewriter rating effect"
```
