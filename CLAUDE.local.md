# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the web UI
streamlit run app.py

# Run the CLI
python3 password_validator.py

# Install dependencies
pip install zxcvbn requests streamlit
```

There are no tests or linter configuration in this project.

## Architecture

The project has two files with a clean separation:

- **`password_validator.py`** — all validation logic, generators, and the CLI entry point. No Streamlit imports. Safe to use standalone.
- **`app.py`** — Streamlit web UI only. Imports from `password_validator.py` and adds all rendering logic via `st.markdown(..., unsafe_allow_html=True)`.

### Validation pipeline (`password_validator.py`)

`full_validate(password)` is the single orchestrator used by both the CLI and the web UI. It calls:

1. `validate_password()` — runs the `_RULES` list sequentially. Each rule function returns `(points, pass_msg, fail_msg)`. The breach rule (`_check_breach_databases`) makes a live HIBP API call using k-anonymity (only the first 5 hex chars of the SHA-1 hash are sent).
2. `analyze_crack_time()` — runs zxcvbn (capped at 72 bytes for bcrypt compatibility) and maps crack seconds to points via `_CRACK_THRESHOLDS`.

The combined score is always out of 100. All possible scores are multiples of 5 (a deliberate invariant — check the comment in `RATING_THRESHOLDS` before changing point values). Any password crackable in under 1 hour, or found in HIBP, is hard-capped to WEAK regardless of score.

### Scoring weights

| Category | Points |
|---|---|
| Length 15+ | 10 |
| Uppercase / Lowercase / Digits / Special | 5 each |
| Not found in breach databases (HIBP) | 20 |
| Crack-time resistance | 0–50 |

Crack-time is intentionally the dominant factor. Diversity rules are nudges, not gatekeepers — a long passphrase with only lowercase can legitimately outscore a short complex password.

### Streamlit UI (`app.py`)

The UI injects a comprehensive CSS block via `inject_global_styles()` at startup. All custom HTML sections use the `_html()` helper, which strips blank lines before passing to `st.markdown()` — this is required because CommonMark exits HTML-block mode on blank lines, causing subsequent indented content to render as raw code blocks.

The "Classified Security Terminal" design uses CSS variables (`--bg`, `--surface`, `--amber`, `--text-dim`, etc.) defined in `:root`. The universal `* { font-family: 'JetBrains Mono' }` rule intentionally overrides Streamlit's defaults, which breaks Material Icons ligatures. The expander icon fix (`details summary > span > span { display: none }`) hides the icon at the correct DOM level — `summary > span` is the full heading wrapper (StyledSummaryHeading), and `summary > span > span` is just the icon (StyledDynamicIcon).

### Data files

- `eff_wordlist.txt` — EFF diceware word list for passphrase generation (loaded fresh on each generate call).
