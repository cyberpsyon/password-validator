# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running

**CLI:**
```bash
python3 password_validator.py
```

Interactive CLI — prompts for a password, prints score/rating/recommendations, then asks to continue. Type `quit`, `exit`, or `q` to stop.

**Streamlit web UI:**
```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. Includes password validation with visual scoring and a password generator.

### Dependencies

Requires `zxcvbn`, `requests`, and `streamlit` (`pip install zxcvbn requests streamlit`).

### Blacklist configuration

The blacklist file defaults to `rockyou.txt` in the project directory. Override with `PV_BLACKLIST_FILE` env var:

```bash
PV_BLACKLIST_FILE=/path/to/wordlist.txt python3 password_validator.py
```

## Architecture

Core validation logic lives in `password_validator.py`. The Streamlit frontend (`app.py`) imports and reuses shared functions, adding a web UI with visual scoring, color-coded ratings, and a password generator.

### `password_validator.py` structure

- **Rule checkers** (`_check_length`, `_check_uppercase`, `_check_lowercase`, `_check_digits`, `_check_special`, `_check_breach_databases`) — Each returns `(points, pass_msg, fail_msg)`. Registered in the `_RULES` list and iterated by `validate_password()`.
- **`validate_password(password, blacklist)`** — Runs all rule checkers via loop. Returns `(score, max_score, failed_rules, passed_rules)`.
- **`check_hibp(password)`** — Queries HIBP Pwned Passwords API using k-anonymity. Returns `(found, count, error)`. Fails open on network errors.
- **`analyze_crack_time(password)`** — Uses zxcvbn for crack-time estimation (up to 30 points). Hard-fail flag if crack time < 1 hour.
- **`full_validate(password, blacklist)`** — Single orchestrator combining `validate_password` + `analyze_crack_time` + `get_rating`. Returns a results dict. Used by both CLI and Streamlit to avoid duplicated logic.
- **`generate_password(length, ...)`** — Cryptographically secure password generator using `secrets.SystemRandom`.
- **`get_rating(score)`** — Maps score to rating: WEAK (<40), FAIR (40-59), GOOD (60-79), STRONG (80-99), EXCELLENT (100).
- **`load_blacklist()`** — Loads the wordlist into a set. Gracefully degrades if file is missing.
- **`_configure_logging()`** — Sets up file + console logging. Called only from `main()` to avoid import side effects.
- **`main()`** — CLI entry point. Uses `full_validate()`, `_print_results()`, `_print_recommendations()`.

### `app.py` structure

- **`render_generator_panel()`** — Password generator UI (expander with length slider, character set checkboxes).
- **`render_validation_results(password, blacklist)`** — Runs `full_validate()` and renders score, rating badge, rules, and recommendations. Includes rate limiting and HIBP failure warnings.
- **`inject_progress_color(rating)`** — Injects CSS to color the progress bar by rating.
- Top-level code is minimal: loads blacklist, renders input, dispatches to render functions.

## Security audits

- `audits/password_validator_audit.md` — Original security audit (prior findings all remediated)
- `audits/security_input_validation_audit.md` — Current security & input validation audit
- `audits/code_complexity_audit.md` — Code complexity analysis

### Key security patterns

- All `unsafe_allow_html=True` content is escaped via `html.escape()`
- HIBP requests include `User-Agent` and `Add-Padding` headers
- Logging uses module-level `_logger` (no root-logger side effects on import)
- Exception messages use `!r` formatting to prevent log injection
- `.streamlit/config.toml` disables CORS and usage stats
