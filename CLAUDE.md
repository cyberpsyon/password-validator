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

Core validation logic lives in `password_validator.py`. The Streamlit frontend (`app.py`) imports and reuses these functions directly, adding a web UI with visual scoring, color-coded ratings, and a password generator.

### Core functions (`password_validator.py`):

- **`validate_password(password, blacklist)`** — Core scoring engine. Checks 6 rules (length, uppercase, lowercase, numbers, special chars, breach databases) worth up to 70 points. Rule 6 combines a local blacklist check with an HIBP Pwned Passwords API check — both must pass to earn the 15 points. Returns `(score, max_score, failed_rules, passed_rules)`.
- **`check_hibp(password)`** — Queries the Have I Been Pwned Pwned Passwords API using k-anonymity (only the first 5 chars of the SHA-1 hash are sent). Returns `(found, count, error)`. Fails open on network errors.
- **`analyze_crack_time(password)`** — Uses zxcvbn to estimate offline crack time and awards up to 30 additional points (Rule 7). Returns a `hard_fail` flag if crack time < 1 hour, which caps the rating at WEAK regardless of score.
- **`get_rating(score)`** — Maps score to rating: WEAK (<40), FAIR (40-59), GOOD (60-79), STRONG (80-99), EXCELLENT (100).
- **`load_blacklist()`** — Loads the wordlist into a set. Gracefully degrades (returns empty set) if the file is missing; `validate_password` flags this as a failed rule.

The `main()` loop loads the blacklist once, then repeatedly collects input, combines rule-based scoring with zxcvbn crack-time scoring, and displays results.

## Security audit

`audits/password_validator_audit.md` contains a prior security audit. Several findings have already been remediated in the current code (log file permissions, max length guard, configurable blacklist path, explicit blacklist-missing handling).
