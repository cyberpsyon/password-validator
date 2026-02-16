# Password Validator

A password strength validator that scores passwords against security policies, a common password blacklist (rockyou.txt), the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach database, and crack-time estimation via [zxcvbn](https://github.com/dwolfhuis/zxcvbn-python).

Available as both a CLI tool and a Streamlit web UI.

## Features

- **7-rule scoring system** (100 points max): length, uppercase, lowercase, numbers, special characters, blacklist check, and crack-time resistance
- **Crack-time estimation** using zxcvbn's offline fast-hashing model
- **Hard fail override** — passwords crackable in under 1 hour are rated WEAK regardless of score
- **Breach database checking** against 14M+ passwords from rockyou.txt and the HIBP Pwned Passwords API (uses k-anonymity — your password never leaves the machine)
- **Streamlit web UI** with color-coded score, rating badges, and a built-in password generator

## Setup

```bash
pip install zxcvbn requests streamlit
```

Place a wordlist file (e.g. `rockyou.txt`) in the project directory, or set the `PV_BLACKLIST_FILE` environment variable to point to your wordlist.

## Usage

**CLI:**
```bash
python3 password_validator.py
```

**Web UI:**
```bash
streamlit run app.py
```

## Scoring

| Rule | Points |
|------|--------|
| Length (12+ characters) | 15 |
| Contains uppercase | 10 |
| Contains lowercase | 10 |
| Contains numbers | 10 |
| Contains special characters | 10 |
| Not in breach databases (rockyou.txt + HIBP) | 15 |
| Crack-time resistance | 0–30 |

| Rating | Score |
|--------|-------|
| EXCELLENT | 100 |
| STRONG | 80–99 |
| GOOD | 60–79 |
| FAIR | 40–59 |
| WEAK | <40 |
