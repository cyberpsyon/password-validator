# Password Validator

A password strength validator that scores passwords against security policies, a common password blacklist (rockyou.txt), the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach database, and crack-time estimation via [zxcvbn](https://github.com/dwolfhuis/zxcvbn-python).

Available as both a CLI tool and a Streamlit web UI.

## Features

- **7-rule scoring system** (100 points max): length, uppercase, lowercase, numbers, special characters, breach database check, and crack-time resistance
- **Crack-time estimation** using zxcvbn's offline slow-hashing model (bcrypt at 10K guesses/sec), aligned with the [Hive Systems 2025 methodology](https://www.hivesystems.com/blog/are-your-passwords-in-the-green)
- **Breach database checking** against 14M+ passwords from rockyou.txt and the HIBP Pwned Passwords API (uses k-anonymity — your password never leaves the machine)
- **Streamlit web UI** with color-coded score, rating badges, threat gauge, and built-in generators
- **Password generator** — cryptographically secure random passwords with configurable length and character sets
- **Passphrase generator** — random passphrases from the [EFF diceware wordlist](https://www.eff.org/dice) (7,776 words) with options for uppercase, leetspeak, digits, special characters, and configurable word count/separator
- **Safety Tips** — expandable panel with concise password hygiene advice
- **How Scoring Works** — expandable panel explaining the full scoring system

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

Passwords are scored out of 100 points across 7 categories:

| Category | Points |
|----------|--------|
| Length (12+ characters) | 15 |
| Contains uppercase letters | 10 |
| Contains lowercase letters | 10 |
| Contains numbers | 10 |
| Contains special characters | 10 |
| Not in breach databases (rockyou.txt + HIBP) | 15 |
| Crack-time resistance | 0–30 |

### Crack-Time Resistance

Points are awarded based on how long it would take to crack the password assuming bcrypt hashing at 10,000 guesses per second:

| Estimated Crack Time | Points |
|----------------------|--------|
| Less than 1 second | 0 |
| Less than 1 minute | 5 |
| Less than 1 hour | 10 |
| Less than 1 day | 15 |
| Less than 1 year | 20 |
| Less than 100 years | 25 |
| 100+ years | 30 |

### Final Rating

| Rating | Score Range |
|--------|-------------|
| EXCELLENT | 100 |
| STRONG | 80–99 |
| GOOD | 60–79 |
| FAIR | 40–59 |
| WEAK | Below 40 |

Any password that can be cracked in under 1 hour or is found in the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach database is automatically rated **WEAK** regardless of its total score.
