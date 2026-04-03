# Author: Ben Mickens
# Date: 12-07-2024
# Purpose: Validates password strength against security policies and breach databases

import hashlib
import logging
import os
import secrets
import string

import requests
import zxcvbn

# -- Module logger (no root-logger side effects on import) --
_logger = logging.getLogger(__name__)

# -- Constants --
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
MIN_LENGTH = 15
MAX_LENGTH = 128

HIBP_HEADERS = {
    "User-Agent": "PasswordValidator/1.0 (+https://github.com/cyberpsyon/password-validator)",
    "Add-Padding": "true",
}

_CRACK_THRESHOLDS = [
    (1,           0),   # less than 1 second
    (60,          5),   # less than 1 minute
    (3600,       10),   # less than 1 hour
    (86400,      20),   # less than 1 day
    (31536000,   30),   # less than 1 year
    (3153600000, 40),   # less than 100 years
]

RATING_THRESHOLDS = [
    (100, "EXCELLENT"),
    (80,  "STRONG"),
    (60,  "GOOD"),
    (40,  "FAIR"),
]  # All scores are multiples of 5, so gaps between tiers (e.g. 96-99) are unreachable


def _configure_logging():
    """Set up file + console logging. Call once from CLI entry point only."""
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "password_validator.log")
    handler = logging.FileHandler(log_path)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[handler, logging.StreamHandler()],
    )
    os.chmod(log_path, 0o600)


# ---------------------------------------------------------------------------
# HIBP API
# ---------------------------------------------------------------------------

def check_hibp(password):
    """Check if a password appears in the Have I Been Pwned database.

    Uses the k-anonymity range API: only the first 5 characters of the
    SHA-1 hash are sent to the server; the full password never leaves
    the machine.

    Returns (found: bool, count: int | None, error: str | None).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers=HIBP_HEADERS,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        _logger.warning(f"HIBP API request failed: {e!r}")
        return False, None, str(e)

    for line in resp.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return True, int(count.strip()), None

    return False, 0, None


# ---------------------------------------------------------------------------
# Individual rule checkers
# Each returns (points: int, pass_msg: str | None, fail_msg: str | None)
# ---------------------------------------------------------------------------

def _check_length(password, **_kwargs):
    if len(password) >= MIN_LENGTH:
        return 10, f"\u2713 Length requirement met ({len(password)} characters)", None
    return 0, None, f"\u2717 Too short (needs {MIN_LENGTH}+ characters, has {len(password)})"


def _check_uppercase(password, **_kwargs):
    if any(c.isupper() for c in password):
        return 5, "\u2713 Contains uppercase letters", None
    return 0, None, "\u2717 No uppercase letters"


def _check_lowercase(password, **_kwargs):
    if any(c.islower() for c in password):
        return 5, "\u2713 Contains lowercase letters", None
    return 0, None, "\u2717 No lowercase letters"


def _check_digits(password, **_kwargs):
    if any(c.isdigit() for c in password):
        return 5, "\u2713 Contains numbers", None
    return 0, None, "\u2717 No numbers"


def _check_special(password, **_kwargs):
    if any(c in SPECIAL_CHARS for c in password):
        return 5, "\u2713 Contains special characters", None
    return 0, None, f"\u2717 No special characters ({SPECIAL_CHARS})"


def _check_breach_databases(password, **_kwargs):
    """Rule 6: HIBP breach check (20 points)."""
    hibp_found, hibp_count, hibp_error = check_hibp(password)
    if hibp_error:
        return 0, None, ["\u26a0 HIBP API unavailable: cannot verify against breach database"]
    if hibp_found:
        return 0, None, [f"\u2717 Found in Have I Been Pwned database ({hibp_count:,} breaches) (CRITICAL)"]
    return 20, "\u2713 Not found in breach databases", None


_RULES = [
    _check_length,
    _check_uppercase,
    _check_lowercase,
    _check_digits,
    _check_special,
    _check_breach_databases,
]


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------

def validate_password(password):
    """Run all rule checks. Returns (score, max_score, failed_rules, passed_rules)."""
    if not password:
        _logger.warning("Validation failed: Empty password provided")
        return 0, 100, ["Password cannot be empty"], []

    if not isinstance(password, str):
        _logger.warning("Validation failed: Password must be a string")
        return 0, 100, ["Password must be text"], []

    if len(password) > MAX_LENGTH:
        _logger.warning("Validation failed: Password exceeds maximum length")
        return 0, 100, [f"Password too long (max {MAX_LENGTH} characters)"], []

    score, passed, failed = 0, [], []

    for rule in _RULES:
        pts, ok_msg, fail_msg = rule(password)
        score += pts
        if ok_msg:
            passed.append(ok_msg)
        if fail_msg:
            if isinstance(fail_msg, list):
                failed.extend(fail_msg)
            else:
                failed.append(fail_msg)

    return score, 100, failed, passed


# ---------------------------------------------------------------------------
# Crack-time analysis
# ---------------------------------------------------------------------------

def analyze_crack_time(password):
    """Rule 7: Crack time resistance (up to 50 points).

    Returns (crack_time_display, crack_time_seconds, points, hard_fail, suggestions, warning).
    """
    # bcrypt truncates at 72 bytes; zxcvbn enforces the same limit
    result = zxcvbn.zxcvbn(password[:72])
    crack_time_display = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    crack_time_seconds = result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]

    points = 50  # default: 100+ years
    for limit, pts in _CRACK_THRESHOLDS:
        if crack_time_seconds < limit:
            points = pts
            break

    hard_fail = crack_time_seconds < 3600

    suggestions = result["feedback"].get("suggestions", [])
    warning = result["feedback"].get("warning", "")

    return crack_time_display, crack_time_seconds, points, hard_fail, suggestions, warning


def get_rating(score):
    """Convert numerical score to rating. Only 100 = EXCELLENT."""
    for threshold, label in RATING_THRESHOLDS:
        if score >= threshold:
            return label
    return "WEAK"


# ---------------------------------------------------------------------------
# Full validation orchestrator (shared by CLI and Streamlit)
# ---------------------------------------------------------------------------

def full_validate(password):
    """Run all checks and return a results dict.

    Combines validate_password() + analyze_crack_time() + get_rating()
    so both CLI and Streamlit call a single function.
    """
    score, max_score, failed, passed = validate_password(password)
    crack_time, crack_seconds, crack_pts, hard_fail, suggestions, warning = analyze_crack_time(password)
    score += crack_pts

    if crack_pts > 0:
        passed.append(f"\u2713 Crack time resistance ({crack_pts}/50 points)")
    else:
        failed.append("\u2717 Crack time resistance: cracks in under 1 second (0/50 points)")

    # Auto-WEAK: crackable in under 1 hour OR found in HIBP
    breach = any("have i been pwned" in r.lower() for r in failed)
    if breach:
        hard_fail = True
    rating = "WEAK" if hard_fail else get_rating(score)

    return {
        "score": score,
        "max_score": max_score,
        "rating": rating,
        "hard_fail": hard_fail,
        "crack_time": crack_time,
        "crack_seconds": crack_seconds,
        "passed": passed,
        "failed": failed,
        "suggestions": suggestions,
        "warning": warning,
    }


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def generate_password(length, use_upper=True, use_lower=True,
                      use_digits=True, use_special=True):
    """Generate a cryptographically secure random password."""
    chars = ""
    required = []
    if use_upper:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        chars += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if use_special:
        chars += SPECIAL_CHARS
        required.append(secrets.choice(SPECIAL_CHARS))
    if not chars:
        return None
    remaining = length - len(required)
    password_chars = required + [secrets.choice(chars) for _ in range(remaining)]
    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)
    return "".join(password_chars)


# ---------------------------------------------------------------------------
# Passphrase generator
# ---------------------------------------------------------------------------

_WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eff_wordlist.txt")

_LEET_MAP = {
    "a": "@", "e": "3", "i": "1", "o": "0", "s": "$",
    "t": "7", "l": "!", "g": "9", "b": "8",
}


def _load_wordlist():
    """Load the EFF diceware word list."""
    try:
        with open(_WORDLIST_PATH, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    except FileNotFoundError:
        _logger.error(f"Wordlist not found: {_WORDLIST_PATH}")
        return []


def _apply_leet(word):
    """Replace all applicable characters with leetspeak substitutions."""
    return "".join(_LEET_MAP.get(c, c) for c in word)


def generate_passphrase(word_count=4, separator="-", use_upper=False,
                        use_leet=False, use_digits=False, use_special=False):
    """Generate a passphrase from random dictionary words.

    Options:
      - use_upper: capitalize each word
      - use_leet: apply full leetspeak substitutions
      - use_digits: append a random digit to each word
      - use_special: append a random special char to each word
    """
    wordlist = _load_wordlist()
    if not wordlist:
        return None

    rng = secrets.SystemRandom()
    words = [rng.choice(wordlist) for _ in range(word_count)]

    if use_upper:
        words = [w.capitalize() for w in words]

    if use_leet:
        words = [_apply_leet(w) for w in words]

    if use_digits:
        words = [w + str(rng.randint(0, 9)) for w in words]

    if use_special:
        words = [w + rng.choice(SPECIAL_CHARS) for w in words]

    return separator.join(words)


# ---------------------------------------------------------------------------
# CLI display helpers
# ---------------------------------------------------------------------------

def _print_results(result):
    """Display validation results to the terminal."""
    print("\n" + "-" * 60)
    print("VALIDATION RESULTS")
    print("-" * 60)
    print(f"Score: {result['score']}/{result['max_score']} ({result['rating']})")
    if result["hard_fail"]:
        print("  *** Rating capped at WEAK: password cracks in under 1 hour ***")
    print(f"Estimated crack time (worst case): {result['crack_time']}")
    print()

    if result["passed"]:
        print("Passed Rules:")
        for rule in result["passed"]:
            print(f"  {rule}")
        print()

    if result["failed"]:
        print("Failed Rules:")
        for rule in result["failed"]:
            print(f"  {rule}")
        print()


def _print_recommendations(result):
    """Display recommendations to the terminal."""
    recs = []
    if result["score"] < 50:
        recs.append("This password is too weak for secure systems")
    if result["failed"]:
        recs.append("Address all failed rules above")
    if any("have i been pwned" in r.lower() for r in result["failed"]):
        recs.append("CRITICAL: Use a unique password not found in breach databases")
    if result["warning"]:
        recs.append(result["warning"])
    recs.extend(result["suggestions"])

    if recs:
        print("Recommendations:")
        for rec in recs:
            print(f"  \u2022 {rec}")
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    _configure_logging()

    print("=" * 60)
    print("PASSWORD STRENGTH VALIDATOR")
    print("=" * 60)
    print()

    _logger.info("Password validator started")

    while True:
        password = input("Enter password to validate (or 'quit' to exit): ")

        if password.lower() in ['quit', 'exit', 'q']:
            _logger.info("User exited validator")
            print("\nThank you for using Password Validator!")
            break

        result = full_validate(password)
        _print_results(result)
        _print_recommendations(result)

        print("-" * 60)

        if input("\nCheck another password? (y/n): ").strip().lower() not in ['y', 'yes']:
            _logger.info("User chose to exit")
            print("\nThank you for using Password Validator!")
            break
        print()


if __name__ == "__main__":
    main()
