# Author: Ben Mickens
# Date: 12-07-2024
# Purpose: Validates password strength against security policies and common password blacklist

import hashlib
import logging
import os

import requests
import zxcvbn

# Configuration
BLACKLIST_FILE = os.environ.get(
    "PV_BLACKLIST_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockyou.txt")
)
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
MIN_LENGTH = 12
MAX_LENGTH = 128

# Configure logging with restricted file permissions
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_validator.log")
file_handler = logging.FileHandler(log_path)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        file_handler,
        logging.StreamHandler()
    ]
)
os.chmod(log_path, 0o600)

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, 'r', encoding='utf-8', errors='ignore') as file:
            blacklist = {line.strip().lower() for line in file if line.strip()}
        logging.info(f"Loaded {len(blacklist)} passwords from blacklist")
        return blacklist
    except FileNotFoundError:
        logging.error(f"Blacklist file not found: {BLACKLIST_FILE}")
        return set()
    except PermissionError:
        logging.error(f"Permission denied reading blacklist: {BLACKLIST_FILE}")
        return set()
    except Exception as e:
        logging.error(f"Unexpected error loading blacklist: {e}")
        return set()

def check_hibp(password):
    """Check if a password appears in the Have I Been Pwned database.

    Uses the k-anonymity range API — only the first 5 characters of the
    SHA-1 hash are sent to the server; the full password never leaves
    the machine.

    Returns (found: bool, count: int | None, error: str | None).
    - found=True, count=N means the password appeared in N breaches.
    - found=False, count=0 means it was not found.
    - error is set (and found=False) if the API call failed.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logging.warning(f"HIBP API request failed: {e}")
        return False, None, str(e)

    for line in resp.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return True, int(count.strip()), None

    return False, 0, None


def validate_password(password, blacklist):
    # Guard clause: password cannot be empty or None
    if not password:
        logging.warning("Validation failed: Empty password provided")
        return 0, 100, ["Password cannot be empty"], []
    
    # Guard clause: password must be a string
    if not isinstance(password, str):
        logging.warning("Validation failed: Password must be a string")
        return 0, 100, ["Password must be text"], []

    # Guard clause: enforce maximum length to prevent resource exhaustion
    if len(password) > MAX_LENGTH:
        logging.warning("Validation failed: Password exceeds maximum length")
        return 0, 100, [f"Password too long (max {MAX_LENGTH} characters)"], []

    failed_rules = []
    passed_rules = []
    max_score = 100
    score = 0

    # Rule 1: Minimum length (15 points)
    if len(password) >= MIN_LENGTH:
        score += 15
        passed_rules.append(f"✓ Length requirement met ({len(password)} characters)")
        logging.info(f"Length check PASSED: {len(password)} chars")
    else:
        failed_rules.append(f"✗ Too short (needs {MIN_LENGTH}+ characters, has {len(password)})")
        logging.info(f"Length check FAILED: {len(password)} chars (needs {MIN_LENGTH}+)")

    # Rule 2: Contains uppercase (10 points)
    if any(c.isupper() for c in password):
        score += 10
        passed_rules.append("✓ Contains uppercase letters")
        logging.info("Uppercase check PASSED")
    else:
        failed_rules.append("✗ No uppercase letters")
        logging.info("Uppercase check FAILED")

    # Rule 3: Contains lowercase (10 points)
    if any(c.islower() for c in password):
        score += 10
        passed_rules.append("✓ Contains lowercase letters")
        logging.info("Lowercase check PASSED")
    else:
        failed_rules.append("✗ No lowercase letters")
        logging.info("Lowercase check FAILED")

    # Rule 4: Contains numbers (10 points)
    if any(c.isdigit() for c in password):
        score += 10
        passed_rules.append("✓ Contains numbers")
        logging.info("Number check PASSED")
    else:
        failed_rules.append("✗ No numbers")
        logging.info("Number check FAILED")

    # Rule 5: Contains special characters (10 points)
    if any(c in SPECIAL_CHARS for c in password):
        score += 10
        passed_rules.append("✓ Contains special characters")
        logging.info("Special character check PASSED")
    else:
        failed_rules.append(f"✗ No special characters ({SPECIAL_CHARS})")
        logging.info("Special character check FAILED")

    # Rule 6: Not in common password databases (15 points)
    # Must pass both the local blacklist AND the HIBP Pwned Passwords check.
    blacklist_clean = True
    hibp_clean = True

    # 6a: Local blacklist
    if blacklist is None or len(blacklist) == 0:
        failed_rules.append("⚠ Local blacklist unavailable — cannot verify against local password list")
        logging.warning("Blacklist check SKIPPED: no blacklist loaded")
        blacklist_clean = False
    elif password.lower() in blacklist:
        failed_rules.append("✗ Found in local password database (CRITICAL)")
        logging.warning("Password found in blacklist (rejected)")
        blacklist_clean = False
    else:
        logging.info("Local blacklist check PASSED")

    # 6b: Have I Been Pwned
    hibp_found, hibp_count, hibp_error = check_hibp(password)
    if hibp_error:
        failed_rules.append("⚠ HIBP API unavailable — cannot verify against breach database")
        logging.warning(f"HIBP check SKIPPED: {hibp_error}")
        hibp_clean = False
    elif hibp_found:
        failed_rules.append(f"✗ Found in Have I Been Pwned database ({hibp_count:,} breaches) (CRITICAL)")
        logging.warning(f"Password found in HIBP ({hibp_count} breaches)")
        hibp_clean = False
    else:
        logging.info("HIBP check PASSED")

    # Award points only if both checks pass (or at least one passed with the other skipped)
    if blacklist_clean and hibp_clean:
        score += 15
        passed_rules.append("✓ Not in common password databases")
        logging.info("Combined breach check PASSED")

    return score, max_score, failed_rules, passed_rules

def analyze_crack_time(password):
    """Use zxcvbn to estimate crack time, score points, and feedback.

    Rule 7: Crack time resistance (30 points).
    Points are awarded based on worst-case offline crack time.
    """
    result = zxcvbn.zxcvbn(password)
    crack_time_display = result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
    crack_time_seconds = result["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"]

    # Points awarded based on crack time thresholds (max 30)
    if crack_time_seconds < 1:              # less than 1 second
        points = 0
    elif crack_time_seconds < 60:           # less than 1 minute
        points = 5
    elif crack_time_seconds < 3600:         # less than 1 hour
        points = 10
    elif crack_time_seconds < 86400:        # less than 1 day
        points = 15
    elif crack_time_seconds < 31536000:     # less than 1 year
        points = 20
    elif crack_time_seconds < 3153600000:   # less than 100 years
        points = 25
    else:                                   # 100+ years
        points = 30

    # Hard fail: if cracked in under 1 hour, flag it
    hard_fail = crack_time_seconds < 3600

    suggestions = result["feedback"].get("suggestions", [])
    warning = result["feedback"].get("warning", "")

    return crack_time_display, points, hard_fail, suggestions, warning

def get_rating(score):
    """Convert numerical score to rating. Only 100 = EXCELLENT."""
    if score >= 100:
        return "EXCELLENT"
    elif score >= 80:
        return "STRONG"
    elif score >= 60:
        return "GOOD"
    elif score >= 40:
        return "FAIR"
    else:
        return "WEAK"

def main():
    print("=" * 60)
    print("PASSWORD STRENGTH VALIDATOR")
    print("=" * 60)
    print()
    
    logging.info("Password validator started")
    
    # Load blacklist once at startup
    blacklist = load_blacklist()
    
    if not blacklist:
        print("⚠ WARNING: Could not load password blacklist.")
        print(f"  Expected file: {BLACKLIST_FILE}")
        print("  Continuing without blacklist checking...\n")
    
    while True:
        # Get password from user
        password = input("Enter password to validate (or 'quit' to exit): ")
        
        # Allow user to exit
        if password.lower() in ['quit', 'exit', 'q']:
            logging.info("User exited validator")
            print("\nThank you for using Password Validator!")
            break
        
        # Validate the password
        score, max_score, failed_rules, passed_rules = validate_password(password, blacklist)

        # Crack time analysis (Rule 7: up to 30 points)
        crack_time, crack_points, hard_fail, suggestions, warning = analyze_crack_time(password)
        score += crack_points
        if crack_points > 0:
            passed_rules.append(f"✓ Crack time resistance ({crack_points}/30 points)")
        else:
            failed_rules.append("✗ Crack time resistance — cracks in under 1 second (0/30 points)")

        if hard_fail:
            rating = "WEAK"
        else:
            rating = get_rating(score)

        # Display results
        print("\n" + "-" * 60)
        print("VALIDATION RESULTS")
        print("-" * 60)
        print(f"Score: {score}/{max_score} ({rating})")
        if hard_fail:
            print("  *** Rating capped at WEAK — password cracks in under 1 hour ***")
        print(f"Estimated crack time (worst case): {crack_time}")
        print()

        if passed_rules:
            print("Passed Rules:")
            for rule in passed_rules:
                print(f"  {rule}")
            print()

        if failed_rules:
            print("Failed Rules:")
            for rule in failed_rules:
                print(f"  {rule}")
            print()

        # Provide recommendations
        has_recommendations = False
        if score < 100 or warning or suggestions:
            print("Recommendations:")
            has_recommendations = True
            if score < 50:
                print("  • This password is too weak for secure systems")
            if len(failed_rules) > 0:
                print("  • Address all failed rules above")
            if any("common password" in rule or "Have I Been Pwned" in rule for rule in failed_rules):
                print("  • CRITICAL: Use a unique password not found in breach databases")
            if warning:
                print(f"  • {warning}")
            for suggestion in suggestions:
                print(f"  • {suggestion}")
        if has_recommendations:
            print()

        logging.info(f"Password validation complete: Score={score}, Rating={rating}, Crack time={crack_time}")
        
        print("-" * 60)
        
        # Ask if user wants to check another password
        continue_check = input("\nCheck another password? (y/n): ").strip().lower()
        if continue_check not in ['y', 'yes']:
            logging.info("User chose to exit")
            print("\nThank you for using Password Validator!")
            break
        print()

if __name__ == "__main__":
    main()
