# Security Audit: password_validator.py

**Date:** 2026-02-15
**Scope:** `/home/ben/automation/password_validator.py` (197 lines)
**Application type:** Standalone CLI tool (not a web service)
**Summary risk score:** 4/10

---

## Finding Report

### Finding 1: Plaintext Password Logged to Disk

| Field | Value |
|-------|-------|
| **Severity** | **High** |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |
| **File** | `password_validator.py` |
| **Function** | `validate_password()` |
| **Line** | 102 |

**Evidence:**

```python
# Line 102
logging.warning(f"Password found in blacklist: '{password}'")
```

When a password matches the blacklist, the raw password is written to both `password_validator.log` and stderr. Any user or process with read access to the log file can harvest attempted passwords.

**Why it matters:** Users frequently reuse passwords or submit slight variations. Logging plaintext passwords creates a credential store on disk that persists indefinitely.

**Reproduction:**

```
$ echo -e "password\nn" | python3 password_validator.py
$ grep -i "password found" password_validator.log
# Output: 2026-02-15 ... - WARNING - Password found in blacklist: 'password'
```

**Remediation:**

```python
# Replace line 102
logging.warning("Password found in blacklist (rejected)")
```

Also audit lines 58 and 61 — they log the password *length*, which is acceptable, but confirm no future edits add the password value there.

**Defense in depth:** Set restrictive permissions on the log file (mode `0600`) and consider log rotation with automatic deletion.

---

### Finding 2: Log File Created with Default Permissions

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **CWE** | CWE-276 (Incorrect Default Permissions) |
| **File** | `password_validator.py` |
| **Function** | Module-level `logging.basicConfig()` |
| **Lines** | 13-20 |

**Evidence:**

```python
# Line 16
logging.FileHandler("password_validator.log"),
```

`FileHandler` creates `password_validator.log` in the current working directory with the process umask (typically `0644`). Combined with Finding 1, this makes logged passwords world-readable.

The log path is also relative, so the file lands wherever the script is invoked from — potentially a shared or web-accessible directory.

**Remediation:**

```python
import os

log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_validator.log")
file_handler = logging.FileHandler(log_path)
# Restrict after creation
os.chmod(log_path, 0o600)
```

---

### Finding 3: No Maximum Input Length

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **CWE** | CWE-770 (Allocation of Resources Without Limits) |
| **File** | `password_validator.py` |
| **Function** | `main()` and `validate_password()` |
| **Lines** | 141, 38-48 |

**Evidence:**

```python
# Line 141 — no length cap on input
password = input("Enter password to validate (or 'quit' to exit): ")

# Lines 64, 72, 80, 91 — iterate full string character-by-character
if any(c.isupper() for c in password):
```

A user (or piped input) can supply a multi-gigabyte string. `input()` will read it into memory, and then four `any()` passes iterate over it.

**Reproduction:**

```bash
python3 -c "print('A'*500_000_000)" | python3 password_validator.py
```

**Remediation:**

Add a max-length guard at the top of `validate_password()`:

```python
MAX_LENGTH = 128

def validate_password(password, blacklist):
    if not password:
        ...
    if not isinstance(password, str):
        ...
    if len(password) > MAX_LENGTH:
        logging.warning("Validation failed: Password exceeds maximum length")
        return 0, 100, [f"Password too long (max {MAX_LENGTH} characters)"], []
```

---

### Finding 4: Hardcoded Absolute Path for Blacklist

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **CWE** | CWE-426 (Untrusted Search Path) |
| **File** | `password_validator.py` |
| **Function** | Module-level constant |
| **Line** | 8 |

**Evidence:**

```python
BLACKLIST_FILE = "/home/ben/wordlists/seclists/Passwords/Common-Credentials/500-worst-passwords.txt"
```

This path is user-home-specific and will break on any other system or deployment. More critically, if the path is ever made configurable (e.g., via env var or CLI arg) without validation, it becomes a path traversal vector.

**Current risk:** Low — the path is a hardcoded constant, not user-controlled.

**Remediation:**

```python
import os

BLACKLIST_FILE = os.environ.get(
    "PV_BLACKLIST_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "500-worst-passwords.txt")
)
```

If made configurable, add path validation:

```python
def _safe_blacklist_path(path):
    resolved = os.path.realpath(path)
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"Blacklist not found: {resolved}")
    return resolved
```

---

### Finding 5: Silent Blacklist Bypass on Load Failure

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **CWE** | CWE-636 (Not Failing Securely) |
| **File** | `password_validator.py` |
| **Function** | `load_blacklist()` / `validate_password()` |
| **Lines** | 28-36, 100 |

**Evidence:**

```python
# Lines 28-36 — returns empty set on any error
except FileNotFoundError:
    ...
    return set()

# Line 100 — empty set skips the check entirely
if blacklist and password.lower() in blacklist:
```

If the blacklist file is missing, moved, or unreadable, every password silently passes the blacklist check. The `main()` function prints a warning (line 135-137), but non-interactive callers importing `validate_password()` directly will never see it.

**Remediation:**

Make the blacklist-missing state explicit in the return value, or raise on failure when used as a library:

```python
def validate_password(password, blacklist):
    ...
    # Rule 6
    if blacklist is None or len(blacklist) == 0:
        failed_rules.append("⚠ Blacklist unavailable — cannot verify against common passwords")
        logging.warning("Blacklist check SKIPPED: no blacklist loaded")
    elif password.lower() in blacklist:
        failed_rules.append("✗ Found in common password database (CRITICAL)")
        logging.warning("Password found in blacklist (rejected)")
    else:
        score += 20
        passed_rules.append("✓ Not in common password database")
```

---

## Validation Matrix

This is a CLI tool with no network endpoints. The matrix below maps the requested checks to the actual codebase.

| Check Category | Status | Notes |
|---|---|---|
| **SQL Injection** | N/A | No database or SQL usage anywhere in file |
| **NoSQL Injection** | N/A | No MongoDB or document-store usage |
| **Command Injection** | Pass | No use of `subprocess`, `os.system`, `os.popen`, or `eval()` |
| **XSS Prevention** | N/A | CLI application; no HTML output or web responses |
| **XXE (XML External Entity)** | N/A | No XML parsing |
| **Path Traversal** | Pass (conditional) | `BLACKLIST_FILE` is hardcoded (safe now); would need validation if made configurable |
| **Request Validation — Body size limits** | **Fail** | No max length on password input (Finding 3) |
| **Request Validation — Type checking** | Pass | `isinstance(password, str)` check at line 45 |
| **Request Validation — Required field validation** | Pass | Empty/None check at line 40 |
| **Request Validation — Parameter pollution** | N/A | No HTTP parameters |
| **Sensitive data in logs** | **Fail** | Plaintext password logged (Finding 1) |
| **Log file permissions** | **Fail** | Default umask, world-readable (Finding 2) |
| **Fail-secure design** | **Fail** | Blacklist failure silently skips check (Finding 5) |

---

## Checklist Diff

| Item | Result |
|---|---|
| SQL Injection | N/A — no SQL |
| NoSQL Injection | N/A — no NoSQL |
| Command Injection | **Pass** |
| XSS Prevention | N/A — CLI only |
| XXE | N/A — no XML |
| Path Traversal | **Pass** (conditional) |
| Body size / input limits | **Fail** |
| Type checking | **Pass** |
| Required field validation | **Pass** |
| Parameter pollution | N/A |

---

## Summary

| Metric | Value |
|---|---|
| **Risk Score** | **4/10** |
| **Critical findings** | 0 |
| **High findings** | 1 |
| **Medium findings** | 2 |
| **Low findings** | 2 |

The score is moderate because this is a standalone CLI tool with no network exposure. The primary real risk is credential leakage through log files (Findings 1 + 2 combined). Most web-specific attack classes (SQLi, XSS, XXE, NoSQL injection) do not apply.

---

## Top 5 Prioritized Fixes

1. **Remove plaintext password from log output** (Finding 1) — single-line change, eliminates the highest-severity issue.
2. **Restrict log file permissions to `0600`** (Finding 2) — limits exposure of any remaining sensitive log content.
3. **Add `MAX_LENGTH` guard** (Finding 3) — prevents resource exhaustion from oversized input.
4. **Make blacklist failure explicit** (Finding 5) — prevents silent security degradation when the wordlist is unavailable.
5. **Use relative/configurable blacklist path with validation** (Finding 4) — improves portability and prevents future path traversal if the path is ever user-supplied.
