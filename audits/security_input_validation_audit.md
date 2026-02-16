# Security & Input Validation Audit: Password Validator

**Date:** 2026-02-15
**Auditor:** Claude Opus 4.6 (automated)
**Scope:** `/home/ben/Projects/password_validator/password_validator.py` (329 lines), `/home/ben/Projects/password_validator/app.py` (197 lines)
**Application type:** Python CLI tool + Streamlit web UI with outbound HIBP API calls
**Prior audit:** `audits/password_validator_audit.md` (recovered from git history at commit `75b8467^`)
**Summary risk score:** 5/10

---

## Executive Summary

The codebase has evolved significantly since the prior audit. Several previous findings have been remediated:

- **Finding 1 (plaintext password in logs):** Fixed. Passwords are no longer logged.
- **Finding 2 (log file permissions):** Fixed. `os.chmod(log_path, 0o600)` is applied at line 32.
- **Finding 3 (no max input length):** Fixed. `MAX_LENGTH = 128` guard at lines 19, 95-97.
- **Finding 4 (hardcoded absolute path):** Fixed. Path is now relative to `__file__` with `PV_BLACKLIST_FILE` env override (lines 13-16).
- **Finding 5 (silent blacklist bypass):** Fixed. Blacklist unavailability is now flagged as a failed rule (lines 155-158).

New attack surface has been introduced: a **Streamlit web frontend** (`app.py`) with `unsafe_allow_html=True` usage, and an **outbound HTTP integration** with the HIBP Pwned Passwords API. This audit focuses on the current state of both files.

---

## Finding Report

### Finding 1: Stored XSS via `unsafe_allow_html=True` Rendering of Validation Rule Text

| Field | Value |
|-------|-------|
| **Severity** | **High** |
| **CWE** | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| **File** | `app.py` |
| **Function** | Validation results display block |
| **Lines** | 169, 177 |

**Evidence:**

```python
# app.py, line 169
for rule in passed_rules:
    st.markdown(f'<p style="color:#22c55e; margin:0.25rem 0;">{rule}</p>', unsafe_allow_html=True)

# app.py, line 177
for rule in failed_rules:
    st.markdown(f'<p style="color:#ef4444; margin:0.25rem 0;">{rule}</p>', unsafe_allow_html=True)
```

The `passed_rules` and `failed_rules` lists are constructed in `validate_password()` (in `password_validator.py`) and `analyze_crack_time()`. Several rule strings embed data derived from the user's password input:

- Line 107 (`password_validator.py`): `f"... ({len(password)} characters)"` -- safe (integer only).
- Line 110: `f"... (needs {MIN_LENGTH}+ characters, has {len(password)})"` -- safe (integer only).
- Line 146: `f"... ({SPECIAL_CHARS})"` -- embeds the constant `!@#$%^&*()_+-=[]{}|;:,.<>?` which contains `<>` characters. These are **static** and not user-controlled, but they will be interpreted as HTML tags by `unsafe_allow_html=True`, potentially causing rendering issues.
- Line 173: `f"... ({hibp_count:,} breaches)"` -- safe (integer only).

The `zxcvbn` library also contributes strings via `suggestions` and `warning` in `analyze_crack_time()`, which flow into `app.py` line 196:

```python
# app.py, line 196
for rec in recs:
    st.markdown(f"- {rec}")
```

This line does **not** use `unsafe_allow_html=True`, so zxcvbn output is safe here. However, `zxcvbn` `warning` and `suggestions` are library-generated strings that could theoretically contain user-influenced substrings in future versions.

**Current exploitability:** Low-to-Medium. The rule text strings do not embed the raw password value. The `SPECIAL_CHARS` constant containing `<>` is the most concrete issue -- it produces malformed HTML `<>?` inside a `<p>` tag. A true stored XSS would require a code change that interpolates user input into these rule strings, but the `unsafe_allow_html=True` pattern creates a latent vulnerability that is one f-string edit away from becoming critical.

**Reproduction (rendering issue with `SPECIAL_CHARS`):**

1. Run `streamlit run app.py`
2. Enter a password without special characters (e.g., `abcdefghijklmn`)
3. Click Validate
4. Observe the "No special characters" failed rule -- the `<>?` portion of `SPECIAL_CHARS` is interpreted as an HTML tag and may not render correctly.

**Remediation:**

Replace `unsafe_allow_html=True` with Streamlit-native styling, or HTML-escape all interpolated values:

```python
import html

# Option A: Use html.escape (drop-in fix)
for rule in passed_rules:
    st.markdown(
        f'<p style="color:#22c55e; margin:0.25rem 0;">{html.escape(rule)}</p>',
        unsafe_allow_html=True,
    )
for rule in failed_rules:
    st.markdown(
        f'<p style="color:#ef4444; margin:0.25rem 0;">{html.escape(rule)}</p>',
        unsafe_allow_html=True,
    )

# Option B: Avoid unsafe_allow_html entirely (preferred)
# Use st.success / st.error / st.write with emoji prefixes for color
for rule in passed_rules:
    st.write(f":green[{rule}]")
for rule in failed_rules:
    st.write(f":red[{rule}]")
```

**Defense in depth:** Adopt a project-wide rule: never pass user-influenced data to `unsafe_allow_html=True` without `html.escape()`. Consider a linting rule (e.g., `ruff` custom check or `semgrep` rule) that flags `unsafe_allow_html=True`.

---

### Finding 2: CSS Injection via `unsafe_allow_html=True` in Style Block

| Field | Value |
|-------|-------|
| **Severity** | **Medium** |
| **CWE** | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| **File** | `app.py` |
| **Function** | `inject_progress_color()` |
| **Lines** | 58-67 |

**Evidence:**

```python
def inject_progress_color(rating):
    color = RATING_COLORS.get(rating, "#6b7280")
    st.markdown(
        f"""<style>
        .stProgress > div > div > div > div {{
            background-color: {color};
        }}
        </style>""",
        unsafe_allow_html=True,
    )
```

The `color` variable is sourced from `RATING_COLORS.get(rating, "#6b7280")`. The `rating` value comes from `get_rating(score)` which returns only one of five hardcoded strings (`EXCELLENT`, `STRONG`, `GOOD`, `FAIR`, `WEAK`), or is hardcoded to `"WEAK"` on `hard_fail`. All five map to valid entries in `RATING_COLORS`, so the fallback `"#6b7280"` is never reached through normal code paths.

**Current exploitability:** None through normal usage. The `rating` value is never user-controlled. However, the pattern of injecting values into `<style>` blocks via `unsafe_allow_html=True` is fragile. If `rating` or `color` were ever derived from user input, this would allow CSS injection or style-based exfiltration attacks.

**Remediation:**

Validate the color against an allowlist before injection:

```python
def inject_progress_color(rating):
    color = RATING_COLORS.get(rating)
    if color is None:
        return  # Unknown rating; skip style injection
    st.markdown(
        f"""<style>
        .stProgress > div > div > div > div {{
            background-color: {color};
        }}
        </style>""",
        unsafe_allow_html=True,
    )
```

---

### Finding 3: Rating Badge Renders with `unsafe_allow_html=True` (Hardened but Fragile)

| Field | Value |
|-------|-------|
| **Severity** | **Low** |
| **CWE** | CWE-79 |
| **File** | `app.py` |
| **Lines** | 149-155 |

**Evidence:**

```python
with col_rating:
    color = RATING_COLORS.get(rating, "#6b7280")
    st.markdown(
        f'<div style="text-align:center; padding:1.5rem 0;">'
        f'<span style="background:{color}; color:white; padding:0.5rem 1.5rem; '
        f'border-radius:0.5rem; font-size:1.5rem; font-weight:bold;">'
        f"{rating}</span></div>",
        unsafe_allow_html=True,
    )
```

Both `color` and `rating` are interpolated into raw HTML. As analyzed above, `rating` is one of five hardcoded strings and `color` is dictionary-looked-up from those strings. Neither is user-controlled.

**Current exploitability:** None. This is a defense-in-depth concern only.

**Remediation:** Same as Finding 2 -- ensure the allowlist is enforced and that `rating` can never be user-supplied:

```python
import html

rating_safe = html.escape(rating)
color = RATING_COLORS.get(rating, "#6b7280")
```

---

### Finding 4: HIBP API Failure Mode -- Fail-Open Design

| Field | Value |
|-------|-------|
| **Severity** | **Medium** |
| **CWE** | CWE-636 (Not Failing Securely) |
| **File** | `password_validator.py` |
| **Function** | `check_hibp()`, `validate_password()` |
| **Lines** | 66-73, 168-171 |

**Evidence:**

```python
# password_validator.py, lines 71-73
except requests.RequestException as e:
    logging.warning(f"HIBP API request failed: {e}")
    return False, None, str(e)
```

```python
# password_validator.py, lines 168-171
if hibp_error:
    failed_rules.append("... HIBP API unavailable ...")
    logging.warning(f"HIBP check SKIPPED: {hibp_error}")
    hibp_clean = False
```

When the HIBP API is unreachable (network error, timeout, 5xx), `check_hibp()` returns `(False, None, error_string)`. In `validate_password()`, this sets `hibp_clean = False` and adds a warning to `failed_rules`, which means the 15-point "not in breach databases" bonus is denied. This is a **fail-closed** design for scoring, which is correct.

However, the failed rule text uses the warning icon ("...unavailable...") rather than marking it as a hard failure. A user might dismiss the warning and use the password anyway, not realizing the breach check was skipped. The password still receives a potentially passing score (up to 85/100) without the breach check.

**Remediation:**

Consider adding a hard fail or explicit UI warning when the HIBP check is skipped:

```python
# In app.py, after validation results are computed:
if any("HIBP API unavailable" in r for r in failed_rules):
    st.warning(
        "The breach database check could not be completed. "
        "This password has NOT been verified against known breaches. "
        "Retry when you have network connectivity."
    )
```

---

### Finding 5: Path Traversal via `PV_BLACKLIST_FILE` Environment Variable

| Field | Value |
|-------|-------|
| **Severity** | **Medium** |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **File** | `password_validator.py` |
| **Function** | Module-level constant, `load_blacklist()` |
| **Lines** | 13-16, 34-48 |

**Evidence:**

```python
# password_validator.py, lines 13-16
BLACKLIST_FILE = os.environ.get(
    "PV_BLACKLIST_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockyou.txt")
)
```

The `PV_BLACKLIST_FILE` environment variable is read without path validation. An attacker who controls the environment (e.g., in a shared hosting scenario, a container with injectable env vars, or a CI/CD pipeline) can point this to any file on the filesystem.

The file is read and loaded into a set (`load_blacklist()`, line 37). While this does not directly leak file contents to the user (the set is only used for membership testing), it does:

1. Confirm the existence of arbitrary files (side-channel via timing or log messages).
2. Load arbitrary file contents into memory (potential DoS with very large files).
3. In the Streamlit deployment, the blacklist size is logged (`Loaded {len(blacklist)} passwords`), which leaks the line count of the target file.

**Exploitability:** Requires the attacker to control the process environment. In a containerized or shared-hosting deployment, this is plausible.

**Reproduction:**

```bash
PV_BLACKLIST_FILE=/etc/shadow streamlit run app.py
# Logs will show "Loaded N passwords from blacklist" or "Permission denied"
# confirming /etc/shadow existence and readability
```

**Remediation:**

Add path validation:

```python
import os

def _validated_blacklist_path(path):
    """Ensure the blacklist path points to a regular file in an expected location."""
    resolved = os.path.realpath(path)
    # Optional: restrict to a specific directory
    # allowed_dir = os.path.dirname(os.path.abspath(__file__))
    # if not resolved.startswith(allowed_dir):
    #     raise ValueError(f"Blacklist path outside allowed directory: {resolved}")
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"Blacklist not found: {resolved}")
    return resolved

BLACKLIST_FILE = _validated_blacklist_path(
    os.environ.get(
        "PV_BLACKLIST_FILE",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockyou.txt"),
    )
)
```

---

### Finding 6: No HTTPS Certificate Pinning or User-Agent on HIBP API Requests

| Field | Value |
|-------|-------|
| **Severity** | **Low** |
| **CWE** | CWE-295 (Improper Certificate Validation) |
| **File** | `password_validator.py` |
| **Function** | `check_hibp()` |
| **Lines** | 66-70 |

**Evidence:**

```python
resp = requests.get(
    f"https://api.pwnedpasswords.com/range/{prefix}",
    timeout=5,
)
```

The HIBP API [requests](https://haveibeenpwned.com/API/v3#PwnedPasswords) that clients send a descriptive `User-Agent` header. While the API currently works without one, omitting it may lead to rate-limiting or blocking in the future. Troy Hunt has previously discussed blocking requests without user agents.

Additionally, the `requests` library uses the system CA bundle by default. This is generally fine, but there is no certificate pinning. In a compromised network environment, an MITM could intercept the partial SHA-1 hash prefix.

**Risk context:** The k-anonymity design means only 5 hex characters of the SHA-1 hash leave the machine. Even with MITM, the attacker learns very little about the actual password.

**Remediation:**

```python
HIBP_HEADERS = {
    "User-Agent": "PasswordValidator/1.0 (Streamlit; +https://github.com/example/password_validator)",
    "Add-Padding": "true",  # Recommended: pads responses to prevent length-based inference
}

resp = requests.get(
    f"https://api.pwnedpasswords.com/range/{prefix}",
    timeout=5,
    headers=HIBP_HEADERS,
)
```

The `Add-Padding: true` header is a defense-in-depth measure that prevents network observers from inferring information based on response size.

---

### Finding 7: Sensitive Data Exposure -- Passwords Potentially Visible in Streamlit Session State

| Field | Value |
|-------|-------|
| **Severity** | **Medium** |
| **CWE** | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) |
| **File** | `app.py` |
| **Function** | Password input and generator blocks |
| **Lines** | 80-85, 107, 112 |

**Evidence:**

```python
# app.py, line 80-85
password = st.text_input(
    "Enter a password",
    type="default" if show else "password",
    max_chars=MAX_LENGTH,
    key="password_input",
)

# app.py, line 107
st.session_state["generated_password"] = generated

# app.py, line 112
st.session_state["password_input"] = st.session_state["generated_password"]
```

Streamlit stores widget state in `st.session_state`, which is held in server memory for the duration of the session. Passwords (both user-entered and generated) persist in `st.session_state` as:
- `st.session_state["password_input"]` -- the user-entered password
- `st.session_state["generated_password"]` -- generated passwords

These values persist in server memory until the session is garbage-collected. In a shared-server deployment, if another vulnerability allows session state inspection (e.g., Streamlit debug mode, memory dump), passwords could be exposed.

Additionally, when `show = True` (line 79), `type="default"` is used, which sends the password as visible text. This is user-intentional but worth noting.

**Remediation:**

Clear generated passwords from session state after use:

```python
if st.button("Use this password"):
    st.session_state["password_input"] = st.session_state["generated_password"]
    del st.session_state["generated_password"]
    st.rerun()
```

This is already done (line 113). For extra caution, also clear after validation:

```python
# After validation completes, consider clearing the password from session state
# if the user has finished reviewing results.
```

This is a low-practical-risk finding given Streamlit's architecture, but important for deployments behind a reverse proxy serving multiple users.

---

### Finding 8: No Rate Limiting on Validation Endpoint

| Field | Value |
|-------|-------|
| **Severity** | **Low** |
| **CWE** | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| **File** | `app.py` |
| **Function** | Validation trigger block |
| **Lines** | 117-197 |

**Evidence:**

The Streamlit app has no rate limiting. Each "Validate" click triggers:
1. `validate_password()` -- iterates the full blacklist set (14M+ entries for membership test -- O(1) per check, but still).
2. `check_hibp()` -- makes an outbound HTTP request to the HIBP API.
3. `analyze_crack_time()` -- runs zxcvbn analysis.

An automated client sending rapid requests could:
- Exhaust outbound HIBP API rate limits (and get the server IP blocked by HIBP).
- Cause excessive CPU usage from repeated zxcvbn computations.
- Fill the log file with validation entries.

**Remediation:**

Streamlit does not natively support rate limiting, but you can add basic throttling:

```python
import time

# Add at the top of the validation block
if "last_validate_time" in st.session_state:
    elapsed = time.time() - st.session_state["last_validate_time"]
    if elapsed < 1.0:  # Minimum 1 second between validations
        st.warning("Please wait before validating again.")
        st.stop()
st.session_state["last_validate_time"] = time.time()
```

For production deployments, place Streamlit behind a reverse proxy (nginx/Caddy) with request rate limiting.

---

### Finding 9: Log Injection via Error Messages

| Field | Value |
|-------|-------|
| **Severity** | **Low** |
| **CWE** | CWE-117 (Improper Output Neutralization for Logs) |
| **File** | `password_validator.py` |
| **Function** | `check_hibp()`, `load_blacklist()` |
| **Lines** | 41-47, 72 |

**Evidence:**

```python
# password_validator.py, line 47
logging.error(f"Unexpected error loading blacklist: {e}")

# password_validator.py, line 72
logging.warning(f"HIBP API request failed: {e}")
```

Exception messages (`{e}`) are logged without sanitization. While Python's `logging` module does not interpret control characters, the exception text could contain newlines or ANSI escape sequences that could:
- Forge log entries (newline injection).
- Corrupt terminal output (ANSI escape injection).

**Current exploitability:** Very low. Exception messages come from Python standard library (`FileNotFoundError`, `requests.RequestException`), not from user input. However, the HIBP API error could theoretically contain server-supplied text.

**Remediation:**

Sanitize or repr-encode exception messages:

```python
logging.warning(f"HIBP API request failed: {e!r}")
```

Using `!r` wraps the string in quotes and escapes special characters.

---

### Finding 10: No Content Security Policy or Security Headers for Streamlit Deployment

| Field | Value |
|-------|-------|
| **Severity** | **Low** |
| **CWE** | CWE-1021 (Improper Restriction of Rendered UI Layers) |
| **File** | N/A (deployment configuration) |
| **Function** | N/A |
| **Lines** | N/A |

**Evidence:**

There is no `.streamlit/config.toml` file in the project. Streamlit's default configuration:
- Serves over HTTP (not HTTPS) on `localhost:8501`.
- Does not set `Content-Security-Policy`, `X-Frame-Options`, or other security headers.
- Allows CORS from any origin by default.
- Has `server.enableXsrfProtection = true` by default (good).

If the Streamlit app is exposed beyond localhost (e.g., via `--server.address 0.0.0.0` or a reverse proxy), it is vulnerable to clickjacking and has no CSP to mitigate XSS.

**Remediation:**

Create `.streamlit/config.toml`:

```toml
[server]
enableCORS = false
enableXsrfProtection = true

[browser]
gatherUsageStats = false
```

For production, deploy behind a reverse proxy that sets:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Validation Matrix

| Check Category | Status | Notes |
|---|---|---|
| **SQL Injection** | **N/A** | No database, ORM, or SQL usage anywhere in either file. |
| **NoSQL Injection** | **N/A** | No MongoDB, Redis, or document-store usage. |
| **Command Injection** | **Pass** | No use of `subprocess`, `os.system`, `os.popen`, `eval()`, or `exec()`. The `os` module is used only for `os.environ.get`, `os.path.*`, and `os.chmod`. |
| **XSS Prevention** | **Fail** | Three instances of `unsafe_allow_html=True` in `app.py` (lines 61-67, 149-155, 169, 177). While current data flow does not inject user input, the `SPECIAL_CHARS` constant containing `<>` is rendered as HTML, and the pattern is fragile. See Findings 1-3. |
| **XXE (XML External Entity)** | **N/A** | No XML parsing, no `lxml`, `xml.etree`, `xml.sax`, or similar imports. No file upload handling. |
| **Path Traversal** | **Fail (conditional)** | `PV_BLACKLIST_FILE` env var is used without path validation. See Finding 5. Default path (relative to `__file__`) is safe. |
| **Request Validation -- Body size limits** | **Pass** | `MAX_LENGTH = 128` enforced in `validate_password()` (line 95) and `max_chars=MAX_LENGTH` on Streamlit input (line 83). |
| **Request Validation -- Parameter pollution** | **N/A** | No HTTP query parameter handling. Streamlit manages its own WebSocket protocol. |
| **Request Validation -- Type checking** | **Pass** | `isinstance(password, str)` guard at line 90. |
| **Request Validation -- Required field validation** | **Pass** | Empty/None check at line 85 (`password_validator.py`) and line 118-120 (`app.py`). |
| **Sensitive data in logs** | **Pass** | Prior Finding 1 is remediated. Passwords are no longer logged. Log messages reference only metadata (lengths, pass/fail status, counts). |
| **Log file permissions** | **Pass** | `os.chmod(log_path, 0o600)` at line 32. |
| **Fail-secure design** | **Pass (partial)** | Blacklist unavailability is flagged as a failed rule (lines 155-158). HIBP failure denies the 15-point bonus but allows up to 85/100 score. See Finding 4. |
| **SSRF** | **N/A** | The only outbound HTTP call is to a hardcoded HIBP API URL (`https://api.pwnedpasswords.com/range/{prefix}`). The `{prefix}` is 5 hex characters derived from SHA-1, not user-controlled URLs. |
| **Streamlit `unsafe_allow_html`** | **Fail** | Three distinct usage sites. See Findings 1-3. |
| **Secrets in code** | **Pass** | No API keys, tokens, or credentials in source. HIBP Pwned Passwords API does not require authentication. |
| **Dependency security** | **Unable to verify** | No `requirements.txt` or `pyproject.toml` with pinned versions. Cannot verify whether installed versions of `requests`, `streamlit`, or `zxcvbn` have known CVEs. |

---

## Summary

| Metric | Value |
|---|---|
| **Risk Score** | **5/10** |
| **Critical findings** | 0 |
| **High findings** | 1 (XSS vector via `unsafe_allow_html`) |
| **Medium findings** | 3 (CSS injection pattern, HIBP fail-open, path traversal via env var) |
| **Low findings** | 5 (HIBP headers, session state, rate limiting, log injection, missing security headers) |
| **Not Applicable** | SQL Injection, NoSQL Injection, XXE, SSRF, Parameter Pollution |

The risk score increased from 4/10 to 5/10 compared to the prior audit. The prior high-severity findings (plaintext password logging, log file permissions) have been remediated. The new Streamlit frontend introduces a new attack surface category (XSS via `unsafe_allow_html=True`) and the HIBP integration adds an outbound network dependency that fails open. The overall posture is reasonable for a local-use tool but requires hardening before any shared or production deployment.

---

## Top 5 Prioritized Fixes

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| **1** | **HTML-escape all values passed to `unsafe_allow_html=True`** (Finding 1) | Low -- add `import html` and wrap interpolated values in `html.escape()` at lines 169, 177 in `app.py`. Or migrate to Streamlit's `:green[]` / `:red[]` markdown syntax. | Eliminates the highest-severity XSS vector and fixes the `SPECIAL_CHARS` rendering bug. |
| **2** | **Add path validation for `PV_BLACKLIST_FILE`** (Finding 5) | Low -- add a validation function that resolves and checks the path before use. | Prevents path traversal and information disclosure via environment variable injection. |
| **3** | **Add `User-Agent` and `Add-Padding` headers to HIBP requests** (Finding 6) | Trivial -- add a `headers=` dict to the `requests.get()` call. | Prevents future API blocking, adds defense against response-size inference attacks. |
| **4** | **Add explicit UI warning when HIBP check is skipped** (Finding 4) | Low -- add an `st.warning()` in `app.py` when the HIBP check fails. | Prevents users from unknowingly using breached passwords when the API is unreachable. |
| **5** | **Create `.streamlit/config.toml` with security settings and pin dependency versions** (Findings 10, dependency security) | Low -- create config file, create `requirements.txt` with pinned versions. | Hardens the deployment posture and enables reproducible, auditable builds. |

---

## Appendix A: `unsafe_allow_html=True` Usage Inventory

| File | Line(s) | Content Interpolated | User-Controlled? | Risk |
|------|---------|---------------------|-------------------|------|
| `app.py` | 61-67 | `{color}` from `RATING_COLORS` dict | No | Low (CSS injection if dict is bypassed) |
| `app.py` | 149-155 | `{color}` and `{rating}` | No | Low (hardcoded values only) |
| `app.py` | 169 | `{rule}` from `passed_rules` list | Indirect -- contains `SPECIAL_CHARS` with `<>` | **Medium** (HTML parsing of `<>` characters) |
| `app.py` | 177 | `{rule}` from `failed_rules` list | Indirect -- contains `SPECIAL_CHARS` with `<>` | **Medium** (HTML parsing of `<>` characters) |

---

## Appendix B: Prior Audit Remediation Status

| Prior Finding | Status | Evidence |
|---|---|---|
| F1: Plaintext password in logs | **Remediated** | Line 162: `logging.warning("Password found in blacklist (rejected)")` -- no password value logged |
| F2: Log file default permissions | **Remediated** | Line 32: `os.chmod(log_path, 0o600)` |
| F3: No max input length | **Remediated** | Lines 19, 95-97: `MAX_LENGTH = 128` with guard clause; line 83 `app.py`: `max_chars=MAX_LENGTH` |
| F4: Hardcoded absolute path | **Remediated** | Lines 13-16: `PV_BLACKLIST_FILE` env var with `__file__`-relative default |
| F5: Silent blacklist bypass | **Remediated** | Lines 155-158: Blacklist unavailability explicitly flagged as failed rule |
