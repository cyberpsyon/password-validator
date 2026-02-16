# Code Complexity Audit

**Project:** `/home/ben/Projects/password_validator/`
**Date:** 2026-02-15
**Files analyzed:** `password_validator.py` (329 lines), `app.py` (197 lines)

---

## 1. Cyclomatic Complexity

Cyclomatic complexity (CC) = number of decision points + 1. Decision points counted: `if`, `elif`, `else`, `for`, `while`, `and`, `or`, `except`, ternary expressions, and comprehension-level `if` filters.

### 1.1 Per-Function Cyclomatic Complexity

| File | Function | Lines | Decision Points | CC | Flag |
|---|---|---|---|---|---|
| `password_validator.py` | `load_blacklist()` | 34-48 | `try`, `except` x3, `if` (comp filter) | 5 | OK |
| `password_validator.py` | `check_hibp()` | 50-80 | `try`, `except`, `for`, `if` | 5 | OK |
| `password_validator.py` | `validate_password()` | 83-185 | `if` x13, `elif` x2, `else` x7, `any()` x4 (each contains an `if` in generator), `or` x1, `and` x1 | **28** | **FLAGGED** |
| `password_validator.py` | `analyze_crack_time()` | 187-219 | `if` x1, `elif` x5, `else` x1 | 8 | OK |
| `password_validator.py` | `get_rating()` | 221-232 | `if`, `elif` x3, `else` | 6 | OK |
| `password_validator.py` | `main()` | 234-329 | `if` x7, `while`, `for` x2, `any()` w/ `or` inside, `not in` | **14** | **FLAGGED** |
| `app.py` | `get_blacklist()` | 29-30 | none | 1 | OK |
| `app.py` | `generate_password()` | 33-55 | `if` x5, `for` (list comp) | 7 | OK |
| `app.py` | `inject_progress_color()` | 58-67 | none | 1 | OK |
| `app.py` | top-level script body | 70-197 | `if` x10, `else` x3, `for` x3, `any()` w/ `or`, `not` | **19** | **FLAGGED** |

### 1.2 Flagged Functions (CC > 10)

#### Finding 1: `validate_password()` -- CC 28

- **File:** `/home/ben/Projects/password_validator/password_validator.py`
- **Lines:** 83-185
- **Importance:** 8/10
- **Detail:** This function has 28 decision paths. It checks 7 password rules inline, each with an if/else pair, plus guard clauses, blacklist null-check, HIBP error branching, and a compound `and` condition. The linear chain of if/else blocks is the primary driver.
- **Max nesting depth:** 2 (the `elif password.lower() in blacklist` at line 159 is nested inside the outer `elif` block that begins at line 155).

**Remediation -- extract each rule into its own function:**

```python
# Drop-in rule-checker pattern (replace lines 104-184)

def _check_length(password):
    if len(password) >= MIN_LENGTH:
        logging.info(f"Length check PASSED: {len(password)} chars")
        return 15, f"Length requirement met ({len(password)} characters)", None
    logging.info(f"Length check FAILED: {len(password)} chars (needs {MIN_LENGTH}+)")
    return 0, None, f"Too short (needs {MIN_LENGTH}+ characters, has {len(password)})"

def _check_uppercase(password):
    if any(c.isupper() for c in password):
        logging.info("Uppercase check PASSED")
        return 10, "Contains uppercase letters", None
    logging.info("Uppercase check FAILED")
    return 0, None, "No uppercase letters"

# ... same pattern for lowercase, digits, special chars, blacklist, HIBP ...

# Then validate_password becomes:
def validate_password(password, blacklist):
    if not password:
        logging.warning("Validation failed: Empty password provided")
        return 0, 100, ["Password cannot be empty"], []
    if not isinstance(password, str):
        logging.warning("Validation failed: Password must be a string")
        return 0, 100, ["Password must be text"], []
    if len(password) > MAX_LENGTH:
        logging.warning("Validation failed: Password exceeds maximum length")
        return 0, 100, [f"Password too long (max {MAX_LENGTH} characters)"], []

    rules = [
        _check_length, _check_uppercase, _check_lowercase,
        _check_digits, _check_special,
    ]
    score, passed, failed = 0, [], []
    for rule in rules:
        pts, ok_msg, fail_msg = rule(password)
        score += pts
        (passed if ok_msg else failed).append(ok_msg or fail_msg)
    # blacklist/HIBP handled separately due to extra args
    return score, 100, failed, passed
```

This reduces `validate_password` CC from 28 to approximately 6.

---

#### Finding 2: `main()` -- CC 14

- **File:** `/home/ben/Projects/password_validator/password_validator.py`
- **Lines:** 234-329
- **Importance:** 6/10
- **Detail:** The `while True` loop with exit conditions, result formatting, and recommendation logic all live in one function. Nesting depth reaches 3 (while > if > for).

**Remediation -- extract display and recommendation logic:**

```python
def _print_results(score, max_score, rating, hard_fail, crack_time,
                   passed_rules, failed_rules):
    """Lines 277-314 extracted."""
    print("\n" + "-" * 60)
    print("VALIDATION RESULTS")
    # ... existing display code ...

def _print_recommendations(score, failed_rules, warning, suggestions):
    """Lines 299-314 extracted."""
    # ... existing recommendation code ...

def main():
    # setup ...
    while True:
        password = input(...)
        if password.lower() in ['quit', 'exit', 'q']:
            break
        score, max_score, failed_rules, passed_rules = validate_password(password, blacklist)
        crack_time, crack_points, hard_fail, suggestions, warning = analyze_crack_time(password)
        score += crack_points
        rating = "WEAK" if hard_fail else get_rating(score)
        _print_results(score, max_score, rating, hard_fail, crack_time,
                       passed_rules, failed_rules)
        _print_recommendations(score, failed_rules, warning, suggestions)
        if input("\nCheck another password? (y/n): ").strip().lower() not in ['y', 'yes']:
            break
```

---

#### Finding 3: `app.py` top-level script body -- CC 19

- **File:** `/home/ben/Projects/password_validator/app.py`
- **Lines:** 70-197
- **Importance:** 7/10
- **Detail:** All Streamlit UI and validation orchestration is written as top-level procedural code. It contains 10 `if` branches, 3 `for` loops, and an `any()` with an `or` inside it. Because Streamlit reruns the script on every interaction, this pattern is common but still harms testability and readability.

**Remediation -- wrap in functions:**

```python
def render_generator_panel(blacklist):
    """Lines 90-114 extracted."""
    with st.expander("Generate a strong password"):
        # ... existing generator code ...

def render_validation_results(password, blacklist):
    """Lines 117-197 extracted."""
    if not password:
        st.warning("Please enter a password first.")
        st.stop()
    # ... existing results code ...

# Top-level becomes:
blacklist = get_blacklist()
st.title("Password Strength Validator")
password = st.text_input(...)
validate_clicked = st.button("Validate", ...)
render_generator_panel(blacklist)
if validate_clicked:
    render_validation_results(password, blacklist)
```

### 1.3 Switch Statement Complexity

Python does not have `switch`/`case` statements in this codebase (no `match`/`case` from Python 3.10+). The if/elif chains in `analyze_crack_time()` (lines 198-211) and `get_rating()` (lines 223-232) act as switches over numeric ranges.

- `analyze_crack_time()` -- 7 branches (lines 198-211). Acceptable for a lookup table, but a data-driven approach would be cleaner.
- `get_rating()` -- 5 branches (lines 223-232). Acceptable.

**Remediation for `analyze_crack_time` threshold logic (optional, importance 3/10):**

```python
_CRACK_THRESHOLDS = [
    (1,          0),
    (60,         5),
    (3600,      10),
    (86400,     15),
    (31536000,  20),
    (3153600000, 25),
]

def _crack_points(seconds):
    for limit, pts in _CRACK_THRESHOLDS:
        if seconds < limit:
            return pts
    return 30
```

---

## 2. Cognitive Complexity

Cognitive complexity measures how hard code is for a human to read. It penalizes nesting, breaks in linear flow, and mixed abstraction levels more heavily than cyclomatic complexity does.

### 2.1 Per-Function Cognitive Complexity

| File | Function | Cognitive Complexity | Assessment |
|---|---|---|---|
| `password_validator.py` | `load_blacklist()` | 4 | Easy to follow |
| `password_validator.py` | `check_hibp()` | 4 | Easy; single responsibility |
| `password_validator.py` | `validate_password()` | **22** | **Hard to follow** |
| `password_validator.py` | `analyze_crack_time()` | 5 | Moderate; linear if/elif chain |
| `password_validator.py` | `get_rating()` | 3 | Trivial |
| `password_validator.py` | `main()` | **15** | **Moderate-hard** |
| `app.py` | `generate_password()` | 5 | Easy |
| `app.py` | `inject_progress_color()` | 1 | Trivial |
| `app.py` | top-level body | **18** | **Hard to follow** |

### 2.2 Detailed Findings

#### Finding 4: `validate_password()` cognitive complexity 22

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 83-185
- **Importance:** 8/10
- **Issues:**
  1. **Repetitive if/else blocks** (lines 104-147): Five nearly identical rule-check blocks. The reader must mentally verify each is the same pattern. This repetition inflates cognitive load without adding information.
  2. **Mixed abstraction levels**: Guard-clause validation (lines 85-97), character-class checking (lines 104-147), external API call via `check_hibp` (line 167), and scoring logic (line 180) all coexist in one function.
  3. **Compound boolean at line 155**: `if blacklist is None or len(blacklist) == 0` -- mixes None-check with emptiness. Idiomatic Python: `if not blacklist`.
  4. **Two boolean flags** (`blacklist_clean`, `hibp_clean`) tracked across 30 lines before being consumed at line 180 -- forces the reader to hold state mentally.

**Remediation:** Same rule-extraction refactor as Finding 1. Each rule becomes self-contained, and `validate_password` becomes a loop over rule functions. See the code snippet in Finding 1.

#### Finding 5: `main()` cognitive complexity 15

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 234-329
- **Importance:** 6/10
- **Issues:**
  1. **while True + break** pattern at line 250/258 and again at line 322/325 -- two separate exit points within the same loop.
  2. **Recommendation block** (lines 299-314) nests multiple `if` conditions and an `any()` with an `or` inside a genexp, all within the `while` body. Nesting depth: 3.
  3. **Mutable `has_recommendations` flag** (line 299) -- used only to conditionally print an empty line, which is a trivial concern that adds a branch.

**Remediation:** Extract `_print_results()` and `_print_recommendations()` as described in Finding 2. Collapse the two exit points into one by removing the second `continue_check` prompt (or unifying the loop exit logic).

#### Finding 6: `app.py` top-level cognitive complexity 18

- **File:** `/home/ben/Projects/password_validator/app.py`, lines 70-197
- **Importance:** 7/10
- **Issues:**
  1. **No function boundaries** -- 128 lines of top-level procedural code.
  2. **Deeply nested Streamlit column blocks** (lines 93-100, 140-155, 163-179) make it hard to see where one logical section ends and another begins.
  3. **Duplicated validation orchestration**: Lines 122-135 in `app.py` mirror lines 261-274 in `main()`. Same score-adjustment, crack-point appending, and hard-fail rating override logic.

**Remediation:** Extract into functions as shown in Finding 3. Also, move the shared score-adjustment/rating logic into `password_validator.py` as a new `full_validate()` wrapper:

```python
# password_validator.py -- new orchestrator
def full_validate(password, blacklist):
    """Run all checks and return final score, rating, and rule lists."""
    score, max_score, failed, passed = validate_password(password, blacklist)
    crack_time, crack_pts, hard_fail, suggestions, warning = analyze_crack_time(password)
    score += crack_pts
    if crack_pts > 0:
        passed.append(f"Crack time resistance ({crack_pts}/30 points)")
    else:
        failed.append("Crack time resistance -- cracks in under 1 second (0/30 points)")
    rating = "WEAK" if hard_fail else get_rating(score)
    return {
        "score": score, "max_score": max_score, "rating": rating,
        "hard_fail": hard_fail, "crack_time": crack_time,
        "passed": passed, "failed": failed,
        "suggestions": suggestions, "warning": warning,
    }
```

Then both `main()` and `app.py` call `full_validate()`, eliminating the duplication.

### 2.3 Recursive Calls

No recursive function calls exist in the codebase. Not applicable.

---

## 3. Lines of Code Metrics

### 3.1 File-Level Metrics

| File | Total Lines | Blank Lines | Comment/Docstring Lines | Code Lines | Flag |
|---|---|---|---|---|---|
| `password_validator.py` | 329 | 31 | 14 | 284 | OK (< 300 code lines) |
| `app.py` | 197 | 16 | 1 | 180 | OK |
| **Total** | **526** | **47** | **15** | **464** | |

Neither file exceeds 300 code lines. No file-level flag.

### 3.2 Per-Function Line Counts

| File | Function | Start | End | Lines | Flag |
|---|---|---|---|---|---|
| `password_validator.py` | `load_blacklist()` | 34 | 48 | 15 | OK |
| `password_validator.py` | `check_hibp()` | 50 | 80 | 31 | OK |
| `password_validator.py` | `validate_password()` | 83 | 185 | **103** | **FLAGGED (>50)** |
| `password_validator.py` | `analyze_crack_time()` | 187 | 219 | 33 | OK |
| `password_validator.py` | `get_rating()` | 221 | 232 | 12 | OK |
| `password_validator.py` | `main()` | 234 | 329 | **96** | **FLAGGED (>50)** |
| `app.py` | `generate_password()` | 33 | 55 | 23 | OK |
| `app.py` | `inject_progress_color()` | 58 | 67 | 10 | OK |
| `app.py` | top-level body | 70 | 197 | **128** | **FLAGGED (>50)** |

#### Finding 7: `validate_password()` is 103 lines

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 83-185
- **Importance:** 8/10
- **Remediation:** Extract individual rule checks as described in Finding 1. Target: reduce to ~20 lines.

#### Finding 8: `main()` is 96 lines

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 234-329
- **Importance:** 5/10
- **Remediation:** Extract `_print_results()` and `_print_recommendations()` as described in Finding 2. Target: reduce to ~30 lines.

#### Finding 9: `app.py` top-level body is 128 lines

- **File:** `/home/ben/Projects/password_validator/app.py`, lines 70-197
- **Importance:** 6/10
- **Remediation:** Extract `render_generator_panel()` and `render_validation_results()` as described in Finding 3. Target: reduce top-level to ~15 lines.

### 3.3 Candidates for Splitting

No individual file exceeds 300 lines, so file splitting is not critical. However, `password_validator.py` mixes three concerns:

1. **Validation logic** (rules, scoring) -- lines 34-232
2. **CLI interface** (`main()`) -- lines 234-329
3. **Module-level configuration and logging setup** -- lines 1-32

A clean split would be:

| Proposed File | Contents |
|---|---|
| `validator.py` | Rule functions, `validate_password()`, `analyze_crack_time()`, `get_rating()`, `full_validate()` |
| `config.py` | Constants (`MIN_LENGTH`, `MAX_LENGTH`, `SPECIAL_CHARS`, `BLACKLIST_FILE`), logging setup |
| `cli.py` | `main()` function and `if __name__ == "__main__"` |

Importance: 4/10 -- worthwhile for maintainability but not urgent at the current codebase size.

---

## 4. Coupling Metrics

### 4.1 Module Dependencies

#### `password_validator.py`

| Direction | Dependency | Type |
|---|---|---|
| Efferent (outgoing) | `hashlib` | stdlib |
| Efferent | `logging` | stdlib |
| Efferent | `os` | stdlib |
| Efferent | `requests` | third-party |
| Efferent | `zxcvbn` | third-party |
| Afferent (incoming) | `app.py` | project |

#### `app.py`

| Direction | Dependency | Type |
|---|---|---|
| Efferent | `secrets` | stdlib |
| Efferent | `string` | stdlib |
| Efferent | `streamlit` | third-party |
| Efferent | `password_validator` | project (imports 7 names) |

### 4.2 Coupling Counts

| Module | Ca (Afferent) | Ce (Efferent, non-stdlib) | Instability I = Ce/(Ca+Ce) |
|---|---|---|---|
| `password_validator.py` | 1 (`app.py`) | 2 (`requests`, `zxcvbn`) | 2/(1+2) = **0.67** |
| `app.py` | 0 | 2 (`streamlit`, `password_validator`) | 2/(0+2) = **1.00** |

**Interpretation:**
- `password_validator.py` has moderate instability (0.67). It depends on two external packages and is depended on by one module. This is acceptable for a core library module.
- `app.py` has maximum instability (1.00). Nothing depends on it, and it depends on everything. This is expected and correct for a top-level application/UI entry point -- leaf modules *should* be maximally unstable.

#### Finding 10: `app.py` imports 7 individual names from `password_validator`

- **File:** `/home/ben/Projects/password_validator/app.py`, lines 6-14
- **Importance:** 4/10
- **Detail:** `app.py` imports `load_blacklist`, `validate_password`, `analyze_crack_time`, `get_rating`, `MIN_LENGTH`, `MAX_LENGTH`, and `SPECIAL_CHARS`. This is a wide coupling surface. If `password_validator.py` exposed a `full_validate()` function (as proposed in Finding 6), `app.py` would need fewer imports.

**Remediation:**

```python
# app.py -- after full_validate() is created
from password_validator import (
    load_blacklist,
    full_validate,
    generate_password,   # if moved here
    MIN_LENGTH,
    MAX_LENGTH,
    SPECIAL_CHARS,
)
```

This reduces functional coupling from 4 functions to 2 (`load_blacklist`, `full_validate`).

### 4.3 Tightly Coupled Modules

There are only two modules, so tight coupling is structural rather than pathological. The main concern is the **duplicated orchestration logic** between `main()` (lines 261-274 of `password_validator.py`) and the top-level body of `app.py` (lines 122-135). Both independently call `validate_password` + `analyze_crack_time` + `get_rating` and perform identical score adjustments. This is temporal coupling: changes to the scoring pipeline must be applied in two places.

#### Finding 11: Duplicated validation orchestration

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 261-274
- **File:** `/home/ben/Projects/password_validator/app.py`, lines 122-135
- **Importance:** 7/10
- **Remediation:** Create `full_validate()` as shown in Finding 6 and call it from both `main()` and `app.py`.

---

## 5. Cohesion Analysis

### 5.1 Module Cohesion Assessment

#### `password_validator.py`

| Aspect | Assessment |
|---|---|
| **Functional grouping** | Mostly cohesive. All functions relate to password validation. |
| **Single responsibility** | **Violated.** The module handles validation logic, crack-time analysis, CLI I/O (`main()`), blacklist loading, external API calls (`check_hibp`), and logging configuration. |
| **Module focus** | The core purpose (password validation) is clear, but `main()` is an unrelated CLI concern. |
| **LCOM (Lack of Cohesion of Methods)** | Functions share data via arguments rather than shared state -- good. Module-level constants (`MIN_LENGTH`, `MAX_LENGTH`, `SPECIAL_CHARS`) are used by `validate_password`, `app.py`, and `main()`. Module-level logging configuration (lines 22-32) is a side effect on import -- poor cohesion practice. |

#### Finding 12: Logging setup runs as import side-effect

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 22-32
- **Importance:** 6/10
- **Detail:** `logging.basicConfig(...)` and `os.chmod(log_path, 0o600)` execute on `import password_validator`. This means importing the module in a test or from `app.py` immediately creates/modifies a log file and configures the root logger. This is a cohesion violation (configuration concern mixed into a validation module) and can cause unexpected side effects.

**Remediation:**

```python
# password_validator.py -- wrap in a function, call only from main()
_logger = logging.getLogger(__name__)

def _configure_logging():
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "password_validator.log")
    handler = logging.FileHandler(log_path)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[handler, logging.StreamHandler()],
    )
    os.chmod(log_path, 0o600)

# Then in main():
def main():
    _configure_logging()
    # ...
```

Replace all `logging.info(...)` calls with `_logger.info(...)` throughout the module.

#### Finding 13: `main()` belongs in a separate CLI module

- **File:** `/home/ben/Projects/password_validator/password_validator.py`, lines 234-329
- **Importance:** 4/10
- **Detail:** `main()` is a CLI entry point that handles user input, output formatting, and flow control. It does not share any internal implementation details with the validation functions -- it only calls their public API. Placing it in the same module as the validation logic reduces cohesion.

**Remediation:** Move `main()` and the `if __name__ == "__main__"` block to a dedicated `cli.py` file. The existing module continues to work as a library for `app.py`.

#### `app.py`

| Aspect | Assessment |
|---|---|
| **Functional grouping** | Good. All code serves the Streamlit UI. |
| **Single responsibility** | Moderate. Handles UI layout, password generation, and validation orchestration. The `generate_password()` function is unrelated to validation and could live elsewhere. |
| **Module focus** | Clear: it is the web UI entry point. |

#### Finding 14: `generate_password()` is unrelated to validation UI

- **File:** `/home/ben/Projects/password_validator/app.py`, lines 33-55
- **Importance:** 3/10
- **Detail:** Password generation is a utility concern independent of the Streamlit UI. If the CLI wanted to offer generation, it would need to duplicate this function. It would be more cohesive in `password_validator.py` (or a dedicated `generator.py`).

**Remediation:** Move `generate_password()` to `password_validator.py` and import it in `app.py`. Low priority -- only matters if a second consumer is added.

### 5.2 Related Functions Grouping

Within `password_validator.py`, functions appear in a logical order:

1. `load_blacklist()` -- data loading
2. `check_hibp()` -- external API
3. `validate_password()` -- core validation (calls `check_hibp`)
4. `analyze_crack_time()` -- strength estimation
5. `get_rating()` -- score-to-label mapping
6. `main()` -- CLI entry point

This ordering is logical: dependencies flow downward (later functions call earlier ones). Grouping is acceptable.

---

## 6. Summary of All Findings

| # | Title | File | Lines | Importance | Category |
|---|---|---|---|---|---|
| 1 | `validate_password()` CC=28 | `password_validator.py` | 83-185 | 8/10 | Cyclomatic |
| 2 | `main()` CC=14 | `password_validator.py` | 234-329 | 6/10 | Cyclomatic |
| 3 | `app.py` top-level CC=19 | `app.py` | 70-197 | 7/10 | Cyclomatic |
| 4 | `validate_password()` cognitive=22 | `password_validator.py` | 83-185 | 8/10 | Cognitive |
| 5 | `main()` cognitive=15 | `password_validator.py` | 234-329 | 6/10 | Cognitive |
| 6 | `app.py` top-level cognitive=18 | `app.py` | 70-197 | 7/10 | Cognitive |
| 7 | `validate_password()` 103 lines | `password_validator.py` | 83-185 | 8/10 | LOC |
| 8 | `main()` 96 lines | `password_validator.py` | 234-329 | 5/10 | LOC |
| 9 | `app.py` top-level 128 lines | `app.py` | 70-197 | 6/10 | LOC |
| 10 | Wide import surface (7 names) | `app.py` | 6-14 | 4/10 | Coupling |
| 11 | Duplicated orchestration logic | both files | PV:261-274, app:122-135 | 7/10 | Coupling |
| 12 | Logging setup as import side-effect | `password_validator.py` | 22-32 | 6/10 | Cohesion |
| 13 | `main()` in validation module | `password_validator.py` | 234-329 | 4/10 | Cohesion |
| 14 | `generate_password()` in UI module | `app.py` | 33-55 | 3/10 | Cohesion |

### Priority Remediation Order

1. **Extract rule-checker functions** from `validate_password()` (Findings 1, 4, 7) -- addresses three high-importance findings simultaneously.
2. **Create `full_validate()` orchestrator** (Findings 6, 11) -- eliminates duplication between CLI and web UI.
3. **Wrap logging configuration** in a function (Finding 12) -- stops side effects on import.
4. **Extract `main()` display helpers** (Findings 2, 5, 8) -- simplifies the CLI loop.
5. **Wrap `app.py` top-level code** in functions (Findings 3, 6, 9) -- improves testability.
6. **Move `generate_password()`** to core module (Finding 14) -- optional, low priority.
7. **Move `main()` to `cli.py`** (Finding 13) -- optional, low priority at current scale.
