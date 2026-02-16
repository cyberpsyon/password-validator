import html
import time

import streamlit as st

from password_validator import (
    load_blacklist,
    full_validate,
    generate_password,
    generate_passphrase,
    MIN_LENGTH,
    MAX_LENGTH,
    SPECIAL_CHARS,
)

# -- Page config --
st.set_page_config(page_title="Password Validator", page_icon="\U0001f510", layout="centered")

RATING_COLORS = {
    "EXCELLENT": "#22c55e",
    "STRONG": "#22c55e",
    "GOOD": "#eab308",
    "FAIR": "#f97316",
    "WEAK": "#ef4444",
}


@st.cache_resource
def get_blacklist():
    return load_blacklist()


def inject_progress_color(rating):
    color = RATING_COLORS.get(rating)
    if color is None:
        return
    st.markdown(
        f"""<style>
        .stProgress > div > div > div > div {{
            background-color: {color};
        }}
        </style>""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Threat gauge
# ---------------------------------------------------------------------------

_GAUGE_SEGMENTS = [
    (0,          "Instant",   "#ef4444"),
    (60,         "Seconds",   "#ef4444"),
    (3600,       "Minutes",   "#f97316"),
    (86400,      "Hours",     "#f97316"),
    (2592000,    "Days",      "#eab308"),
    (31536000,   "Months",    "#eab308"),
    (315360000,  "Years",     "#22c55e"),
    (3153600000, "Decades",   "#22c55e"),
    (float("inf"), "Centuries", "#15803d"),
]


def _gauge_segment_index(seconds):
    """Return the index of the segment this crack time falls into."""
    for i, (threshold, _, _) in enumerate(_GAUGE_SEGMENTS):
        if i + 1 < len(_GAUGE_SEGMENTS) and seconds < _GAUGE_SEGMENTS[i + 1][0]:
            return i
    return len(_GAUGE_SEGMENTS) - 1


def render_threat_gauge(crack_time_display, crack_seconds):
    """Render a segmented threat gauge for crack time."""
    seg_idx = _gauge_segment_index(crack_seconds)
    tier_color = _GAUGE_SEGMENTS[seg_idx][2]
    total = len(_GAUGE_SEGMENTS)

    # Build segmented gauge bar
    segments_html = ""
    for i, (_, label, color) in enumerate(_GAUGE_SEGMENTS):
        width_pct = 100 / total
        opacity = "1.0" if i <= seg_idx else "0.25"
        segments_html += (
            f'<div style="width:{width_pct:.1f}%; height:100%; '
            f'background:{color}; opacity:{opacity}; display:inline-block;"></div>'
        )

    gauge_html = f"""
    <div style="margin:1rem 0;">
      <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:0.25rem;">
        <span style="font-size:0.85rem; color:#888;">Estimated crack time</span>
        <span style="font-size:1.3rem; font-weight:bold; color:{tier_color};">
          {html.escape(crack_time_display)}
        </span>
      </div>
      <div style="position:relative; width:100%; height:1.2rem; border-radius:0.6rem;
                  overflow:hidden; background:#1a1a2e; display:flex;">
        {segments_html}
      </div>
      <div style="display:flex; justify-content:space-between; margin-top:0.25rem;">
        <span style="font-size:0.7rem; color:#ef4444;">Instant</span>
        <span style="font-size:0.7rem; color:#15803d;">Centuries</span>
      </div>
    </div>
    """
    st.markdown(gauge_html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Password / passphrase generators
# ---------------------------------------------------------------------------

def render_generator_panel():
    """Password generator UI inside an expander."""
    with st.expander("Generate a strong password"):
        gen_length = st.slider("Length", min_value=MIN_LENGTH, max_value=MAX_LENGTH, value=20)
        gc1, gc2, gc3, gc4 = st.columns(4)
        with gc1:
            gen_upper = st.checkbox("Uppercase", value=True)
        with gc2:
            gen_lower = st.checkbox("Lowercase", value=True)
        with gc3:
            gen_digits = st.checkbox("Digits", value=True)
        with gc4:
            gen_special = st.checkbox("Special", value=True)

        if st.button("Generate"):
            generated = generate_password(
                gen_length, gen_upper, gen_lower, gen_digits, gen_special,
            )
            if generated is None:
                st.warning("Select at least one character set.")
            else:
                st.session_state["generated_password"] = generated

        if "generated_password" in st.session_state:
            st.code(st.session_state["generated_password"], language=None)
            if st.button("Use this password"):
                st.session_state["password_input"] = st.session_state["generated_password"]
                del st.session_state["generated_password"]
                st.rerun()


_SEPARATORS = {
    "Hyphen (-)": "-",
    "Space": " ",
    "Period (.)": ".",
    "Underscore (_)": "_",
    "None": "",
}


def render_passphrase_panel():
    """Passphrase generator UI inside an expander."""
    with st.expander("Generate a strong passphrase"):
        pp_words = st.slider("Word count", min_value=3, max_value=8, value=4,
                             key="pp_word_count")
        pp_sep = st.selectbox("Separator", list(_SEPARATORS.keys()),
                              index=0, key="pp_separator")
        pc1, pc2, pc3, pc4 = st.columns(4)
        with pc1:
            pp_upper = st.checkbox("Uppercase", value=True, key="pp_upper")
        with pc2:
            pp_leet = st.checkbox("Leetspeak", value=False, key="pp_leet")
        with pc3:
            pp_digits = st.checkbox("Digits", value=False, key="pp_digits")
        with pc4:
            pp_special = st.checkbox("Special", value=False, key="pp_special")

        if st.button("Generate Passphrase"):
            passphrase = generate_passphrase(
                word_count=pp_words,
                separator=_SEPARATORS[pp_sep],
                use_upper=pp_upper,
                use_leet=pp_leet,
                use_digits=pp_digits,
                use_special=pp_special,
            )
            if passphrase is None:
                st.error("Wordlist not found. Ensure eff_wordlist.txt is in the project directory.")
            else:
                st.session_state["generated_passphrase"] = passphrase

        if "generated_passphrase" in st.session_state:
            st.code(st.session_state["generated_passphrase"], language=None)
            if st.button("Use this passphrase"):
                st.session_state["password_input"] = st.session_state["generated_passphrase"]
                del st.session_state["generated_passphrase"]
                st.rerun()


# ---------------------------------------------------------------------------
# Info dialogs
# ---------------------------------------------------------------------------

_SAFETY_TIPS = """\
**Use a unique password for every account.** If one site is breached, \
attackers will try that password on every other service you use.

**Use a password manager.** No one can remember dozens of strong, unique \
passwords. Let a password manager generate and store them for you.

**Enable two-factor authentication (2FA).** Even a strong password can be \
phished. A second factor (authenticator app or hardware key) stops most \
account takeovers.

**Longer beats more complex.** A 20-character passphrase made of random \
words is both stronger and easier to type than an 8-character mess of symbols.

**Never share passwords over email or chat.** Legitimate services will never \
ask for your password. If someone does, it's a scam.

**Watch for breaches.** Services like Have I Been Pwned will notify you \
if your email appears in a data breach so you can change your passwords \
before attackers use them.

**Change passwords that have been exposed.** If a password shows up in a \
breach database, stop using it everywhere — immediately.\
"""

def render_safety_tips_panel():
    """Render password safety tips inside an expander."""
    with st.expander("Safety Tips"):
        st.markdown(_SAFETY_TIPS)


def render_scoring_panel():
    """Render a generic scoring explanation inside an expander."""
    with st.expander("How Scoring Works"):
        st.markdown(
            "Your password is scored out of **100 points** across 7 categories. "
            "Each category checks a different aspect of password strength."
        )

        st.markdown("#### Point Breakdown")
        st.markdown(
            "| Category | Points |\n"
            "|----------|--------|\n"
            "| Length (12+ characters) | 15 |\n"
            "| Contains uppercase letters | 10 |\n"
            "| Contains lowercase letters | 10 |\n"
            "| Contains numbers | 10 |\n"
            "| Contains special characters | 10 |\n"
            "| Not in breach databases | 15 |\n"
            "| Crack-time resistance | 0\u201330 |"
        )

        st.markdown("#### Crack-Time Resistance")
        st.markdown(
            "This category uses [zxcvbn](https://github.com/dwolfhuis/zxcvbn-python) "
            "pattern analysis to estimate how long a real-world attacker would need to "
            "crack your password assuming bcrypt hashing at 10,000 guesses per second."
        )
        st.markdown(
            "| Estimated Crack Time | Points |\n"
            "|----------------------|--------|\n"
            "| Less than 1 second | 0 |\n"
            "| Less than 1 minute | 5 |\n"
            "| Less than 1 hour | 10 |\n"
            "| Less than 1 day | 15 |\n"
            "| Less than 1 year | 20 |\n"
            "| Less than 100 years | 25 |\n"
            "| 100+ years | 30 |"
        )

        st.markdown("#### Final Rating")
        st.markdown(
            "| Rating | Score Range |\n"
            "|--------|-------------|\n"
            "| EXCELLENT | 100 |\n"
            "| STRONG | 80\u201399 |\n"
            "| GOOD | 60\u201379 |\n"
            "| FAIR | 40\u201359 |\n"
            "| WEAK | Below 40 |"
        )
        st.markdown(
            "Any password that can be cracked in **under 1 hour** or is found in the "
            "**Have I Been Pwned** breach database is automatically rated **WEAK** "
            "regardless of its total score."
        )


# ---------------------------------------------------------------------------
# Validation results
# ---------------------------------------------------------------------------

def render_validation_results(password, blacklist):
    """Run validation and display results."""
    if not password:
        st.warning("Please enter a password first.")
        st.stop()

    # Rate limiting: minimum 1 second between validations
    if "last_validate_time" in st.session_state:
        elapsed = time.time() - st.session_state["last_validate_time"]
        if elapsed < 1.0:
            st.warning("Please wait before validating again.")
            st.stop()
    st.session_state["last_validate_time"] = time.time()

    result = full_validate(password, blacklist)

    st.divider()

    # Score + Rating
    col_score, col_rating = st.columns([2, 1])

    with col_score:
        st.metric("Score", f"{result['score']} / {result['max_score']}")
        inject_progress_color(result["rating"])
        st.progress(min(result["score"] / result["max_score"], 1.0))

    with col_rating:
        color = RATING_COLORS.get(result["rating"], "#6b7280")
        rating_safe = html.escape(result["rating"])
        st.markdown(
            f'<div style="text-align:center; padding:1.5rem 0;">'
            f'<span style="background:{color}; color:white; padding:0.5rem 1.5rem; '
            f'border-radius:0.5rem; font-size:1.5rem; font-weight:bold;">'
            f"{rating_safe}</span></div>",
            unsafe_allow_html=True,
        )

    # HIBP failure warning
    if any("HIBP API unavailable" in r for r in result["failed"]):
        st.warning(
            "The breach database check could not be completed. "
            "This password has NOT been verified against known breaches. "
            "Retry when you have network connectivity."
        )

    render_threat_gauge(result["crack_time"], result["crack_seconds"])

    # Passed / Failed rules
    col_pass, col_fail = st.columns(2)

    with col_pass:
        st.subheader("Passed")
        if result["passed"]:
            for rule in result["passed"]:
                st.markdown(
                    f'<p style="color:#22c55e; margin:0.25rem 0;">{html.escape(rule)}</p>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No rules passed.")

    with col_fail:
        st.subheader("Failed")
        if result["failed"]:
            for rule in result["failed"]:
                st.markdown(
                    f'<p style="color:#ef4444; margin:0.25rem 0;">{html.escape(rule)}</p>',
                    unsafe_allow_html=True,
                )
        else:
            st.success("All rules passed!")

    # Recommendations
    recs = []
    if result["score"] < 50:
        recs.append("This password is too weak for secure systems.")
    if result["failed"]:
        recs.append("Address all failed rules listed above.")
    if any("common password" in r.lower() or "have i been pwned" in r.lower()
           for r in result["failed"]):
        recs.append("**CRITICAL:** Use a unique password not found in breach databases.")
    if result["warning"]:
        recs.append(result["warning"])
    recs.extend(result["suggestions"])

    if recs:
        st.subheader("Recommendations")
        for rec in recs:
            st.markdown(f"- {rec}")


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

with st.spinner("Loading password database..."):
    blacklist = get_blacklist()

st.title("Password Strength Validator")

password = st.text_input(
    f"Enter a password (max {MAX_LENGTH} characters)",
    type="password",
    max_chars=MAX_LENGTH,
    key="password_input",
)

validate_clicked = st.button("Validate", type="primary", use_container_width=True)

render_generator_panel()
render_passphrase_panel()
render_safety_tips_panel()
render_scoring_panel()

if validate_clicked:
    render_validation_results(password, blacklist)
