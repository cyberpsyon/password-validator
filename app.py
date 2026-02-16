import secrets
import string

import streamlit as st

from password_validator import (
    load_blacklist,
    validate_password,
    analyze_crack_time,
    get_rating,
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


def generate_password(length, use_upper, use_lower, use_digits, use_special):
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


# -- Load blacklist once --
with st.spinner("Loading password database..."):
    blacklist = get_blacklist()

# -- Title --
st.title("Password Strength Validator")
st.caption(f"Min {MIN_LENGTH} characters \u2022 Max {MAX_LENGTH} characters")

# -- Password input --
show = st.checkbox("Show password", value=False)
password = st.text_input(
    "Enter a password",
    type="default" if show else "password",
    max_chars=MAX_LENGTH,
    key="password_input",
)

validate_clicked = st.button("Validate", type="primary", use_container_width=True)

# -- Password generator --
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
        generated = generate_password(gen_length, gen_upper, gen_lower, gen_digits, gen_special)
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

# -- Validation results --
if validate_clicked:
    if not password:
        st.warning("Please enter a password first.")
        st.stop()

    # Run validation
    score, max_score, failed_rules, passed_rules = validate_password(password, blacklist)
    crack_time, crack_points, hard_fail, suggestions, warning = analyze_crack_time(password)
    score += crack_points

    if crack_points > 0:
        passed_rules.append(f"\u2713 Crack time resistance ({crack_points}/30 points)")
    else:
        failed_rules.append("\u2717 Crack time resistance \u2014 cracks in under 1 second (0/30 points)")

    if hard_fail:
        rating = "WEAK"
    else:
        rating = get_rating(score)

    st.divider()

    # Score + Rating
    col_score, col_rating = st.columns([2, 1])

    with col_score:
        st.metric("Score", f"{score} / {max_score}")
        inject_progress_color(rating)
        st.progress(min(score / max_score, 1.0))

    with col_rating:
        color = RATING_COLORS.get(rating, "#6b7280")
        st.markdown(
            f'<div style="text-align:center; padding:1.5rem 0;">'
            f'<span style="background:{color}; color:white; padding:0.5rem 1.5rem; '
            f'border-radius:0.5rem; font-size:1.5rem; font-weight:bold;">'
            f"{rating}</span></div>",
            unsafe_allow_html=True,
        )

    if hard_fail:
        st.error("Rating capped at WEAK \u2014 this password can be cracked in under 1 hour.")

    st.markdown(f"**Estimated crack time (offline fast attack):** `{crack_time}`")

    # Passed / Failed rules
    col_pass, col_fail = st.columns(2)

    with col_pass:
        st.subheader("Passed")
        if passed_rules:
            for rule in passed_rules:
                st.markdown(f'<p style="color:#22c55e; margin:0.25rem 0;">{rule}</p>', unsafe_allow_html=True)
        else:
            st.info("No rules passed.")

    with col_fail:
        st.subheader("Failed")
        if failed_rules:
            for rule in failed_rules:
                st.markdown(f'<p style="color:#ef4444; margin:0.25rem 0;">{rule}</p>', unsafe_allow_html=True)
        else:
            st.success("All rules passed!")

    # Recommendations
    recs = []
    if score < 50:
        recs.append("This password is too weak for secure systems.")
    if failed_rules:
        recs.append("Address all failed rules listed above.")
    if any("common password" in r.lower() or "have i been pwned" in r.lower() for r in failed_rules):
        recs.append("**CRITICAL:** Use a unique password not found in breach databases.")
    if warning:
        recs.append(warning)
    recs.extend(suggestions)

    if recs:
        st.subheader("Recommendations")
        for rec in recs:
            st.markdown(f"- {rec}")
