import datetime
import html
import re
import time

import streamlit as st
import streamlit.components.v1 as components

from password_validator import (
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
    "EXCELLENT": "#3DDC97",
    "STRONG":    "#3DDC97",
    "GOOD":      "#FFB020",
    "FAIR":      "#FFB020",
    "WEAK":      "#FF5577",
}

RATING_SHADOWS = {
    "EXCELLENT": "0 0 18px rgba(61,220,151,0.35)",
    "STRONG":    "0 0 18px rgba(61,220,151,0.35)",
    "GOOD":      "0 0 18px rgba(255,176,32,0.35)",
    "FAIR":      "0 0 18px rgba(255,176,32,0.35)",
    "WEAK":      "0 0 18px rgba(255,85,119,0.35)",
}

# Gradient stop pairs for the score ring (start/end at same hue, two shades)
RATING_GRADIENTS = {
    "EXCELLENT": ("#3DDC97", "#A4F0CF"),
    "STRONG":    ("#3DDC97", "#A4F0CF"),
    "GOOD":      ("#FFB020", "#FFD980"),
    "FAIR":      ("#FFB020", "#FFD980"),
    "WEAK":      ("#FF5577", "#FF8FA8"),
}

_GAUGE_SEGMENTS = [
    (0,          "Instant",   "#FF1744"),
    (60,         "Minutes",   "#FF1744"),
    (3600,       "Hours",     "#FF6D00"),
    (86400,      "Days",      "#FF6D00"),
    (2592000,    "Months",    "#FFD600"),
    (31536000,   "Years",     "#FFD600"),
    (315360000,  "Decades",   "#00E676"),
    (3153600000, "Centuries", "#00897B"),
]

_SEPARATORS = {
    "Hyphen (-)":    "-",
    "Space":         " ",
    "Period (.)":    ".",
    "Underscore (_)": "_",
    "None":          "",
}

_SEVERITY_COLORS = {
    "critical": "#FF1744",
    "moderate": "#FF6D00",
    "low":      "#F5A623",
    "none":     "#7878A0",
}

_TAG_DISPLAY = {
    "DICT":  "[DICT]",
    "KEY":   "[KEY]",
    "DATE":  "[DATE]",
    "SEQ":   "[SEQ]",
    "RPT":   "[RPT]",
    "BRUTE": "[BRUTE]",
}

_SAFETY_TIPS = [
    ("Use a unique password for every account",
     "When a company gets hacked, attackers take the stolen passwords and try "
     "them on other websites like your email, bank, and social media. If you "
     "use the <span style='color:#FF1744;font-weight:700'>same password everywhere</span>, "
     "one breach can compromise all of your accounts. Always use a "
     "<span style='color:#00E676;font-weight:700'>different password for each account</span>."),

    ("Use a password manager",
     "Nobody can remember dozens of strong, unique passwords. A "
     "<span style='color:#F5A623;font-weight:700'>password manager</span> is an app "
     "that securely stores all of your passwords for you. You only need to remember "
     "<span style='color:#00E676;font-weight:700'>one master password</span>, and the manager fills in "
     "the rest. <a href='https://1password.com/' target='_blank' style='color:#F5A623'>1Password</a> "
     "is the industry-leading option for individuals and teams."),

    ("Enable multi-factor authentication (MFA)",
     "<span style='color:#F5A623;font-weight:700'>Multi-factor authentication</span> adds another step "
     "when you log in, like a code from an app on your phone or a physical security key. Even if "
     "someone steals your password, they still cannot get into your account without that second step. "
     "<span style='color:#00E676;font-weight:700'>Turn on MFA everywhere it is available</span>, "
     "especially for email, banking, and work accounts. "
     "<span style='color:#FF1744;font-weight:700'>Avoid SMS-based MFA when possible.</span> "
     "Authenticator apps (like Authy or Google Authenticator) and hardware security keys "
     "(like <a href='https://www.yubico.com/get-yubikey' target='_blank' style='color:#F5A623'>YubiKey</a>) "
     "are significantly harder to intercept or bypass."),

    ("Longer passwords are stronger passwords",
     "A <span style='color:#F5A623;font-weight:700'>20-character passphrase</span> made of random words "
     "(like <span style='color:#00E676;font-weight:700'>\"correct-horse-battery-staple\"</span>) "
     "is both stronger and easier to type than a short, complicated password "
     "like <span style='color:#FF1744;font-weight:700'>\"P@s5w0rd!\"</span>. "
     "Aim for <span style='color:#F5A623;font-weight:700'>at least 15 characters</span>, but longer is always better."),

    ("Never share passwords over email or chat",
     "No legitimate company, IT department, or government agency will ever ask "
     "you for your password. If someone contacts you asking for your password, "
     "<span style='color:#FF1744;font-weight:700'>it is a scam</span>. Always type your password "
     "<span style='color:#00E676;font-weight:700'>directly</span> into the official website or app, "
     "<span style='color:#FF1744;font-weight:700'>never</span> into an email, text message, or phone call."),

    ("Watch for data breaches",
     "Data breaches happen regularly, and your information may be exposed "
     "without you knowing. Sign up for "
     "<span style='color:#00E676;font-weight:700'>free alerts</span> at "
     "<a href='https://haveibeenpwned.com' target='_blank' style='color:#F5A623'>Have I Been Pwned</a> to "
     "get notified if your email appears in a breach. When you get an alert, "
     "<span style='color:#00E676;font-weight:700'>change the password</span> for that account immediately."),

    ("Change passwords that have been exposed",
     "If you find out that one of your passwords was part of a data breach, "
     "<span style='color:#00E676;font-weight:700'>stop using it right away</span> on every account where you used it. "
     "Attackers share stolen passwords widely, so a breached password is "
     "<span style='color:#FF1744;font-weight:700'>never safe to use again</span>, even if you change it slightly."),

    ("A high score does not mean your password is unbreakable",
     "Even if this tool rates your password as \"Excellent\" with a crack time "
     "of centuries, <span style='color:#FF1744;font-weight:700'>no password is truly permanent</span>. "
     "Advances in technology, including "
     "<span style='color:#F5A623;font-weight:700'>quantum computing</span>, will make password cracking "
     "significantly faster in the future. "
     "<span style='color:#00E676;font-weight:700'>Combine strong passwords with MFA</span> and change a "
     "password only when you have reason to believe it has been compromised. "
     "Routine rotation tends to produce weaker, predictable passwords and is no longer recommended."),
]



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _md_bold(text: str) -> str:
    """HTML-escape text, then render **bold** as <strong>."""
    text = html.escape(text)
    return re.sub(r"\*\*(.+?)\*\*", r'<strong style="color:#F5A623;">\1</strong>', text)


def _html(markup: str) -> str:
    """Strip blank lines so CommonMark never exits HTML-block mode mid-tag."""
    return "\n".join(line for line in markup.split("\n") if line.strip())


def _format_guesses(n: float) -> str:
    """Format a raw guess count into a human-readable string."""
    if n < 1_000:
        return f"{int(n)} guesses"
    if n < 1_000_000:
        return f"{n / 1_000:.0f}K guesses"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.0f}M guesses"
    if n < 1_000_000_000_000:
        return f"{n / 1_000_000_000:.0f}B guesses"
    return f"{n / 1_000_000_000_000:.0f}T guesses"


# -- Per-metric color tiers ------------------------------------------------
# Each helper returns one of: "good", "mid", "bad", "unknown".
# Color tokens for each tier are defined in CSS via .m-good / .m-mid / .m-bad.

_TIER_COLORS = {
    "good":    "#3DDC97",
    "mid":     "#FFB020",
    "bad":     "#FF5577",
    "unknown": "#7878A0",
}


def _crack_time_tier(seconds: float) -> str:
    if seconds < 3600:           # < 1 hour
        return "bad"
    if seconds < 31_536_000:     # < 1 year
        return "mid"
    return "good"


def _breach_tier(hibp_count, hibp_unavailable: bool) -> str:
    if hibp_unavailable:
        return "unknown"
    return "bad" if hibp_count else "good"


def _length_tier(n: int) -> str:
    if n < 12:
        return "bad"
    if n < MIN_LENGTH:  # 12–14
        return "mid"
    return "good"


def _format_breach_count(count) -> str:
    if count is None or count == 0:
        return "Clean"
    if count < 1_000:
        return f"Pwned {count}×"
    if count < 1_000_000:
        return f"Pwned {count / 1_000:.1f}K×"
    return f"Pwned {count / 1_000_000:.1f}M×"


# ---------------------------------------------------------------------------
# Global styles
# ---------------------------------------------------------------------------

def inject_global_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');

        :root {
            --bg:          #0A1220;
            --surface:     #141C2E;
            --surface2:    #1A2238;
            --border:      rgba(255,255,255,0.06);
            --border2:     rgba(255,255,255,0.10);
            --mint:        #3DDC97;
            --mint-soft:   #A4F0CF;
            --mint-dim:    rgba(61, 220, 151, 0.10);
            --mint-glow:   rgba(61, 220, 151, 0.25);
            --text:        #FFFFFF;
            --text-body:   #C9D2E2;
            --text-dim:    #6B7488;
            --good:        #3DDC97;
            --mid:         #FFB020;
            --bad:         #FF5577;
        }

        /* ── Global typography ── */
        html, body, [class^="st"], [class*=" st"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .pv-mono, .pv-mono * {
            font-family: 'JetBrains Mono', 'SF Mono', Menlo, monospace !important;
        }

        /* ── App background: flat navy + subtle dot grid ── */
        .stApp {
            background-color: var(--bg) !important;
            background-image: radial-gradient(circle at center, rgba(255,255,255,0.025) 1px, transparent 1px);
            background-size: 24px 24px;
            background-attachment: fixed;
        }

        .block-container {
            padding-top: 3rem !important;
            padding-bottom: 5rem !important;
            max-width: 760px !important;
        }

        /* ── Typography ── */
        h1, h2, h3, h4, h5, h6 { color: var(--text) !important; letter-spacing: -0.02em !important; }
        p, li { color: var(--text-body) !important; }
        a { color: var(--mint) !important; text-decoration: none; }
        a:hover { color: var(--mint-soft) !important; }

        /* ── Text input: pill shape, solid fill, no thin border ── */
        .stTextInput > div > div {
            background: var(--surface) !important;
            border: 0 !important;
            border-radius: 999px !important;
            box-shadow: 0 1px 0 rgba(255,255,255,0.04), 0 8px 24px rgba(0,0,0,0.3) !important;
            transition: box-shadow 0.2s !important;
        }
        .stTextInput > div > div:focus-within {
            box-shadow: 0 0 0 2px var(--mint), 0 8px 24px rgba(0,0,0,0.4) !important;
        }
        .stTextInput input {
            background: transparent !important;
            color: var(--text) !important;
            font-size: 0.95rem !important;
            font-family: 'JetBrains Mono', monospace !important;
            letter-spacing: 0.04em !important;
            caret-color: var(--mint) !important;
            padding: 0.95rem 1.5rem !important;
            border: 0 !important;
        }
        .stTextInput input::placeholder { color: #4A5468 !important; }
        .stTextInput label {
            color: var(--text-body) !important;
            font-size: 0.75rem !important;
            letter-spacing: 0.04em !important;
            text-transform: none !important;
            font-weight: 500 !important;
            margin-bottom: 0.5rem !important;
        }

        /* ── Buttons: filled mint pill ── */
        .stButton > button {
            background: var(--mint) !important;
            color: #0A1220 !important;
            border: 0 !important;
            border-radius: 999px !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 700 !important;
            font-size: 0.85rem !important;
            letter-spacing: 0.02em !important;
            text-transform: none !important;
            padding: 0.8rem 1.75rem !important;
            box-shadow: 0 4px 14px rgba(61, 220, 151, 0.25), inset 0 1px 0 rgba(255,255,255,0.25) !important;
            transition: transform 0.15s ease, box-shadow 0.2s ease, background-color 0.2s !important;
        }
        .stButton > button p, .stButton > button span, .stButton > button div {
            color: inherit !important;
        }
        .stButton > button:hover {
            background: var(--mint-soft) !important;
            color: #0A1220 !important;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(61, 220, 151, 0.35), inset 0 1px 0 rgba(255,255,255,0.25) !important;
        }
        .stButton > button:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(61, 220, 151, 0.25), inset 0 1px 0 rgba(255,255,255,0.25) !important;
        }

        /* ── Progress bar ── */
        .stProgress > div > div {
            background: var(--surface) !important;
            border-radius: 999px !important;
            height: 8px !important;
            overflow: hidden !important;
        }
        .stProgress > div > div > div > div {
            border-radius: 999px !important;
            transition: width 0.9s cubic-bezier(0.4,0,0.2,1) !important;
        }

        /* ── Expanders ── */
        details {
            background: var(--surface) !important;
            border: 0 !important;
            border-radius: 14px !important;
            margin-bottom: 0.5rem !important;
            overflow: hidden;
        }
        details summary {
            display: flex !important;
            align-items: center !important;
            list-style: none !important;
            color: var(--text) !important;
            font-size: 0.85rem !important;
            font-weight: 600 !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
            padding: 1rem 1.25rem !important;
            cursor: pointer !important;
            transition: color 0.15s, background 0.15s !important;
        }
        details summary::-webkit-details-marker { display: none !important; }
        /* Hide Streamlit's built-in icon span (Material ligature breaks under non-mono font) */
        details summary > span > span,
        details summary > span > svg { display: none !important; }
        /* Custom toggle indicator */
        details summary::after {
            content: '+' !important;
            color: var(--mint) !important;
            font-size: 1.2rem !important;
            font-weight: 400 !important;
            flex-shrink: 0 !important;
            transition: transform 0.2s ease !important;
            display: inline-block !important;
            margin-left: 0.75rem !important;
        }
        details[open] summary::after {
            transform: rotate(45deg) !important;
        }
        details summary:hover { color: var(--mint) !important; }
        details[open] summary {
            color: var(--mint) !important;
            border-bottom: 1px solid var(--border) !important;
        }
        .streamlit-expanderContent {
            background: var(--surface) !important;
            padding: 1.25rem !important;
        }

        /* ── Slider ── */
        [data-baseweb="slider"] [data-testid="stTickBar"] { color: var(--text-dim) !important; }

        /* ── Selectbox ── */
        [data-baseweb="select"] > div {
            background: var(--surface2) !important;
            border: 0 !important;
            border-radius: 10px !important;
        }
        [data-baseweb="select"] span, [data-baseweb="select"] div { color: var(--text) !important; }

        /* ── Checkbox ── */
        .stCheckbox label p, .stCheckbox label span {
            color: var(--text-body) !important;
            font-size: 0.85rem !important;
        }

        /* ── Divider ── */
        hr { border-color: var(--border) !important; opacity: 1 !important; margin: 1.5rem 0 !important; }

        /* ── Alerts ── */
        .stAlert {
            background: var(--surface) !important;
            border-radius: 14px !important;
            border: 0 !important;
        }
        .stAlert > div { font-size: 0.85rem !important; color: var(--text) !important; }

        /* ── Code blocks ── */
        .stCode > div, pre {
            background: var(--surface2) !important;
            border: 0 !important;
            border-radius: 10px !important;
        }
        code { color: var(--mint) !important; background: transparent !important; font-family: 'JetBrains Mono', monospace !important; }

        /* ── Tables (kept for legacy sections) ── */
        table { border-collapse: collapse !important; width: 100% !important; }
        th {
            background: var(--surface2) !important;
            color: var(--mint) !important;
            border: 0 !important;
            padding: 0.6rem 0.85rem !important;
            font-size: 0.7rem !important;
            letter-spacing: 0.04em !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
            text-transform: uppercase !important;
            text-align: left !important;
        }
        td {
            background: var(--surface) !important;
            color: var(--text-body) !important;
            border-top: 1px solid var(--border) !important;
            padding: 0.6rem 0.85rem !important;
            font-size: 0.85rem !important;
        }
        td a { color: var(--mint) !important; }

        /* ── Spinner ── */
        .stSpinner > div { border-top-color: var(--mint) !important; }

        /* ── Fade-in animation ── */
        @keyframes pvReveal {
            from { opacity: 0; transform: translateY(8px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .t-reveal { animation: pvReveal 0.35s ease-out forwards; }

        /* ── Result row color coding (kept for legacy rule analysis section) ── */
        .pv-row-pass {
            background: rgba(61, 220, 151, 0.06);
            border-left: 2px solid var(--good);
            padding-left: 0.7rem;
            margin-left: -0.7rem;
            border-radius: 0 6px 6px 0;
        }
        .pv-row-fail {
            background: rgba(255, 85, 119, 0.06);
            border-left: 2px solid var(--bad);
            padding-left: 0.7rem;
            margin-left: -0.7rem;
            border-radius: 0 6px 6px 0;
        }
        .pv-row-warn {
            background: rgba(255, 176, 32, 0.07);
            border-left: 2px solid var(--mid);
            padding-left: 0.7rem;
            margin-left: -0.7rem;
            border-radius: 0 6px 6px 0;
        }
        .pv-row-opt {
            background: rgba(255, 255, 255, 0.025);
            border-left: 2px solid var(--text-dim);
            padding-left: 0.7rem;
            margin-left: -0.7rem;
            border-radius: 0 6px 6px 0;
        }

        /* ── Score ring + metrics ── */
        .pv-result {
            background: linear-gradient(180deg, var(--surface2) 0%, var(--surface) 100%);
            border-radius: 22px;
            padding: 2rem 2rem 1.75rem;
            margin: 1.5rem 0;
            box-shadow: 0 1px 0 rgba(255,255,255,0.05), 0 20px 40px rgba(0,0,0,0.35);
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 2rem;
            align-items: center;
        }
        .pv-result .ring-wrap { position: relative; width: 200px; height: 200px; }
        .pv-result .ring-wrap svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .pv-result .ring-bg { fill: none; stroke: var(--surface); stroke-width: 14; }
        .pv-result .ring-fg { fill: none; stroke-width: 14; stroke-linecap: round; stroke-dasharray: 565.48; }
        .pv-result .ring-center {
            position: absolute; inset: 0;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
        }
        .pv-result .ring-center .num {
            font-size: 3.2rem; font-weight: 700;
            letter-spacing: -0.04em; line-height: 1;
            color: var(--text);
        }
        .pv-result .ring-center .num .of {
            font-size: 1rem; color: var(--text-dim); font-weight: 500;
        }
        .pv-result .ring-center .badge {
            font-size: 0.65rem; letter-spacing: 0.18em;
            text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
            font-weight: 800; margin-top: 0.5rem;
        }
        .pv-result .breakdown {
            display: flex; flex-direction: column; gap: 0.65rem;
        }
        .pv-result .breakdown .row {
            display: flex; justify-content: space-between; align-items: center;
            padding-bottom: 0.6rem;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .pv-result .breakdown .row:last-child { border-bottom: 0; padding-bottom: 0; }
        .pv-result .breakdown .lbl-wrap { display: flex; align-items: center; gap: 0.6rem; }
        .pv-result .breakdown .dot {
            width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
        }
        .pv-result .breakdown .lbl {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem; letter-spacing: 0.12em;
            text-transform: uppercase; color: var(--text);
            font-weight: 700;
        }
        .pv-result .breakdown .val {
            font-size: 0.95rem; font-weight: 600;
        }

        @media (max-width: 600px) {
            .pv-result {
                grid-template-columns: 1fr;
                justify-items: center;
                text-align: center;
            }
            .pv-result .breakdown { width: 100%; max-width: 280px; }
        }

        /* ── Empty-state hint ── */
        .pv-empty-hint {
            text-align: center;
            margin: 2rem 0 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            color: var(--mint);
        }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 999px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--mint); }

        /* ── Hide Streamlit chrome ── */
        #MainMenu { visibility: hidden; }
        footer    { visibility: hidden; }
        header    { visibility: hidden; }

        /* ── Footer ── */
        .pv-footer a { color: var(--text-dim) !important; }
        .pv-footer a:hover { color: var(--mint) !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def render_header():
    st.markdown(
        _html("""
        <div style="text-align:center; margin: 0 auto 2rem; max-width:640px;">
            <h1 style="font-family:'Inter',sans-serif; font-size:2.75rem; font-weight:700; line-height:1.05; letter-spacing:-0.03em; color:#FFFFFF; margin:0 0 1rem 0;">
                How strong is your <span style="color:#3DDC97;">password</span>?
            </h1>
            <p style="font-family:'Inter',sans-serif; font-size:0.95rem; color:#C9D2E2; line-height:1.6; max-width:480px; margin: 0 auto;">
                An audit against 850M breached passwords and modern cracking benchmarks.
                No accounts, no logging, no storage.
            </p>
        </div>
        """),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Threat gauge
# ---------------------------------------------------------------------------

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

    segments_html = ""
    for i, (_, label, color) in enumerate(_GAUGE_SEGMENTS):
        width_pct = 100 / total
        opacity = "1.0" if i <= seg_idx else "0.11"
        segments_html += (
            f'<div title="{html.escape(label)}" style="'
            f'width:{width_pct:.2f}%; height:100%; '
            f'background:{color}; opacity:{opacity}; '
            f'display:inline-block; border-right:2px solid #06060C;'
            f'"></div>'
        )

    st.markdown(
        _html(f"""
        <div class="t-reveal" style="background:#0D0D1A; border:1px solid #222240; padding:1.25rem 1.5rem; margin:0.75rem 0;">
            <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:0.8rem;">
                <span style="font-size:0.6rem; color:#7878A0; letter-spacing:0.2em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">Estimated Crack Time</span>
                <span style="font-size:1.3rem; font-weight:800; color:{tier_color}; letter-spacing:0.06em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">{html.escape(crack_time_display)}</span>
            </div>
            <div style="width:100%; height:1.35rem; display:flex; overflow:hidden;">
                {segments_html}
            </div>
            <div style="display:flex; justify-content:space-between; margin-top:0.4rem;">
                <span style="font-size:0.56rem; color:#FF1744; letter-spacing:0.1em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">&#8592; Instant</span>
                <span style="font-size:0.56rem; color:#00897B; letter-spacing:0.1em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">Centuries &#8594;</span>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Password / passphrase generators
# ---------------------------------------------------------------------------

def _render_copy_output(value: str) -> None:
    """Render a code-style output div with a working copy button via iframe."""
    import json
    js_value = html.escape(json.dumps(value))  # &quot; survives the onclick attribute
    components.html(
        f"""
        <style>
        * {{ margin:0; padding:0; box-sizing:border-box; font-family:'JetBrains Mono',monospace; }}
        body {{ background:transparent; }}
        #wrap {{ display:flex; align-items:stretch; }}
        #out {{
            flex:1; background:#111120; border:1px solid #222240;
            padding:0.75rem 1rem; font-size:0.9rem; color:#00E676;
            letter-spacing:0.08em; word-break:break-all; user-select:all;
        }}
        #btn {{
            background:transparent; border:1px solid #222240; border-left:0;
            color:#F5A623; font-size:0.65rem; letter-spacing:0.15em;
            text-transform:uppercase; padding:0 0.9rem; cursor:pointer;
            white-space:nowrap; display:flex; align-items:center;
            user-select:none; outline:none;
        }}
        #btn:hover {{ background:rgba(245,166,35,0.08); }}
        #btn:focus {{ outline:none; }}
        </style>
        <div id="wrap">
            <div id="out">{html.escape(value)}</div>
            <div id="btn" onclick="navigator.clipboard.writeText({js_value});this.textContent='✓';setTimeout(()=>this.textContent='Copy',2000);">Copy</div>
        </div>
        """,
        height=52,
    )


def render_generator_panel():
    """Password generator UI inside an expander."""
    def _on_generate():
        st.session_state["pw_gen_open"] = True
        generated = generate_password(
            st.session_state.get("gen_length", 20),
            st.session_state.get("gen_upper", True),
            st.session_state.get("gen_lower", True),
            st.session_state.get("gen_digits", True),
            st.session_state.get("gen_special", True),
        )
        if generated is None:
            st.session_state["pw_gen_error"] = True
        else:
            st.session_state.pop("pw_gen_error", None)
            st.session_state["generated_password"] = generated

    _pw_expand = {"expanded": True} if st.session_state.pop("pw_gen_open", False) else {}
    with st.expander("Generate a strong password", **_pw_expand):
        st.slider("Length", min_value=MIN_LENGTH, max_value=MAX_LENGTH, value=20, key="gen_length")
        gc1, gc2, gc3, gc4 = st.columns(4)
        with gc1:
            st.checkbox("Uppercase", value=True, key="gen_upper")
        with gc2:
            st.checkbox("Lowercase", value=True, key="gen_lower")
        with gc3:
            st.checkbox("Numbers", value=True, key="gen_digits")
        with gc4:
            st.checkbox("Special", value=True, key="gen_special")

        st.button("Generate", on_click=_on_generate)
        if st.session_state.get("pw_gen_error"):
            st.warning("Select at least one character set.")

        if "generated_password" in st.session_state:
            _render_copy_output(st.session_state["generated_password"])


def render_passphrase_panel():
    """Passphrase generator UI inside an expander."""
    def _on_generate():
        st.session_state["pp_gen_open"] = True
        passphrase = generate_passphrase(
            word_count=st.session_state.get("pp_word_count", 4),
            separator=_SEPARATORS[st.session_state.get("pp_separator", "Hyphen (-)")],
            use_upper=st.session_state.get("pp_upper", True),
            use_leet=st.session_state.get("pp_leet", False),
            use_digits=st.session_state.get("pp_digits", False),
            use_special=st.session_state.get("pp_special", False),
        )
        if passphrase is None:
            st.session_state["pp_gen_error"] = True
        else:
            st.session_state.pop("pp_gen_error", None)
            st.session_state["generated_passphrase"] = passphrase

    _pp_expand = {"expanded": True} if st.session_state.pop("pp_gen_open", False) else {}
    with st.expander("Generate a strong passphrase", **_pp_expand):
        st.slider("Word count", min_value=3, max_value=8, value=4, key="pp_word_count")
        st.selectbox("Separator", list(_SEPARATORS.keys()), index=0, key="pp_separator")
        pc1, pc2, pc3, pc4 = st.columns(4)
        with pc1:
            st.checkbox("Uppercase", value=True, key="pp_upper")
        with pc2:
            st.checkbox("Leetspeak", value=False, key="pp_leet")
        with pc3:
            st.checkbox("Numbers", value=False, key="pp_digits")
        with pc4:
            st.checkbox("Special", value=False, key="pp_special")

        st.button("Generate Passphrase", on_click=_on_generate)
        if st.session_state.get("pp_gen_error"):
            st.error("Wordlist not found. Ensure eff_wordlist.txt is in the project directory.")

        if "generated_passphrase" in st.session_state:
            _render_copy_output(st.session_state["generated_passphrase"])


# ---------------------------------------------------------------------------
# Info panels
# ---------------------------------------------------------------------------

def render_safety_tips_panel():
    """Render password safety tips as collapsible sub-expanders."""
    with st.expander("Safety Tips"):
        st.markdown(
            '<p style="color:#7878A0; font-size:0.76rem; margin-bottom:1rem;">'
            "Follow these tips to keep your accounts safe. "
            "Click on any tip to learn more.</p>",
            unsafe_allow_html=True,
        )
        for title, body in _SAFETY_TIPS:
            with st.expander(title):
                st.markdown(body, unsafe_allow_html=True)
        st.markdown(
            '<p style="color:#7878A0; font-size:0.76rem; margin-top:0.75rem;">'
            "These recommendations are aligned with <a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf' target='_blank' style='color:#7878A0;'>NIST SP 800-63B Rev. 4</a>.</p>",
            unsafe_allow_html=True,
        )


def render_scoring_panel():
    """Render a generic scoring explanation inside an expander."""
    with st.expander("How Scoring Works"):
        st.markdown(
            "Your password is scored out of <span style='color:#F5A623;font-weight:700'>100 points</span> across 7 categories. "
            "Crack-time resistance carries the most weight because it directly measures "
            "real-world entropy. Character diversity rules are useful nudges, not a "
            "substitute for genuine unpredictability.",
            unsafe_allow_html=True,
        )

        st.markdown("#### Point Breakdown")
        st.markdown(
            "| Category | Points |\n"
            "|----------|--------|\n"
            "| Length (15+ characters) | 10 |\n"
            "| Contains uppercase letters | 5 |\n"
            "| Contains lowercase letters | 5 |\n"
            "| Contains numbers | 5 |\n"
            "| Contains special characters | 5 |\n"
            "| Not found in breach databases | 20 |\n"
            "| Crack-time resistance | 0\u201350 |"
        )

        st.markdown("#### Breach Database Checks")
        st.markdown(
            "Your password is checked against **[Have I Been Pwned](https://haveibeenpwned.com)**, "
            "a database of over 900 million passwords collected from hundreds of real-world data breaches. "
            "If your password appears here, it means someone, somewhere, has already used it, and attackers have it too. "
            "Your password is checked privately using k-anonymity: only the first 5 characters of its hash "
            "are ever transmitted, so your actual password never leaves your device.\n\n"
            "Attackers commonly use wordlists like [rockyou.txt](https://en.wikipedia.org/wiki/RockYou), "
            "a list of 14 million real passwords leaked in the 2009 RockYou breach, as their first line of attack. "
            "Have I Been Pwned contains rockyou.txt and far more, making it the definitive check."
        )

        st.markdown("#### Crack-Time Resistance")
        st.markdown(
            "This category uses [zxcvbn](https://dropbox.tech/security/zxcvbn-realistic-password-strength-estimation) "
            "pattern analysis to estimate how long a real-world attacker would need to "
            "crack your password assuming bcrypt hashing at 10,000 guesses per second. "
            "At 50 points it is the single largest factor in your score."
        )
        st.markdown(
            "| Estimated Crack Time | Points |\n"
            "|----------------------|--------|\n"
            "| Less than 1 second | 0 |\n"
            "| Less than 1 minute | 5 |\n"
            "| Less than 1 hour | 10 |\n"
            "| Less than 1 day | 20 |\n"
            "| Less than 1 year | 30 |\n"
            "| Less than 100 years | 40 |\n"
            "| 100+ years | 50 |"
        )

        st.markdown("#### Entropy: What Are Bits and Guesses?")
        st.markdown(_html("""
            <p>Alongside your score, you'll see an
            <span style='color:#F5A623;font-weight:700'>entropy</span> value measured in
            <span style='color:#F5A623;font-weight:700'>bits</span>.
            Entropy is a way of measuring how unpredictable your password is, not how complex it looks,
            but how many attempts an attacker would need to guess it.</p>
            <p><span style='color:#F5A623;font-weight:700'>Bits</span> are the unit. Each additional bit doubles the number of guesses required.
            Think of it like this: 10 bits = ~1,000 guesses. 20 bits = ~1 million. 40 bits = ~1 trillion.
            Every bit you add makes the attacker's job exponentially harder, not just a little harder.</p>
            <p><span style='color:#F5A623;font-weight:700'>Guesses</span> is the same number written in plain English: the raw count of attempts
            a computer would have to make before it's likely to crack your password.
            A modern offline attack can test billions of guesses per second, so anything under
            a few trillion (~42 bits) is considered reachable with enough hardware and time.</p>
            <p>A long passphrase like
            <code style='color:#00E676;background:rgba(0,230,118,0.08);padding:0.1rem 0.35rem'>correct-horse-battery-staple</code>
            can reach 50+ bits of entropy with no uppercase, numbers, or symbols, because its length
            and randomness create a search space too large to brute-force. That's the core insight:
            <span style='color:#00E676;font-weight:700'>length beats complexity</span>.</p>
        """), unsafe_allow_html=True)

        st.markdown("#### Final Rating")
        st.markdown(_html("""
            <table style='width:100%;border-collapse:collapse;font-size:0.82rem'>
            <thead><tr>
            <th style='color:#46466A;font-size:0.65rem;letter-spacing:0.12em;text-transform:uppercase;text-align:left;padding:0.4rem 0.6rem;border-bottom:1px solid #222240'>Rating</th>
            <th style='color:#46466A;font-size:0.65rem;letter-spacing:0.12em;text-transform:uppercase;text-align:left;padding:0.4rem 0.6rem;border-bottom:1px solid #222240'>Score Range</th>
            </tr></thead>
            <tbody>
            <tr><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830'><span style='color:#00E676;font-weight:700;font-size:0.72rem;letter-spacing:0.08em;border:1px solid #00E676;padding:0.1rem 0.45rem'>EXCELLENT</span></td><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830;color:#CECEE0'>100</td></tr>
            <tr><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830'><span style='color:#00E676;font-weight:700;font-size:0.72rem;letter-spacing:0.08em;border:1px solid #00E676;padding:0.1rem 0.45rem'>STRONG</span></td><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830;color:#CECEE0'>80&ndash;95</td></tr>
            <tr><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830'><span style='color:#FFD600;font-weight:700;font-size:0.72rem;letter-spacing:0.08em;border:1px solid #FFD600;padding:0.1rem 0.45rem'>GOOD</span></td><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830;color:#CECEE0'>60&ndash;75</td></tr>
            <tr><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830'><span style='color:#FF6D00;font-weight:700;font-size:0.72rem;letter-spacing:0.08em;border:1px solid #FF6D00;padding:0.1rem 0.45rem'>FAIR</span></td><td style='padding:0.35rem 0.6rem;border-bottom:1px solid #181830;color:#CECEE0'>40&ndash;55</td></tr>
            <tr><td style='padding:0.35rem 0.6rem'><span style='color:#FF1744;font-weight:700;font-size:0.72rem;letter-spacing:0.08em;border:1px solid #FF1744;padding:0.1rem 0.45rem'>WEAK</span></td><td style='padding:0.35rem 0.6rem;color:#CECEE0'>Below 40</td></tr>
            </tbody></table>
        """), unsafe_allow_html=True)
        st.markdown(
            "Any password that can be cracked in <span style='color:#FF1744;font-weight:700'>under 1 hour</span> "
            "or is found in Have I Been Pwned is automatically rated "
            "<span style='color:#FF1744;font-weight:700'>WEAK</span> regardless of its total score.",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Validation results
# ---------------------------------------------------------------------------

def _compute_policy_compliance(password, result):
    """Compute old-school corporate and NIST SP 800-63B compliance booleans."""
    return {
        "cs_length":     len(password) >= 8,
        "cs_complexity": (any(c.isupper() for c in password)
                         and any(c.islower() for c in password)
                         and any(c.isdigit() for c in password)
                         and any(c in SPECIAL_CHARS for c in password)),
        "nist_length":   len(password) >= MIN_LENGTH,
        "nist_breach":   not any("have i been pwned" in r.lower() for r in result["failed"]),
    }


def render_policy_compliance(password, result, compliance):
    """Render the policy compliance panel (Deep Analysis section)."""

    def _cell(passed, pass_label, fail_label, na=False):
        if na:
            return (
                f'<div style="text-align:center;">'
                f'<span style="color:#7878A0; font-size:0.62rem; font-weight:700; '
                f'font-family:JetBrains Mono,monospace;">[N/A]</span>'
                f'<div style="font-size:0.58rem; color:#7878A0; margin-top:0.15rem; '
                f'font-family:JetBrains Mono,monospace;">{html.escape(pass_label)}</div>'
                f'</div>'
            )
        color = "#00E676" if passed else "#FF1744"
        badge = "[PASS]" if passed else "[FAIL]"
        label = pass_label if passed else fail_label
        return (
            f'<div style="text-align:center;">'
            f'<span style="color:{color}; font-size:0.62rem; font-weight:700; '
            f'font-family:JetBrains Mono,monospace;">{badge}</span>'
            f'<div style="font-size:0.58rem; color:#7878A0; margin-top:0.15rem; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(label)}</div>'
            f'</div>'
        )

    def _row(criterion, old_cell, nist_cell):
        return (
            f'<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; '
            f'padding:0.5rem 0; border-bottom:1px solid #111120; align-items:center;">'
            f'<div style="font-size:0.7rem; color:#CECEE0; font-family:JetBrains Mono,monospace;">'
            f'{html.escape(criterion)}</div>'
            f'{old_cell}{nist_cell}'
            f'</div>'
        )

    pw_len = len(password)
    header = (
        '<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:0.5rem;">'
        '<div></div>'
        '<div style="font-size:0.52rem; color:#7878A0; letter-spacing:0.1em; text-transform:uppercase; '
        'text-align:center; font-family:JetBrains Mono,monospace;">Old-School Corporate</div>'
        '<div style="font-size:0.52rem; color:#F5A623; letter-spacing:0.1em; text-transform:uppercase; '
        'text-align:center; font-family:JetBrains Mono,monospace;">NIST SP 800-63B</div>'
        '</div>'
    )

    rows_html = (
        header
        + _row("Minimum length",
               _cell(compliance["cs_length"],
                     f"requires 8+, has {pw_len}",
                     f"requires 8+, has {pw_len}"),
               _cell(compliance["nist_length"],
                     f"recommends 15+, has {pw_len}",
                     f"recommends 15+, has {pw_len}"))
        + _row("Character complexity",
               _cell(compliance["cs_complexity"],
                     "upper, lower, digit, special",
                     "requires upper, lower, digit, special"),
               _cell(True, "not required", "not required"))
        + _row("Breach database check",
               _cell(False, "not performed", "not performed", na=True),
               _cell(compliance["nist_breach"],
                     "not found in HIBP",
                     "found in HIBP"))
        + (
            '<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; '
            'padding:0.5rem 0; align-items:center;">'
            '<div style="font-size:0.7rem; color:#CECEE0; font-family:JetBrains Mono,monospace;">'
            'Forced rotation</div>'
            + _cell(False, "typically every 90 days", "typically every 90 days", na=True)
            + _cell(True, "not recommended", "not recommended")
            + '</div>'
        )
    )

    cs_pass   = compliance["cs_length"] and compliance["cs_complexity"]
    nist_pass = compliance["nist_length"] and compliance["nist_breach"]

    if cs_pass and nist_pass:
        summary = "This password meets both standards."
        summary_color = "#00E676"
    elif nist_pass and not cs_pass:
        summary = ("This password would be rejected by a typical corporate policy but is fully "
                   "compliant with NIST SP 800-63B, and significantly harder to crack.")
        summary_color = "#F5A623"
    elif cs_pass and not nist_pass:
        summary = ("This password meets old-school corporate requirements but does not meet "
                   "current NIST guidance.")
        summary_color = "#FF6D00"
    else:
        summary = "This password fails both standards."
        summary_color = "#FF1744"

    st.markdown(
        _html(f"""
        <div class="t-reveal" style="background:#0D0D1A; border:1px solid #222240; padding:1.25rem 1.5rem; margin:0.75rem 0;">
            <div style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.9rem; padding-bottom:0.75rem; border-bottom:1px solid #181830;">Policy Compliance</div>
            {rows_html}
            <div style="margin-top:0.9rem; padding-top:0.7rem; border-top:1px solid #181830; font-size:0.65rem; color:{summary_color}; letter-spacing:0.04em; line-height:1.6; font-family:'JetBrains Mono',monospace;">{html.escape(summary)}</div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_share_card(result, compliance):
    """Render the shareable result card at the bottom of Deep Analysis."""
    score      = result["score"]
    max_score  = result["max_score"]
    rating     = result["rating"]
    color      = RATING_COLORS.get(rating, "#46466A")
    crack_time = result["crack_time"]
    today      = datetime.date.today().strftime("%Y-%m-%d")

    hibp_passed      = not any("have i been pwned" in r.lower() for r in result["failed"])
    hibp_unavailable = any("hibp api unavailable" in r.lower() for r in result["failed"])
    nist_pass        = compliance["nist_length"] and compliance["nist_breach"]
    crack_resistant  = result["crack_seconds"] >= 3_153_600_000  # 100 years

    def _check_row(passed, pass_text, fail_text):
        icon  = "\u2713" if passed else "\u2717"
        text  = pass_text if passed else fail_text
        color = "#00E676" if passed else "#FF1744"
        return (
            f'<div style="font-size:0.68rem; color:{color}; letter-spacing:0.04em; '
            f'font-family:JetBrains Mono,monospace;">{icon} {html.escape(text)}</div>'
        )

    hibp_count = result.get("hibp_count")
    if hibp_unavailable:
        hibp_row = _check_row(False, "", "Breach database check unavailable")
    elif hibp_passed:
        hibp_row = _check_row(True, "Not found in Have I Been Pwned breach database", "")
    else:
        count_str = f" ({hibp_count:,} breaches)" if hibp_count is not None else ""
        hibp_row = _check_row(False, "",
                              f"Found in Have I Been Pwned breach database{count_str}")

    checks_html = (
        hibp_row
        + _check_row(nist_pass,
                     "NIST SP 800-63B compliant",
                     "Does not meet NIST SP 800-63B")
        + _check_row(crack_resistant,
                     "Resists offline brute-force attack",
                     "Vulnerable to offline brute-force attack")
    )

    st.markdown(
        _html(f"""
        <div class="t-reveal" style="border:1px solid #F5A623; margin:0.75rem 0;">
            <div style="background:#F5A623; padding:0.4rem 1.25rem; display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#06060C; font-size:0.6rem; font-weight:800; letter-spacing:0.2em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">Password Validator // Security Report</span>
                <span style="color:#06060C; font-size:0.58rem; letter-spacing:0.1em; font-family:'JetBrains Mono',monospace;">{today}</span>
            </div>
            <div style="background:#0D0D1A; padding:1.25rem 1.5rem;">
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:1rem; margin-bottom:1rem; padding-bottom:1rem; border-bottom:1px solid #181830;">
                    <div>
                        <div style="font-size:0.5rem; color:#7878A0; letter-spacing:0.16em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.25rem;">Score</div>
                        <div style="font-size:1.6rem; font-weight:800; color:{color}; line-height:1; font-family:'JetBrains Mono',monospace;">{score}<span style="font-size:0.75rem; color:#7878A0; font-weight:400;">/{max_score}</span></div>
                    </div>
                    <div>
                        <div style="font-size:0.5rem; color:#7878A0; letter-spacing:0.16em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.35rem;">Rating</div>
                        <div style="border:1px solid {color}; padding:0.25rem 0.75rem; display:inline-block;">
                            <span style="font-size:1rem; font-weight:800; color:{color}; font-family:'JetBrains Mono',monospace;">{html.escape(rating)}</span>
                        </div>
                    </div>
                    <div>
                        <div style="font-size:0.5rem; color:#7878A0; letter-spacing:0.16em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.25rem;">Crack Time</div>
                        <div style="font-size:1.2rem; font-weight:800; color:{color}; line-height:1; font-family:'JetBrains Mono',monospace; margin-top:0.15rem;">{html.escape(crack_time.capitalize())}</div>
                    </div>
                </div>
                <div style="display:flex; flex-direction:column; gap:0.3rem; margin-bottom:1rem; padding-bottom:1rem; border-bottom:1px solid #181830;">
                    {checks_html}
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:0.58rem; color:#46466A; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">pw-validator.streamlit.app</span>
                    <span style="font-size:0.58rem; color:#46466A; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">Built by Ben Mickens</span>
                </div>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_attack_breakdown(result):
    """Render the attack method breakdown panel (Deep Analysis section)."""
    sequence = result.get("attack_sequence", [])
    non_brute = [s for s in sequence if s["tag"] != "BRUTE"]

    if not non_brute:
        content_html = (
            '<div style="color:#00E676; font-size:0.75rem; letter-spacing:0.06em; '
            'font-family:JetBrains Mono,monospace;">'
            '\u2713 No exploitable patterns detected. Attacker falls back to pure brute force.</div>'
        )
        summary = "Without a recognizable pattern, cracking requires testing every possible combination."
        summary_color = "#7878A0"
    else:
        rows = ""
        for item in non_brute:
            color = _SEVERITY_COLORS.get(item["severity"], "#7878A0")
            tag_display = _TAG_DISPLAY.get(item["tag"], item["tag"])
            rows += (
                f'<div style="display:flex; gap:0.8rem; align-items:baseline; margin:0.38rem 0;">'
                f'<span style="color:{color}; font-size:0.62rem; font-weight:700; '
                f'white-space:nowrap; font-family:JetBrains Mono,monospace;">{html.escape(tag_display)}</span>'
                f'<span style="color:#F5A623; font-size:0.82rem; font-weight:700; '
                f'font-family:JetBrains Mono,monospace; white-space:nowrap;">'
                f'&quot;{html.escape(item["token"])}&quot;</span>'
                f'<span style="color:#7878A0; font-size:0.72rem; font-family:JetBrains Mono,monospace;">'
                f'{html.escape(item["description"])}</span>'
                f'</div>'
            )
        content_html = rows
        summary = ("Attackers use automated tools that try dictionary words, dates, and keyboard "
                   "patterns before brute force.")
        summary_color = "#7878A0"

    st.markdown(
        _html(f"""
        <div class="t-reveal" style="background:#0D0D1A; border:1px solid #222240; padding:1.25rem 1.5rem; margin:0.75rem 0;">
            <div style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.9rem; padding-bottom:0.75rem; border-bottom:1px solid #181830;">How An Attacker Would Crack This</div>
            {content_html}
            <div style="margin-top:0.9rem; padding-top:0.7rem; border-top:1px solid #181830; font-size:0.65rem; color:{summary_color}; letter-spacing:0.04em; line-height:1.6; font-family:'JetBrains Mono',monospace;">{html.escape(summary)}</div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_validation_results(password):
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

    result = full_validate(password)

    score      = result["score"]
    max_score  = result["max_score"]
    rating     = result["rating"]
    color      = RATING_COLORS.get(rating, "#7878A0")
    grad_a, grad_b = RATING_GRADIENTS.get(rating, ("#7878A0", "#7878A0"))
    score_pct  = min(score / max_score, 1.0)

    # Ring geometry: r=90, circumference ≈ 565.48
    ring_circumference = 565.48
    ring_dashoffset    = ring_circumference * (1 - score_pct)

    # Per-metric tiers + display values
    crack_tier  = _crack_time_tier(result["crack_seconds"])
    hibp_unavailable = any("hibp api unavailable" in r.lower() for r in result["failed"])
    breach_tier = _breach_tier(result.get("hibp_count"), hibp_unavailable)
    length_tier = _length_tier(len(password))

    crack_val   = result["crack_time"].capitalize()
    breach_val  = "Unknown" if hibp_unavailable else _format_breach_count(result.get("hibp_count"))
    length_val  = f"{len(password)} chars"

    crack_color  = _TIER_COLORS[crack_tier]
    breach_color = _TIER_COLORS[breach_tier]
    length_color = _TIER_COLORS[length_tier]

    # Unique gradient id per render so multiple results don't collide
    grad_id = f"pv-grad-{hash(rating) & 0xFFFF}"

    st.markdown(
        _html(f"""
        <div class="t-reveal pv-result">
            <div class="ring-wrap">
                <svg viewBox="0 0 200 200">
                    <defs>
                        <linearGradient id="{grad_id}" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="{grad_a}" />
                            <stop offset="100%" stop-color="{grad_b}" />
                        </linearGradient>
                    </defs>
                    <circle class="ring-bg" cx="100" cy="100" r="90" />
                    <circle class="ring-fg" cx="100" cy="100" r="90"
                        style="stroke:url(#{grad_id}); stroke-dashoffset:{ring_dashoffset:.2f};" />
                </svg>
                <div class="ring-center">
                    <div class="num">{score}<span class="of">/{max_score}</span></div>
                    <div class="badge" style="color:{color};">{html.escape(rating)}</div>
                </div>
            </div>
            <div class="breakdown">
                <div class="row">
                    <span class="lbl-wrap">
                        <span class="dot" style="background:{crack_color};"></span>
                        <span class="lbl">Crack time</span>
                    </span>
                    <span class="val" style="color:{crack_color};">{html.escape(crack_val)}</span>
                </div>
                <div class="row">
                    <span class="lbl-wrap">
                        <span class="dot" style="background:{breach_color};"></span>
                        <span class="lbl">Breach check</span>
                    </span>
                    <span class="val" style="color:{breach_color};">{html.escape(breach_val)}</span>
                </div>
                <div class="row">
                    <span class="lbl-wrap">
                        <span class="dot" style="background:{length_color};"></span>
                        <span class="lbl">Length</span>
                    </span>
                    <span class="val" style="color:{length_color};">{html.escape(length_val)}</span>
                </div>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # ── HIBP failure warning ───────────────────────────────────────────────
    if any("HIBP API unavailable" in r for r in result["failed"]):
        st.warning(
            "The breach database check could not be completed. "
            "This password has NOT been verified against known breaches. "
            "Retry when you have network connectivity."
        )

    # ── Threat gauge ───────────────────────────────────────────────────────
    render_threat_gauge(result["crack_time"], result["crack_seconds"])

    # ── Rule analysis ──────────────────────────────────────────────────────
    passed = result["passed"]
    failed = result["failed"]
    opt_count  = sum(1 for r in failed if r.startswith("\u25cb"))
    fail_count = len(failed) - opt_count

    rows_html = ""
    badge_style = "display:inline-block; min-width:2.8rem; font-size:0.62rem; font-weight:700; letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; padding-top:2px;"
    for rule in passed:
        rows_html += (
            f'<div class="pv-row-pass" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'<span style="color:#00E676; {badge_style}">[OK]</span>'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
            f'</div>'
        )
    for rule in failed:
        if rule.startswith("\u26a0"):
            row_class = "pv-row-warn"
            badge = f'<span style="color:#F5A623; {badge_style}">[WARN]</span>'
        elif rule.startswith("\u25cb"):
            row_class = "pv-row-opt"
            badge = f'<span style="color:#7878A0; {badge_style}">[OPT]</span>'
        else:
            row_class = "pv-row-fail"
            badge = f'<span style="color:#FF1744; {badge_style}">[FAIL]</span>'
        rows_html += (
            f'<div class="{row_class}" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'{badge}'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
            f'</div>'
        )
        if "have i been pwned" in rule.lower() and result.get("hibp_count") is not None:
            count = result["hibp_count"]
            rows_html += (
                f'<div style="padding:0.3rem 0.6rem 0.5rem 2.5rem; font-size:0.67rem; '
                f'color:#7878A0; line-height:1.6; font-family:JetBrains Mono,monospace;">'
                f'Passwords in breach databases are loaded into automated credential stuffing tools '
                f'and tried against millions of accounts. A count of {count:,} means this exact '
                f'password has been seen that many times in real-world breaches.'
                f'</div>'
            )

    if not rows_html:
        rows_html = (
            '<span style="color:#7878A0; font-size:0.78rem; '
            'font-family:JetBrains Mono,monospace;">No rules evaluated.</span>'
        )

    st.markdown(
        _html(f"""
        <div class="t-reveal" style="background:#0D0D1A; border:1px solid #222240; padding:1.25rem 1.5rem; margin:0.75rem 0;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.9rem; padding-bottom:0.75rem; border-bottom:1px solid #181830;">
                <span style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">Rule Analysis</span>
                <div style="display:flex; gap:1.25rem;">
                    <span style="font-size:0.6rem; color:#00E676; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">&#x2713; {len(passed)} passed</span>
                    <span style="font-size:0.6rem; color:#FF1744; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">&#x2717; {fail_count} failed</span>
                    <span style="font-size:0.6rem; color:#7878A0; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">&#x25cb; {opt_count} optional</span>
                </div>
            </div>
            {rows_html}
        </div>
        """),
        unsafe_allow_html=True,
    )

    # ── Recommendations ────────────────────────────────────────────────────
    recs = []
    if result["score"] < 50:
        recs.append("This password is too weak for secure systems.")
    if result["failed"]:
        recs.append("Address all failed rules listed above.")
    if any("have i been pwned" in r.lower() for r in result["failed"]):
        recs.append("Use a unique password not found in the Have I Been Pwned database.")
    if result["warning"]:
        recs.append(result["warning"])
    recs.extend(result["suggestions"])

    if recs:
        items_html = "".join(
            f'<div style="display:flex; gap:0.8rem; margin:0.45rem 0;">'
            f'<span style="color:#F5A623; font-size:0.68rem; flex-shrink:0; '
            f'font-family:JetBrains Mono,monospace; padding-top:2px;">&#8594;</span>'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.5; '
            f'font-family:JetBrains Mono,monospace;">{_md_bold(rec)}</span>'
            f'</div>'
            for rec in recs
        )
        st.markdown(
            _html(f"""
            <div class="t-reveal" style="background:#0D0D1A; border:1px solid #222240; border-left:3px solid #F5A623; padding:1.25rem 1.5rem; margin:0.75rem 0;">
                <div style="font-size:0.58rem; color:#F5A623; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.75rem;">Recommendations</div>
                {items_html}
            </div>
            """),
            unsafe_allow_html=True,
        )

    # ── Deep Analysis ──────────────────────────────────────────────────────
    st.markdown(
        _html('<div style="display:flex; align-items:center; gap:1rem; margin:2rem 0 1.25rem;"><div style="flex:1; height:1px; background:#181830;"></div><span style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; white-space:nowrap; font-family:JetBrains Mono,monospace;">Deep Analysis</span><div style="flex:1; height:1px; background:#181830;"></div></div>'),
        unsafe_allow_html=True,
    )

    compliance = _compute_policy_compliance(password, result)
    render_attack_breakdown(result)
    render_policy_compliance(password, result, compliance)
    render_share_card(result, compliance)

    st.session_state["validation_done"] = True
    st.session_state["last_validated_password"] = password


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

inject_global_styles()

render_header()

def _on_password_change():
    st.session_state.pop("validation_done", None)

_input_col, _button_col = st.columns([4, 1], gap="small")
with _input_col:
    password = st.text_input(
        "Password",
        type="password",
        max_chars=MAX_LENGTH,
        key="password_input",
        on_change=_on_password_change,
        placeholder="test your password...",
        label_visibility="collapsed",
    )
with _button_col:
    validate_clicked = st.button("Analyze", use_container_width=True)

st.markdown(
    '<p style="text-align:center; font-size:0.75rem; color:#6B7488; margin:0.75rem 0 0;">'
    'Your password never leaves this device. We send only a partial SHA-1 prefix to HIBP.'
    '</p>',
    unsafe_allow_html=True,
)

render_generator_panel()
render_passphrase_panel()
render_safety_tips_panel()
render_scoring_panel()

if validate_clicked:
    render_validation_results(password)
elif st.session_state.get("validation_done") and \
        st.session_state.get("last_validated_password") == password:
    render_validation_results(password)

st.markdown(
    '<div class="pv-footer" style="margin-top:3rem; padding-top:1.25rem; '
    'border-top:1px solid #181830; text-align:center;">'
    '<span style="color:#7878A0; font-size:0.62rem; letter-spacing:0.14em;">BUILT BY BEN MICKENS</span>'
    '<span style="color:#7878A0; font-size:0.62rem; margin:0 0.75rem;">·</span>'
    '<a href="https://github.com/cyberpsyon/password-validator" target="_blank" '
    'style="font-size:0.62rem; letter-spacing:0.14em; transition:color 0.2s;">'
    '[ SOURCE: GITHUB ]'
    '</a>'
    '</div>',
    unsafe_allow_html=True,
)
