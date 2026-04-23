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
st.set_page_config(page_title="Password Validator", page_icon="○", layout="centered")

# ---------------------------------------------------------------------------
# Palette — wabi-sabi / ensō
# ---------------------------------------------------------------------------
# A single vermilion accent against a warm near-black ground. Secondary hues
# stay within the earth-pigment family (ochre, muted crimson, sage) so nothing
# competes with the ensō and score.

RATING_COLORS = {
    "EXCELLENT": "#D24D3E",
    "STRONG":    "#D24D3E",
    "GOOD":      "#B08C5A",
    "FAIR":      "#A67448",
    "WEAK":      "#9B3F35",
}

# (upper-bound-seconds, human label) — first entry the password beats wins.
_TIER_LABELS = [
    (60,          "instant"),
    (3600,        "minutes"),
    (86400,       "hours"),
    (2592000,     "days"),
    (31536000,    "months"),
    (315360000,   "years"),
    (3153600000,  "decades"),
    (float("inf"), "centuries"),
]

_SEPARATORS = {
    "Hyphen (-)":    "-",
    "Space":         " ",
    "Period (.)":    ".",
    "Underscore (_)": "_",
    "None":          "",
}

_SEVERITY_COLORS = {
    "critical": "#9B3F35",
    "moderate": "#A67448",
    "low":      "#B08C5A",
    "none":     "rgba(232,223,211,0.35)",
}

_TAG_DISPLAY = {
    "DICT":  "dictionary",
    "KEY":   "keyboard",
    "DATE":  "date",
    "SEQ":   "sequence",
    "RPT":   "repetition",
    "BRUTE": "brute force",
}

# Accent / safe / warn colors used inside the safety-tip prose
_ACCENT = "#D24D3E"
_OK     = "#7A8F65"
_WARN   = "#9B3F35"

_SAFETY_TIPS = [
    ("Use a unique password for every account",
     f"When a company gets hacked, attackers take the stolen passwords and try "
     f"them on other websites like your email, bank, and social media. If you "
     f"use the <span style='color:{_WARN}'>same password everywhere</span>, "
     f"one breach can compromise all of your accounts. Always use a "
     f"<span style='color:{_OK}'>different password for each account</span>."),

    ("Use a password manager",
     f"Nobody can remember dozens of strong, unique passwords. A "
     f"<span style='color:{_ACCENT}'>password manager</span> is an app "
     f"that securely stores all of your passwords for you. You only need to remember "
     f"<span style='color:{_OK}'>one master password</span>, and the manager fills in "
     f"the rest. <a href='https://1password.com/' target='_blank' style='color:{_ACCENT}'>1Password</a> "
     f"is the industry-leading option for individuals and teams."),

    ("Enable multi-factor authentication",
     f"<span style='color:{_ACCENT}'>Multi-factor authentication</span> adds another step "
     f"when you log in, like a code from an app on your phone or a physical security key. Even if "
     f"someone steals your password, they still cannot get into your account without that second step. "
     f"<span style='color:{_OK}'>Turn on MFA everywhere it is available</span>, "
     f"especially for email, banking, and work accounts. "
     f"<span style='color:{_WARN}'>Avoid SMS-based MFA when possible.</span> "
     f"Authenticator apps (like Authy or Google Authenticator) and hardware security keys "
     f"(like <a href='https://www.yubico.com/get-yubikey' target='_blank' style='color:{_ACCENT}'>YubiKey</a>) "
     f"are significantly harder to intercept or bypass."),

    ("Longer passwords are stronger passwords",
     f"A <span style='color:{_ACCENT}'>20-character passphrase</span> made of random words "
     f"(like <span style='color:{_OK}'>&ldquo;correct-horse-battery-staple&rdquo;</span>) "
     f"is both stronger and easier to type than a short, complicated password "
     f"like <span style='color:{_WARN}'>&ldquo;P@s5w0rd!&rdquo;</span>. "
     f"Aim for <span style='color:{_ACCENT}'>at least 15 characters</span>, but longer is always better."),

    ("Never share passwords over email or chat",
     f"No legitimate company, IT department, or government agency will ever ask "
     f"you for your password. If someone contacts you asking for your password, "
     f"<span style='color:{_WARN}'>it is a scam</span>. Always type your password "
     f"<span style='color:{_OK}'>directly</span> into the official website or app, "
     f"<span style='color:{_WARN}'>never</span> into an email, text message, or phone call."),

    ("Watch for data breaches",
     f"Data breaches happen regularly, and your information may be exposed "
     f"without you knowing. Sign up for "
     f"<span style='color:{_OK}'>free alerts</span> at "
     f"<a href='https://haveibeenpwned.com' target='_blank' style='color:{_ACCENT}'>Have I Been Pwned</a> to "
     f"get notified if your email appears in a breach. When you get an alert, "
     f"<span style='color:{_OK}'>change the password</span> for that account immediately."),

    ("Change passwords that have been exposed",
     f"If you find out that one of your passwords was part of a data breach, "
     f"<span style='color:{_OK}'>stop using it right away</span> on every account where you used it. "
     f"Attackers share stolen passwords widely, so a breached password is "
     f"<span style='color:{_WARN}'>never safe to use again</span>, even if you change it slightly."),

    ("A high score does not mean your password is unbreakable",
     f"Even if this tool rates your password as &ldquo;excellent&rdquo; with a crack time "
     f"of centuries, <span style='color:{_WARN}'>no password is truly permanent</span>. "
     f"Advances in technology, including "
     f"<span style='color:{_ACCENT}'>quantum computing</span>, will make password cracking "
     f"significantly faster in the future. "
     f"<span style='color:{_OK}'>Combine strong passwords with MFA</span> and change a "
     f"password only when you have reason to believe it has been compromised. "
     f"Routine rotation tends to produce weaker, predictable passwords and is no longer recommended."),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _md_bold(text: str) -> str:
    """HTML-escape text, then render **bold** as a vermilion emphasis."""
    text = html.escape(text)
    return re.sub(r"\*\*(.+?)\*\*", r'<em style="color:#D24D3E; font-style:normal;">\1</em>', text)


def _html(markup: str) -> str:
    """Strip blank lines so CommonMark never exits HTML-block mode mid-tag."""
    return "\n".join(line for line in markup.split("\n") if line.strip())


def _format_guesses(n: float) -> str:
    if n < 1_000:
        return f"{int(n)} guesses"
    if n < 1_000_000:
        return f"{n / 1_000:.0f} thousand guesses"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.0f} million guesses"
    if n < 1_000_000_000_000:
        return f"{n / 1_000_000_000:.0f} billion guesses"
    if n < 1_000_000_000_000_000:
        return f"{n / 1_000_000_000_000:.0f} trillion guesses"
    if n < 1_000_000_000_000_000_000:
        return f"{n / 1_000_000_000_000_000:.0f} quadrillion guesses"
    return f"{n / 1_000_000_000_000_000_000:.0f} quintillion guesses"


def _tier_label(seconds: float) -> str:
    for upper, label in _TIER_LABELS:
        if seconds < upper:
            return label
    return "centuries"


# ---------------------------------------------------------------------------
# Global styles
# ---------------------------------------------------------------------------

def inject_global_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Shippori+Mincho:wght@400;500;600;700&family=JetBrains+Mono:wght@300;400;500&display=swap');

        :root {
            --bg:            #14110E;
            --washi:         #E8DFD3;
            --washi-dim:     rgba(232, 223, 211, 0.35);
            --washi-faint:   rgba(232, 223, 211, 0.14);
            --washi-whisper: rgba(232, 223, 211, 0.06);
            --vermilion:     #D24D3E;
            --vermilion-dim: rgba(210, 77, 62, 0.10);
            --ochre:         #B08C5A;
            --amber-dim:     #A67448;
            --crimson:       #9B3F35;
            --sage:          #7A8F65;
        }

        /* ── Type: mincho is the default body voice, mono is reserved for data ── */
        html, body, [class^="st"], [class*=" st"] {
            font-family: 'Shippori Mincho', 'Hiragino Mincho ProN', 'Yu Mincho', Georgia, serif;
        }
        .pv-mono, .pv-mono * {
            font-family: 'JetBrains Mono', 'SF Mono', 'Menlo', monospace !important;
        }

        /* ── Meditative dark ground: warm near-black with a whisper of paper grain ── */
        .stApp {
            background-color: var(--bg) !important;
            background-image:
                radial-gradient(ellipse 80% 60% at 20% 0%, rgba(210,77,62,0.025), transparent 70%),
                radial-gradient(ellipse 60% 50% at 100% 100%, rgba(176,140,90,0.02), transparent 70%);
            background-attachment: fixed;
        }

        .block-container {
            padding-top: 3.5rem !important;
            padding-bottom: 6rem !important;
            max-width: 640px !important;
        }

        /* ── Typography defaults ── */
        h1, h2, h3, h4, h5, h6 {
            color: var(--washi) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-weight: 500 !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
        }
        p, li, span, div {
            color: var(--washi);
        }
        a {
            color: var(--vermilion) !important;
            text-decoration: none !important;
            border-bottom: 1px solid rgba(210,77,62,0.25) !important;
            transition: border-color 0.3s ease !important;
        }
        a:hover { border-bottom-color: var(--vermilion) !important; }

        /* ── Password input: no box, just a breathing underline ── */
        .stTextInput > div > div {
            background: transparent !important;
            border: 0 !important;
            border-bottom: 1px solid var(--washi-faint) !important;
            border-radius: 0 !important;
            transition: border-color 0.5s ease !important;
            box-shadow: none !important;
        }
        .stTextInput > div > div:focus-within {
            border-bottom-color: var(--vermilion) !important;
            box-shadow: none !important;
        }
        .stTextInput input {
            background: transparent !important;
            color: var(--washi) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-size: 1.15rem !important;
            letter-spacing: 0.02em !important;
            padding: 0.9rem 0 !important;
            caret-color: var(--vermilion) !important;
        }
        .stTextInput label {
            color: var(--washi-dim) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-size: 0.88rem !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
            margin-bottom: 0.35rem !important;
            font-weight: 400 !important;
        }

        /* ── Buttons: restrained hairline that warms to vermilion on hover ── */
        .stButton > button {
            background: transparent !important;
            border: 1px solid var(--washi-faint) !important;
            border-radius: 0 !important;
            color: var(--washi) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-weight: 400 !important;
            font-size: 1.0rem !important;
            letter-spacing: 0.03em !important;
            text-transform: none !important;
            padding: 0.8rem 1.5rem !important;
            box-shadow: none !important;
            transition: border-color 0.55s ease, color 0.55s ease,
                        background-color 0.55s ease, letter-spacing 0.55s ease !important;
        }
        .stButton > button p,
        .stButton > button span,
        .stButton > button div { color: inherit !important; transition: color 0.55s ease !important; }
        .stButton > button:hover {
            border-color: var(--vermilion) !important;
            color: var(--vermilion) !important;
            background: var(--vermilion-dim) !important;
            letter-spacing: 0.08em !important;
        }
        .stButton > button:active { background: var(--vermilion-dim) !important; }
        .stButton > button:focus { box-shadow: none !important; }

        /* ── Borderless disclosure (expanders): title line only, no card ── */
        details {
            background: transparent !important;
            border: 0 !important;
            border-top: 1px solid var(--washi-whisper) !important;
            border-radius: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
        }
        details summary {
            display: flex !important;
            align-items: center !important;
            list-style: none !important;
            color: var(--washi) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-weight: 400 !important;
            font-size: 0.98rem !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
            padding: 1rem 0 !important;
            cursor: pointer !important;
            transition: color 0.4s ease !important;
        }
        details summary::-webkit-details-marker { display: none !important; }
        /* Verified Streamlit DOM: hide the icon ligature span, keep the label div. */
        details summary > span > span,
        details summary > span > svg { display: none !important; }
        details summary::after {
            content: '○' !important;
            color: var(--washi-dim) !important;
            font-size: 0.8rem !important;
            flex-shrink: 0 !important;
            margin-left: auto !important;
            padding-left: 1rem !important;
            transition: color 0.4s ease, transform 0.7s cubic-bezier(0.22,1,0.36,1) !important;
            display: inline-block !important;
            font-family: 'Shippori Mincho', serif !important;
        }
        details summary:hover { color: var(--vermilion) !important; }
        details summary:hover::after { color: var(--vermilion) !important; }
        details[open] summary {
            color: var(--vermilion) !important;
            padding-bottom: 0.5rem !important;
        }
        details[open] summary::after {
            content: '●' !important;
            color: var(--vermilion) !important;
            transform: rotate(180deg);
        }
        .streamlit-expanderContent,
        details > div:not(summary) {
            background: transparent !important;
            padding: 0.25rem 0 1.5rem 0 !important;
            border: 0 !important;
        }

        /* Sub-expanders (inside safety tips) get a lighter rule */
        details details { border-top-color: var(--washi-whisper) !important; }

        /* ── Slider / selectbox / checkbox: light touch ── */
        [data-baseweb="slider"] [role="slider"] {
            background: var(--vermilion) !important;
            border-color: var(--vermilion) !important;
            box-shadow: none !important;
        }
        [data-baseweb="slider"] [data-testid="stTickBar"] {
            color: var(--washi-dim) !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.7rem !important;
        }

        [data-baseweb="select"] > div {
            background: transparent !important;
            border: 0 !important;
            border-bottom: 1px solid var(--washi-faint) !important;
            border-radius: 0 !important;
            box-shadow: none !important;
        }
        [data-baseweb="select"] > div:hover { border-bottom-color: var(--vermilion) !important; }
        [data-baseweb="select"] span,
        [data-baseweb="select"] div { color: var(--washi) !important; font-family: 'Shippori Mincho', serif !important; }

        .stCheckbox label p,
        .stCheckbox label span {
            color: var(--washi) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-size: 0.9rem !important;
            font-style: italic !important;
        }
        .stCheckbox [data-baseweb="checkbox"] > span:first-child {
            border-color: var(--washi-faint) !important;
            border-radius: 0 !important;
            background: transparent !important;
        }
        .stCheckbox [data-baseweb="checkbox"][aria-checked="true"] > span:first-child,
        .stCheckbox [data-baseweb="checkbox"] > span[data-checked="true"] {
            background: var(--vermilion) !important;
            border-color: var(--vermilion) !important;
        }

        /* Labels above sliders / selects */
        .stSlider label,
        .stSelectbox label {
            color: var(--washi-dim) !important;
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-size: 0.85rem !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
        }

        /* ── Divider / hr: hair-thin washi line ── */
        hr { border-color: var(--washi-whisper) !important; opacity: 1 !important; margin: 2rem 0 !important; }

        /* ── Alerts: a single left rule, nothing else ── */
        .stAlert {
            background: transparent !important;
            border: 0 !important;
            border-left: 1px solid var(--vermilion) !important;
            border-radius: 0 !important;
            padding: 0.4rem 0 0.4rem 1rem !important;
        }
        .stAlert > div {
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-size: 0.92rem !important;
            color: var(--washi) !important;
        }

        /* ── Code / tables ── */
        pre, .stCode > div {
            background: transparent !important;
            border: 0 !important;
            border-left: 1px solid var(--washi-whisper) !important;
            border-radius: 0 !important;
            padding-left: 1rem !important;
        }
        code { color: var(--sage) !important; background: transparent !important; font-family: 'JetBrains Mono', monospace !important; font-size: 0.86em !important; }

        table { border-collapse: collapse !important; width: 100% !important; margin: 0.5rem 0 1rem !important; }
        th {
            background: transparent !important;
            color: var(--washi-dim) !important;
            border: 0 !important;
            border-bottom: 1px solid var(--washi-whisper) !important;
            padding: 0.6rem 0.75rem !important;
            font-family: 'Shippori Mincho', serif !important;
            font-style: italic !important;
            font-weight: 400 !important;
            font-size: 0.82rem !important;
            text-align: left !important;
            letter-spacing: 0 !important;
            text-transform: none !important;
        }
        td {
            background: transparent !important;
            color: var(--washi) !important;
            border: 0 !important;
            border-bottom: 1px solid var(--washi-whisper) !important;
            padding: 0.55rem 0.75rem !important;
            font-size: 0.9rem !important;
            font-family: 'Shippori Mincho', serif !important;
        }
        td code { font-size: 0.82rem !important; }

        /* ── Spinner ── */
        .stSpinner > div { border-top-color: var(--vermilion) !important; }

        /* ── Reveal: a soft rise ── */
        @keyframes pvRise {
            from { opacity: 0; transform: translateY(6px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .pv-reveal { animation: pvRise 0.85s cubic-bezier(0.22, 1, 0.36, 1) both; }
        .pv-reveal-1 { animation-delay: 0.15s; }
        .pv-reveal-2 { animation-delay: 0.40s; }
        .pv-reveal-3 { animation-delay: 0.70s; }
        .pv-reveal-4 { animation-delay: 1.00s; }

        /* ── Input disclaimer cycling (preserved exactly per design brief) ── */
        @keyframes pvLeft {
            0%, 35%  { opacity: 1; }
            40%      { opacity: 0; }
            95%      { opacity: 0; }
            100%     { opacity: 1; }
        }
        @keyframes pvRight {
            0%, 45%  { opacity: 0; }
            50%      { opacity: 1; }
            80%      { opacity: 1; }
            85%      { opacity: 0; }
            100%     { opacity: 0; }
        }
        .pv-left  { animation: pvLeft  10s linear infinite; }
        .pv-right { animation: pvRight 10s linear infinite; }

        /* ── Sparse metric grid ── */
        .pv-metrics {
            display: grid;
            grid-template-columns: auto 1fr;
            column-gap: 2.5rem;
            row-gap: 0.7rem;
            max-width: 360px;
            margin: 2.75rem auto 1rem auto;
        }
        .pv-label {
            font-family: 'Shippori Mincho', serif;
            font-style: italic;
            color: var(--washi-dim);
            font-size: 0.92rem;
            text-align: right;
            white-space: nowrap;
        }
        .pv-value {
            font-family: 'JetBrains Mono', monospace;
            color: var(--washi);
            font-size: 0.88rem;
            letter-spacing: 0.02em;
            font-weight: 400;
        }

        /* ── Rule lines ── */
        .pv-rule {
            display: flex;
            gap: 1rem;
            align-items: baseline;
            padding: 0.42rem 0;
            max-width: 560px;
            margin: 0 auto;
        }
        .pv-rule-mark {
            font-family: 'Shippori Mincho', serif;
            font-size: 1.1rem;
            width: 1.1rem;
            text-align: center;
            flex-shrink: 0;
            line-height: 1.3;
        }
        .pv-rule-text {
            color: var(--washi);
            font-family: 'Shippori Mincho', serif;
            font-size: 0.94rem;
            line-height: 1.55;
        }
        .pv-rule-pass .pv-rule-mark { color: var(--sage); }
        .pv-rule-fail .pv-rule-mark { color: var(--crimson); }
        .pv-rule-warn .pv-rule-mark { color: var(--vermilion); }
        .pv-rule-opt  .pv-rule-mark { color: var(--washi-dim); }
        .pv-rule-opt  .pv-rule-text { color: var(--washi-dim); }

        /* ── Soft summary block for attacker breakdown / policy / report ── */
        .pv-soft-head {
            font-family: 'Shippori Mincho', serif;
            font-style: italic;
            color: var(--washi-dim);
            font-size: 0.95rem;
            margin: 0 0 1rem 0;
        }
        .pv-soft-row {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 1.25rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--washi-whisper);
            align-items: baseline;
        }
        .pv-soft-row:last-child { border-bottom: 0; }
        .pv-soft-k {
            font-family: 'Shippori Mincho', serif;
            font-style: italic;
            color: var(--washi-dim);
            font-size: 0.88rem;
            white-space: nowrap;
        }
        .pv-soft-v {
            font-family: 'JetBrains Mono', monospace;
            color: var(--washi);
            font-size: 0.85rem;
            letter-spacing: 0.01em;
        }

        /* ── Section whisper: an italic lowercase label between sections ── */
        .pv-section {
            text-align: center;
            margin: 3rem 0 1.5rem;
            color: var(--washi-dim);
            font-family: 'Shippori Mincho', serif;
            font-style: italic;
            font-size: 0.92rem;
            letter-spacing: 0;
        }
        .pv-section-mark {
            display: block;
            color: var(--washi-faint);
            font-size: 0.9rem;
            margin-bottom: 0.75rem;
            font-family: 'Shippori Mincho', serif;
        }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--washi-whisper); }
        ::-webkit-scrollbar-thumb:hover { background: var(--vermilion); }

        /* ── Hide Streamlit chrome ── */
        #MainMenu { visibility: hidden; }
        footer    { visibility: hidden; }
        header    { visibility: hidden; }

        /* ── Footer ── */
        .pv-footer {
            margin-top: 5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--washi-whisper);
            text-align: center;
        }
        .pv-footer span,
        .pv-footer a {
            color: var(--washi-dim) !important;
            font-family: 'Shippori Mincho', serif;
            font-style: italic;
            font-size: 0.82rem;
            border-bottom: 0 !important;
            transition: color 0.4s ease !important;
        }
        .pv-footer a:hover { color: var(--vermilion) !important; }
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
        <div style="margin-bottom: 2.5rem;">
            <div style="font-family:'Shippori Mincho', serif; color:#E8DFD3;
                        font-size:2.4rem; font-weight:500; line-height:1.1;
                        letter-spacing:-0.005em;">
                Password Validator
            </div>
            <div style="font-family:'Shippori Mincho', serif; font-style:italic;
                        color:rgba(232,223,211,0.35); font-size:0.95rem;
                        margin-top:0.55rem; line-height:1.4;">
                a quiet measure of strength
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Ensō hero + sparse metrics (replaces card + gauge)
# ---------------------------------------------------------------------------

def render_enso_hero(score, max_score, rating, color, shadow=None):
    """Big ensō arc with the score centered inside and an italic rating below."""
    score_pct = min(score / max_score * 100, 100) if max_score else 0
    offset    = 100 - score_pct  # stroke-dashoffset target value

    st.markdown(
        _html(f"""
        <div class="pv-reveal" style="position:relative; width:100%; max-width:320px;
                    aspect-ratio:1; margin:2.5rem auto 0.5rem auto;">
            <svg viewBox="0 0 240 240" style="width:100%; height:100%; overflow:visible; display:block;">
                <defs>
                    <filter id="pvBrush" x="-6%" y="-6%" width="112%" height="112%">
                        <feTurbulence type="fractalNoise" baseFrequency="0.95" numOctaves="2" seed="7"/>
                        <feDisplacementMap in="SourceGraphic" scale="1.6"/>
                    </filter>
                </defs>
                <g transform="rotate(-95 120 120)">
                    <path d="M 120 22 A 98 98 0 1 1 87 29"
                          fill="none"
                          stroke="rgba(232,223,211,0.06)"
                          stroke-width="3.5"
                          stroke-linecap="round"/>
                    <path id="pv-enso-stroke"
                          d="M 120 22 A 98 98 0 1 1 87 29"
                          fill="none"
                          stroke="{color}"
                          stroke-width="4"
                          stroke-linecap="round"
                          pathLength="100"
                          stroke-dasharray="100"
                          stroke-dashoffset="100"
                          data-target-offset="{offset:.2f}"
                          filter="url(#pvBrush)"
                          style="transition: stroke-dashoffset 1.2s cubic-bezier(0.22, 1, 0.36, 1);"/>
                </g>
            </svg>
            <div style="position:absolute; inset:0;
                        display:flex; flex-direction:column;
                        justify-content:center; align-items:center;
                        pointer-events:none;">
                <div style="font-family:'Shippori Mincho', serif;
                            font-weight:500;
                            font-size:5.25rem;
                            color:{color};
                            line-height:1;
                            letter-spacing:-0.02em;">
                    <span id="pv-score" data-target="{int(score)}">0</span>
                </div>
                <div style="font-family:'Shippori Mincho', serif; font-style:italic;
                            color:rgba(232,223,211,0.35); font-size:0.8rem;
                            margin-top:0.55rem; letter-spacing:0;">
                    out of one hundred
                </div>
            </div>
        </div>
        <div id="pv-rating" class="pv-reveal"
             style="text-align:center;
                    font-family:'Shippori Mincho', serif;
                    font-style:italic;
                    color:{color};
                    font-size:1.55rem;
                    margin-top:0.9rem;
                    letter-spacing:0.02em;
                    opacity:0;
                    transition:opacity 0.9s ease;">
            {html.escape(rating.lower())}
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_sparse_metrics(crack_time, crack_seconds, entropy_bits, guesses):
    tier = _tier_label(crack_seconds)
    st.markdown(
        _html(f"""
        <div class="pv-metrics pv-reveal pv-reveal-1">
            <span class="pv-label">crack time</span>
            <span class="pv-value">{html.escape(crack_time)}</span>
            <span class="pv-label">resistance tier</span>
            <span class="pv-value">{html.escape(tier)}</span>
            <span class="pv-label">entropy</span>
            <span class="pv-value">{entropy_bits:.1f} bits</span>
            <span class="pv-label">search space</span>
            <span class="pv-value">~{_format_guesses(guesses)}</span>
        </div>
        """),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Password / passphrase generators
# ---------------------------------------------------------------------------

def _render_copy_output(value: str) -> None:
    """Render a quiet output line with a single-word copy link via iframe."""
    import json
    js_value = html.escape(json.dumps(value))  # &quot; survives the onclick attribute
    components.html(
        f"""
        <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ background:transparent; }}
        #wrap {{
            display:flex; align-items:baseline;
            gap:1rem;
            padding: 0.75rem 0 0 0;
            border-top: 1px solid rgba(232,223,211,0.06);
            margin-top: 0.75rem;
        }}
        #out {{
            flex:1;
            background:transparent;
            padding:0.35rem 0;
            font-family:'JetBrains Mono', monospace;
            font-size:0.95rem;
            color:#B08C5A;
            letter-spacing:0.02em;
            word-break:break-all;
            user-select:all;
        }}
        #btn {{
            background:transparent; border:0;
            color:rgba(232,223,211,0.35);
            font-family:'Shippori Mincho', serif;
            font-style:italic;
            font-size:0.88rem;
            cursor:pointer;
            white-space:nowrap;
            user-select:none; outline:none;
            transition: color 0.35s ease;
        }}
        #btn:hover {{ color:#D24D3E; }}
        #btn:focus {{ outline:none; }}
        </style>
        <div id="wrap">
            <div id="out">{html.escape(value)}</div>
            <div id="btn" onclick="navigator.clipboard.writeText({js_value});this.textContent='copied';setTimeout(()=>this.textContent='copy',2000);">copy</div>
        </div>
        """,
        height=64,
    )


def render_generator_panel():
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

        st.button("Generate", on_click=_on_generate, key="btn_gen_pw")
        if st.session_state.get("pw_gen_error"):
            st.warning("Select at least one character set.")

        if "generated_password" in st.session_state:
            _render_copy_output(st.session_state["generated_password"])


def render_passphrase_panel():
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

        st.button("Generate passphrase", on_click=_on_generate, key="btn_gen_pp")
        if st.session_state.get("pp_gen_error"):
            st.error("Wordlist not found. Ensure eff_wordlist.txt is in the project directory.")

        if "generated_passphrase" in st.session_state:
            _render_copy_output(st.session_state["generated_passphrase"])


# ---------------------------------------------------------------------------
# Info panels
# ---------------------------------------------------------------------------

def render_safety_tips_panel():
    with st.expander("Safety tips"):
        st.markdown(
            '<p style="color:rgba(232,223,211,0.35); font-family:\'Shippori Mincho\',serif; '
            'font-style:italic; font-size:0.92rem; margin-bottom:1.25rem;">'
            "Small habits, compounded. Open any line to read more.</p>",
            unsafe_allow_html=True,
        )
        for title, body in _SAFETY_TIPS:
            with st.expander(title):
                st.markdown(body, unsafe_allow_html=True)
        st.markdown(
            '<p style="color:rgba(232,223,211,0.35); font-family:\'Shippori Mincho\',serif; '
            'font-style:italic; font-size:0.88rem; margin-top:1.25rem;">'
            "Aligned with <a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf' target='_blank'>NIST SP 800-63B Rev. 4</a>.</p>",
            unsafe_allow_html=True,
        )


def render_scoring_panel():
    with st.expander("How scoring works"):
        st.markdown(
            f"Your password is scored out of <em style='color:{_ACCENT};font-style:normal;'>100 points</em> "
            "across seven categories. Crack-time resistance carries the most weight because it directly "
            "measures real-world entropy. Character diversity rules are useful nudges, not a "
            "substitute for genuine unpredictability.",
            unsafe_allow_html=True,
        )

        st.markdown("##### Point breakdown")
        st.markdown(
            "| Category | Points |\n"
            "|----------|--------|\n"
            "| Length (15+ characters) | 10 |\n"
            "| Contains uppercase letters | 5 |\n"
            "| Contains lowercase letters | 5 |\n"
            "| Contains numbers | 5 |\n"
            "| Contains special characters | 5 |\n"
            "| Not found in breach databases | 20 |\n"
            "| Crack-time resistance | 0–50 |"
        )

        st.markdown("##### Breach database checks")
        st.markdown(
            "Your password is checked against **[Have I Been Pwned](https://haveibeenpwned.com)**, "
            "a database of over 900 million passwords collected from hundreds of real-world breaches. "
            "If your password appears there, someone has used it, and attackers have it too. "
            "The check is private: only the first 5 characters of its hash are ever transmitted, "
            "so your actual password never leaves your device.\n\n"
            "Attackers commonly use wordlists like [rockyou.txt](https://en.wikipedia.org/wiki/RockYou), "
            "14 million real passwords leaked in the 2009 RockYou breach, as their first line of attack. "
            "Have I Been Pwned contains rockyou.txt and far more."
        )

        st.markdown("##### Crack-time resistance")
        st.markdown(
            "This category uses [zxcvbn](https://dropbox.tech/security/zxcvbn-realistic-password-strength-estimation) "
            "pattern analysis to estimate how long a real-world attacker would need to crack your password "
            "assuming bcrypt hashing at 10,000 guesses per second. At 50 points it is the single largest "
            "factor in the score."
        )
        st.markdown(
            "| Estimated crack time | Points |\n"
            "|----------------------|--------|\n"
            "| Less than 1 second | 0 |\n"
            "| Less than 1 minute | 5 |\n"
            "| Less than 1 hour | 10 |\n"
            "| Less than 1 day | 20 |\n"
            "| Less than 1 year | 30 |\n"
            "| Less than 100 years | 40 |\n"
            "| 100+ years | 50 |"
        )

        st.markdown("##### Entropy, in plain words")
        st.markdown(_html(f"""
            <p>Alongside your score you&rsquo;ll see an <em style='color:{_ACCENT};font-style:normal;'>entropy</em>
            value measured in <em style='color:{_ACCENT};font-style:normal;'>bits</em>.
            Entropy measures unpredictability, not complexity: how many attempts it would take to guess the password.</p>
            <p>Each additional bit doubles the guesses required. 10 bits is about 1,000 guesses;
            20 bits, about a million; 40 bits, about a trillion.</p>
            <p>A long passphrase like
            <code>correct-horse-battery-staple</code>
            reaches 50+ bits of entropy with no uppercase, numbers, or symbols, because its length
            and randomness create a search space too large to brute-force. The insight:
            <em style='color:{_OK};font-style:normal;'>length beats complexity</em>.</p>
        """), unsafe_allow_html=True)

        st.markdown("##### Final rating")
        st.markdown(_html(f"""
            <table>
            <thead><tr><th>Rating</th><th>Score</th></tr></thead>
            <tbody>
              <tr><td><em style='color:{_ACCENT};font-style:italic;'>excellent</em></td><td>100</td></tr>
              <tr><td><em style='color:{_ACCENT};font-style:italic;'>strong</em></td><td>80&ndash;95</td></tr>
              <tr><td><em style='color:#B08C5A;font-style:italic;'>good</em></td><td>60&ndash;75</td></tr>
              <tr><td><em style='color:#A67448;font-style:italic;'>fair</em></td><td>40&ndash;55</td></tr>
              <tr><td><em style='color:#9B3F35;font-style:italic;'>weak</em></td><td>below 40</td></tr>
            </tbody></table>
        """), unsafe_allow_html=True)
        st.markdown(
            f"Any password that can be cracked in <em style='color:{_WARN};font-style:normal;'>under an hour</em> "
            f"or is found in Have I Been Pwned is rated <em style='color:{_WARN};font-style:normal;'>weak</em> "
            "regardless of its total score.",
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
    """Render policy compliance as a light two-column disclosure."""
    pw_len = len(password)

    def _mark(passed, na=False):
        if na:
            return f'<span style="color:rgba(232,223,211,0.35);">n/a</span>'
        color = "#7A8F65" if passed else "#9B3F35"
        word = "met" if passed else "not met"
        return f'<span style="color:{color}; font-style:italic;">{word}</span>'

    def _row(criterion, detail, old_cell, nist_cell):
        return (
            f'<div style="padding:0.5rem 0; border-bottom:1px solid rgba(232,223,211,0.06);">'
            f'  <div style="display:grid; grid-template-columns:1.2fr 0.9fr 0.9fr; gap:1rem; align-items:baseline;">'
            f'    <div style="font-family:\'Shippori Mincho\',serif; font-size:0.92rem; color:#E8DFD3;">{html.escape(criterion)}</div>'
            f'    <div style="font-family:\'Shippori Mincho\',serif; font-size:0.85rem;">{old_cell}</div>'
            f'    <div style="font-family:\'Shippori Mincho\',serif; font-size:0.85rem;">{nist_cell}</div>'
            f'  </div>'
            f'  <div style="color:rgba(232,223,211,0.35); font-family:\'JetBrains Mono\',monospace; font-size:0.72rem; margin-top:0.2rem; letter-spacing:0.02em;">{html.escape(detail)}</div>'
            f'</div>'
        )

    header = (
        '<div style="display:grid; grid-template-columns:1.2fr 0.9fr 0.9fr; gap:1rem; '
        'padding-bottom:0.5rem; border-bottom:1px solid rgba(232,223,211,0.06); margin-bottom:0.25rem;">'
        '<div></div>'
        '<div style="font-family:\'Shippori Mincho\',serif; font-style:italic; color:rgba(232,223,211,0.35); font-size:0.82rem;">old-school corporate</div>'
        '<div style="font-family:\'Shippori Mincho\',serif; font-style:italic; color:#D24D3E; font-size:0.82rem;">NIST SP 800-63B</div>'
        '</div>'
    )

    rows = (
        header
        + _row("Minimum length", f"{pw_len} characters",
               _mark(compliance["cs_length"]),
               _mark(compliance["nist_length"]))
        + _row("Character complexity", "upper, lower, digit, special",
               _mark(compliance["cs_complexity"]),
               _mark(True))
        + _row("Breach database check", "Have I Been Pwned",
               _mark(False, na=True),
               _mark(compliance["nist_breach"]))
        + _row("Forced rotation", "typically every 90 days",
               _mark(False, na=True),
               _mark(True))
    )

    cs_pass   = compliance["cs_length"] and compliance["cs_complexity"]
    nist_pass = compliance["nist_length"] and compliance["nist_breach"]

    if cs_pass and nist_pass:
        summary = "This password meets both standards."
        summary_color = "#7A8F65"
    elif nist_pass and not cs_pass:
        summary = ("This password would be rejected by a typical corporate policy but is fully "
                   "compliant with NIST SP 800-63B, and significantly harder to crack.")
        summary_color = "#D24D3E"
    elif cs_pass and not nist_pass:
        summary = ("This password meets old-school corporate requirements but does not meet "
                   "current NIST guidance.")
        summary_color = "#A67448"
    else:
        summary = "This password fails both standards."
        summary_color = "#9B3F35"

    st.markdown(
        _html(f"""
        <div class="pv-reveal pv-reveal-2" style="margin: 1.5rem auto; max-width:560px;">
            <div class="pv-soft-head">policy compliance</div>
            {rows}
            <div style="margin-top:1rem; color:{summary_color};
                        font-family:'Shippori Mincho',serif; font-style:italic;
                        font-size:0.92rem; line-height:1.55;">
                {html.escape(summary)}
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_share_summary(result, compliance):
    """A spare, borderless security summary — no report-card chrome."""
    score      = result["score"]
    max_score  = result["max_score"]
    rating     = result["rating"]
    color      = RATING_COLORS.get(rating, "#E8DFD3")
    crack_time = result["crack_time"]
    today      = datetime.date.today().strftime("%Y-%m-%d")

    hibp_passed      = not any("have i been pwned" in r.lower() for r in result["failed"])
    hibp_unavailable = any("hibp api unavailable" in r.lower() for r in result["failed"])
    nist_pass        = compliance["nist_length"] and compliance["nist_breach"]
    crack_resistant  = result["crack_seconds"] >= 3_153_600_000  # 100 years
    hibp_count       = result.get("hibp_count")

    def _line(passed, pass_text, fail_text):
        mark = "·" if passed else "✕"
        text = pass_text if passed else fail_text
        c    = "#7A8F65" if passed else "#9B3F35"
        return (
            f'<div style="display:flex; gap:0.9rem; align-items:baseline; padding:0.35rem 0;">'
            f'<span style="color:{c}; font-family:\'Shippori Mincho\',serif; font-size:1rem; width:1rem; text-align:center; flex-shrink:0;">{mark}</span>'
            f'<span style="color:#E8DFD3; font-family:\'Shippori Mincho\',serif; font-size:0.92rem; line-height:1.55;">{html.escape(text)}</span>'
            f'</div>'
        )

    if hibp_unavailable:
        hibp_line = _line(False, "", "Breach database check was unavailable.")
    elif hibp_passed:
        hibp_line = _line(True, "Not found in Have I Been Pwned.", "")
    else:
        count_str = f" (seen {hibp_count:,} times)" if hibp_count is not None else ""
        hibp_line = _line(False, "", f"Found in Have I Been Pwned{count_str}.")

    checks_html = (
        hibp_line
        + _line(nist_pass,
                "NIST SP 800-63B compliant.",
                "Does not meet NIST SP 800-63B.")
        + _line(crack_resistant,
                "Resists offline brute-force attack.",
                "Vulnerable to offline brute-force attack.")
    )

    st.markdown(
        _html(f"""
        <div class="pv-reveal pv-reveal-3" style="margin: 2.5rem auto 1rem auto; max-width:560px;">
            <div style="display:flex; justify-content:space-between; align-items:baseline;
                        padding-bottom:0.5rem; margin-bottom:1.25rem;
                        border-bottom:1px solid rgba(232,223,211,0.06);">
                <span class="pv-soft-head" style="margin:0;">security summary</span>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.78rem; color:rgba(232,223,211,0.35);">{today}</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:1.5rem; margin-bottom:1.5rem;">
                <div>
                    <div style="font-family:'Shippori Mincho',serif; font-style:italic; color:rgba(232,223,211,0.35); font-size:0.82rem; margin-bottom:0.4rem;">score</div>
                    <div style="font-family:'Shippori Mincho',serif; font-weight:500; color:{color}; font-size:1.75rem; line-height:1;">
                        {score}<span style="color:rgba(232,223,211,0.35); font-size:0.9rem; font-weight:400;"> / {max_score}</span>
                    </div>
                </div>
                <div>
                    <div style="font-family:'Shippori Mincho',serif; font-style:italic; color:rgba(232,223,211,0.35); font-size:0.82rem; margin-bottom:0.4rem;">rating</div>
                    <div style="font-family:'Shippori Mincho',serif; font-style:italic; color:{color}; font-size:1.35rem; line-height:1; letter-spacing:0.01em;">
                        {html.escape(rating.lower())}
                    </div>
                </div>
                <div>
                    <div style="font-family:'Shippori Mincho',serif; font-style:italic; color:rgba(232,223,211,0.35); font-size:0.82rem; margin-bottom:0.4rem;">crack time</div>
                    <div style="font-family:'JetBrains Mono',monospace; color:{color}; font-size:1rem; line-height:1.25; letter-spacing:0.02em;">
                        {html.escape(crack_time)}
                    </div>
                </div>
            </div>
            {checks_html}
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_attack_breakdown(result):
    sequence = result.get("attack_sequence", [])
    non_brute = [s for s in sequence if s["tag"] != "BRUTE"]

    if not non_brute:
        body = (
            '<div style="color:#7A8F65; font-family:\'Shippori Mincho\',serif; '
            'font-style:italic; font-size:0.94rem; line-height:1.55;">'
            "No exploitable patterns detected. An attacker would have to try every combination."
            '</div>'
        )
        tail = ("Without a recognizable pattern, cracking requires testing every possible "
                "combination, which is what makes length and randomness so decisive.")
    else:
        rows = ""
        for item in non_brute:
            color = _SEVERITY_COLORS.get(item["severity"], "rgba(232,223,211,0.35)")
            tag_display = _TAG_DISPLAY.get(item["tag"], item["tag"].lower())
            rows += (
                f'<div style="display:grid; grid-template-columns:7.5rem 1fr; gap:1rem; padding:0.45rem 0; '
                f'border-bottom:1px solid rgba(232,223,211,0.06); align-items:baseline;">'
                f'<div>'
                f'  <div style="color:{color}; font-family:\'Shippori Mincho\',serif; font-style:italic; font-size:0.88rem;">{html.escape(tag_display)}</div>'
                f'  <div style="color:#D24D3E; font-family:\'JetBrains Mono\',monospace; font-size:0.9rem; letter-spacing:0.02em; margin-top:0.2rem;">&ldquo;{html.escape(item["token"])}&rdquo;</div>'
                f'</div>'
                f'<div style="color:rgba(232,223,211,0.75); font-family:\'Shippori Mincho\',serif; font-size:0.9rem; line-height:1.55;">'
                f'  {html.escape(item["description"])}'
                f'</div>'
                f'</div>'
            )
        body = rows
        tail = ("Attackers work through dictionaries, dates, and keyboard patterns before "
                "falling back to brute force. Each recognizable fragment collapses the search space.")

    st.markdown(
        _html(f"""
        <div class="pv-reveal pv-reveal-2" style="margin: 2rem auto 0 auto; max-width:560px;">
            <div class="pv-soft-head">how an attacker would approach this</div>
            {body}
            <div style="margin-top:1rem; color:rgba(232,223,211,0.35);
                        font-family:'Shippori Mincho',serif; font-style:italic;
                        font-size:0.88rem; line-height:1.6;">
                {html.escape(tail)}
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def render_validation_results(password):
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

    score     = result["score"]
    max_score = result["max_score"]
    rating    = result["rating"]
    color     = RATING_COLORS.get(rating, "#E8DFD3")

    # ── Ensō + score + rating (the hero) ───────────────────────────────────
    render_enso_hero(score, max_score, rating, color)

    # ── HIBP failure warning (inline, quiet) ───────────────────────────────
    if any("HIBP API unavailable" in r for r in result["failed"]):
        st.warning(
            "The breach database check could not be completed. "
            "This password has not been verified against known breaches. "
            "Retry when you have network connectivity."
        )

    # ── Sparse single-line metrics ─────────────────────────────────────────
    render_sparse_metrics(
        result["crack_time"],
        result["crack_seconds"],
        result["entropy_bits"],
        result["guesses"],
    )

    # ── Rule analysis ──────────────────────────────────────────────────────
    passed = result["passed"]
    failed = result["failed"]
    opt_count  = sum(1 for r in failed if r.startswith("○"))
    fail_count = len(failed) - opt_count

    rules_html = ""
    for rule in passed:
        rules_html += (
            f'<div class="pv-rule pv-rule-pass">'
            f'<span class="pv-rule-mark">·</span>'
            f'<span class="pv-rule-text">{html.escape(rule)}</span>'
            f'</div>'
        )
    for rule in failed:
        if rule.startswith("⚠"):
            cls, mark = "pv-rule-warn", "—"
        elif rule.startswith("○"):
            cls, mark = "pv-rule-opt", "○"
        else:
            cls, mark = "pv-rule-fail", "✕"
        rules_html += (
            f'<div class="pv-rule {cls}">'
            f'<span class="pv-rule-mark">{mark}</span>'
            f'<span class="pv-rule-text">{html.escape(rule)}</span>'
            f'</div>'
        )
        if "have i been pwned" in rule.lower() and result.get("hibp_count") is not None:
            count = result["hibp_count"]
            rules_html += (
                f'<div style="max-width:560px; margin:0 auto; padding:0.15rem 0 0.4rem 2.1rem; '
                f'color:rgba(232,223,211,0.45); font-family:\'Shippori Mincho\',serif; '
                f'font-size:0.85rem; font-style:italic; line-height:1.55;">'
                f'Seen {count:,} times in real-world breaches. Credential-stuffing tools will try '
                f'it against every account you own.'
                f'</div>'
            )

    if not rules_html:
        rules_html = (
            '<div class="pv-rule"><span class="pv-rule-mark">·</span>'
            '<span class="pv-rule-text" style="color:rgba(232,223,211,0.35);">No rules evaluated.</span></div>'
        )

    tally = (
        f'<span style="color:#7A8F65; font-family:\'Shippori Mincho\',serif; font-style:italic; font-size:0.85rem;">{len(passed)} passed</span>'
        f'<span style="color:rgba(232,223,211,0.25); margin:0 0.6rem;">·</span>'
        f'<span style="color:#9B3F35; font-family:\'Shippori Mincho\',serif; font-style:italic; font-size:0.85rem;">{fail_count} failed</span>'
    )
    if opt_count:
        tally += (
            f'<span style="color:rgba(232,223,211,0.25); margin:0 0.6rem;">·</span>'
            f'<span style="color:rgba(232,223,211,0.35); font-family:\'Shippori Mincho\',serif; font-style:italic; font-size:0.85rem;">{opt_count} optional</span>'
        )

    st.markdown(
        _html(f"""
        <div class="pv-reveal pv-reveal-1" style="margin: 2.5rem auto 1rem auto; max-width:560px;">
            <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:0.75rem;">
                <span class="pv-soft-head" style="margin:0;">analysis</span>
                <div>{tally}</div>
            </div>
            {rules_html}
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
            f'<div class="pv-rule">'
            f'<span class="pv-rule-mark" style="color:#D24D3E;">→</span>'
            f'<span class="pv-rule-text">{_md_bold(rec)}</span>'
            f'</div>'
            for rec in recs
        )
        st.markdown(
            _html(f"""
            <div class="pv-reveal pv-reveal-2" style="margin: 2rem auto 1rem auto; max-width:560px;">
                <div class="pv-soft-head" style="color:#D24D3E;">recommendations</div>
                {items_html}
            </div>
            """),
            unsafe_allow_html=True,
        )

    # ── Deep analysis ──────────────────────────────────────────────────────
    st.markdown(
        _html(
            '<div class="pv-section pv-reveal pv-reveal-2">'
            '<span class="pv-section-mark">○</span>'
            'deeper analysis'
            '</div>'
        ),
        unsafe_allow_html=True,
    )

    compliance = _compute_policy_compliance(password, result)
    render_attack_breakdown(result)
    render_policy_compliance(password, result, compliance)
    render_share_summary(result, compliance)

    st.session_state["validation_done"] = True
    st.session_state["last_validated_password"] = password

    # ── Ensō draw + score counter + rating fade-in ─────────────────────────
    components.html(
        """
        <script>
        (function() {
            var attempts = 0;
            var poll = setInterval(function() {
                var scoreEl  = window.parent.document.getElementById('pv-score');
                var ensoEl   = window.parent.document.getElementById('pv-enso-stroke');
                var ratingEl = window.parent.document.getElementById('pv-rating');
                if (scoreEl && ensoEl && ratingEl) {
                    clearInterval(poll);
                    run(scoreEl, ensoEl, ratingEl);
                } else if (++attempts > 60) {
                    clearInterval(poll);
                }
            }, 40);

            function run(scoreEl, ensoEl, ratingEl) {
                var target       = parseInt(scoreEl.dataset.target, 10);
                var targetOffset = parseFloat(ensoEl.dataset.targetOffset);

                // Ensō draws via CSS transition on stroke-dashoffset.
                requestAnimationFrame(function() {
                    ensoEl.style.strokeDashoffset = String(targetOffset);
                });

                // Score counts up in sync (1.2s), easing out.
                var start = performance.now();
                var dur   = 1200;
                function tick(now) {
                    var t = Math.min((now - start) / dur, 1);
                    var e = 1 - Math.pow(1 - t, 3);
                    scoreEl.textContent = Math.round(e * target);
                    if (t < 1) requestAnimationFrame(tick);
                }
                requestAnimationFrame(tick);

                // Rating fades in near the end of the stroke.
                setTimeout(function() { ratingEl.style.opacity = '1'; }, 700);
            }
        })();
        </script>
        """,
        height=0,
    )


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

inject_global_styles()

render_header()

def _on_password_change():
    st.session_state.pop("validation_done", None)

password = st.text_input(
    f"Enter a password (up to {MAX_LENGTH} characters)",
    type="password",
    max_chars=MAX_LENGTH,
    key="password_input",
    on_change=_on_password_change,
)

st.markdown(
    '<div style="position:relative; height:1rem; '
    'margin:-0.5rem 0 0.75rem 0;">'
    '<span class="pv-left" style="position:absolute; width:100%; left:0; '
    'font-family:\'JetBrains Mono\',monospace; '
    'font-size:0.6rem; color:rgba(232,223,211,0.35); letter-spacing:0.1em; text-align:left;">'
    'YOUR PASSWORD IS NEVER SENT TO ANY SERVER OR STORED.</span>'
    '<span class="pv-right" style="position:absolute; width:100%; left:0; '
    'font-family:\'JetBrains Mono\',monospace; '
    'font-size:0.6rem; color:rgba(232,223,211,0.35); letter-spacing:0.1em; text-align:left;">'
    'CHECK YOUR SURROUNDINGS BEFORE REVEALING YOUR PASSWORD.</span>'
    '</div>',
    unsafe_allow_html=True,
)

validate_clicked = st.button("Measure", type="primary", use_container_width=True, key="btn_validate")

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
    '<div class="pv-footer">'
    '<span>built by Ben Mickens</span>'
    '<span style="margin:0 0.75rem;">·</span>'
    '<a href="https://github.com/cyberpsyon/password-validator" target="_blank">source</a>'
    '</div>',
    unsafe_allow_html=True,
)
