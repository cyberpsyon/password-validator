import html
import re
import time

import streamlit as st
import streamlit.components.v1 as components

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
    "EXCELLENT": "#00E676",
    "STRONG":    "#00E676",
    "GOOD":      "#FFD600",
    "FAIR":      "#FF6D00",
    "WEAK":      "#FF1744",
}

RATING_SHADOWS = {
    "EXCELLENT": "0 0 18px #00E67650",
    "STRONG":    "0 0 18px #00E67650",
    "GOOD":      "0 0 18px #FFD60050",
    "FAIR":      "0 0 18px #FF6D0050",
    "WEAK":      "0 0 18px #FF174450",
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

_SAFETY_TIPS = [
    ("Use a unique password for every account",
     "When a company gets hacked, attackers take the stolen passwords and try "
     "them on other websites like your email, bank, and social media. If you "
     "use the same password everywhere, one breach can compromise all of your "
     "accounts. Always use a different password for each account."),

    ("Use a password manager",
     "Nobody can remember dozens of strong, unique passwords. A password "
     "manager is an app that securely stores all of your passwords for you. "
     "You only need to remember one master password, and the manager fills in "
     "the rest. Popular options include 1Password, Bitwarden, and KeePass."),

    ("Enable multi-factor authentication (MFA)",
     "Multi-factor authentication adds another step when you log in, like a "
     "code from an app on your phone or a physical security key. Even if "
     "someone steals your password, they still cannot get into your account "
     "without that second step. Turn on MFA everywhere it is available, "
     "especially for email, banking, and work accounts. Avoid SMS-based MFA "
     "when possible — authenticator apps (like Authy or Google Authenticator) "
     "and hardware security keys (like YubiKey) are significantly harder to "
     "intercept or bypass."),

    ("Longer passwords are stronger passwords",
     "A 20-character passphrase made of random words (like \"correct-horse-battery-staple\") "
     "is both stronger and easier to type than a short, complicated password "
     "like \"P@s5w0rd!\". Aim for at least 15 characters — but longer is always better."),

    ("Never share passwords over email or chat",
     "No legitimate company, IT department, or government agency will ever ask "
     "you for your password. If someone contacts you asking for your password, "
     "it is a scam. Always type your password directly into the official "
     "website or app, never into an email, text message, or phone call."),

    ("Watch for data breaches",
     "Data breaches happen regularly, and your information may be exposed "
     "without you knowing. Sign up for free alerts at [Have I Been Pwned](https://haveibeenpwned.com) to "
     "get notified if your email appears in a breach. When you get an alert, "
     "change the password for that account immediately."),

    ("Change passwords that have been exposed",
     "If you find out that one of your passwords was part of a data breach, "
     "stop using it right away on every account where you used it. Attackers "
     "share stolen passwords widely, so a breached password is never safe "
     "to use again, even if you change it slightly."),

    ("A high score does not mean your password is unbreakable",
     "Even if this tool rates your password as \"Excellent\" with a crack time "
     "of centuries, no password is truly permanent. Advances in technology, "
     "including quantum computing, will make password cracking significantly "
     "faster in the future. Combine strong passwords with MFA and change a "
     "password only when you have reason to believe it has been compromised — "
     "routine rotation tends to produce weaker, predictable passwords and is "
     "no longer recommended."),
]


@st.cache_resource
def get_blacklist():
    return load_blacklist()


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


# ---------------------------------------------------------------------------
# Global styles
# ---------------------------------------------------------------------------

def inject_global_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700;800&display=swap');

        :root {
            --bg:          #06060C;
            --surface:     #0D0D1A;
            --surface2:    #111120;
            --border:      #181830;
            --border2:     #222240;
            --amber:       #F5A623;
            --amber-dim:   rgba(245, 166, 35, 0.08);
            --amber-glow:  rgba(245, 166, 35, 0.22);
            --text:        #CECEE0;
            --text-dim:    #7878A0;
            --green:       #00E676;
            --red:         #FF1744;
            --orange:      #FF6D00;
            --yellow:      #FFD600;
            --teal:        #00897B;
        }

        /* ── Global ── */
        * { font-family: 'JetBrains Mono', 'Courier New', monospace !important; }

        /* ── App background: dark grid ── */
        .stApp {
            background-color: var(--bg) !important;
            background-image:
                linear-gradient(rgba(245,166,35,0.016) 1px, transparent 1px),
                linear-gradient(90deg, rgba(245,166,35,0.016) 1px, transparent 1px);
            background-size: 52px 52px;
            background-attachment: fixed;
        }

        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 5rem !important;
            max-width: 700px !important;
        }

        /* ── Typography ── */
        h1, h2, h3, h4, h5, h6 { color: var(--text) !important; letter-spacing: 0.05em !important; }
        p, li { color: var(--text) !important; }
        a { color: var(--amber) !important; }

        /* ── Text input ── */
        .stTextInput > div > div {
            background: var(--surface) !important;
            border: 1px solid var(--border2) !important;
            border-radius: 0 !important;
            transition: border-color 0.2s, box-shadow 0.2s !important;
        }
        .stTextInput > div > div:focus-within {
            border-color: var(--amber) !important;
            box-shadow: 0 0 0 1px var(--amber), inset 0 0 30px var(--amber-dim) !important;
        }
        .stTextInput input {
            background: transparent !important;
            color: var(--amber) !important;
            font-size: 1.05rem !important;
            letter-spacing: 0.18em !important;
            caret-color: var(--amber) !important;
            padding: 0.75rem 1rem !important;
        }
        .stTextInput label {
            color: var(--text-dim) !important;
            font-size: 0.68rem !important;
            letter-spacing: 0.14em !important;
            text-transform: uppercase !important;
        }

        /* ── Buttons ── */
        .stButton > button {
            background: linear-gradient(to right, transparent 50%, var(--amber) 50%) !important;
            background-size: 200% 100% !important;
            background-position: left center !important;
            color: var(--amber) !important;
            border: 1px solid var(--amber) !important;
            border-radius: 0 !important;
            font-weight: 700 !important;
            font-size: 0.8rem !important;
            letter-spacing: 0.22em !important;
            text-transform: uppercase !important;
            padding: 0.7rem 2rem !important;
            transition: background-position 0.3s cubic-bezier(0.4,0,0.2,1), color 0.3s, box-shadow 0.3s, letter-spacing 0.3s !important;
        }
        /* ensure nested text nodes inherit the transitioning color */
        .stButton > button p, .stButton > button span, .stButton > button div {
            color: inherit !important;
            transition: color 0.3s !important;
        }
        .stButton > button:hover {
            background-position: right center !important;
            color: #060610 !important;
            letter-spacing: 0.28em !important;
            box-shadow: 0 0 22px var(--amber-glow), 0 4px 16px rgba(245,166,35,0.2) !important;
        }
        .stButton > button:active {
            background-position: right center !important;
            color: #060610 !important;
            box-shadow: none !important;
        }

        /* ── Progress bar ── */
        .stProgress > div > div {
            background: var(--surface2) !important;
            border-radius: 0 !important;
            height: 5px !important;
        }
        .stProgress > div > div > div > div {
            border-radius: 0 !important;
            transition: width 0.9s cubic-bezier(0.4,0,0.2,1) !important;
        }

        /* ── Metric ── */
        [data-testid="stMetricValue"] {
            color: var(--amber) !important;
            font-size: 2.6rem !important;
            font-weight: 800 !important;
        }
        [data-testid="stMetricLabel"] {
            color: var(--text-dim) !important;
            font-size: 0.68rem !important;
            letter-spacing: 0.15em !important;
            text-transform: uppercase !important;
        }

        /* ── Expanders ── */
        details {
            background: var(--surface) !important;
            border: 1px solid var(--border2) !important;
            border-radius: 0 !important;
            margin-bottom: 0.4rem !important;
        }
        details summary {
            display: flex !important;
            align-items: center !important;
            list-style: none !important;
            color: var(--text-dim) !important;
            font-size: 0.7rem !important;
            letter-spacing: 0.12em !important;
            text-transform: uppercase !important;
            padding: 0.8rem 1rem !important;
            cursor: pointer !important;
            transition: color 0.15s, background 0.15s !important;
        }
        details summary::-webkit-details-marker { display: none !important; }
        /* Verified Streamlit expander DOM (from streamlit static JS source):
             summary
               └── span (StyledSummaryHeading)   [flex-grow:1]
                     ├── span (StyledDynamicIcon) ← HIDE: contains the icon ligature text
                     └── div  (StyledSummaryLabelWrapper) ← KEEP: contains the title
           summary > span hides the ENTIRE heading; we must go one level deeper. */
        details summary > span > span,
        details summary > span > svg { display: none !important; }
        /* Custom terminal toggle indicator */
        details summary::after {
            content: '▸' !important;
            color: var(--text-dim) !important;
            font-size: 0.75rem !important;
            flex-shrink: 0 !important;
            transition: transform 0.2s ease, color 0.15s !important;
            display: inline-block !important;
            margin-left: 0.75rem !important;
        }
        details summary:hover::after { color: var(--amber) !important; }
        details[open] summary::after {
            transform: rotate(90deg) !important;
            color: var(--amber) !important;
        }
        details summary:hover {
            color: var(--amber) !important;
            background: var(--amber-dim) !important;
        }
        details[open] summary {
            color: var(--amber) !important;
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
            border-color: var(--border2) !important;
            border-radius: 0 !important;
        }
        [data-baseweb="select"] span, [data-baseweb="select"] div { color: var(--text) !important; }

        /* ── Checkbox ── */
        .stCheckbox label p, .stCheckbox label span {
            color: var(--text-dim) !important;
            font-size: 0.76rem !important;
        }

        /* ── Divider ── */
        hr { border-color: var(--border) !important; opacity: 1 !important; margin: 1.5rem 0 !important; }

        /* ── Alerts ── */
        .stAlert {
            background: var(--surface2) !important;
            border-radius: 0 !important;
            border: 1px solid var(--border2) !important;
            border-left: 3px solid var(--amber) !important;
        }
        .stAlert > div { font-size: 0.8rem !important; color: var(--text) !important; }

        /* ── Code blocks ── */
        .stCode > div, pre {
            background: var(--surface2) !important;
            border: 1px solid var(--border2) !important;
            border-radius: 0 !important;
        }
        code { color: var(--green) !important; background: transparent !important; letter-spacing: 0.05em !important; }

        /* ── Tables ── */
        table { border-collapse: collapse !important; width: 100% !important; }
        th {
            background: var(--surface2) !important;
            color: var(--amber) !important;
            border: 1px solid var(--border2) !important;
            padding: 0.5rem 0.75rem !important;
            font-size: 0.66rem !important;
            letter-spacing: 0.12em !important;
            text-transform: uppercase !important;
        }
        td {
            background: var(--surface) !important;
            color: var(--text) !important;
            border: 1px solid var(--border2) !important;
            padding: 0.5rem 0.75rem !important;
            font-size: 0.78rem !important;
        }
        td a { color: var(--amber) !important; }

        /* ── Spinner ── */
        .stSpinner > div { border-top-color: var(--amber) !important; }

        /* ── Fade-in animation ── */
        @keyframes terminalReveal {
            from { opacity: 0; transform: translateY(5px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .t-reveal {
            animation: terminalReveal 0.3s ease-out forwards;
        }

        /* ── Input disclaimer cycling ── */
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

        /* ── Result row color coding ── */
        .pv-row-pass {
            background: rgba(0, 230, 118, 0.06);
            border-left: 2px solid var(--green);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }
        .pv-row-fail {
            background: rgba(255, 23, 68, 0.06);
            border-left: 2px solid var(--red);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }
        .pv-row-warn {
            background: rgba(245, 166, 35, 0.08);
            border-left: 2px solid var(--amber);
            padding-left: 0.6rem;
            margin-left: -0.6rem;
        }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border2); }
        ::-webkit-scrollbar-thumb:hover { background: var(--amber); }

        /* ── Hide Streamlit chrome ── */
        #MainMenu { visibility: hidden; }
        footer    { visibility: hidden; }
        header    { visibility: hidden; }
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
        <div style="border:1px solid #222240; border-top:2px solid #F5A623; background:#0D0D1A; padding:1.75rem 2rem 1.5rem; margin-bottom:2rem; position:relative;">
            <div style="position:absolute; top:0; right:0; background:#F5A623; color:#06060C; font-size:0.55rem; font-weight:800; letter-spacing:0.2em; padding:0.2rem 0.8rem; text-transform:uppercase; font-family:'JetBrains Mono',monospace;">PSV-01 // SECURE</div>
            <div style="color:#7878A0; font-size:0.6rem; letter-spacing:0.24em; text-transform:uppercase; margin-bottom:0.55rem; font-family:'JetBrains Mono',monospace;">Security Analysis Terminal</div>
            <div style="color:#CECEE0; font-size:1.65rem; font-weight:800; letter-spacing:0.06em; text-transform:uppercase; line-height:1; font-family:'JetBrains Mono',monospace;">Password Validator</div>
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

    with st.expander("Generate a strong password", expanded=st.session_state.pop("pw_gen_open", False)):
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

    with st.expander("Generate a strong passphrase", expanded=st.session_state.pop("pp_gen_open", False)):
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
                st.markdown(body)
        st.markdown(
            '<p style="color:#46466A; font-size:0.65rem; margin-top:0.75rem; letter-spacing:0.04em;">'
            "These recommendations are aligned with <a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf' target='_blank' style='color:#46466A;'>NIST SP 800-63B Rev. 4</a> (finalized August 2025).</p>",
            unsafe_allow_html=True,
        )


def render_scoring_panel():
    """Render a generic scoring explanation inside an expander."""
    with st.expander("How Scoring Works"):
        st.markdown(
            "Your password is scored out of **100 points** across 7 categories. "
            "Crack-time resistance carries the most weight because it directly measures "
            "real-world entropy — character diversity rules are useful nudges, not a "
            "substitute for genuine unpredictability."
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
            "| Not in breach databases | 20 |\n"
            "| Crack-time resistance | 0\u201350 |"
        )

        st.markdown("#### Breach Database Checks")
        st.markdown(
            "Your password is checked against two independent sources:\n\n"
            "- **rockyou.txt** — A wordlist of 14 million real passwords leaked in the [2009 RockYou breach](https://en.wikipedia.org/wiki/RockYou). "
            "It is one of the first files attackers load into cracking tools. "
            "If your password is on this list, it will be tried within seconds of any attack.\n\n"
            "- **[Have I Been Pwned](https://haveibeenpwned.com)** — A database of over 900 million passwords "
            "collected from hundreds of real-world data breaches. If your password appears here, it means "
            "someone, somewhere, has already used it — and attackers have it too. "
            "Your password is checked privately using k-anonymity: only the first 5 characters of its hash "
            "are ever transmitted, so your actual password never leaves your device."
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

        st.markdown("#### Final Rating")
        st.markdown(
            "| Rating | Score Range |\n"
            "|--------|-------------|\n"
            "| EXCELLENT | 100 |\n"
            "| STRONG | 80\u201395 |\n"
            "| GOOD | 60\u201375 |\n"
            "| FAIR | 40\u201355 |\n"
            "| WEAK | Below 40 |"
        )
        st.markdown(
            "Any password that can be cracked in **under 1 hour** or is found in either breach database "
            "is automatically rated **WEAK** regardless of its total score."
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

    score      = result["score"]
    max_score  = result["max_score"]
    rating     = result["rating"]
    color      = RATING_COLORS.get(rating, "#46466A")
    shadow     = RATING_SHADOWS.get(rating, "none")
    score_pct  = min(score / max_score * 100, 100)

    # ── Section separator ──────────────────────────────────────────────────
    st.markdown(
        _html('<div style="display:flex; align-items:center; gap:1rem; margin:2rem 0 1.25rem;"><div style="flex:1; height:1px; background:#181830;"></div><span style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; white-space:nowrap; font-family:JetBrains Mono,monospace;">Analysis Results</span><div style="flex:1; height:1px; background:#181830;"></div></div>'),
        unsafe_allow_html=True,
    )

    # ── Score + Rating card ────────────────────────────────────────────────
    st.markdown(
        _html(f"""
        <div class="t-reveal" style="display:grid; grid-template-columns:2fr 1fr; gap:1px; background:#181830; border:1px solid #222240; margin-bottom:0.75rem;">
            <div style="background:#0D0D1A; padding:1.5rem 2rem;">
                <div style="font-size:0.58rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.45rem;">Security Score</div>
                <div style="font-size:3rem; font-weight:800; color:{color}; line-height:1; font-family:'JetBrains Mono',monospace; letter-spacing:-0.02em;"><span id="pv-score" data-target="{score}">0</span><span style="font-size:1rem; color:#7878A0; font-weight:400;"> / {max_score}</span></div>
                <div style="margin-top:1rem; width:100%; height:4px; background:#111120;">
                    <div id="pv-bar" data-target-width="{score_pct:.1f}" style="width:0%; height:100%; background:{color}; transition:none;"></div>
                </div>
            </div>
            <div style="background:#0D0D1A; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:1.5rem; text-align:center;">
                <div style="font-size:0.56rem; color:#7878A0; letter-spacing:0.22em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:0.75rem;">Rating</div>
                <div id="pv-rating" data-rating="{html.escape(rating)}" style="color:{color}; font-size:1.1rem; font-weight:800; letter-spacing:0.12em; text-transform:uppercase; font-family:'JetBrains Mono',monospace; border:1px solid {color}; padding:0.4rem 0.9rem; box-shadow:{shadow};"></div>
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

    rows_html = ""
    for rule in passed:
        rows_html += (
            f'<div class="pv-row-pass" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'<span style="color:#00E676; font-size:0.62rem; font-weight:700; '
            f'letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; '
            f'padding-top:2px;">[ OK ]</span>'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
            f'</div>'
        )
    for rule in failed:
        row_class = "pv-row-warn" if rule.startswith("\u26a0") else "pv-row-fail"
        if row_class == "pv-row-warn":
            badge = '<span style="color:#F5A623; font-size:0.62rem; font-weight:700; letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; padding-top:2px;">[WARN ]</span>'
        else:
            badge = '<span style="color:#FF1744; font-size:0.62rem; font-weight:700; letter-spacing:0.05em; white-space:nowrap; font-family:JetBrains Mono,monospace; padding-top:2px;">[FAIL]</span>'
        rows_html += (
            f'<div class="{row_class}" style="display:flex; gap:0.8rem; align-items:flex-start; margin:0.38rem 0;">'
            f'{badge}'
            f'<span style="color:#CECEE0; font-size:0.78rem; line-height:1.4; '
            f'font-family:JetBrains Mono,monospace;">{html.escape(rule)}</span>'
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
                    <span style="font-size:0.6rem; color:#FF1744; letter-spacing:0.08em; font-family:'JetBrains Mono',monospace;">&#x2717; {len(failed)} failed</span>
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
    if any("common password" in r.lower() or "have i been pwned" in r.lower()
           for r in result["failed"]):
        recs.append("**CRITICAL:** Use a unique password not found in breach databases.")
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

    # ── Animations ─────────────────────────────────────────────────────────
    components.html(
        f"""
        <script>
        (function() {{
            var attempts = 0;
            var poll = setInterval(function() {{
                var scoreEl  = window.parent.document.getElementById('pv-score');
                var barEl    = window.parent.document.getElementById('pv-bar');
                var ratingEl = window.parent.document.getElementById('pv-rating');
                if (scoreEl && barEl && ratingEl) {{
                    clearInterval(poll);
                    runAnimations(scoreEl, barEl, ratingEl);
                }} else if (++attempts > 40) {{
                    clearInterval(poll);
                }}
            }}, 50);

            function runAnimations(scoreEl, barEl, ratingEl) {{
                var targetScore = parseInt(scoreEl.dataset.target);
                var targetWidth = parseFloat(barEl.dataset.targetWidth);
                var ratingText  = ratingEl.dataset.rating;
                var duration    = 800;
                var start       = performance.now();

                function easeOut(t) {{ return 1 - Math.pow(1 - t, 3); }}

                function tick(now) {{
                    var t = Math.min((now - start) / duration, 1);
                    var eased = easeOut(t);
                    scoreEl.textContent = Math.round(eased * targetScore);
                    barEl.style.width = (eased * targetWidth) + '%';
                    if (t < 1) requestAnimationFrame(tick);
                }}
                requestAnimationFrame(tick);

                ratingEl.textContent = '';
                var i = 0;
                setTimeout(function() {{
                    var interval = setInterval(function() {{
                        ratingEl.textContent += ratingText[i++];
                        if (i >= ratingText.length) clearInterval(interval);
                    }}, 80);
                }}, 100);
            }}
        }})();
        </script>
        """,
        height=0,
    )


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

inject_global_styles()

with st.spinner("Initializing security database..."):
    blacklist = get_blacklist()

render_header()

password = st.text_input(
    f"Enter password to analyze (max {MAX_LENGTH} characters)",
    type="password",
    max_chars=MAX_LENGTH,
    key="password_input",
)

st.markdown(
    '<div style="position:relative; height:1rem; '
    'margin:-0.5rem 0 0.75rem 0;">'
    '<span class="pv-left" style="position:absolute; width:100%; left:0; '
    'font-size:0.6rem; color:#7878A0; letter-spacing:0.1em; text-align:left;">'
    '&#128274; YOUR PASSWORD IS NEVER SENT TO OUR SERVERS OR STORED.</span>'
    '<span class="pv-right" style="position:absolute; width:100%; left:0; '
    'font-size:0.6rem; color:#7878A0; letter-spacing:0.1em; text-align:right;">'
    '&#9888; CHECK YOUR SURROUNDINGS BEFORE REVEALING YOUR PASSWORD.</span>'
    '</div>',
    unsafe_allow_html=True,
)

validate_clicked = st.button("Run Analysis", type="primary", use_container_width=True)

render_generator_panel()
render_passphrase_panel()
render_safety_tips_panel()
render_scoring_panel()

if validate_clicked:
    render_validation_results(password, blacklist)
