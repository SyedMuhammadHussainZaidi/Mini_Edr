import os
import sys
import time
import functools
import logging
import ctypes
import subprocess
from datetime import datetime
import psutil
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import db_manager as db
from edr_engine import (
    BASE_DIR,
    DEMO_SANDBOX,
    VAULT_DIR,
    LOG_FILE,
    TRAP_FOLDER_NAME,
    get_sha256,
    calculate_entropy
)

st.set_page_config(
    page_title="Mini-EDR | Endpoint Security Console",
    layout="wide",
    initial_sidebar_state="collapsed"
)


def safe_render(fn):
    """Keeps a live fragment from crashing the whole page on a transient error."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except Exception as e:  # st.rerun()/stop are BaseException, so they pass through
            logging.error(f"{fn.__name__} render error: {e}")
            st.warning(f"Live view refreshing ({type(e).__name__})...")
    return wrapper


# Initialize DB only once per Streamlit server process (not on every rerun)
@st.cache_resource
def _boot_once():
    db.init_db()
    return True


_boot_once()

# Register current dashboard PID so the Engine never touches it
if db.get_setting("dashboard_pid") != str(os.getpid()):
    db.set_setting("dashboard_pid", str(os.getpid()))


def get_engine_state():
    hb = float(db.get_setting("engine_heartbeat", "0") or 0)
    pid = int(db.get_setting("engine_pid", "0") or 0)
    is_admin = db.get_setting("engine_is_admin", "0") == "1"
    is_alive = (time.time() - hb) < 10 and (pid == 0 or psutil.pid_exists(pid))
    return is_alive, pid, is_admin


def start_background_engine(as_admin=False, force=False):
    """
    Starts the sensor without blocking the UI (no long sleeps).
    A 'launching' lock prevents Streamlit reruns from spawning duplicate engines.
    force=True is used by explicit user button clicks.
    """
    alive, old_pid, old_admin = get_engine_state()
    engine_script = os.path.join(BASE_DIR, "edr_engine.py")
    launching_until = float(db.get_setting("engine_launching_until", "0") or 0)

    if as_admin and os.name == "nt":
        if alive and old_admin:
            return get_engine_state()
        if alive:
            db.send_command("SHUTDOWN_ENGINE")
            t0 = time.time()
            while time.time() - t0 < 6 and psutil.pid_exists(old_pid):
                time.sleep(0.2)
        db.set_setting("engine_launching_until", str(time.time() + 60))
        # Triggers Windows UAC Prompt ("Run as Administrator") to enable Tier-1 VSS
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{engine_script}"', BASE_DIR, 0
        )
    elif not alive and (force or time.time() > launching_until):
        db.set_setting("engine_launching_until", str(time.time() + 30))
        subprocess.Popen(
            [sys.executable, engine_script],
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
    return get_engine_state()


# Auto-start the sensor only once per browser session
if "engine_boot_done" not in st.session_state:
    st.session_state.engine_boot_done = True
    start_background_engine(as_admin=False)

# ---------------- THEME SWITCHER STATE ---------------- #
if "ui_theme" not in st.session_state:
    st.session_state.ui_theme = "Blue & White (Light)"

top_bar_col1, top_bar_col2 = st.columns([4, 1])
with top_bar_col2:
    selected_theme = st.selectbox(
        "Console Theme Mode",
        ["Blue & White (Light)", "Cyber Navy (Dark)"],
        index=0 if st.session_state.ui_theme == "Blue & White (Light)" else 1,
        label_visibility="collapsed"
    )
    st.session_state.ui_theme = selected_theme

is_dark = st.session_state.ui_theme == "Cyber Navy (Dark)"

if is_dark:
    BG_MAIN = "#0b1120"
    BG_CARD = "#111c33"
    BG_INPUT = "#1e293b"
    TEXT_PRIMARY = "#f8fafc"
    TEXT_SECONDARY = "#cbd5e1"
    TEXT_MUTED = "#94a3b8"
    BORDER_COLOR = "#263554"
    ACCENT_BLUE = "#3b82f6"
    TABLE_HEADER_BG = "#172544"
    TABLE_ROW_HOVER = "#16223d"
    BANNER_SEC_BG = "#0f1d36"
    BANNER_SEC_TEXT = "#f1f5f9"
    BANNER_ALR_BG = "#2c1219"
    BANNER_ALR_TEXT = "#fecaca"
    BADGE_CLEAN_BG = "#0c4a6e"
    BADGE_CLEAN_TXT = "#e0f2fe"
    BADGE_DANGER_BG = "#7f1d1d"
    BADGE_DANGER_TXT = "#fee2e2"
    PLOTLY_TEMPLATE = "plotly_dark"
else:
    BG_MAIN = "#f4f7fb"
    BG_CARD = "#ffffff"
    BG_INPUT = "#ffffff"
    TEXT_PRIMARY = "#0f172a"
    TEXT_SECONDARY = "#1e293b"
    TEXT_MUTED = "#475569"
    BORDER_COLOR = "#cbd5e1"
    ACCENT_BLUE = "#0052cc"
    TABLE_HEADER_BG = "#eaf2ff"
    TABLE_ROW_HOVER = "#f8fafc"
    BANNER_SEC_BG = "#ffffff"
    BANNER_SEC_TEXT = "#0f172a"
    BANNER_ALR_BG = "#fff1f2"
    BANNER_ALR_TEXT = "#7f1d1d"
    BADGE_CLEAN_BG = "#e0f2fe"
    BADGE_CLEAN_TXT = "#0369a1"
    BADGE_DANGER_BG = "#fee2e2"
    BADGE_DANGER_TXT = "#b91c1c"
    PLOTLY_TEMPLATE = "plotly_white"


# ---------------- DUAL-THEME COMPLETE CSS OVERRIDE ---------------- #
st.markdown(f"""
<style>
    :root {{
        --bg-main: {BG_MAIN};
        --bg-card: {BG_CARD};
        --bg-input: {BG_INPUT};
        --text-primary: {TEXT_PRIMARY};
        --text-secondary: {TEXT_SECONDARY};
        --text-muted: {TEXT_MUTED};
        --border-color: {BORDER_COLOR};
        --accent-blue: {ACCENT_BLUE};
    }}
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {{
        background-color: var(--bg-main) !important;
        color: var(--text-primary) !important;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif !important;
    }}
    .block-container {{
        padding-top: 0.6rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 98% !important;
    }}
    div[data-testid="stMarkdownContainer"] p,
    div[data-testid="stMarkdownContainer"] li,
    div[data-testid="stMarkdownContainer"] span,
    label[data-testid="stWidgetLabel"] p,
    label[data-testid="stWidgetLabel"] span,
    div[data-testid="stWidgetLabel"] p,
    div[data-testid="stCheckbox"] label span,
    div[data-testid="stCheckbox"] p {{
        color: var(--text-primary) !important;
        font-weight: 500 !important;
    }}
    div[data-testid="stCaptionContainer"],
    div[data-testid="stCaptionContainer"] p {{
        color: var(--text-muted) !important;
        font-size: 0.82rem !important;
    }}
    div[data-testid="stForm"] {{
        background-color: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        padding: 16px !important;
    }}
    div[data-baseweb="input"],
    div[data-baseweb="input"] > div,
    div[data-baseweb="base-input"],
    input[type="text"],
    input[type="number"] {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
        -webkit-text-fill-color: var(--text-primary) !important;
    }}
    div[data-testid="stNumberInput"] button {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }}
    div[data-baseweb="select"] > div {{
        background-color: var(--bg-input) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }}
    div[data-baseweb="select"] span {{
        color: var(--text-primary) !important;
    }}
    div.stButton > button,
    div[data-testid="stDownloadButton"] > button,
    div[data-testid="stFormSubmitButton"] > button {{
        border-radius: 5px !important;
        font-weight: 600 !important;
        font-size: 0.8rem !important;
        letter-spacing: 0.03em !important;
        border: 1px solid var(--border-color) !important;
        background-color: var(--bg-card) !important;
        color: var(--text-primary) !important;
        padding: 0.45rem 0.9rem !important;
        min-height: 38px !important;
    }}
    div.stButton > button p,
    div[data-testid="stDownloadButton"] > button p,
    div[data-testid="stFormSubmitButton"] > button p {{
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }}
    div.stButton > button:hover,
    div[data-testid="stDownloadButton"] > button:hover,
    div[data-testid="stFormSubmitButton"] > button:hover {{
        border-color: var(--accent-blue) !important;
        background-color: {TABLE_HEADER_BG} !important;
    }}
    div.stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] > button {{
        background-color: #0052cc !important;
        color: #ffffff !important;
        border: 1px solid #0043a4 !important;
    }}
    div.stButton > button[kind="primary"] p,
    div[data-testid="stFormSubmitButton"] > button p {{
        color: #ffffff !important;
    }}
    div.stButton > button[kind="primary"]:hover,
    div[data-testid="stFormSubmitButton"] > button:hover {{
        background-color: #003d99 !important;
    }}
    div[data-testid="stCodeBlock"], pre, code {{
        background-color: #0f172a !important;
        color: #e2e8f0 !important;
        border: 1px solid #334155 !important;
        border-radius: 6px !important;
    }}
    div[data-testid="stCodeBlock"] span {{
        color: #e2e8f0 !important;
    }}
    button[data-baseweb="tab"] {{
        font-weight: 700 !important;
        color: var(--text-muted) !important;
        font-size: 0.83rem !important;
        letter-spacing: 0.04em !important;
        background-color: transparent !important;
    }}
    button[data-baseweb="tab"] p {{
        color: var(--text-muted) !important;
        font-weight: 700 !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] {{
        color: var(--accent-blue) !important;
        border-bottom: 3px solid var(--accent-blue) !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] p {{
        color: var(--accent-blue) !important;
    }}
    .edr-navbar {{
        background: linear-gradient(90deg, #0a2540 0%, #0043a4 60%, #0052cc 100%);
        color: #ffffff !important;
        padding: 16px 24px;
        border-radius: 8px;
        box-shadow: 0 4px 14px rgba(0, 82, 204, 0.16);
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        border-bottom: 3px solid #38bdf8;
    }}
    .edr-brand-title {{
        font-size: 1.3rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        color: #ffffff !important;
        text-transform: uppercase;
        margin: 0;
    }}
    .edr-brand-sub {{
        font-size: 0.78rem;
        color: #bae6fd !important;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin-top: 4px;
    }}
    .edr-nav-meta {{
        text-align: right;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.78rem;
        color: #e0f2fe !important;
        background: rgba(255, 255, 255, 0.12);
        padding: 8px 14px;
        border-radius: 6px;
        border: 1px solid rgba(255, 255, 255, 0.22);
    }}
    .edr-banner-secure {{
        background-color: {BANNER_SEC_BG};
        border: 1px solid var(--border-color);
        border-left: 6px solid #0284c7;
        padding: 12px 18px;
        border-radius: 6px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        font-size: 0.85rem;
        color: {BANNER_SEC_TEXT} !important;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .edr-banner-alert {{
        background-color: {BANNER_ALR_BG};
        border: 1px solid #ef4444;
        border-left: 6px solid #dc2626;
        padding: 12px 18px;
        border-radius: 6px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        font-size: 0.85rem;
        color: {BANNER_ALR_TEXT} !important;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 12px;
        margin-bottom: 18px;
    }}
    .kpi-card {{
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-top: 3px solid var(--accent-blue);
        border-radius: 6px;
        padding: 14px 16px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.04);
    }}
    .kpi-title {{
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted) !important;
        margin-bottom: 6px;
    }}
    .kpi-value {{
        font-size: 1.38rem;
        font-weight: 700;
        font-family: 'Consolas', monospace;
        color: var(--text-primary) !important;
        margin-bottom: 4px;
    }}
    .kpi-sub {{
        font-size: 0.74rem;
        color: var(--accent-blue) !important;
        font-weight: 500;
        white-space: normal;
        word-wrap: break-word;
    }}
    .edr-section-hdr {{
        font-size: 0.84rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-primary) !important;
        border-left: 4px solid var(--accent-blue);
        padding-left: 10px;
        margin-top: 10px;
        margin-bottom: 12px;
    }}
    .edr-table-wrap {{
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        overflow-x: auto;
        margin-bottom: 14px;
    }}
    table.edr-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.82rem;
        color: var(--text-primary) !important;
    }}
    table.edr-table thead th {{
        background-color: {TABLE_HEADER_BG};
        color: var(--text-primary) !important;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 0.73rem;
        letter-spacing: 0.04em;
        padding: 10px 14px;
        border-bottom: 2px solid var(--border-color);
        text-align: left;
    }}
    table.edr-table tbody td {{
        padding: 9px 14px;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-secondary) !important;
        word-break: break-word;
    }}
    table.edr-table tbody tr:hover {{
        background-color: {TABLE_ROW_HOVER};
    }}
    .mono-cell {{
        font-family: 'Consolas', monospace !important;
        font-size: 0.79rem;
        color: var(--text-primary) !important;
    }}
    .badge-clean {{
        background-color: {BADGE_CLEAN_BG};
        color: {BADGE_CLEAN_TXT} !important;
        border: 1px solid #38bdf8;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
    }}
    .badge-danger {{
        background-color: {BADGE_DANGER_BG};
        color: {BADGE_DANGER_TXT} !important;
        border: 1px solid #f87171;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
    }}
    .badge-killed {{
        background-color: #0052cc;
        color: #ffffff !important;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.71rem;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
    }}
</style>
""", unsafe_allow_html=True)


# ---------------- PURE-PYTHON PDF REPORT GENERATOR ---------------- #
def build_pdf_incident_report(df_alerts: pd.DataFrame) -> bytes:
    def escape_pdf_text(text: str) -> str:
        clean = str(text).encode("ascii", "replace").decode("ascii")
        return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [
        "DAWOOD UNIVERSITY OF ENGINEERING & TECHNOLOGY (DUET)",
        "MINI-EDR SECURITY OPERATIONS CENTER - INCIDENT AUDIT REPORT",
        f"Generated Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 92
    ]

    if df_alerts.empty:
        lines.append("No ransomware incidents recorded during the current monitoring period.")
    else:
        for idx, row in df_alerts.iterrows():
            lines.append(
                f"INCIDENT #{row.get('id', idx + 1)} | TIMESTAMP: {row.get('timestamp', 'N/A')} | "
                f"PROCESS: {row.get('process_name', 'Unknown')} (PID: {row.get('pid', 0)})"
            )
            lines.append(
                f"  Disposition      : {str(row.get('disposition', 'N/A')).upper()} | "
                f"Affected Assets: {row.get('affected_files', 0)}"
            )
            lines.append(f"  Trigger Heuristic: {row.get('reason', 'N/A')}")
            lines.append(
                f"  Recovery Tier    : {row.get('recovery_method', 'N/A')} "
                f"({row.get('recovery_details', 'N/A')})"
            )
            lines.append(
                f"  Telemetry SLA    : Detection = {row.get('detection_time_ms', 0)} ms | "
                f"Restoration = {row.get('restore_time_ms', 0)} ms"
            )
            lines.append("-" * 92)

    page_size = 48
    pages_lines = [lines[i:i + page_size] for i in range(0, max(1, len(lines)), page_size)]

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"
    ]

    page_obj_ids = []
    for p_lines in pages_lines:
        content_ops = ["BT", "/F1 8.5 Tf", "36 756 Td", "14 TL"]
        for line in p_lines:
            content_ops.append(f"({escape_pdf_text(line[:105])}) Tj T*")
        content_ops.append("ET")
        stream_bytes = "\n".join(content_ops).encode("latin-1")

        content_obj_id = len(objects) + 1
        objects.append(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream"
        )

        page_obj_id = len(objects) + 1
        page_obj_ids.append(page_obj_id)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_id} 0 R >>".encode("latin-1")
        )

    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_ids)} >>".encode("latin-1")

    pdf_out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj_body in enumerate(objects, start=1):
        offsets.append(len(pdf_out))
        pdf_out.extend(f"{i} 0 obj\n".encode("latin-1"))
        pdf_out.extend(obj_body)
        pdf_out.extend(b"\nendobj\n")

    xref_pos = len(pdf_out)
    pdf_out.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf_out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

    pdf_out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1")
    )
    return bytes(pdf_out)


# ---------------- TOP ENTERPRISE COMMAND BAR ---------------- #
with top_bar_col1:
    st.markdown(f"""
    <div class="edr-navbar">
        <div>
            <div class="edr-brand-title">Behavior-Based Ransomware Detector (Mini-EDR)</div>
            <div class="edr-brand-sub">Dawood University of Engineering & Technology (DUET) — Group F | Information Security Lab</div>
        </div>
        <div class="edr-nav-meta">
            MODE: ENFORCING (ZERO-SIGNATURE)<br>
            CONSOLE PID: {os.getpid()} | THEME: {st.session_state.ui_theme.upper()}
        </div>
    </div>
    """, unsafe_allow_html=True)


# ---------------- LIVE STATUS BANNER & KPI RIBBON ---------------- #
@st.fragment(run_every=1.5)
@safe_render
def render_live_telemetry_header():
    alive, engine_pid, is_admin = get_engine_state()
    status = db.get_setting("system_status", "SECURE")
    priv_badge = "<span class='badge-killed'>ADMIN (TIER-1 VSS ENABLED)</span>" if is_admin else "<span class='badge-clean'>STANDARD USER (TIER-2 VAULT)</span>"

    launching = float(db.get_setting("engine_launching_until", "0") or 0) > time.time()

    if not alive:
        c_off1, c_off2 = st.columns([4, 2])
        with c_off1:
            if launching:
                st.markdown(
                    '<div class="edr-banner-secure">'
                    '<div><span class="badge-clean">STARTING</span> &nbsp;&nbsp;'
                    '<b>Sensor is initializing (vault backup / VSS snapshot). Please wait...</b></div>'
                    '</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="edr-banner-alert">'
                    '<div><span class="badge-danger">SENSOR OFFLINE</span> &nbsp;&nbsp;'
                    '<b>Background behavioral monitoring service is not running.</b></div>'
                    '</div>',
                    unsafe_allow_html=True
                )
        with c_off2:
            b_sub1, b_sub2 = st.columns(2)
            with b_sub1:
                if st.button("START SENSOR", use_container_width=True):
                    start_background_engine(as_admin=False, force=True)
                    st.rerun()
            with b_sub2:
                if st.button("START AS ADMIN (VSS)", use_container_width=True, type="primary"):
                    start_background_engine(as_admin=True)
                    st.rerun()
    elif status == "SECURE":
        if not is_admin:
            c_s1, c_s2 = st.columns([4, 1])
            with c_s1:
                st.markdown(
                    f'<div class="edr-banner-secure">'
                    f'<div><span class="badge-clean">NOMINAL</span> &nbsp;&nbsp;<b>ENDPOINT STATE: SECURE</b> &nbsp;|&nbsp; '
                    f'Watchdog I/O, Entropy & Canary Inspection Online</div>'
                    f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
            with c_s2:
                if st.button("ENABLE TIER-1 VSS (ADMIN)", use_container_width=True, type="primary"):
                    start_background_engine(as_admin=True)
                    st.rerun()
        else:
            st.markdown(
                f'<div class="edr-banner-secure">'
                f'<div><span class="badge-clean">NOMINAL</span> &nbsp;&nbsp;<b>ENDPOINT STATE: SECURE</b> &nbsp;|&nbsp; '
                f'Watchdog I/O, Entropy, Canary Trap & Tier-1 Windows VSS Active</div>'
                f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        c_inc1, c_inc2 = st.columns([5, 1])
        with c_inc1:
            st.markdown(
                f'<div class="edr-banner-alert">'
                f'<div><span class="badge-danger">INCIDENT CONTAINED</span> &nbsp;&nbsp;<b>{status}</b></div>'
                f'<div class="mono-cell">PID: <b>{engine_pid}</b> &nbsp;|&nbsp; {priv_badge}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with c_inc2:
            if st.button("ACKNOWLEDGE ALERT", use_container_width=True, type="primary"):
                db.set_setting("system_status", "SECURE")
                st.rerun()

    # Level 3: show files that could not be recovered by VSS or Vault
    unrec = db.get_setting("last_unrecovered", "")
    if unrec:
        st.error(f"UNRECOVERED FILES — manual recovery required: {unrec}")
        if st.button("DISMISS UNRECOVERED LIST", key="dismiss_unrec"):
            db.set_setting("last_unrecovered", "")
            st.rerun()

    monitored_cnt = db.get_setting("monitored_files_count", "12")
    vault_kb = db.get_setting("vault_size_kb", "0.0")
    savings_pct = db.get_setting("vault_savings_pct", "0.0")
    cpu_pct = db.get_setting("engine_cpu", "0.0")
    ram_mb = db.get_setting("engine_ram_mb", "0.0")
    vss_state = db.get_setting("vss_status", "Tier-2 Compressed Vault Active")

    st.markdown(f"""
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Protected Assets</div>
            <div class="kpi-value">{monitored_cnt} Files</div>
            <div class="kpi-sub">+25 Hidden Canary Traps (!000_Trap)</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Vault Storage Footprint</div>
            <div class="kpi-value">{vault_kb} KB</div>
            <div class="kpi-sub">zlib DEFLATE Level-6 ({savings_pct}% Space Saved)</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Sensor CPU Overhead</div>
            <div class="kpi-value">{cpu_pct} %</div>
            <div class="kpi-sub">Event-Driven Target: Near 0% Idle</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Sensor Memory Allocation</div>
            <div class="kpi-value">{ram_mb} MB</div>
            <div class="kpi-sub">Target Envelope: 60 - 100 MB</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">3-Tier Recovery Engine</div>
            <div class="kpi-value">{"TIER-1 VSS" if is_admin else "TIER-2 VAULT"}</div>
            <div class="kpi-sub">{vss_state}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

render_live_telemetry_header()


# ---------------- NAVIGATION TABS ---------------- #
tab_sandbox, tab_monitor, tab_alerts, tab_policy = st.tabs([
    "01 | ADVERSARIAL SIMULATION SANDBOX (LIVE DEMO)",
    "02 | LIVE SOC TELEMETRY & GRAPHS",
    "03 | INCIDENT RESPONSE & RECOVERY AUDIT",
    "04 | DETECTION POLICY, WHITELIST & VSS"
])


# ==============================================================================
# TAB 1: ADVERSARIAL SIMULATION SANDBOX (LIVE DEMO)
# ==============================================================================
with tab_sandbox:
    st.markdown('<div class="edr-section-hdr">Controlled Ransomware Emulation & Instant Recovery Verification</div>', unsafe_allow_html=True)
    st.caption(
        f"Isolated Sandbox Path: {DEMO_SANDBOX}  |  Canary Folder: {os.path.join(DEMO_SANDBOX, TRAP_FOLDER_NAME)}  |  "
        f"All simulated attacks are strictly asserted to run only inside this directory."
    )

    sim_c1, sim_c2, sim_c3, sim_c4, sim_c5, sim_c6 = st.columns(6)

    with sim_c1:
        if st.button("LAUNCH FULL BURST ATTACK", type="primary", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "normal"])
            st.toast("Dispatched high-speed encryption burst (.locked).")

    with sim_c2:
        if st.button("TRIGGER CANARY HONEYPOT", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "trap"])
            st.toast("Dispatched !000_Trap canary modification workload.")

    with sim_c3:
        if st.button("LAUNCH HEADER CORRUPTION", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "partial"])
            st.toast("Dispatched 4KB header corruption workload.")

    with sim_c4:
        if st.button("LAUNCH SLOW EVASION ATTACK", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "slow"])
            st.toast("Dispatched low-and-slow encryption workload.")

    with sim_c5:
        if st.button("LAUNCH TRAP-EVADING BURST", use_container_width=True):
            subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "fake_ransomware.py"), "notrap"])
            st.toast("Dispatched burst that skips !000_Trap (entropy/speed detection demo).")

    with sim_c6:
        if st.button("RE-INITIALIZE CLEAN SANDBOX", use_container_width=True):
            db.send_command("REINIT_SANDBOX")
            st.toast("Dispatched sandbox & vault re-initialization command to sensor.")

    @st.fragment(run_every=1.5)
    @safe_render
    def render_sandbox_inventory():
        if db.get_setting("engine_busy", "0") == "1" and get_engine_state()[0]:
            st.info("Sensor is creating vault backups / re-initializing the sandbox. Live inventory resumes automatically...")
            return

        # Live Latest Blocked Attack Telemetry right inside the Demo Sandbox tab!
        df_latest = db.read_df("SELECT * FROM alerts ORDER BY id DESC LIMIT 1")
        if not df_latest.empty:
            r = df_latest.iloc[0]
            st.markdown(
                f"<div class='edr-banner-alert'>"
                f"<div><span class='badge-killed'>LATEST INTERCEPTED INCIDENT #{r['id']}</span> &nbsp;&nbsp;"
                f"<b>Process:</b> <code>{r['process_name']} (PID: {r['pid']})</code> &rarr; <b>{str(r['disposition']).upper()}</b> &nbsp;|&nbsp; "
                f"<b>Trigger:</b> {r['reason']}</div>"
                f"<div class='mono-cell'><b>Recovery:</b> {r['recovery_method']} ({r['affected_files']} files) &nbsp;|&nbsp; "
                f"<b>Detect:</b> {r['detection_time_ms']} ms &nbsp;|&nbsp; <b>Restore:</b> {r['restore_time_ms']} ms</div>"
                f"</div>",
                unsafe_allow_html=True
            )

        col_inv1, col_inv2 = st.columns([3, 2])

        with col_inv1:
            st.markdown('<div class="edr-section-hdr">Protected Sandbox Asset Inventory (Live Integrity State)</div>', unsafe_allow_html=True)
            try:
                sandbox_exists = os.path.exists(DEMO_SANDBOX)
                sandbox_names = sorted(os.listdir(DEMO_SANDBOX)) if sandbox_exists else []
            except OSError:
                sandbox_exists, sandbox_names = False, []

            if sandbox_exists:
                asset_html = []
                for fname in sandbox_names:
                    fpath = os.path.join(DEMO_SANDBOX, fname)
                    # Files can vanish mid-attack: guard every filesystem call
                    try:
                        if not os.path.isfile(fpath):
                            continue
                        ent = calculate_entropy(fpath)
                        sz = os.path.getsize(fpath)
                        sha = get_sha256(fpath)
                    except OSError:
                        continue
                    is_comp = fname.endswith(".locked") or ent >= 7.2
                    badge = "<span class='badge-danger'>COMPROMISED</span>" if is_comp else "<span class='badge-clean'>VERIFIED CLEAN</span>"
                    asset_html.append(
                        f"<tr>"
                        f"<td>{badge}</td>"
                        f"<td class='mono-cell'><b>{fname}</b></td>"
                        f"<td class='mono-cell'>{sz:,} Bytes</td>"
                        f"<td class='mono-cell'>{ent:.3f}</td>"
                        f"<td class='mono-cell'>{sha[:28]}...</td>"
                        f"</tr>"
                    )
                st.markdown(
                    "<div class='edr-table-wrap'><table class='edr-table'>"
                    "<thead><tr><th>Integrity Status</th><th>Full Asset Name</th><th>Size</th><th>Entropy</th><th>SHA-256 Digest</th></tr></thead>"
                    f"<tbody>{''.join(asset_html)}</tbody></table></div>",
                    unsafe_allow_html=True
                )

        with col_inv2:
            st.markdown('<div class="edr-section-hdr">Tier-2 Compressed Backup Vault (.zvault) Audit</div>', unsafe_allow_html=True)
            try:
                vault_exists = os.path.exists(VAULT_DIR)
                vault_names = sorted(os.listdir(VAULT_DIR)) if vault_exists else []
            except OSError:
                vault_exists, vault_names = False, []

            if vault_exists:
                vault_html = []
                for vname in vault_names:
                    vpath = os.path.join(VAULT_DIR, vname)
                    try:
                        if not os.path.isfile(vpath):
                            continue
                        orig_name = vname.replace(".zvault", "")
                        orig_path = os.path.join(DEMO_SANDBOX, orig_name)
                        orig_sz = os.path.getsize(orig_path) if os.path.exists(orig_path) else 0
                        comp_sz = os.path.getsize(vpath)
                    except OSError:
                        continue
                    saving_pct = round((1.0 - (comp_sz / orig_sz)) * 100, 1) if orig_sz > 0 else 0.0
                    vault_html.append(
                        f"<tr>"
                        f"<td class='mono-cell'><b>{vname}</b></td>"
                        f"<td class='mono-cell'>{orig_sz:,} B</td>"
                        f"<td class='mono-cell'>{comp_sz:,} B</td>"
                        f"<td><span class='badge-clean'>-{saving_pct}%</span></td>"
                        f"</tr>"
                    )
                st.markdown(
                    "<div class='edr-table-wrap'><table class='edr-table'>"
                    "<thead><tr><th>Vault Object Name</th><th>Raw Size</th><th>Compressed</th><th>Saved</th></tr></thead>"
                    f"<tbody>{''.join(vault_html)}</tbody></table></div>",
                    unsafe_allow_html=True
                )

    render_sandbox_inventory()


# ==============================================================================
# TAB 2: LIVE SOC TELEMETRY & GRAPHS
# ==============================================================================
with tab_monitor:
    @st.fragment(run_every=2)
    @safe_render
    def render_soc_monitor():
        df_events = db.read_df("SELECT * FROM file_events ORDER BY id DESC LIMIT 50")

        if not df_events.empty:
            df_chron = df_events.iloc[::-1].copy()
            df_chron["seq_label"] = "#" + df_chron["id"].astype(str) + " " + df_chron["file_path"]
            df_chron["time_sec"] = df_chron["timestamp"].str.slice(0, 8)

            col_chart1, col_chart2 = st.columns(2)

            with col_chart1:
                st.markdown('<div class="edr-section-hdr">File System Activity Over Time (I/O Operations / Second)</div>', unsafe_allow_html=True)
                df_rate = (
                    df_chron.groupby(["time_sec", "event_type"])
                    .size()
                    .reset_index(name="event_count")
                )
                fig_activity = px.bar(
                    df_rate,
                    x="time_sec",
                    y="event_count",
                    color="event_type",
                    barmode="stack",
                    template=PLOTLY_TEMPLATE,
                    color_discrete_map={
                        "MODIFIED": "#0052cc",
                        "RENAMED": "#d97706",
                        "CREATED": "#0284c7",
                        "DELETED": "#dc2626",
                        "TRAP_MODIFIED": "#991b1b",
                        "TRAP_RENAMED": "#991b1b",
                        "TRAP_DELETED": "#991b1b"
                    }
                )
                fig_activity.update_layout(
                    paper_bgcolor=BG_CARD,
                    plot_bgcolor=BG_CARD,
                    font=dict(color=TEXT_PRIMARY, size=11),
                    height=340,
                    margin=dict(l=15, r=15, t=25, b=40),
                    xaxis=dict(
                        title=dict(text="Timestamp (HH:MM:SS)", font=dict(color=TEXT_PRIMARY)),
                        tickfont=dict(color=TEXT_SECONDARY),
                        gridcolor=BORDER_COLOR,
                        linecolor=BORDER_COLOR
                    ),
                    yaxis=dict(
                        title=dict(text="Events / Second", font=dict(color=TEXT_PRIMARY)),
                        tickfont=dict(color=TEXT_SECONDARY),
                        gridcolor=BORDER_COLOR,
                        linecolor=BORDER_COLOR
                    ),
                    legend=dict(
                        orientation="h",
                        y=1.14,
                        x=0,
                        title=None,
                        font=dict(color=TEXT_PRIMARY)
                    )
                )
                st.plotly_chart(fig_activity, use_container_width=True, theme=None)

            with col_chart2:
                st.markdown('<div class="edr-section-hdr">Shannon Entropy Differential (Baseline vs. Post-Event)</div>', unsafe_allow_html=True)
                fig_entropy = go.Figure()
                fig_entropy.add_trace(go.Scatter(
                    x=df_chron["seq_label"],
                    y=df_chron["old_entropy"],
                    name="Baseline Entropy (Clean)",
                    mode="lines+markers",
                    line=dict(color="#0284c7", width=2.2, shape="spline"),
                    marker=dict(size=5, color="#0284c7"),
                    fill="tozeroy",
                    fillcolor="rgba(2, 132, 199, 0.10)"
                ))
                fig_entropy.add_trace(go.Scatter(
                    x=df_chron["seq_label"],
                    y=df_chron["new_entropy"],
                    name="Observed Entropy (Post-Event)",
                    mode="lines+markers",
                    line=dict(color="#dc2626", width=2.5, shape="spline"),
                    marker=dict(size=6, color="#dc2626"),
                    fill="tonexty",
                    fillcolor="rgba(220, 38, 38, 0.16)"
                ))
                high_ent_limit = float(db.get_setting("absolute_high_entropy", 7.2))
                fig_entropy.add_hline(
                    y=high_ent_limit,
                    line_dash="dash",
                    line_color="#d97706",
                    annotation_text=f"HIGH ENTROPY LIMIT ({high_ent_limit:.2f} bits/byte)",
                    annotation_position="top left",
                    annotation_font=dict(size=10, color="#d97706")
                )
                fig_entropy.update_layout(
                    template=PLOTLY_TEMPLATE,
                    paper_bgcolor=BG_CARD,
                    plot_bgcolor=BG_CARD,
                    font=dict(color=TEXT_PRIMARY, size=11),
                    height=340,
                    margin=dict(l=15, r=15, t=25, b=65),
                    xaxis=dict(
                        title=dict(text="File Event Sequence", font=dict(color=TEXT_PRIMARY)),
                        tickfont=dict(color=TEXT_SECONDARY, size=10),
                        gridcolor=BORDER_COLOR,
                        linecolor=BORDER_COLOR,
                        tickangle=-25
                    ),
                    yaxis=dict(
                        range=[0, 8.4],
                        title=dict(text="Shannon Entropy (0.0 - 8.0)", font=dict(color=TEXT_PRIMARY)),
                        tickfont=dict(color=TEXT_SECONDARY),
                        gridcolor=BORDER_COLOR,
                        linecolor=BORDER_COLOR
                    ),
                    legend=dict(
                        orientation="h",
                        y=1.14,
                        x=0,
                        font=dict(color=TEXT_PRIMARY)
                    )
                )
                st.plotly_chart(fig_entropy, use_container_width=True, theme=None)

            c_hdr1, c_hdr2 = st.columns([5, 1])
            with c_hdr1:
                st.markdown('<div class="edr-section-hdr">Real-Time Watchdog I/O Telemetry Stream</div>', unsafe_allow_html=True)
            with c_hdr2:
                if st.button("CLEAR TELEMETRY", use_container_width=True):
                    db.execute_write("DELETE FROM file_events")
                    st.rerun()

            rows_html = []
            for _, r in df_events.head(30).iterrows():
                ev_type = str(r["event_type"])
                badge_cls = "badge-danger" if ("TRAP" in ev_type or r["new_entropy"] >= 7.2) else "badge-clean"
                rows_html.append(
                    f"<tr>"
                    f"<td class='mono-cell'>#{r['id']}</td>"
                    f"<td class='mono-cell'>{r['timestamp']}</td>"
                    f"<td><span class='{badge_cls}'>{ev_type}</span></td>"
                    f"<td class='mono-cell'><b>{r['file_path']}</b></td>"
                    f"<td class='mono-cell'>{r['old_entropy']:.3f}</td>"
                    f"<td class='mono-cell'><b>{r['new_entropy']:.3f}</b></td>"
                    f"<td class='mono-cell'>+{r['delta_entropy']:.3f}</td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>Event ID</th><th>Timestamp</th><th>Operation</th><th>Target Asset Name</th>"
                "<th>Baseline Entropy</th><th>Observed Entropy</th><th>Entropy Delta</th></tr></thead>"
                f"<tbody>{''.join(rows_html)}</tbody></table></div>",
                unsafe_allow_html=True
            )
        else:
            st.markdown('<div class="edr-section-hdr">Real-Time Watchdog I/O Telemetry Stream</div>', unsafe_allow_html=True)
            st.info("No file system operations recorded yet. Use Tab 01 to launch a simulated attack.")

    render_soc_monitor()


# ==============================================================================
# TAB 3: INCIDENT RESPONSE & RECOVERY AUDIT
# ==============================================================================
with tab_alerts:
    @st.fragment(run_every=2)
    @safe_render
    def render_incident_history():
        st.markdown('<div class="edr-section-hdr">Contained Ransomware Incidents & Three-Tier Recovery Audit Log</div>', unsafe_allow_html=True)
        df_alerts = db.read_df("SELECT * FROM alerts ORDER BY id DESC")

        if not df_alerts.empty:
            inc_rows = []
            for _, row in df_alerts.iterrows():
                disp = str(row["disposition"]).upper()
                disp_badge = f"<span class='badge-killed'>{disp}</span>" if disp == "KILLED" else f"<span class='badge-danger'>{disp}</span>"
                inc_rows.append(
                    f"<tr>"
                    f"<td class='mono-cell'><b>#{row['id']}</b></td>"
                    f"<td class='mono-cell'>{row['timestamp']}</td>"
                    f"<td class='mono-cell'><b>{row['process_name']}</b> (PID: {row['pid']})</td>"
                    f"<td>{disp_badge}</td>"
                    f"<td>{row['reason']}</td>"
                    f"<td class='mono-cell'><b>{row['affected_files']}</b></td>"
                    f"<td><span class='badge-clean'>{row['recovery_method']}</span><br><small>{row['recovery_details']}</small></td>"
                    f"<td class='mono-cell'>{row['detection_time_ms']} ms / {row['restore_time_ms']} ms</td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>ID</th><th>Timestamp</th><th>Process & PID</th><th>Disposition</th>"
                "<th>Behavioral Trigger Heuristic</th><th>Assets</th><th>Recovery Tier & Result</th><th>Detect / Restore SLA</th></tr></thead>"
                f"<tbody>{''.join(inc_rows)}</tbody></table></div>",
                unsafe_allow_html=True
            )

            exp_c1, exp_c2, exp_c3 = st.columns(3)
            with exp_c1:
                csv_bytes = df_alerts.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="DOWNLOAD AUDIT LOG (CSV)",
                    data=csv_bytes,
                    file_name="mini_edr_incident_report.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with exp_c2:
                pdf_bytes = build_pdf_incident_report(df_alerts)
                st.download_button(
                    label="DOWNLOAD EXECUTIVE REPORT (PDF)",
                    data=pdf_bytes,
                    file_name="mini_edr_incident_report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            with exp_c3:
                if st.button("PURGE INCIDENT LOGS", use_container_width=True):
                    db.execute_write("DELETE FROM alerts")
                    db.set_setting("system_status", "SECURE")
                    st.rerun()
        else:
            st.info("Zero ransomware incidents recorded. All monitored assets match their clean SHA-256 baseline hashes.")

    render_incident_history()


# ==============================================================================
# TAB 4: DETECTION POLICY, WHITELIST & VSS DIAGNOSTICS
# ==============================================================================
with tab_policy:
    col_pol1, col_pol2 = st.columns(2)

    with col_pol1:
        st.markdown('<div class="edr-section-hdr">Behavioral Heuristic Detection Parameters</div>', unsafe_allow_html=True)
        with st.form("heuristic_policy_form"):
            speed_files = st.number_input(
                "Speed Check: Max Unique Modified Files in Sliding Window (Proposal: 4 - 15)",
                value=int(db.get_setting("speed_limit_files", 4)),
                min_value=2,
                max_value=50
            )
            speed_win = st.number_input(
                "Speed Check: Sliding Window Duration (Seconds)",
                value=int(db.get_setting("speed_window_sec", 5)),
                min_value=1,
                max_value=60
            )
            ent_delta = st.slider(
                "Entropy Check: Minimum Shannon Entropy Jump (Delta Threshold)",
                min_value=0.1,
                max_value=4.0,
                value=float(db.get_setting("entropy_delta_threshold", 0.8)),
                step=0.1
            )
            abs_ent = st.slider(
                "Entropy Check: Absolute High Entropy Threshold (bits/byte)",
                min_value=6.0,
                max_value=7.95,
                value=float(db.get_setting("absolute_high_entropy", 7.2)),
                step=0.05
            )
            if st.form_submit_button("UPDATE DETECTION POLICY", use_container_width=True):
                db.set_settings_batch({
                    "speed_limit_files": speed_files,
                    "speed_window_sec": speed_win,
                    "entropy_delta_threshold": ent_delta,
                    "absolute_high_entropy": abs_ent
                })
                st.success("Heuristic policy updated and synchronized with background sensor.")

        st.markdown('<div class="edr-section-hdr">Tier-1 Recovery: Windows Volume Shadow Copy (VSS) Diagnostic</div>', unsafe_allow_html=True)
        st.code(
            f"Sensor Admin Mode : {'ENABLED (Administrator)' if db.get_setting('engine_is_admin') == '1' else 'DISABLED (Standard User)'}\n"
            f"Subsystem Status  : {db.get_setting('vss_status', 'Standby')}\n"
            f"Last Self-Test    : {db.get_setting('vss_last_test', 'Not Executed')}",
            language="text"
        )
        vss_b1, vss_b2 = st.columns(2)
        with vss_b1:
            if st.button("ELEVATE SENSOR AS ADMIN (ENABLE VSS)", use_container_width=True, type="primary"):
                start_background_engine(as_admin=True)
                st.rerun()
        with vss_b2:
            if st.button("RUN WMI SHADOW COPY DIAGNOSTIC", use_container_width=True):
                db.send_command("VSS_SELF_TEST")
                st.toast("Dispatched VSS self-test command to background engine.")

    with col_pol2:
        st.markdown('<div class="edr-section-hdr">False Positive Prevention: SHA-256 & Authenticode Whitelist</div>', unsafe_allow_html=True)
        exe_input = st.text_input(
            "Authorized Executable Path (.exe)",
            placeholder="C:\\Program Files\\WinRAR\\WinRAR.exe"
        )
        req_sig = st.checkbox("Require Valid Microsoft Authenticode Digital Signature", value=True)

        if st.button("AUTHORIZE BINARY IN WHITELIST", use_container_width=True, type="primary"):
            cleaned_path = exe_input.strip().strip('"')
            base_exe = os.path.basename(cleaned_path).lower()
            blocked_interpreters = {"python.exe", "pythonw.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}

            if base_exe in blocked_interpreters:
                st.error(f"Policy Violation: Scripting interpreter '{base_exe}' cannot be whitelisted.")
            elif os.path.exists(cleaned_path) and os.path.isfile(cleaned_path) and cleaned_path.lower().endswith(".exe"):
                exe_hash = get_sha256(cleaned_path)
                db.execute_write(
                    "INSERT OR REPLACE INTO whitelist (process_name, exe_path, sha256_hash, require_signature) VALUES (?, ?, ?, ?)",
                    (os.path.basename(cleaned_path), cleaned_path, exe_hash, 1 if req_sig else 0)
                )
                st.success(f"Whitelisted '{os.path.basename(cleaned_path)}' | SHA-256: {exe_hash}")
            else:
                st.error("Specify an existing local .exe binary path.")

        df_wl = db.read_df(
            "SELECT id, process_name, exe_path, sha256_hash, require_signature FROM whitelist ORDER BY id DESC"
        )
        if not df_wl.empty:
            wl_rows = []
            for _, w in df_wl.iterrows():
                sig_badge = "<span class='badge-clean'>REQUIRED</span>" if w["require_signature"] else "<span class='badge-danger'>OPTIONAL</span>"
                wl_rows.append(
                    f"<tr>"
                    f"<td class='mono-cell'>#{w['id']}</td>"
                    f"<td class='mono-cell'><b>{w['process_name']}</b></td>"
                    f"<td class='mono-cell'>{w['exe_path']}</td>"
                    f"<td class='mono-cell'>{w['sha256_hash']}</td>"
                    f"<td>{sig_badge}</td>"
                    f"</tr>"
                )
            st.markdown(
                "<div class='edr-table-wrap'><table class='edr-table'>"
                "<thead><tr><th>ID</th><th>Binary Name</th><th>Full Executable Path</th><th>Full SHA-256 Hash</th><th>Authenticode Policy</th></tr></thead>"
                f"<tbody>{''.join(wl_rows)}</tbody></table></div>",
                unsafe_allow_html=True
            )

            c_del1, c_del2 = st.columns([3, 1])
            with c_del1:
                del_id = st.selectbox("Select Whitelist ID to Revoke", df_wl["id"].tolist())
            with c_del2:
                st.write("")
                if st.button("REVOKE", use_container_width=True):
                    db.execute_write("DELETE FROM whitelist WHERE id=?", (int(del_id),))
                    st.rerun()
        else:
            st.info("No external binaries whitelisted yet.")

    st.markdown('<div class="edr-section-hdr">Sensor Diagnostic Telemetry Log (engine.log)</div>', unsafe_allow_html=True)
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as lf:
                log_lines = lf.readlines()[-20:]
            st.code("".join(log_lines) if log_lines else "Sensor log initialized. Zero runtime errors.", language="text")
        except Exception:
            st.code("Unable to read engine.log", language="text")