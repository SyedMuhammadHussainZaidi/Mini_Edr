import os
import re
import sys
import time
import math
import zlib
import ctypes
import socket
import shutil
import hashlib
import logging
import threading
import subprocess
from datetime import datetime
from collections import Counter, deque
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import db_manager as db

logging.getLogger("asyncio").setLevel(logging.CRITICAL)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEMO_SANDBOX = os.path.join(BASE_DIR, "Demo_Protected_Folder")
VAULT_DIR = os.path.join(BASE_DIR, "MiniEDR_Backup_Vault")
LOG_FILE = os.path.join(BASE_DIR, "engine.log")
TRAP_FOLDER_NAME = "!000_Trap"
MAX_VAULT_FILE_SIZE = 15 * 1024 * 1024  # 15 MB cap per file

# Cached Windows VSS DeviceObject path (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1)
ACTIVE_VSS_DEVICE = None

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

PROTECTED_EXTS = {'.docx', '.pdf', '.jpg', '.mp4', '.txt', '.xlsx', '.png', '.csv', '.zip', '.pptx'}
COMPRESSED_EXTS = {'.docx', '.pdf', '.jpg', '.mp4', '.xlsx', '.png', '.zip', '.pptx'}
TEXT_EXTS = {'.txt', '.csv'}
IGNORED_EXTS = {'.tmp', '.sys', '.cache', '.log', '.db', '.db-journal', '.db-wal', '.db-shm', '.zvault'}
SUSPICIOUS_EXTS = {'.locked', '.enc', '.crypted', '.ransom', '.hacked'}

PROTECTED_PROCESSES = {
    'system', 'idle', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe',
    'dwm.exe', 'taskhostw.exe', 'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe',
    'searchindexer.exe', 'searchhost.exe', 'onedrive.exe', 'code.exe', 'devenv.exe',
    'pycharm64.exe', 'conhost.exe', 'windowsterminal.exe', 'streamlit.exe', 'cmd.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'msedgewebview2.exe',
    'teams.exe', 'discord.exe', 'spotify.exe', 'steam.exe', 'whatsapp.exe', 'claude.exe'
}

MAGIC_HEADERS = {
    '.pdf': [b'%PDF'],
    '.jpg': [b'\xff\xd8\xff'],
    '.png': [b'\x89PNG\r\n\x1a\n'],
    '.docx': [b'PK\x03\x04'],
    '.xlsx': [b'PK\x03\x04'],
    '.pptx': [b'PK\x03\x04'],
    '.zip': [b'PK\x03\x04'],
}

# Pristine canary content: lets the engine tell a REAL trap modification from a stale/self-generated event
TRAP_PRISTINE = b"PK\x03\x04" + b"CONFIDENTIAL FINANCIAL & USER DATA - DO NOT MODIFY OR ENCRYPT. " * 15
TRAP_NAME_RE = re.compile(r"^00_confidential_records_\d{2}\.docx$")

# Human-readable names for the simulator modes (read from the attacker's own command line)
ATTACK_LABELS = {
    "normal": "Full Burst Attack",
    "trap": "Canary Honeypot Probe",
    "partial": "Header Corruption Attack",
    "slow": "Slow Evasion Attack",
    "notrap": "Trap-Evading Burst",
}

_sig_cache = {}

# ---------------- SINGLE-INSTANCE GUARD ---------------- #
_instance_sock = None


def acquire_single_instance(port=47651):
    """Binds a localhost port; only one engine process can hold it at a time."""
    global _instance_sock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
    except OSError:
        s.close()
        return False
    _instance_sock = s
    return True


def is_running_as_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def heartbeat_loop():
    """Independent heartbeat so the dashboard sees the engine alive even during slow startup."""
    my_proc = psutil.Process(os.getpid())
    my_proc.cpu_percent(None)
    while True:
        try:
            db.set_settings_batch({
                "engine_cpu": f"{my_proc.cpu_percent(None):.1f}",
                "engine_ram_mb": f"{my_proc.memory_info().rss / (1024 * 1024):.1f}",
                "engine_pid": str(os.getpid()),
                "engine_is_admin": "1" if is_running_as_admin() else "0",
                "engine_heartbeat": str(time.time()),
            })
        except Exception:
            pass
        time.sleep(1.0)


_safe_cache = {"ts": 0.0, "pids": set()}


def get_protected_family_pids(max_age=2.0) -> set:
    """
    Cached wrapper (full process scan is expensive and was slowing down detection).
    """
    now = time.time()
    if _safe_cache["pids"] and (now - _safe_cache["ts"]) < max_age:
        return set(_safe_cache["pids"])
    pids = _compute_protected_family_pids()
    _safe_cache["pids"] = pids
    _safe_cache["ts"] = now
    return set(pids)


def _compute_protected_family_pids() -> set:
    """
    Returns the Engine PID, Dashboard PID, and all parent/ancestor PIDs of both
    so the Engine NEVER suspends or kills itself or the Streamlit Dashboard.
    """
    my_pid = os.getpid()
    dash_pid = int(db.get_setting("dashboard_pid", "0") or 0)
    safe_pids = {my_pid, dash_pid}

    try:
        curr = psutil.Process(my_pid)
        while curr is not None:
            safe_pids.add(curr.pid)
            curr = curr.parent()
    except Exception:
        pass

    try:
        dp = psutil.Process(dash_pid) if dash_pid else None
        while dp is not None:
            safe_pids.add(dp.pid)
            dp = dp.parent()
    except Exception:
        pass

    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = " ".join(proc.info.get('cmdline') or []).lower()
            if "edr_engine.py" in cmdline or "streamlit" in cmdline or "app.py" in cmdline:
                safe_pids.add(proc.info['pid'])
        except Exception:
            continue

    return safe_pids


def calculate_entropy(file_path):
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return 0.0
        with open(file_path, "rb") as f:
            data = f.read(65536)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
    except Exception:
        return 0.0


def get_file_header(file_path, num_bytes=8):
    try:
        if not os.path.exists(file_path):
            return b""
        with open(file_path, "rb") as f:
            return f.read(num_bytes)
    except Exception:
        return b""


def has_valid_magic_header(ext, header_bytes):
    if not header_bytes:
        return False
    expected = MAGIC_HEADERS.get(ext.lower())
    if not expected:
        return False
    return any(header_bytes.startswith(prefix) for prefix in expected)


def get_sha256(file_path):
    try:
        if not os.path.exists(file_path):
            return ""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def verify_authenticode_signature(exe_path):
    if not exe_path or not os.path.exists(exe_path):
        return False
    try:
        mtime = os.path.getmtime(exe_path)
        cache_key = (os.path.normcase(exe_path), mtime)
        if cache_key in _sig_cache:
            return _sig_cache[cache_key]

        escaped_path = exe_path.replace("'", "''")
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{escaped_path}').Status"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        is_valid = "Valid" in res.stdout.strip()
        _sig_cache[cache_key] = is_valid
        return is_valid
    except Exception:
        return False


# ---------------- CANARY (HONEYPOT) STATE HELPERS ---------------- #

def trap_is_intact(path) -> bool:
    """True only if the canary file exists with its exact original content."""
    try:
        if not os.path.isfile(path):
            return False
        if os.path.getsize(path) != len(TRAP_PRISTINE):
            return False
        with open(path, "rb") as f:
            return f.read() == TRAP_PRISTINE
    except Exception:
        return False


def count_trap_damage(target_dir) -> int:
    """Counts canary files that are modified, deleted, renamed (.locked) or stray right now."""
    trap_dir = os.path.join(target_dir, TRAP_FOLDER_NAME)
    if not os.path.isdir(trap_dir):
        return 0
    try:
        names = os.listdir(trap_dir)
    except OSError:
        return 0
    damaged = 0
    present = set()
    for n in names:
        if TRAP_NAME_RE.match(n):
            present.add(n)
            if not trap_is_intact(os.path.join(trap_dir, n)):
                damaged += 1
        else:
            damaged += 1  # .locked or any stray file inside the trap folder
    for i in range(1, 26):
        n = f"00_confidential_records_{i:02d}.docx"
        if n not in present and not any(x.startswith(n) for x in names):
            damaged += 1  # canary deleted outright
    return damaged


# ---------------- REAL-TIME PROCESS I/O DELTA TRACKER ---------------- #

class ProcessIOTracker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.history = {}
        self.proc_meta = {}  # pid -> (name, exe, link_score, display_label)
        self.recent_writers = deque(maxlen=40)  # (timestamp, pid, name, exe, delta_bytes)
        self.lock = threading.Lock()
        self.running = True
        self.base_norm = os.path.normcase(BASE_DIR)

    def _cmd_link(self, cmdline):
        cmd = os.path.normcase(" ".join(cmdline or []))
        if self.base_norm in cmd or "demo_protected_folder" in cmd:
            return 300_000
        return 0

    def _link_score(self, proc):
        """
        Evidence that a process is tied to the protected sandbox/project folder.
        Computed ONCE per new process (cheap). Unrelated apps (browsers etc.) score 0
        and can therefore never be selected for termination.
        """
        score = 0
        try:
            score += self._cmd_link(proc.cmdline())
        except Exception:
            pass
        try:
            cwd = os.path.normcase(proc.cwd() or "")
            if self.base_norm in cwd:
                score += 100_000
        except Exception:
            pass
        return score

    def _describe(self, proc, name):
        """
        Builds the name shown on the dashboard: the actual script the process is running
        (python.exe alone is useless), plus the attack mode when it is the simulator.
        """
        try:
            cmd = proc.cmdline() or []
        except Exception:
            return name
        for i, part in enumerate(cmd):
            if part.lower().endswith(".py"):
                script = os.path.basename(part)
                if "fake_ransom" in script.lower():
                    mode = cmd[i + 1].lower() if i + 1 < len(cmd) else "normal"
                    label = ATTACK_LABELS.get(mode)
                    if label:
                        return f"{script} [{label}]"
                return f"{script} ({name})" if name else script
        return name

    def run(self):
        while self.running:
            now = time.time()
            safe_pids = get_protected_family_pids()
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                try:
                    pid = proc.info['pid']
                    if pid in safe_pids:
                        continue
                    name = (proc.info['name'] or "")
                    if name.lower() in PROTECTED_PROCESSES:
                        continue
                    io = proc.io_counters()
                    w_bytes = io.write_bytes
                    with self.lock:
                        is_new = pid not in self.history
                    link = self._link_score(proc) if is_new else None
                    label = self._describe(proc, name) if (is_new and link) else None
                    with self.lock:
                        if pid not in self.history:
                            ctime = proc.info.get('create_time') or now
                            self.history[pid] = deque(maxlen=20)
                            if now - ctime < 15.0:
                                self.history[pid].append((ctime, 0))
                        prev_w = self.history[pid][-1][1] if self.history[pid] else w_bytes
                        self.history[pid].append((now, w_bytes))
                        exe = proc.info.get('exe') or ""
                        old = self.proc_meta.get(pid)
                        self.proc_meta[pid] = (
                            name,
                            exe,
                            link if link is not None else (old[2] if old else 0),
                            label if label is not None else (old[3] if old else name),
                        )
                        if w_bytes - prev_w > 0:
                            self.recent_writers.append((now, pid, name, exe, w_bytes - prev_w))
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue
            with self.lock:
                for dead in [k for k, h in self.history.items() if h and now - h[-1][0] > 30.0]:
                    self.history.pop(dead, None)
                    self.proc_meta.pop(dead, None)
            time.sleep(0.12)

    # ---- candidate collection ---- #

    def _history_candidates(self, safe_pids, window_sec, now):
        """Processes with proven link to this project AND real write activity (from the polling history)."""
        candidates = {}  # pid -> [score, name, exe, label]
        with self.lock:
            for pid, hist in self.history.items():
                if pid in safe_pids or not hist:
                    continue
                name, exe, link, label = self.proc_meta.get(pid, ("", "", 0, ""))
                if link <= 0 or name.lower() in PROTECTED_PROCESSES:
                    continue
                if now - hist[-1][0] > window_sec + 2.0:
                    continue
                base_w = hist[0][1]
                for ts, wb in hist:
                    if now - ts <= window_sec:
                        base_w = wb
                        break
                delta = max(0, hist[-1][1] - base_w)
                if delta >= 1024:
                    candidates[pid] = [delta + link, name, exe, label or name]

            # fast processes that already exited - linked ones only
            for ts, pid, name, exe, d_bytes in self.recent_writers:
                if now - ts <= window_sec and pid not in safe_pids:
                    meta = self.proc_meta.get(pid, ("", "", 0, ""))
                    if meta[2] > 0:
                        if pid in candidates:
                            candidates[pid][0] += d_bytes
                        else:
                            candidates[pid] = [d_bytes + meta[2], name, exe, meta[3] or name]
        return candidates

    def _direct_scan(self, safe_pids):
        """
        Instant fresh scan (no polling history needed). This is what catches an attacker that was
        spawned only milliseconds before the first canary hit, i.e. before the poller ever saw it.
        """
        candidates = {}
        now = time.time()
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ""
                if pid in safe_pids or name.lower() in PROTECTED_PROCESSES:
                    continue
                link = self._cmd_link(proc.info.get('cmdline'))
                if link <= 0:
                    continue
                ctime = proc.info.get('create_time') or 0
                recency = max(0.0, 100.0 - (now - ctime))  # newest linked process wins ties
                candidates[pid] = [link + recency, name, proc.info.get('exe') or "", self._describe(proc, name)]
            except Exception:
                continue
        return candidates

    def find_suspect_and_stop(self, target_dir, window_sec=6.0):
        safe_pids = get_protected_family_pids()
        target_norm = os.path.normcase(os.path.abspath(target_dir))

        # 1. Linked + write-proven processes; if none yet, an instant direct scan.
        #    Retry briefly: the attacker may still be spawning when the first canary event fires.
        deadline = time.time() + 2.0
        candidates = {}
        while True:
            now = time.time()
            candidates = self._history_candidates(safe_pids, window_sec, now)
            if not candidates:
                candidates = self._direct_scan(safe_pids)
            if candidates or time.time() >= deadline:
                break
            time.sleep(0.05)

        # 2. LAST RESORT (time-boxed: open_files() is very slow on Windows, it used to block ~30 s)
        if not candidates:
            budget_end = time.time() + 1.0
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if time.time() > budget_end:
                    break
                try:
                    pid = proc.info['pid']
                    name = (proc.info['name'] or "")
                    if pid in safe_pids or name.lower() in PROTECTED_PROCESSES:
                        continue
                    for of in proc.open_files():
                        if target_norm in os.path.normcase(of.path):
                            candidates[pid] = [500_000, name, proc.info.get('exe') or "", self._describe(proc, name)]
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue

        # Safety: never terminate anything without evidence tying it to the protected folder
        if not candidates:
            return ("Unknown Process", 0, "not_found")

        sorted_cands = sorted(candidates.items(), key=lambda item: item[1][0], reverse=True)
        suspect_pid, (_, suspect_name, suspect_exe, suspect_label) = sorted_cands[0]
        display = suspect_label or suspect_name

        try:
            suspect_proc = psutil.Process(suspect_pid)
            children = [
                ch for ch in suspect_proc.children(recursive=True)
                if ch.pid not in safe_pids
            ]

            for ch in children:
                try:
                    ch.suspend()
                except Exception:
                    pass
            if suspect_pid not in safe_pids:
                suspect_proc.suspend()

            # Check Whitelist (SHA-256 + Authenticode)
            if suspect_exe and os.path.exists(suspect_exe):
                exe_hash = get_sha256(suspect_exe)
                wl_row = db.is_whitelisted_hash(exe_hash)
                if wl_row is not None:
                    req_sig = bool(wl_row[0])
                    if not req_sig or verify_authenticode_signature(suspect_exe):
                        suspect_proc.resume()
                        for ch in children:
                            try:
                                ch.resume()
                            except Exception:
                                pass
                        return (display, suspect_pid, "whitelisted")

            for ch in children:
                try:
                    ch.kill()
                except Exception:
                    pass
            if suspect_pid not in safe_pids:
                suspect_proc.kill()
            logging.warning(f"Terminated malicious process: {display} (PID {suspect_pid})")
            return (display, suspect_pid, "killed")

        except psutil.NoSuchProcess:
            # Process exited right as we reached it (fast ransomware finished its burst)
            return (display, suspect_pid, "killed")
        except Exception as e:
            logging.error(f"Kill error: {e}")
            return (display, suspect_pid, "not_found")


# ---------------- LEVEL 1 (WINDOWS VSS) & LEVEL 2 (COMPRESSED VAULT) ---------------- #

def get_sandbox_drive():
    drive, _ = os.path.splitdrive(os.path.abspath(DEMO_SANDBOX))
    return (drive + "\\") if drive else "C:\\"


def query_latest_vss_device() -> str:
    """Queries WMI once for the latest ShadowCopy DeviceObject path."""
    try:
        ps_find = (
            "Get-WmiObject Win32_ShadowCopy | Sort-Object InstallDate -Descending | "
            "Select-Object -First 1 -ExpandProperty DeviceObject"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_find],
            capture_output=True, text=True, timeout=8
        )
        dev = res.stdout.strip()
        if dev and "HarddiskVolumeShadowCopy" in dev:
            return dev
    except Exception:
        pass
    return ""


def create_vss_snapshot(drive=None):
    """Creates a Windows Volume Shadow Copy snapshot and caches the DeviceObject path in memory."""
    global ACTIVE_VSS_DEVICE
    if not drive:
        drive = get_sandbox_drive()

    admin = is_running_as_admin()
    db.set_setting("engine_is_admin", "1" if admin else "0")

    if not admin:
        ACTIVE_VSS_DEVICE = None
        db.set_setting("vss_status", "Tier-2 Vault Active (Elevate Sensor for Tier-1 VSS)")
        return False

    try:
        # Ensure Volume Shadow Copy service is running
        subprocess.run(["sc", "config", "vss", "start=", "demand"], capture_output=True, timeout=4)
        subprocess.run(["sc", "config", "swprv", "start=", "demand"], capture_output=True, timeout=4)
        subprocess.run(["net", "start", "vss"], capture_output=True, timeout=6)

        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"([WMICLASS]'Win32_ShadowCopy').Create('{drive}', 'ClientAccessible')"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        dev_path = query_latest_vss_device()

        if re.search(r"ReturnValue\s*[:=]\s*0", res.stdout) or dev_path:
            ACTIVE_VSS_DEVICE = dev_path
            db.set_setting("vss_status", f"Tier-1 VSS Active ({drive}) + Tier-2 Vault")
            logging.info(f"Tier-1 VSS Snapshot Ready: {ACTIVE_VSS_DEVICE}")
            return True
        else:
            ACTIVE_VSS_DEVICE = None
            db.set_setting("vss_status", "Tier-2 Compressed Vault Active (VSS Service Unavailable)")
            return False
    except Exception as e:
        ACTIVE_VSS_DEVICE = None
        logging.warning(f"VSS creation failed: {e}")
        db.set_setting("vss_status", "Tier-2 Compressed Vault Active")
        return False


def try_vss_restore(file_path) -> bool:
    """
    Fast, zero-PowerShell Tier-1 VSS restoration using the cached GLOBALROOT device path.
    Executes in < 5 milliseconds when running as Administrator.
    """
    global ACTIVE_VSS_DEVICE
    if not ACTIVE_VSS_DEVICE:
        return False

    try:
        abs_path = os.path.abspath(file_path)
        _, tail = os.path.splitdrive(abs_path)
        vss_source = ACTIVE_VSS_DEVICE.rstrip("\\") + tail

        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        # Direct Win32 kernel device read in Python
        with open(vss_source, "rb") as f_src:
            raw_bytes = f_src.read()
        with open(abs_path, "wb") as f_dst:
            f_dst.write(raw_bytes)
        logging.info(f"Restored file via Tier-1 VSS: {os.path.basename(abs_path)}")
        return True
    except Exception:
        # Fallback via cmd copy if direct handle is restricted
        try:
            copy_res = subprocess.run(
                ["cmd.exe", "/c", "copy", "/Y", vss_source, abs_path],
                capture_output=True, text=True, timeout=3
            )
            return copy_res.returncode == 0 and os.path.exists(abs_path)
        except Exception:
            return False


def run_vss_self_test():
    drive = get_sandbox_drive()
    if not is_running_as_admin():
        msg = f"Sensor is running without Admin rights. Click 'ELEVATE SENSOR FOR TIER-1 VSS' on top bar."
        db.set_setting("vss_last_test", msg)
        return msg

    ok = create_vss_snapshot(drive)
    test_file = os.path.join(DEMO_SANDBOX, "01_Project_Report_DUET.docx")
    if ok and os.path.exists(test_file) and try_vss_restore(test_file):
        msg = f"PASS: Tier-1 VSS Snapshot ({ACTIVE_VSS_DEVICE}) & Direct Restore Verified!"
    elif ok:
        msg = f"PASS: Tier-1 VSS Snapshot Created on {drive} ({ACTIVE_VSS_DEVICE})"
    else:
        msg = f"FAIL: Windows Volume Shadow Copy service blocked snapshot creation on {drive}"
    db.set_setting("vss_last_test", msg)
    return msg


class VaultManager:
    def __init__(self, watch_dir, vault_dir):
        self.watch_dir = os.path.abspath(watch_dir)
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        self.file_metadata = db.get_all_vault_meta()

    def get_vault_path(self, original_path):
        rel = os.path.relpath(os.path.abspath(original_path), self.watch_dir)
        return os.path.join(self.vault_dir, rel + ".zvault")

    def is_file_healthy(self, file_path):
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUSPICIOUS_EXTS or ext in IGNORED_EXTS:
            return False
        try:
            sz = os.path.getsize(file_path)
            if sz > MAX_VAULT_FILE_SIZE:
                return False
            if sz == 0:
                return True
            hdr = get_file_header(file_path)
            if has_valid_magic_header(ext, hdr):
                return True
            ent = calculate_entropy(file_path)
            if ent >= float(db.get_setting("absolute_high_entropy", 7.2)):
                return False
            return True
        except Exception:
            return False

    def backup_all(self):
        for root, _, files in os.walk(self.watch_dir):
            if TRAP_FOLDER_NAME in root or self.vault_dir in root:
                continue
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in PROTECTED_EXTS:
                    full_p = os.path.abspath(os.path.join(root, file))
                    if self.is_file_healthy(full_p):
                        self.backup_single_file(full_p, update_metrics=False)
        db.update_vault_storage_metrics(self.vault_dir)

    def backup_single_file(self, file_path, update_metrics=True):
        try:
            abs_p = os.path.abspath(file_path)
            if not self.is_file_healthy(abs_p):
                return
            v_path = self.get_vault_path(abs_p)
            os.makedirs(os.path.dirname(v_path), exist_ok=True)
            new_hash = get_sha256(abs_p)
            orig_size = os.path.getsize(abs_p)
            old_meta = self.file_metadata.get(abs_p)

            if not old_meta or old_meta[2] != new_hash or not os.path.exists(v_path):
                with open(abs_p, "rb") as f_in:
                    raw_data = f_in.read()
                compressed_data = zlib.compress(raw_data, level=6)
                with open(v_path, "wb") as f_out:
                    f_out.write(compressed_data)

            comp_size = os.path.getsize(v_path) if os.path.exists(v_path) else 0
            ent = calculate_entropy(abs_p)
            hdr = get_file_header(abs_p)
            self.file_metadata[abs_p] = (ent, hdr, new_hash)
            db.upsert_vault_meta(abs_p, ent, hdr, new_hash, orig_size, comp_size)
            if update_metrics:
                db.update_vault_storage_metrics(self.vault_dir)
        except Exception as e:
            logging.error(f"Compressed vault backup error for {file_path}: {e}")

    def restore_from_vault(self, file_path):
        try:
            abs_p = os.path.abspath(file_path)
            v_path = self.get_vault_path(abs_p)
            if os.path.exists(v_path):
                os.makedirs(os.path.dirname(abs_p), exist_ok=True)
                with open(v_path, "rb") as f_in:
                    compressed_data = f_in.read()
                raw_data = zlib.decompress(compressed_data)
                with open(abs_p, "wb") as f_out:
                    f_out.write(raw_data)
                return True
        except Exception as e:
            logging.error(f"Vault restore error for {file_path}: {e}")
        return False


def setup_honeypots(target_dir):
    """Creates the canary folder and (re)seeds every canary with its pristine content."""
    trap_dir = os.path.join(target_dir, TRAP_FOLDER_NAME)
    os.makedirs(trap_dir, exist_ok=True)
    for existing in os.listdir(trap_dir):
        if not TRAP_NAME_RE.match(existing):
            try:
                os.remove(os.path.join(trap_dir, existing))  # leftover .locked / stray files
            except Exception:
                pass
    for i in range(1, 26):
        t_file = os.path.join(trap_dir, f"00_confidential_records_{i:02d}.docx")
        # Re-seed missing OR tampered canaries (previously tampered ones stayed garbage forever)
        if not trap_is_intact(t_file):
            try:
                with open(t_file, "wb") as f:
                    f.write(TRAP_PRISTINE)
            except Exception:
                pass
    if os.name == 'nt':
        subprocess.run(["attrib", "+h", trap_dir], capture_output=True)
    return trap_dir


def populate_demo_sandbox(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    for root, _, files in os.walk(target_dir):
        for f in files:
            if os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTS:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass

    samples = {
        "01_Project_Report_DUET.docx": b"PK\x03\x04" + b"Dawood University Information Security Lab Project Report Content. " * 45,
        "02_Student_Grades_2025.xlsx": b"PK\x03\x04" + b"ID,Name,Grade\n25F-DS-014,Syed Shayan,A+\n25F-DS-017,Muhammad Arsalan,A+\n" * 35,
        "03_University_Contract.pdf": b"%PDF-1.5\n" + b"Clean readable document body for entropy baseline testing.\n" * 45,
        "04_CyberSecurity_Notes.txt": b"Ransomware behavior detection relies on entropy delta and rapid file modification checks. " * 40,
        "05_Network_Diagram.jpg": b"\xff\xd8\xff\xe0" + b"Clean_Image_Payload_Stream_" * 65,
        "06_Financial_Budget_2026.xlsx": b"PK\x03\x04" + b"Month,Allocated,Spent,Variance\nJan,50000,48000,2000\nFeb,62000,60500,1500\n" * 35,
        "07_Thesis_Literature_Review.pdf": b"%PDF-1.5\n" + b"Enterprise SOC VLAN segmentation and firewall policy specification.\n" * 40,
        "08_Server_Credentials_Backup.csv": b"Server,IP,Role,Status\nSOC-DB-01,10.0.1.15,Primary,Active\nSOC-EDR-02,10.0.1.20,Sensor,Active\n" * 35,
        "09_Endpoint_Audit_Policy.docx": b"PK\x03\x04" + b"Zero-trust endpoint security configuration and privilege restriction guidelines. " * 40,
        "10_Incident_Response_Playbook.pdf": b"%PDF-1.5\n" + b"Standard operating procedure for ransomware containment and VSS recovery.\n" * 40,
        "11_Faculty_Research_Data.csv": b"ProjectID,Department,GrantPKR,Status\nDS-101,DataScience,450000,Approved\n" * 35,
        "12_Architecture_Blueprint.png": b"\x89PNG\r\n\x1a\n" + b"Clean_PNG_Vector_Graphics_Payload_" * 55
    }
    for name, content in samples.items():
        p = os.path.join(target_dir, name)
        with open(p, "wb") as f:
            f.write(content)


# ---------------- WATCHDOG REAL-TIME EVENT HANDLER ---------------- #

class MiniEDRHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, vault: VaultManager, io_tracker: ProcessIOTracker):
        self.watch_dir = os.path.abspath(watch_dir)
        self.vault = vault
        self.io_tracker = io_tracker
        self.recent_files = {}
        self.compromised_files = set()
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        self.response_lock = threading.Lock()
        self.recovering = False
        self.last_alert_time = 0.0
        self.first_suspicious_time = None

    def is_ignored(self, path):
        abs_p = os.path.abspath(path)
        ext = os.path.splitext(abs_p)[1].lower()
        return ext in IGNORED_EXTS or VAULT_DIR in abs_p

    def queue_event_log(self, event_type, file_path, old_ent, new_ent, delta_ent):
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        with self.buffer_lock:
            self.event_buffer.append((
                now_str, event_type, os.path.basename(file_path),
                round(old_ent, 3), round(new_ent, 3), round(delta_ent, 3)
            ))

    def flush_events(self):
        with self.buffer_lock:
            if not self.event_buffer:
                return
            batch = list(self.event_buffer)
            self.event_buffer.clear()
        db.log_events_batch(batch)

    def strip_locked_ext(self, path):
        abs_p = os.path.abspath(path)
        base, ext = os.path.splitext(abs_p)
        if ext.lower() in SUSPICIOUS_EXTS:
            return base
        return abs_p

    def handle_event(self, event_type, src_path, dest_path=None):
        if self.recovering or (time.time() - self.last_alert_time < 1.5):
            return

        target_path = os.path.abspath(dest_path if dest_path else src_path)
        orig_path = self.strip_locked_ext(src_path)
        if self.is_ignored(target_path):
            return

        now = time.time()

        # 1. HONEYPOT CHECK (!000_Trap)
        if TRAP_FOLDER_NAME in orig_path or (dest_path and TRAP_FOLDER_NAME in target_path):
            if event_type in ("MODIFIED", "RENAMED", "DELETED"):
                # STALE-EVENT FILTER: events queued during a previous recovery (or caused by our own
                # re-seeding of the canaries) are replayed later by watchdog. If the canary is currently
                # intact with its original content, nothing hostile happened -> ignore it.
                if trap_is_intact(orig_path):
                    return
                if self.first_suspicious_time is None:
                    self.first_suspicious_time = time.perf_counter()
                self.queue_event_log(f"TRAP_{event_type}", orig_path, 3.9, 7.98, 4.08)
                self.trigger_response(f"Honeypot Canary Trap Triggered: {event_type} in !000_Trap")
            return

        # 2. DELETION HANDLING
        if event_type == "DELETED":
            if orig_path in self.vault.file_metadata:
                if self.first_suspicious_time is None:
                    self.first_suspicious_time = time.perf_counter()
                self.compromised_files.add(orig_path)
                self.recent_files[orig_path] = now
            return

        # 3. ENTROPY, HEADER & EXTENSION CHECK
        known_meta = self.vault.file_metadata.get(orig_path)
        new_ent = calculate_entropy(target_path)
        new_hdr = get_file_header(target_path)
        ext = os.path.splitext(target_path)[1].lower()
        orig_ext = os.path.splitext(orig_path)[1].lower()

        suspicious_ext = ext in SUSPICIOUS_EXTS
        ent_threshold = float(db.get_setting("entropy_delta_threshold", 0.8))
        abs_high_ent = float(db.get_setting("absolute_high_entropy", 7.2))

        if known_meta is not None:
            old_ent, old_hdr, _ = known_meta
            if new_ent == 0.0 and suspicious_ext:
                new_ent = 7.95
            delta_ent = max(0.0, new_ent - old_ent)
            header_corrupted = (old_hdr != b"" and new_hdr != b"" and old_hdr[:4] != new_hdr[:4] and not has_valid_magic_header(orig_ext, new_hdr))
            is_suspicious_file = header_corrupted or suspicious_ext or (delta_ent >= ent_threshold and new_ent >= 6.5)
        else:
            old_ent = 4.2 if suspicious_ext else new_ent
            delta_ent = max(0.0, new_ent - old_ent)
            is_suspicious_file = suspicious_ext or (new_ent >= abs_high_ent and not has_valid_magic_header(ext, new_hdr))

        if new_ent > 0.0 or suspicious_ext or event_type == "CREATED":
            self.queue_event_log(event_type, target_path, old_ent, new_ent, delta_ent)

        window_sec = float(db.get_setting("speed_window_sec", 5))
        speed_limit = int(db.get_setting("speed_limit_files", 4))
        self.recent_files = {p: t for p, t in self.recent_files.items() if now - t <= window_sec}

        if is_suspicious_file:
            if self.first_suspicious_time is None:
                self.first_suspicious_time = time.perf_counter()
            self.recent_files[orig_path] = now
            self.compromised_files.add(orig_path)
        else:
            if ext in PROTECTED_EXTS and os.path.exists(target_path):
                self.vault.backup_single_file(target_path)

        files_in_window = len(self.recent_files)

        # 4. DECISION RULE
        if files_in_window >= speed_limit and is_suspicious_file:
            reason = f"Speed ({files_in_window} files/{window_sec}s) + Entropy Spike (Entropy={new_ent:.2f}, Delta=+{delta_ent:.2f})"
            self.trigger_response(reason)
        elif suspicious_ext and len(self.compromised_files) >= 2:
            reason = f"Ransomware Extension Burst ({ext}) + High Entropy ({new_ent:.2f} bits/byte)"
            self.trigger_response(reason)
        elif is_suspicious_file and len(self.compromised_files) >= 3:
            reason = f"Multi-Asset Header/Entropy Corruption ({len(self.compromised_files)} files compromised)"
            self.trigger_response(reason)

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.handle_event("CREATED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.handle_event("RENAMED", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.handle_event("DELETED", event.src_path)

    def trigger_response(self, reason):
        with self.response_lock:
            if self.recovering:
                return
            self.recovering = True

        try:
            det_start = self.first_suspicious_time or time.perf_counter()
            proc_name, pid, disposition = self.io_tracker.find_suspect_and_stop(self.watch_dir)
            detect_ms = max(1.5, (time.perf_counter() - det_start) * 1000.0)

            if disposition == "whitelisted":
                self.compromised_files.clear()
                self.recent_files.clear()
                self.first_suspicious_time = None
                return

            # Wait 150ms for killed ransomware process to release OS file handles
            time.sleep(0.15)

            # Measure canary damage BEFORE anything gets re-seeded
            trap_damaged = count_trap_damage(self.watch_dir)

            start_restore = time.perf_counter()
            vss_restored = 0
            vault_restored = 0
            failed_files = []
            locked_user_files = 0

            # 1. Sweep & delete all .locked files and mark their base names for restoration
            for root, _, files in os.walk(self.watch_dir):
                if TRAP_FOLDER_NAME in root:
                    continue
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in SUSPICIOUS_EXTS:
                        locked_full = os.path.join(root, f)
                        orig_full = self.strip_locked_ext(locked_full)
                        self.compromised_files.add(orig_full)
                        locked_user_files += 1
                        try:
                            os.remove(locked_full)
                        except Exception:
                            pass

            # 2. Identify all missing or corrupted tracked files
            targets_to_restore = set(self.compromised_files)
            for tracked_path, (_, old_hdr, clean_hash) in list(self.vault.file_metadata.items()):
                if not os.path.exists(tracked_path):
                    targets_to_restore.add(tracked_path)
                else:
                    cur_hash = get_sha256(tracked_path)
                    cur_hdr = get_file_header(tracked_path)
                    ext = os.path.splitext(tracked_path)[1].lower()
                    if cur_hash != clean_hash and (
                        (old_hdr and cur_hdr[:4] != old_hdr[:4] and not has_valid_magic_header(ext, cur_hdr))
                        or calculate_entropy(tracked_path) >= 7.2
                        or tracked_path in self.compromised_files
                    ):
                        targets_to_restore.add(tracked_path)

            user_targets = [p for p in targets_to_restore if TRAP_FOLDER_NAME not in p]

            # FALSE-ALARM GUARD: no process found, canaries untouched, no user file damaged
            # -> this was a stale event, not an attack. Do not log a phantom incident.
            if disposition == "not_found" and trap_damaged == 0 and not user_targets:
                logging.info(f"Discarded stale/phantom trigger (no attacker, no damage): {reason}")
                self.flush_events()
                return

            # 3. Restore via Tier-1 VSS first; fallback to Tier-2 Compressed Vault
            for dmg_path in sorted(targets_to_restore):
                if TRAP_FOLDER_NAME in dmg_path:
                    continue
                if try_vss_restore(dmg_path):
                    vss_restored += 1
                elif self.vault.restore_from_vault(dmg_path):
                    vault_restored += 1
                else:
                    failed_files.append(os.path.basename(dmg_path))

            setup_honeypots(self.watch_dir)

            restore_ms = (time.perf_counter() - start_restore) * 1000.0
            total_affected = vss_restored + vault_restored + len(failed_files)

            if vss_restored > 0 and vault_restored > 0:
                method = "Level 1 VSS + Level 2 Vault"
                details = f"{vss_restored} files restored via Windows VSS, {vault_restored} via Compressed Vault"
            elif vss_restored > 0:
                method = "Level 1: Windows VSS Snapshot"
                details = f"{vss_restored} damaged files restored from Volume Shadow Copy ({ACTIVE_VSS_DEVICE})"
            elif vault_restored > 0:
                method = "Level 2: Compressed Local Vault"
                details = f"{vault_restored} damaged files restored from Local Vault (.zvault)"
            elif failed_files:
                method = "Level 3: Contain & Report"
                details = f"Process stopped. Unrecovered files: {', '.join(failed_files)}"
            else:
                method = "Honeypot Containment (Pre-Encryption)"
                details = f"Threat neutralized at !000_Trap canary layer; {trap_damaged} decoys re-seeded, 0 user files damaged"

            # Always surface unrecovered files (Level 3), even when other tiers partly succeeded
            if failed_files and method != "Level 3: Contain & Report":
                details += f" | UNRECOVERED ({len(failed_files)}): {', '.join(failed_files)}"
            db.set_setting("last_unrecovered", ", ".join(failed_files))

            # Describe the ACTUAL behavior observed (not only the first signal that fired)
            behavior = []
            if locked_user_files:
                behavior.append(f"Mass Encryption Burst ({locked_user_files} user files renamed to ransomware extension)")
            elif user_targets:
                behavior.append(f"Header/Entropy Corruption ({len(user_targets)} user files damaged)")
            if trap_damaged:
                behavior.append(f"Canary Trap hit ({trap_damaged} decoys damaged)")
            if behavior:
                final_reason = " + ".join(behavior) + f"  [first signal: {reason}]"
            else:
                final_reason = reason

            self.flush_events()
            db.log_alert(proc_name, pid, disposition, final_reason, max(1, total_affected), method, details, detect_ms, restore_ms)

        except Exception as e:
            logging.exception(f"Trigger response error: {e}")
        finally:
            self.compromised_files.clear()
            self.recent_files.clear()
            self.first_suspicious_time = None
            self.last_alert_time = time.time()
            self.recovering = False


def active_patrol_check(vault: VaultManager, handler: MiniEDRHandler):
    if handler.recovering or (time.time() - handler.last_alert_time < 2.0):
        return
    locked_count = 0
    for root, _, files in os.walk(DEMO_SANDBOX):
        if TRAP_FOLDER_NAME in root or VAULT_DIR in root:
            continue
        for f in files:
            fp = os.path.abspath(os.path.join(root, f))
            ext = os.path.splitext(f)[1].lower()
            if ext in SUSPICIOUS_EXTS:
                locked_count += 1
            elif ext in PROTECTED_EXTS:
                meta = vault.file_metadata.get(fp)
                if meta is None or not os.path.exists(vault.get_vault_path(fp)):
                    vault.backup_single_file(fp)

    if locked_count > 0 and not handler.recovering:
        handler.trigger_response(f"Active Patrol: {locked_count} encrypted (.locked) files intercepted and restored")


def process_dashboard_commands(vault: VaultManager, handler: MiniEDRHandler):
    for cmd_id, cmd_name in db.fetch_pending_commands():
        logging.info(f"Executing dashboard command: {cmd_name}")
        if cmd_name == "REINIT_SANDBOX":
            handler.recovering = True
            db.set_setting("engine_busy", "1")
            try:
                populate_demo_sandbox(DEMO_SANDBOX)
                setup_honeypots(DEMO_SANDBOX)
                vault.backup_all()
                if is_running_as_admin():
                    create_vss_snapshot()
                db.set_setting("system_status", "SECURE")
                db.set_setting("last_unrecovered", "")
                db.complete_command(cmd_id, "Sandbox, VSS & Compressed Vault re-initialized.")
            except Exception as e:
                logging.exception("REINIT_SANDBOX failed")
                db.complete_command(cmd_id, f"Failed: {e}")
            finally:
                db.set_setting("engine_busy", "0")
                handler.last_alert_time = time.time()
                handler.recovering = False
        elif cmd_name == "VSS_SELF_TEST":
            res = run_vss_self_test()
            db.complete_command(cmd_id, res)
        elif cmd_name == "SHUTDOWN_ENGINE":
            db.complete_command(cmd_id, "Shutting down for Admin elevation.")
            os._exit(0)
        else:
            db.complete_command(cmd_id, "Done")


def run_engine():
    # If an old engine is shutting down (admin elevation), wait up to 10s for it to release the lock
    for _ in range(40):
        if acquire_single_instance():
            break
        time.sleep(0.25)
    else:
        print("[!] Another engine instance is running. Exiting.")
        return

    db.init_db()
    # Heartbeat starts immediately so the dashboard sees us alive during slow startup (VSS, backups)
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    db.set_setting("engine_busy", "1")
    vault = VaultManager(DEMO_SANDBOX, VAULT_DIR)

    # --- Startup recovery (attack happened while sensor was offline) — now recorded in alerts ---
    t0 = time.perf_counter()
    found, recovered, failed = 0, 0, []
    if os.path.exists(DEMO_SANDBOX):
        for root, _, files in os.walk(DEMO_SANDBOX):
            if TRAP_FOLDER_NAME in root:
                continue  # canary leftovers are cleaned by setup_honeypots(); they are not user files
            for f in files:
                if os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTS:
                    found += 1
                    locked_p = os.path.join(root, f)
                    orig_p = os.path.splitext(locked_p)[0]
                    if vault.restore_from_vault(orig_p):
                        recovered += 1
                    else:
                        failed.append(os.path.basename(orig_p))
                    try:
                        os.remove(locked_p)
                    except Exception:
                        pass
    if found:
        details = f"{recovered} restored from Local Vault (.zvault)"
        if failed:
            details += f" | UNRECOVERED ({len(failed)}): {', '.join(failed)}"
        db.log_alert(
            "Unknown (sensor was offline)", 0, "contained",
            f"Startup Recovery: {found} encrypted file(s) found from attack while sensor was offline",
            found, "Level 2: Compressed Local Vault", details,
            0, (time.perf_counter() - t0) * 1000.0
        )
        db.set_setting("last_unrecovered", ", ".join(failed))

    # Only create sample files when sandbox is empty (otherwise it overwrites user files)
    has_files = os.path.exists(DEMO_SANDBOX) and any(
        os.path.splitext(f)[1].lower() in PROTECTED_EXTS
        for _, _, fs in os.walk(DEMO_SANDBOX) for f in fs
    )
    if not has_files:
        populate_demo_sandbox(DEMO_SANDBOX)
    try:
        setup_honeypots(DEMO_SANDBOX)
        vault.backup_all()
        create_vss_snapshot()
    except Exception:
        logging.exception("Startup backup / VSS failed (engine continues in degraded mode)")
    finally:
        db.set_setting("engine_busy", "0")

    io_tracker = ProcessIOTracker()
    io_tracker.start()

    handler = MiniEDRHandler(DEMO_SANDBOX, vault, io_tracker)
    # Ignore the burst of events generated by our own startup file writes
    handler.last_alert_time = time.time()
    observer = Observer()
    observer.schedule(handler, DEMO_SANDBOX, recursive=True)
    observer.start()

    # Don't wipe the ATTACK BLOCKED banner if startup recovery just logged one
    if not found:
        db.set_setting("system_status", "SECURE")
    db.set_setting("engine_launching_until", "0")

    print(f"[*] Mini-EDR Engine Running (PID: {os.getpid()} | Admin: {is_running_as_admin()}) | Watching: {DEMO_SANDBOX}")

    try:
        while True:
            try:
                handler.flush_events()
                active_patrol_check(vault, handler)
                process_dashboard_commands(vault, handler)
            except Exception:
                logging.exception("Main loop error")
            time.sleep(0.8)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    run_engine()