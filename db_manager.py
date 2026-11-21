import sqlite3
import os
import time
import threading
import logging
from datetime import datetime
import pandas as pd

# Silence harmless Windows asyncio websocket reset logs
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "mini_edr.db")
VAULT_DIR = os.path.join(BASE_DIR, "MiniEDR_Backup_Vault")

_local = threading.local()
_write_lock = threading.Lock()


def _is_lock_error(e):
    msg = str(e).lower()
    return "locked" in msg or "busy" in msg


def _create_connection():
    """
    Creates an SQLite connection in native Autocommit mode (isolation_level=None)
    so Python never holds an implicit transaction lock open across calls.
    """
    conn = sqlite3.connect(
        DB_PATH,
        timeout=60.0,
        isolation_level=None,
        check_same_thread=False
    )
    conn.execute("PRAGMA busy_timeout=60000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_conn():
    """
    Legacy helper. Prefer read_df() for dashboard reads (no leaked connections).
    """
    old_conn = getattr(_local, "conn", None)
    if old_conn is not None:
        try:
            old_conn.close()
        except Exception:
            pass
    _local.conn = _create_connection()
    return _local.conn


def read_df(query, params=()):
    """
    Runs a SELECT in a short-lived connection and always closes it.
    Returns an empty DataFrame on any failure so the UI never crashes.
    """
    conn = None
    try:
        conn = _create_connection()
        return pd.read_sql_query(query, conn, params=params)
    except Exception as e:
        logging.error(f"read_df error: {e}")
        return pd.DataFrame()
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def execute_write(query, params=(), many=False):
    """
    Executes write operations in a short-lived, self-closing connection with
    automatic rollback on failure so the database can never stay locked.
    """
    with _write_lock:
        for attempt in range(6):
            conn = None
            try:
                conn = _create_connection()
                if many:
                    conn.execute("BEGIN IMMEDIATE;")
                    conn.executemany(query, params)
                    conn.execute("COMMIT;")
                else:
                    conn.execute(query, params)
                return True
            except sqlite3.OperationalError as e:
                if conn is not None:
                    try:
                        conn.execute("ROLLBACK;")
                    except Exception:
                        pass
                if _is_lock_error(e) and attempt < 5:
                    time.sleep(0.15 * (attempt + 1))
                else:
                    logging.error(f"SQLite write error: {e}")
                    return False
            except BaseException:
                if conn is not None:
                    try:
                        conn.execute("ROLLBACK;")
                    except Exception:
                        pass
                raise
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
    return False


def init_db():
    for attempt in range(6):
        conn = None
        try:
            conn = _create_connection()
            conn.execute("PRAGMA journal_mode=WAL;")
            c = conn.cursor()

            # Auto-migrate alerts table if missing 'disposition'
            c.execute("PRAGMA table_info(alerts)")
            a_cols = [row[1] for row in c.fetchall()]
            if a_cols and "disposition" not in a_cols:
                c.execute("DROP TABLE IF EXISTS alerts")

            # Auto-migrate vault_metadata table if missing 'orig_size' or 'comp_size'
            c.execute("PRAGMA table_info(vault_metadata)")
            v_cols = [row[1] for row in c.fetchall()]
            if v_cols and ("orig_size" not in v_cols or "comp_size" not in v_cols):
                c.execute("DROP TABLE IF EXISTS vault_metadata")

            c.execute('''CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                file_path TEXT,
                old_entropy REAL,
                new_entropy REAL,
                delta_entropy REAL
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                process_name TEXT,
                pid INTEGER,
                disposition TEXT,
                reason TEXT,
                affected_files INTEGER,
                recovery_method TEXT,
                recovery_details TEXT,
                detection_time_ms REAL,
                restore_time_ms REAL
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT,
                exe_path TEXT,
                sha256_hash TEXT UNIQUE,
                require_signature INTEGER DEFAULT 1
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS vault_metadata (
                file_path TEXT PRIMARY KEY,
                entropy REAL,
                header_hex TEXT,
                sha256_hash TEXT,
                orig_size INTEGER DEFAULT 0,
                comp_size INTEGER DEFAULT 0,
                updated_at TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cmd TEXT,
                status TEXT DEFAULT 'PENDING',
                result TEXT DEFAULT '',
                created_at TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')

            defaults = [
                ("speed_limit_files", "4"),
                ("speed_window_sec", "5"),
                ("entropy_delta_threshold", "0.8"),
                ("absolute_high_entropy", "7.2"),
                ("system_status", "SECURE"),
                ("monitored_files_count", "0"),
                ("vault_size_kb", "0.0"),
                ("vault_orig_kb", "0.0"),
                ("vault_comp_kb", "0.0"),
                ("vault_savings_pct", "0.0"),
                ("engine_cpu", "0.0"),
                ("engine_ram_mb", "0.0"),
                ("engine_pid", "0"),
                ("engine_heartbeat", "0"),
                ("dashboard_pid", "0"),
                ("engine_launching_until", "0"),
                ("last_unrecovered", ""),
                ("engine_busy", "0"),
                ("vss_status", "Level 2 Compressed Vault Active"),
                ("vss_last_test", "Never Run")
            ]
            # Autocommit mode: a single executemany is enough (no BEGIN IMMEDIATE needed)
            c.executemany("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", defaults)
            return
        except sqlite3.OperationalError as e:
            if _is_lock_error(e) and attempt < 5:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


def get_setting(key, default=None):
    conn = None
    try:
        conn = _create_connection()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        return row[0] if row else default
    except Exception:
        return default
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def set_setting(key, value):
    execute_write("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))


def set_settings_batch(settings_dict):
    data = [(k, str(v)) for k, v in settings_dict.items()]
    execute_write("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", data, many=True)


def log_events_batch(events_list):
    if not events_list:
        return
    execute_write(
        '''INSERT INTO file_events 
           (timestamp, event_type, file_path, old_entropy, new_entropy, delta_entropy) 
           VALUES (?, ?, ?, ?, ?, ?)''',
        events_list,
        many=True
    )
    execute_write(
        '''DELETE FROM file_events WHERE id NOT IN (
               SELECT id FROM file_events ORDER BY id DESC LIMIT 5000
           )'''
    )


def log_alert(process_name, pid, disposition, reason, affected_files, recovery_method, recovery_details, det_ms, res_ms):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    saved = False
    for attempt in range(3):
        saved = execute_write(
            '''INSERT INTO alerts 
               (timestamp, process_name, pid, disposition, reason, affected_files, recovery_method, recovery_details, detection_time_ms, restore_time_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (now, process_name, pid, disposition, reason, affected_files, recovery_method, recovery_details, round(det_ms, 2), round(res_ms, 2))
        )
        if saved:
            break
        time.sleep(0.4 * (attempt + 1))
    if not saved:
        logging.error("log_alert: failed to persist alert after 3 attempts")

    if disposition == "killed":
        set_setting("system_status", "ATTACK BLOCKED — PROCESS TERMINATED & FILES RESTORED")
    else:
        set_setting("system_status", "ATTACK CONTAINED — ALL DAMAGED FILES RESTORED")


def upsert_vault_meta(file_path, entropy, header_bytes, sha256_hash, orig_size=0, comp_size=0):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hdr_hex = header_bytes.hex() if isinstance(header_bytes, (bytes, bytearray)) else str(header_bytes)
    execute_write(
        '''INSERT OR REPLACE INTO vault_metadata 
           (file_path, entropy, header_hex, sha256_hash, orig_size, comp_size, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (os.path.abspath(file_path), round(float(entropy), 4), hdr_hex, sha256_hash, int(orig_size), int(comp_size), now)
    )


def delete_vault_meta(file_path):
    execute_write("DELETE FROM vault_metadata WHERE file_path=?", (os.path.abspath(file_path),))


def get_all_vault_meta():
    conn = None
    try:
        conn = _create_connection()
        c = conn.cursor()
        c.execute("SELECT file_path, entropy, header_hex, sha256_hash FROM vault_metadata")
        rows = c.fetchall()
        result = {}
        for fp, ent, h_hex, sha in rows:
            result[fp] = (float(ent), bytes.fromhex(h_hex) if h_hex else b"", sha)
        return result
    except Exception:
        return {}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def update_vault_storage_metrics(vault_dir=None):
    conn = None
    try:
        conn = _create_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*), COALESCE(SUM(orig_size), 0), COALESCE(SUM(comp_size), 0) FROM vault_metadata")
        count, total_orig, total_comp = c.fetchone()
    except Exception:
        return
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    target_vault = vault_dir or VAULT_DIR
    if total_comp == 0 and os.path.exists(target_vault):
        for root, _, files in os.walk(target_vault):
            for f in files:
                fp = os.path.join(root, f)
                if os.path.exists(fp):
                    total_comp += os.path.getsize(fp)

    orig_kb = total_orig / 1024.0
    comp_kb = total_comp / 1024.0
    savings_pct = ((1.0 - (total_comp / total_orig)) * 100.0) if total_orig > 0 else 0.0

    set_settings_batch({
        "monitored_files_count": str(count),
        "vault_size_kb": f"{comp_kb:.1f}",
        "vault_orig_kb": f"{orig_kb:.1f}",
        "vault_comp_kb": f"{comp_kb:.1f}",
        "vault_savings_pct": f"{max(0.0, savings_pct):.1f}"
    })


def is_whitelisted_hash(sha256_hash):
    conn = None
    try:
        conn = _create_connection()
        c = conn.cursor()
        c.execute("SELECT require_signature FROM whitelist WHERE sha256_hash=?", (sha256_hash,))
        return c.fetchone()
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def send_command(cmd_name):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    execute_write("INSERT INTO commands (cmd, status, created_at) VALUES (?, 'PENDING', ?)", (cmd_name, now))


def fetch_pending_commands():
    conn = None
    try:
        conn = _create_connection()
        c = conn.cursor()
        c.execute("SELECT id, cmd FROM commands WHERE status='PENDING' ORDER BY id ASC")
        return c.fetchall()
    except Exception:
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def complete_command(cmd_id, result_text):
    execute_write("UPDATE commands SET status='DONE', result=? WHERE id=?", (result_text, cmd_id))