"""
restart_engine.py - Purane Mini-EDR engine ko band kar ke nayi edr_engine.py se start karta hai.

Usage (project folder mein, jahan edr_engine.py hai):
    python restart_engine.py            -> normal user engine (hidden window)
    python restart_engine.py --admin    -> UAC prompt ke saath Admin engine (Tier-1 VSS)
    python restart_engine.py --visible  -> console window ke saath (debug prints dekhne ke liye)
"""
import os
import sys
import time
import ctypes
import subprocess
import psutil
import db_manager as db

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ENGINE_SCRIPT = os.path.join(BASE_DIR, "edr_engine.py")
ENGINE_PORT = 47651


def find_engine_pids():
    """Sab python processes jinki cmdline mein edr_engine.py hai (is script ko chhor kar)."""
    me = os.getpid()
    pids = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            if proc.info["pid"] == me:
                continue
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            if "edr_engine.py" in cmd:
                pids.append(proc.info["pid"])
        except Exception:
            continue
    return pids


def stop_old_engine():
    db.init_db()
    old = find_engine_pids()
    recorded = int(db.get_setting("engine_pid", "0") or 0)
    if recorded and psutil.pid_exists(recorded) and recorded not in old:
        old.append(recorded)

    if not old:
        print("[*] Koi purana engine nahi chal raha.")
        return

    print(f"[*] Purana engine mila: PID {old}. Graceful shutdown bhej raha hon...")
    db.send_command("SHUTDOWN_ENGINE")
    t0 = time.time()
    while time.time() - t0 < 6 and any(psutil.pid_exists(p) for p in old):
        time.sleep(0.25)

    for pid in old:
        if psutil.pid_exists(pid):
            print(f"[!] PID {pid} abhi bhi zinda hai, force kill kar raha hon...")
            try:
                psutil.Process(pid).kill()
            except Exception as e:
                print(f"    kill fail: {e}  (admin engine ho to is script ko Administrator terminal se chalao)")

    time.sleep(0.8)
    left = [p for p in old if psutil.pid_exists(p)]
    if left:
        print(f"[X] Engine PID {left} band nahi hua. Administrator terminal se dobara chalao.")
        sys.exit(1)
    print("[+] Purana engine band ho gaya.")


def clear_stale_state():
    # Purane SHUTDOWN commands jo pending reh gaye ho, unhe dobara execute hone se bachao
    db.execute_write("UPDATE commands SET status='DONE' WHERE status='PENDING'")
    db.set_setting("engine_heartbeat", "0")
    db.set_setting("engine_pid", "0")
    db.set_setting("engine_busy", "0")
    db.set_setting("engine_launching_until", str(time.time() + 60))


def start_new_engine(as_admin=False, visible=False):
    if as_admin and os.name == "nt":
        print("[*] Admin engine start ho raha hai (UAC prompt aayega)...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{ENGINE_SCRIPT}"', BASE_DIR, 1 if visible else 0)
        return
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_CONSOLE if visible else subprocess.CREATE_NO_WINDOW
    subprocess.Popen([sys.executable, ENGINE_SCRIPT], cwd=BASE_DIR, creationflags=flags)
    print("[*] Naya engine launch kar diya.")


def wait_until_alive(timeout=40):
    print("[*] Heartbeat ka intezar (vault backup / VSS mein thora time lagta hai)...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        hb = float(db.get_setting("engine_heartbeat", "0") or 0)
        pid = int(db.get_setting("engine_pid", "0") or 0)
        if hb and (time.time() - hb) < 5 and pid and psutil.pid_exists(pid):
            admin = db.get_setting("engine_is_admin", "0") == "1"
            print(f"[+] Naya engine alive hai. PID: {pid} | Admin: {admin}")
            db.set_setting("engine_launching_until", "0")
            return True
        time.sleep(0.5)
    print("[X] Engine heartbeat nahi aaya. engine.log check karo, ya --visible se chalao.")
    return False


if __name__ == "__main__":
    if not os.path.exists(ENGINE_SCRIPT):
        print(f"[X] edr_engine.py nahi mili: {ENGINE_SCRIPT}")
        sys.exit(1)
    args = set(sys.argv[1:])
    stop_old_engine()
    clear_stale_state()
    start_new_engine(as_admin="--admin" in args, visible="--visible" in args)
    ok = wait_until_alive()
    sys.exit(0 if ok else 1)    