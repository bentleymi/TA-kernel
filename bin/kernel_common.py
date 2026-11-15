"""Shared collection logic for TA-kernel scripted inputs (crash readiness + crash signals)."""
import json
import os
import re
import subprocess
import sys
import time

STATE_FILE = "/var/tmp/ta_kernel_state.json"
SAME_CYCLE_SECS = 60

KEXEC_CRASH_LOADED = "/sys/kernel/kexec_crash_loaded"
TAINTED_FILE = "/proc/sys/kernel/tainted"
UPTIME_FILE = "/proc/uptime"

OOPS_RE = re.compile(r"oops", re.IGNORECASE)
PANIC_RE = re.compile(r"panic", re.IGNORECASE)
BUG_RE = re.compile(r"\bBUG:|kernel BUG", re.IGNORECASE)
UNREADABLE_MARKERS = ("Permission denied", "Failed to open")
NEW_KEYS = ("oops_new", "panic_new", "bug_new")


def read_file(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _readiness():
    data = {}
    kr = read_file(KEXEC_CRASH_LOADED)
    data["kexec_crash_loaded"] = 1 if kr == "1" else 0
    try:
        p = subprocess.run(["systemctl", "is-active", "kdump"], capture_output=True, text=True, timeout=25)
        data["kdump_active"] = 1 if p.stdout.strip() == "active" else 0
    except (OSError, subprocess.TimeoutExpired):
        data["kdump_active"] = 0
    t = _num(read_file(TAINTED_FILE))
    if t is not None:
        data["tainted"] = int(t)
    up = read_file(UPTIME_FILE)
    if up:
        u = _num(up.split(" ")[0])
        if u is not None:
            data["uptime_s"] = int(u)
    return data


def _query_journal(since_ts):
    """Return (readable, stdout) for kernel journal lines since since_ts (unix seconds)."""
    try:
        p = subprocess.run(
            ["journalctl", "-k", "-q", "--since", "@%d" % int(since_ts)],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    out = p.stdout
    if p.returncode != 0:
        return False, ""
    if any(marker in out or marker in (p.stderr or "") for marker in UNREADABLE_MARKERS):
        return False, ""
    return True, out


def _count_new(text):
    counts = dict((key, 0) for key in NEW_KEYS)
    for line in text.splitlines():
        if OOPS_RE.search(line):
            counts["oops_new"] += 1
        if PANIC_RE.search(line):
            counts["panic_new"] += 1
        if BUG_RE.search(line):
            counts["bug_new"] += 1
    return counts


def _load_state():
    try:
        with open(STATE_FILE) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def _save_state(state):
    try:
        os.makedirs("/var/tmp", exist_ok=True)
        with open(STATE_FILE, "w") as fh:
            json.dump(state, fh)
    except (OSError, TypeError, ValueError):
        pass


def discover():
    data = _readiness()
    data["status"] = "ok"
    state = _load_state()
    last_ts = _num(state.get("ts"))
    if last_ts is None:
        now = int(time.time())
        readable, _ = _query_journal(now)
        journal = dict((key, 0) for key in NEW_KEYS)
        journal["journal_readable"] = 1 if readable else 0
        data["journal"] = journal
        _save_state({"ts": now, "deltas": dict(journal), "journal_readable": journal["journal_readable"]})
        return data
    last_deltas = state.get("deltas")
    if isinstance(last_deltas, dict) and (time.time() - last_ts) < SAME_CYCLE_SECS:
        counts = {}
        for key in NEW_KEYS:
            v = _num(last_deltas.get(key))
            counts[key] = max(0, int(v)) if v is not None else 0
        v = _num(state.get("journal_readable"))
        journal = dict(counts)
        journal["journal_readable"] = int(v) if v is not None else 0
        data["journal"] = journal
    else:
        readable, text = _query_journal(last_ts)
        counts = _count_new(text) if readable else dict((key, 0) for key in NEW_KEYS)
        journal = dict(counts)
        journal["journal_readable"] = 1 if readable else 0
        data["journal"] = journal
        _save_state({"ts": int(time.time()), "deltas": counts, "journal_readable": journal["journal_readable"]})
    if any(data["journal"][key] for key in NEW_KEYS):
        data["status"] = "alarm"
    return data


def metrics_payload(data):
    if not isinstance(data, dict):
        data = {}
    payload = {}
    for key in ("kexec_crash_loaded", "kdump_active", "tainted", "uptime_s"):
        v = _num(data.get(key))
        if v is not None:
            payload[key] = int(v)
    j = data.get("journal")
    if not isinstance(j, dict):
        j = {}
    for key in NEW_KEYS + ("journal_readable",):
        v = _num(j.get(key))
        if v is not None:
            payload[key] = int(v)
    return payload


def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def fail(message):
    sys.stderr.write("TA-kernel collection error: %s\n" % message)
    return 1
