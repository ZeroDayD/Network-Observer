import subprocess
import json
import re
import logging
import shlex
import threading
from utils import strip_ansi, terminate_process_group
from constants import SKIP_BSSIDS, SKIP_SSIDS, TARGETS_FILE

MAX_SCAN_TIME = 75  # seconds
MAC_LIKE_TARGET = re.compile(r"^\(?([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\)?$")
TARGET_ROW = re.compile(
    r"^\s*\d+\s+"
    r"(?P<essid>.+?)\s+"
    r"(?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+"
    r"(?P<channel>\d+)\s+"
    r"(?P<encryption>\S+)\s+"
    r"(?P<power>\d+)db"
)


class ScanProcessCleanup:
    """Ensure timeout and normal-exit paths clean a scan process only once."""

    def __init__(self, proc):
        self.proc = proc
        self._lock = threading.Lock()
        self._started = False
        self._finished = threading.Event()

    def run(self):
        with self._lock:
            if self._started:
                wait_for_cleanup = True
            else:
                self._started = True
                wait_for_cleanup = False

        if wait_for_cleanup:
            self._finished.wait()
            return False

        try:
            terminate_process_group(self.proc)
        finally:
            self._finished.set()
        return True


def kill_scan_later(proc, timeout, cleanup):
    def _kill():
        if proc.poll() is None:
            logging.warning(
                "Scan timeout reached (%ss), terminating wifite.",
                timeout,
            )
            cleanup.run()

    timer = threading.Timer(timeout, _kill)
    timer.daemon = True
    timer.start()
    return timer

def parse_wifite_line(line):
    line = strip_ansi(line.strip())
    if not line or not re.match(r"^\s*\d+\s+", line):
        return None

    logging.debug(f"[wifite] {line}")

    match = TARGET_ROW.match(line)
    if not match:
        return None

    essid = match.group("essid").strip()
    bssid = match.group("bssid").upper()
    if MAC_LIKE_TARGET.fullmatch(essid):
        logging.debug("Ignoring MAC-like client row: %s", essid)
        return None
    if essid in SKIP_SSIDS or bssid in SKIP_BSSIDS:
        logging.info("Skipping configured Wi-Fi target: %s", essid)
        return None
    try:
        return {
            "essid": essid,
            "bssid": bssid,
            "channel": int(match.group("channel")),
            "power": int(match.group("power")),
        }
    except ValueError as e:
        logging.debug(f"Failed to extract power for {essid}: {e}")
        return None


def save_targets_to_file(targets):
    try:
        with open(TARGETS_FILE, "w") as f:
            json.dump(targets, f, indent=2)
        logging.info(f"{len(targets)} targets saved to {TARGETS_FILE}")
    except Exception as e:
        logging.error(f"Failed to save targets: {e}")


def scan_targets(interface, timeout=MAX_SCAN_TIME):
    logging.info("Scanning for targets using wifite...")

    proc = None
    cleanup = None
    timeout_timer = None
    try:
        scan_command = shlex.join([
            "wifite",
            "--wps-only",
            "--ignore-locks",
            "--showb",
            "-i",
            interface,
        ])
        proc = subprocess.Popen(
            ["script", "-q", "-c", scan_command, "/dev/null"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            start_new_session=True,
        )

        targets = {}
        cleanup = ScanProcessCleanup(proc)
        timeout_timer = kill_scan_later(proc, timeout, cleanup)

        for line in iter(proc.stdout.readline, ""):
            parsed = parse_wifite_line(line)
            if parsed:
                bssid = parsed["bssid"]
                if bssid not in targets or targets[bssid]["power"] < parsed["power"]:
                    targets[bssid] = parsed

        sorted_targets = sorted(targets.values(), key=lambda target: -target["power"])
        save_targets_to_file(sorted_targets)
        return sorted_targets

    except Exception as e:
        logging.error(f"Failed to scan with wifite: {e}")
        return []
    finally:
        if timeout_timer is not None:
            timeout_timer.cancel()
        if cleanup is not None:
            cleanup.run()
        elif proc is not None:
            terminate_process_group(proc)
