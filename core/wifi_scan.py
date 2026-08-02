import subprocess
import time
import json
import re
import logging
from utils import strip_ansi, terminate_process_group
from constants import TARGETS_FILE

MAX_SCAN_TIME = 75  # seconds

def parse_wifite_line(line):
    line = strip_ansi(line.strip())
    if not line or not re.match(r"^\s*\d+\s+", line):
        return None

    logging.debug(f"[wifite] {line}")

    regex = re.compile(
        r"^\s*\d+\s+(?P<essid>.+?)\s+(?P<ch>\d+)\s+(?P<enc>\S+)\s+(?P<pwr>\d+)db"
    )
    match = regex.match(line)
    if not match:
        return None

    essid = match.group("essid").strip()
    try:
        power = int(match.group("pwr"))
        return essid, power
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


def scan_targets(interface):
    logging.info("Scanning for targets using wifite...")

    proc = None
    try:
        proc = subprocess.Popen(
            ["script", "-q", "-c", f"wifite --wps-only --ignore-locks -i {interface}", "/dev/null"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            start_new_session=True,
        )

        targets = {}
        start_time = time.monotonic()

        for line in iter(proc.stdout.readline, ""):
            if time.monotonic() - start_time > MAX_SCAN_TIME:
                logging.warning(f"Scan timeout reached ({MAX_SCAN_TIME}s), terminating wifite.")
                break

            parsed = parse_wifite_line(line)
            if parsed:
                essid, power = parsed
                if essid not in targets or targets[essid] < power:
                    targets[essid] = power

        sorted_targets = sorted(targets.items(), key=lambda x: -x[1])
        save_targets_to_file(sorted_targets)
        return sorted_targets

    except Exception as e:
        logging.error(f"Failed to scan with wifite: {e}")
        return []
    finally:
        if proc is not None:
            terminate_process_group(proc)
