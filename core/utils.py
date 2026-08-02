import os
import subprocess
import re
import logging
import signal
from constants import (MAX_LOG_FILES, LOG_DIR)

def setup_logging():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    # find the last log file index
    existing_logs = [
        f for f in os.listdir(LOG_DIR)
        if f.startswith("log_") and f.endswith(".log")
    ]
    if existing_logs:
        existing_logs.sort()
        last_log = existing_logs[-1]
        try:
            last_index = int(last_log.split("_")[1].split(".")[0])
        except (IndexError, ValueError):
            last_index = -1
    else:
        last_index = -1

    next_index = last_index + 1
    log_file = os.path.join(LOG_DIR, f"log_{next_index}.log")

    # remove old logs if we exceed the maximum number
    while len(existing_logs) >= MAX_LOG_FILES:
        oldest = existing_logs.pop(0)
        try:
            os.remove(os.path.join(LOG_DIR, oldest))
        except Exception as e:
            print(f"Failed to delete old log {oldest}: {e}")

    # configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


def run_cmd(cmd):
    logging.debug(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        logging.debug(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            logging.debug(f"Command error output: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        logging.error(f"Exception while running command {' '.join(cmd)}: {e}")
        return ""


def clean_files(*files):
    for f in files:
        try:
            if os.path.exists(f):
                os.remove(f)
                logging.debug(f"Removed file: {f}")
        except Exception as e:
            logging.warning(f"Failed to remove {f}: {e}")


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _signal_process_group(process_group_id, signal_number):
    try:
        os.killpg(process_group_id, signal_number)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as error:
        logging.error(
            "Unable to signal process group %s: %s",
            process_group_id,
            error,
        )
        return False


def terminate_process_group(proc, grace_period=5):
    """Terminate a subprocess and every descendant in its process group."""
    process_group_id = proc.pid
    if not _signal_process_group(process_group_id, signal.SIGTERM):
        return

    try:
        proc.wait(timeout=grace_period)
    except subprocess.TimeoutExpired:
        logging.warning(
            "Process group %s did not stop after %ss; sending SIGKILL.",
            process_group_id,
            grace_period,
        )
        _signal_process_group(process_group_id, signal.SIGKILL)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            logging.error("Process group %s did not exit after SIGKILL.", process_group_id)
        return

    # The parent may exit before tools spawned by Wifite. Because every Wifite
    # invocation starts a new session, its PID is also the stable process-group
    # ID and can still be used to remove those remaining descendants.
    if _signal_process_group(process_group_id, 0):
        logging.warning(
            "Process group %s still has descendants; sending SIGKILL.",
            process_group_id,
        )
        _signal_process_group(process_group_id, signal.SIGKILL)

def is_ssh_connected():
    try:
        output = subprocess.check_output(["who"]).decode()
        return any("pts/" in line and "(" in line for line in output.splitlines())
    except Exception:
        return False

def shutdown_device():
    try:
        subprocess.call(["sudo", "shutdown", "now"])
    except Exception as e:
        logging.error(f"Shutdown failed: {e}")

def has_internet():
    try:
        subprocess.check_call(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False
