import os
import subprocess
import re
import logging
import signal
from logging.handlers import RotatingFileHandler
from constants import (MAX_LOG_FILES, MAX_LOG_FILE_SIZE_KB, LOG_DIR)


class SecureRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        file_descriptor = os.open(
            self.baseFilename,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        return os.fdopen(
            file_descriptor,
            self.mode,
            encoding=self.encoding,
            errors=self.errors,
        )


def setup_logging():
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
    os.chmod(LOG_DIR, 0o700)

    log_file = os.path.join(LOG_DIR, "log_current.log")
    retained_file_count = max(2, int(MAX_LOG_FILES))
    max_log_bytes = max(1, int(MAX_LOG_FILE_SIZE_KB)) * 1024

    file_handler = SecureRotatingFileHandler(
        log_file,
        maxBytes=max_log_bytes,
        backupCount=retained_file_count - 1,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)

    journal_handler = logging.StreamHandler()
    journal_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    journal_handler.setFormatter(formatter)

    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, journal_handler],
        force=True,
    )

    # Legacy indexed logs are retained for manual review, but their historical
    # sensitive contents should no longer be world-readable.
    for legacy_log in os.listdir(LOG_DIR):
        if legacy_log.startswith("log_") and legacy_log.endswith(".log"):
            try:
                os.chmod(os.path.join(LOG_DIR, legacy_log), 0o600)
            except OSError as error:
                logging.warning("Failed to restrict legacy log %s: %s", legacy_log, error)


def redact_sensitive_text(text):
    patterns = (
        (r"(?i)(WPS\s+PIN\s*:\s*)\S+", r"\1<redacted>"),
        (r"(?i)(WPA\s+PSK\s*:\s*)\S+", r"\1<redacted>"),
        (r"(?i)(PSK/Password\s*:\s*)\S+", r"\1<redacted>"),
        (r"(?i)(Password\s*:\s*)\S+", r"\1<redacted>"),
    )
    redacted = str(text)
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def redact_command(cmd):
    redacted = []
    hide_next_argument = False
    for argument in cmd:
        argument_text = str(argument)
        if hide_next_argument:
            redacted.append("<redacted>")
            hide_next_argument = False
            continue
        redacted.append(argument_text)
        if argument_text.lower() in {"password", "passwd", "psk", "pin"}:
            hide_next_argument = True
    return redacted


def run_cmd(cmd):
    safe_command = redact_command(cmd)
    logging.debug(f"Running command: {' '.join(safe_command)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        logging.debug(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            logging.debug(f"Command error output: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        logging.error(
            "Exception while running command %s: %s",
            " ".join(safe_command),
            e,
        )
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
