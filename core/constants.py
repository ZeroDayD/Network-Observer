from pathlib import Path
import json
import os

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"

with open(CONFIG_PATH) as f:
    config = json.load(f)

# Config values
TELEGRAM_TOKEN = os.environ.get("NETWORK_OBSERVER_TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("NETWORK_OBSERVER_TELEGRAM_CHAT_ID", "").strip()
STOP_ON_SUCCESS = config.get("stop_on_success", True)
ATTACK_INTERFACE = config.get("attack_interface", "wlan1")
ATTACK_TIMEOUT = config.get("attack_timeout_sec", 360)
MAX_RUNTIME = config.get("max_runtime_sec", 1800)
SKIP_SSIDS = set(config.get("skip_ssids", []))
SKIP_BSSIDS = {bssid.upper() for bssid in config.get("skip_bssids", [])}
ENABLE_NMAP_SCAN = config.get("enable_nmap_scan", False)
MAX_LOG_FILES = config.get("max_log_files", 5)
MAX_LOG_FILE_SIZE_KB = config.get("max_log_file_size_kb", 512)

ENABLE_LLM_ANALYSIS = config.get("enable_llm_analysis", False)
LLM_MODEL = config.get("llm_model", "").strip()

# Hard-coded constants
TARGETS_FILE = BASE_DIR / "data" / "targets.json"
CRACKED_FILE = BASE_DIR / "data" / "cracked.json"
PCAP_FILE = BASE_DIR / "data" / "reaver_output.pcap"
LOG_DIR = BASE_DIR / "logs"
