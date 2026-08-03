import subprocess
import logging
import ipaddress


def run_nmap_scan(network):
    try:
        logging.info(f"Running nmap scan on local network ({network})...")
        result = subprocess.run(
            ["nmap", "-sV", "-O", "-T4", "-oN", "-", network],
            capture_output=True, text=True, timeout=300
        )
        return result.stdout.strip()
    except Exception as e:
        logging.error(f"Failed to run nmap scan: {e}")
        return None

def get_wifi_network(interface):
    try:
        ip_output = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"],
            text=True,
        )
        for line in ip_output.splitlines():
            fields = line.split()
            if "inet" not in fields:
                continue
            address = fields[fields.index("inet") + 1]
            return str(ipaddress.ip_interface(address).network)
    except Exception as e:
        logging.warning(f"Failed to get IPv4 network of {interface}: {e}")
    return None

def clean_nmap_output(raw_output):
    lines = raw_output.splitlines()
    cleaned_lines = []
    inside_fingerprint = False

    for line in lines:
        if line.startswith("SF-Port"):
            inside_fingerprint = True
            continue
        if inside_fingerprint:
            if line.endswith('");'):
                inside_fingerprint = False
            continue
        if line.strip().startswith("# Nmap scan initiated") or line.strip().startswith("# Nmap done"):
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()
