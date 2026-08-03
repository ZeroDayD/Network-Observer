import logging
import subprocess

from constants import ENABLE_LLM_ANALYSIS, LLM_MODEL


def get_llm_attack_insights(nmap_output):
    """Optionally analyze already-collected Nmap output through a local CLI."""
    if not ENABLE_LLM_ANALYSIS:
        return None
    if not LLM_MODEL:
        logging.warning("LLM analysis enabled without an explicit llm_model; skipping.")
        return None

    prompt = f"""Analyze this authorized Nmap scan and summarize the exposed services, likely security risks, and useful defensive validation steps. Keep the response short and evidence-based.

NMAP SCAN RESULTS:
{nmap_output[:3000]}
"""

    try:
        result = subprocess.run(
            ["llm", "-m", LLM_MODEL],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logging.error("LLM CLI failed with exit status %s.", result.returncode)
        return None
    except FileNotFoundError:
        logging.error("LLM CLI not found.")
        return None
    except Exception as error:
        logging.error("LLM analysis failed: %s", error)
        return None
