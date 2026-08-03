import html
import logging
import re

import requests

from constants import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID


TELEGRAM_MESSAGE_LIMIT = 4096
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TOOL_NOISE = (
    re.compile(r"^Starting Nmap \d", re.IGNORECASE),
    re.compile(r"^Nmap done:", re.IGNORECASE),
    re.compile(r"^Service detection performed\.", re.IGNORECASE),
    re.compile(r"^Please report any incorrect results", re.IGNORECASE),
)


def clean_message(message):
    """Remove terminal/tool noise without removing useful result content."""
    text = ANSI_ESCAPE.sub("", str(message).replace("\r\n", "\n").replace("\r", "\n"))
    text = CONTROL_CHARACTERS.sub("", text)

    cleaned_lines = []
    previous_content = None
    previous_was_blank = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if any(pattern.search(line.strip()) for pattern in TOOL_NOISE):
            continue

        if not line.strip():
            if cleaned_lines and not previous_was_blank:
                cleaned_lines.append("")
            previous_was_blank = True
            continue

        normalized = line.strip()
        if normalized == previous_content:
            continue
        cleaned_lines.append(line)
        previous_content = normalized
        previous_was_blank = False

    return "\n".join(cleaned_lines).strip()


def _escaped_chunks(message, escaped_prefix):
    wrapper_size = len(escaped_prefix) + len("\n<pre></pre>")
    chunk_budget = TELEGRAM_MESSAGE_LIMIT - wrapper_size
    if chunk_budget <= 0:
        raise ValueError("Telegram message prefix is too long")

    current = []
    current_size = 0
    for character in message:
        escaped_character = html.escape(character)
        if current and current_size + len(escaped_character) > chunk_budget:
            yield "".join(current)
            current = []
            current_size = 0
        current.append(escaped_character)
        current_size += len(escaped_character)

    if current:
        yield "".join(current)


def send_message(message, prefix="[nmap scan result]"):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.error("Missing Telegram settings in the service environment.")
        return False

    cleaned_message = clean_message(message)
    if not cleaned_message:
        logging.info("Telegram message is empty after cleanup; skipping.")
        return False

    escaped_prefix = html.escape(clean_message(prefix))
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    all_chunks_sent = True

    try:
        chunks = _escaped_chunks(cleaned_message, escaped_prefix)
        for escaped_chunk in chunks:
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": f"{escaped_prefix}\n<pre>{escaped_chunk}</pre>",
                "parse_mode": "HTML",
            }
            try:
                response = requests.post(url, data=payload, timeout=10)
                if response.status_code == 200:
                    logging.info("Message sent to Telegram.")
                else:
                    all_chunks_sent = False
                    logging.error(
                        "Failed to send message. HTTP %s: %s",
                        response.status_code,
                        response.text,
                    )
            except Exception as error:
                all_chunks_sent = False
                safe_error = str(error).replace(TELEGRAM_TOKEN, "<redacted>")
                logging.exception(
                    "Exception while sending Telegram message: %s",
                    safe_error,
                )
    except ValueError as error:
        logging.error("Cannot format Telegram message: %s", error)
        return False

    return all_chunks_sent
