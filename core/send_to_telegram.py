import logging
import requests
from constants import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

MAX_TELEGRAM_MESSAGE_LENGTH = 4000

def send_message(message, prefix="[nmap scan result]"):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.error("Missing 'telegram_token' or 'chat_id' in config.json")
        return

    def send_chunk(chunk):
        formatted = f"{prefix}\n```{chunk}```"
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": formatted,
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                logging.info("Message sent to Telegram.")
            else:
                logging.error(f"Failed to send message. HTTP {response.status_code}: {response.text}")
        except Exception as e:
            # requests exceptions can include the request URL, which contains
            # the bot token for Telegram API calls.
            safe_error = str(e).replace(TELEGRAM_TOKEN, "<redacted>")
            logging.exception("Exception while sending Telegram message: %s", safe_error)

    if len(f"{prefix}\n```{message}```") <= 4096:
        send_chunk(message)
    else:
        current_chunk = ""
        for line in message.splitlines():
            if len(f"{current_chunk}\n{line}") > MAX_TELEGRAM_MESSAGE_LENGTH:
                send_chunk(current_chunk)
                current_chunk = line
            else:
                current_chunk += f"\n{line}"
        if current_chunk.strip():
            send_chunk(current_chunk)
