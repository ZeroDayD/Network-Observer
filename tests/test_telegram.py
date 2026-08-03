import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import send_to_telegram


class TelegramFormattingTests(unittest.TestCase):
    def test_cleanup_removes_noise_controls_and_consecutive_duplicates(self):
        message = (
            "\x1b[31mStarting Nmap 7.93\x1b[0m\n"
            "Useful result\x00\n"
            "Useful result\n\n\n"
            "Nmap done: 1 IP address scanned\n"
            "Final line\n"
        )

        self.assertEqual(
            send_to_telegram.clean_message(message),
            "Useful result\n\nFinal line",
        )

    @mock.patch("send_to_telegram.requests.post")
    def test_long_single_line_is_escaped_and_split_within_limit(self, post):
        post.return_value.status_code = 200
        post.return_value.text = "ok"
        message = "<&>" * 5000

        self.assertTrue(send_to_telegram.send_message(message, prefix="<result>"))
        self.assertGreater(post.call_count, 1)
        for call in post.call_args_list:
            payload = call.kwargs["data"]
            self.assertEqual(payload["parse_mode"], "HTML")
            self.assertLessEqual(len(payload["text"]), 4096)
            self.assertIn("&lt;", payload["text"])
            self.assertNotIn("<result>", payload["text"])


if __name__ == "__main__":
    unittest.main()
