import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import constants


class EnvironmentConfigurationTests(unittest.TestCase):
    def tearDown(self):
        with mock.patch.dict(
            os.environ,
            {
                "NETWORK_OBSERVER_TELEGRAM_TOKEN": "",
                "NETWORK_OBSERVER_TELEGRAM_CHAT_ID": "",
            },
        ):
            importlib.reload(constants)

    def test_telegram_settings_are_loaded_from_environment(self):
        with mock.patch.dict(
            os.environ,
            {
                "NETWORK_OBSERVER_TELEGRAM_TOKEN": "test-token",
                "NETWORK_OBSERVER_TELEGRAM_CHAT_ID": "test-chat",
            },
        ):
            importlib.reload(constants)

        self.assertEqual(constants.TELEGRAM_TOKEN, "test-token")
        self.assertEqual(constants.TELEGRAM_CHAT_ID, "test-chat")


if __name__ == "__main__":
    unittest.main()
