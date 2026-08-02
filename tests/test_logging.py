import logging
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import utils


class LoggingTests(unittest.TestCase):
    def tearDown(self):
        logging.shutdown()
        for handler in logging.getLogger().handlers[:]:
            logging.getLogger().removeHandler(handler)
            handler.close()

    def test_command_exception_logs_full_command(self):
        command = ["nmcli", "connect", "authorized-test", "password", "private-value"]

        with (
            mock.patch.object(utils.subprocess, "run", side_effect=OSError("failed")),
            self.assertLogs(level=logging.ERROR) as captured,
        ):
            utils.run_cmd(command)

        output = "\n".join(captured.output)
        self.assertIn("private-value", output)

    def test_rotating_logs_are_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            log_directory = Path(temp_directory) / "logs"
            with (
                mock.patch.object(utils, "LOG_DIR", log_directory),
                mock.patch.object(utils, "MAX_LOG_FILES", 3),
                mock.patch.object(utils, "MAX_LOG_FILE_SIZE_KB", 1),
            ):
                utils.setup_logging()
                for index in range(100):
                    logging.debug("line %s %s", index, "x" * 100)

                for handler in logging.getLogger().handlers:
                    handler.flush()

                log_files = sorted(log_directory.glob("log_current.log*"))
                self.assertLessEqual(len(log_files), 3)
                self.assertEqual(stat.S_IMODE(log_directory.stat().st_mode), 0o700)
                for log_file in log_files:
                    self.assertEqual(stat.S_IMODE(log_file.stat().st_mode), 0o600)

                file_handlers = [
                    handler
                    for handler in logging.getLogger().handlers
                    if isinstance(handler, utils.SecureRotatingFileHandler)
                ]
                stream_handlers = [
                    handler
                    for handler in logging.getLogger().handlers
                    if type(handler) is logging.StreamHandler
                ]
                self.assertEqual(file_handlers[0].level, logging.DEBUG)
                self.assertEqual(stream_handlers[0].level, logging.INFO)


if __name__ == "__main__":
    unittest.main()
