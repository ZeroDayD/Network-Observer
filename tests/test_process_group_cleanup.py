import signal
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import utils
import wifi_attack
import wifi_scan


class ProcessGroupCleanupTests(unittest.TestCase):
    @mock.patch("utils._signal_process_group")
    def test_terminate_process_group_uses_sigterm_when_group_exits(self, signal_group):
        proc = mock.Mock(pid=1234)
        signal_group.side_effect = [True, False]

        utils.terminate_process_group(proc)

        self.assertEqual(
            signal_group.call_args_list,
            [mock.call(1234, signal.SIGTERM), mock.call(1234, 0)],
        )
        proc.wait.assert_called_once_with(timeout=5)

    @mock.patch("utils._signal_process_group")
    def test_terminate_process_group_kills_lingering_descendants(self, signal_group):
        proc = mock.Mock(pid=4321)
        signal_group.side_effect = [True, True, True]

        utils.terminate_process_group(proc)

        self.assertEqual(
            signal_group.call_args_list,
            [
                mock.call(4321, signal.SIGTERM),
                mock.call(4321, 0),
                mock.call(4321, signal.SIGKILL),
            ],
        )

    @mock.patch("utils._signal_process_group")
    def test_terminate_process_group_escalates_when_parent_ignores_sigterm(self, signal_group):
        proc = mock.Mock(pid=9876)
        proc.wait.side_effect = [subprocess.TimeoutExpired("wifite", 5), None]
        signal_group.return_value = True

        utils.terminate_process_group(proc)

        self.assertEqual(
            signal_group.call_args_list,
            [mock.call(9876, signal.SIGTERM), mock.call(9876, signal.SIGKILL)],
        )

    @mock.patch("wifi_attack.terminate_process_group")
    @mock.patch("wifi_attack.kill_proc_later")
    @mock.patch("wifi_attack.subprocess.Popen")
    @mock.patch("wifi_attack.os.chdir")
    def test_attack_starts_wifite_in_new_session(
        self,
        _change_directory,
        popen,
        _kill_later,
        terminate_group,
    ):
        proc = mock.Mock()
        proc.stdout = []
        popen.return_value = proc

        self.assertIsNone(wifi_attack.attack_target("wlan1", "authorized-test"))

        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        terminate_group.assert_called_once_with(proc)

    @mock.patch("wifi_scan.terminate_process_group")
    @mock.patch("wifi_scan.save_targets_to_file")
    @mock.patch("wifi_scan.subprocess.Popen")
    def test_scan_starts_wifite_in_new_session(
        self,
        popen,
        _save_targets,
        terminate_group,
    ):
        proc = mock.Mock()
        proc.stdout.readline.return_value = ""
        popen.return_value = proc

        self.assertEqual(wifi_scan.scan_targets("wlan1"), [])

        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        terminate_group.assert_called_once_with(proc)


if __name__ == "__main__":
    unittest.main()
