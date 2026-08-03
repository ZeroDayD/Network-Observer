import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import utils
import wifi_attack
import wifi_scan


class ProcessGroupCleanupTests(unittest.TestCase):
    @mock.patch("wifi_attack.terminate_process_group")
    def test_attack_cleanup_runs_only_once(self, terminate_group):
        proc = mock.Mock()
        cleanup = wifi_attack.ProcessGroupCleanup(proc)

        self.assertTrue(cleanup.run(timeout=360))
        self.assertFalse(cleanup.run())

        terminate_group.assert_called_once_with(proc)

    @mock.patch("wifi_attack.terminate_process_group")
    def test_duplicate_cleanup_waits_for_first_cleanup(self, terminate_group):
        cleanup_started = threading.Event()
        allow_cleanup_to_finish = threading.Event()

        def block_cleanup(_proc):
            cleanup_started.set()
            allow_cleanup_to_finish.wait(timeout=1)

        terminate_group.side_effect = block_cleanup
        cleanup = wifi_attack.ProcessGroupCleanup(mock.Mock())
        first = threading.Thread(target=cleanup.run)
        second = threading.Thread(target=cleanup.run)

        first.start()
        self.assertTrue(cleanup_started.wait(timeout=1))
        second.start()
        self.assertTrue(second.is_alive())
        allow_cleanup_to_finish.set()
        first.join(timeout=1)
        second.join(timeout=1)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        terminate_group.assert_called_once()

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
        _kill_later.return_value.cancel.assert_called_once_with()

    @mock.patch("wifi_attack.terminate_process_group")
    @mock.patch("wifi_attack.kill_proc_later")
    @mock.patch("wifi_attack.subprocess.Popen")
    @mock.patch("wifi_attack.os.chdir")
    def test_attack_targets_specific_bssid(
        self,
        _change_directory,
        popen,
        _kill_later,
        _terminate_group,
    ):
        proc = mock.Mock()
        proc.stdout = []
        popen.return_value = proc

        wifi_attack.attack_target(
            "wlan1",
            "authorized-test",
            bssid="AA:BB:CC:DD:EE:FF",
        )

        command = popen.call_args.args[0]
        self.assertIn("-b", command)
        self.assertEqual(command[command.index("-b") + 1], "AA:BB:CC:DD:EE:FF")
        self.assertNotIn("-e", command)

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
        self.assertIn("--showb", popen.call_args.args[0][3])
        terminate_group.assert_called_once_with(proc)

    @mock.patch("wifi_scan.save_targets_to_file")
    @mock.patch("wifi_scan.subprocess.Popen")
    def test_scan_timeout_does_not_depend_on_stdout_activity(
        self,
        popen,
        _save_targets,
    ):
        output_released = threading.Event()
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.stdout.readline.side_effect = lambda: (
            output_released.wait(timeout=1) and ""
        )
        popen.return_value = proc

        def release_blocked_output(_proc):
            output_released.set()

        started = time.monotonic()
        with mock.patch(
            "wifi_scan.terminate_process_group",
            side_effect=release_blocked_output,
        ) as terminate_group:
            self.assertEqual(wifi_scan.scan_targets("wlan1", timeout=0.02), [])

        self.assertLess(time.monotonic() - started, 0.5)
        terminate_group.assert_called_once_with(proc)

    @mock.patch("wifi_scan.terminate_process_group")
    @mock.patch("wifi_scan.save_targets_to_file")
    @mock.patch("wifi_scan.subprocess.Popen")
    def test_scan_keeps_same_ssid_on_distinct_bssids(
        self,
        popen,
        _save_targets,
        _terminate_group,
    ):
        proc = mock.Mock()
        proc.stdout.readline.side_effect = [
            "1 authorized-test AA:BB:CC:DD:EE:01 6 WPA-P 72db yes 1\n",
            "2 authorized-test AA:BB:CC:DD:EE:02 11 WPA-P 65db yes 0\n",
            "",
        ]
        popen.return_value = proc

        targets = wifi_scan.scan_targets("wlan1")

        self.assertEqual(len(targets), 2)
        self.assertEqual(
            {target["bssid"] for target in targets},
            {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"},
        )


if __name__ == "__main__":
    unittest.main()
