import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import main


class MainWorkflowTests(unittest.TestCase):
    @mock.patch("main.send_message")
    @mock.patch("main.connect_to_wifi", return_value=True)
    @mock.patch("main.attack_target", return_value={"psk": "private-psk"})
    @mock.patch("main.scan_targets")
    @mock.patch("main.clean_files")
    @mock.patch("main.disconnect_all_wifi_devices")
    def test_bssid_flows_from_scan_to_attack_and_connection(
        self,
        reset_wifi,
        _clean_files,
        scan_targets,
        attack_target,
        connect_to_wifi,
        _send_message,
    ):
        scan_targets.return_value = [
            {
                "essid": "authorized-test",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 6,
                "power": 72,
            }
        ]

        with (
            mock.patch.object(main, "STOP_ON_SUCCESS", True),
            mock.patch.object(main, "ENABLE_NMAP_SCAN", False),
        ):
            main.run_workflow()

        reset_wifi.assert_called_once_with()
        attack_target.assert_called_once_with(
            main.ATTACK_INTERFACE,
            "authorized-test",
            bssid="AA:BB:CC:DD:EE:FF",
        )
        connect_to_wifi.assert_called_once_with(
            "authorized-test",
            bssid="AA:BB:CC:DD:EE:FF",
            pin=None,
            psk="private-psk",
        )


if __name__ == "__main__":
    unittest.main()
