import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import wifi_connect
import wifi_scan


class TargetParsingTests(unittest.TestCase):
    def test_normal_access_point_row_is_parsed(self):
        line = "1 authorized-test 6 WPA-P 72db yes 1"

        self.assertEqual(wifi_scan.parse_wifite_line(line), ("authorized-test", 72))

    def test_parenthesized_mac_client_row_is_ignored(self):
        line = "1 (28:EE:52:D5:E4:FF) 6 WPA-P 99db yes 1"

        self.assertIsNone(wifi_scan.parse_wifite_line(line))

    def test_plain_mac_client_row_is_ignored(self):
        line = "1 28:EE:52:D5:E4:FF 6 WPA-P 99db yes 1"

        self.assertIsNone(wifi_scan.parse_wifite_line(line))


class WifiConnectionTests(unittest.TestCase):
    @mock.patch("wifi_connect.time.sleep")
    @mock.patch("wifi_connect.run_cmd")
    def test_psk_is_preferred_when_pin_is_also_available(self, run_cmd, _sleep):
        run_cmd.side_effect = [
            "",
            "",
            "",
            "",
            "authorized-test",
            "",
            "",
            "",
            "success",
            "inet 192.0.2.2/24",
        ]

        connected = wifi_connect.connect_to_wifi(
            "authorized-test",
            pin="12345670",
            psk="private-psk",
        )

        self.assertTrue(connected)
        connect_command = next(
            call.args[0]
            for call in run_cmd.call_args_list
            if call.args[0][:4] == ["nmcli", "device", "wifi", "connect"]
        )
        password_index = connect_command.index("password") + 1
        self.assertEqual(connect_command[password_index], "private-psk")

    @mock.patch("wifi_connect.run_cmd")
    def test_pin_without_recovered_psk_is_not_used_as_password(self, run_cmd):
        self.assertFalse(
            wifi_connect.connect_to_wifi("authorized-test", pin="12345670")
        )

        run_cmd.assert_not_called()

    @mock.patch("wifi_connect.subprocess.run")
    def test_startup_disconnect_preserves_saved_profiles(self, run):
        run.return_value.stdout = "wlan1:wifi:connected\n"

        wifi_connect.disconnect_all_wifi_devices()

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            commands,
            [
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"],
                ["nmcli", "device", "disconnect", "wlan1"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
