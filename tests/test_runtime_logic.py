import sys
import unittest
from pathlib import Path
from unittest import mock


CORE_DIR = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE_DIR))

import wifi_connect
import wifi_scan
import nmap_scan


class TargetParsingTests(unittest.TestCase):
    def test_normal_access_point_row_is_parsed(self):
        line = "1 authorized-test AA:BB:CC:DD:EE:FF 6 WPA-P 72db yes 1"

        self.assertEqual(
            wifi_scan.parse_wifite_line(line),
            {
                "essid": "authorized-test",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 6,
                "power": 72,
            },
        )

    def test_parenthesized_mac_client_row_is_ignored(self):
        line = "1 (28:EE:52:D5:E4:FF) 28:EE:52:D5:E4:FF 6 WPA-P 99db yes 1"

        self.assertIsNone(wifi_scan.parse_wifite_line(line))

    def test_plain_mac_client_row_is_ignored(self):
        line = "1 28:EE:52:D5:E4:FF 28:EE:52:D5:E4:FF 6 WPA-P 99db yes 1"

        self.assertIsNone(wifi_scan.parse_wifite_line(line))

    def test_configured_bssid_is_skipped_exactly(self):
        line = "1 authorized-test AA:BB:CC:DD:EE:FF 6 WPA-P 72db yes 1"

        with mock.patch.object(wifi_scan, "SKIP_BSSIDS", {"AA:BB:CC:DD:EE:FF"}):
            self.assertIsNone(wifi_scan.parse_wifite_line(line))

    def test_configured_ssid_does_not_skip_partial_match(self):
        line = "1 authorized-test-guest AA:BB:CC:DD:EE:FF 6 WPA-P 72db yes 1"

        with mock.patch.object(wifi_scan, "SKIP_SSIDS", {"authorized-test"}):
            self.assertIsNotNone(wifi_scan.parse_wifite_line(line))


class WifiConnectionTests(unittest.TestCase):
    @mock.patch("wifi_connect.time.sleep")
    @mock.patch("wifi_connect.run_cmd")
    def test_psk_is_preferred_when_pin_is_also_available(self, run_cmd, _sleep):
        run_cmd.side_effect = [
            "",
            "",
            "",
            "",
            "AA:BB:CC:DD:EE:FF",
            "",
            "",
            "",
            "success",
            "inet 192.0.2.2/24",
        ]

        connected = wifi_connect.connect_to_wifi(
            "authorized-test",
            bssid="AA:BB:CC:DD:EE:FF",
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
        self.assertEqual(connect_command[4], "AA:BB:CC:DD:EE:FF")

    @mock.patch("wifi_connect.time.sleep")
    @mock.patch("wifi_connect.run_cmd")
    def test_pin_is_used_when_psk_is_unavailable(self, run_cmd, _sleep):
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
        )

        self.assertTrue(connected)
        connect_command = next(
            call.args[0]
            for call in run_cmd.call_args_list
            if call.args[0][:4] == ["nmcli", "device", "wifi", "connect"]
        )
        password_index = connect_command.index("password") + 1
        self.assertEqual(connect_command[password_index], "12345670")

    @mock.patch("wifi_connect.subprocess.run")
    def test_startup_reset_deletes_only_saved_wireless_profiles(self, run):
        device_result = mock.Mock(stdout="wlan1:wifi:connected\neth0:ethernet:connected\n")
        connection_result = mock.Mock(
            stdout=(
                "wifi-uuid:802-11-wireless\n"
                "ethernet-uuid:802-3-ethernet\n"
            )
        )
        run.side_effect = [
            device_result,
            mock.Mock(),
            connection_result,
            mock.Mock(),
        ]

        wifi_connect.disconnect_all_wifi_devices()

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            commands,
            [
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"],
                ["nmcli", "device", "disconnect", "wlan1"],
                ["nmcli", "-t", "-f", "UUID,TYPE", "connection", "show"],
                ["nmcli", "connection", "delete", "uuid", "wifi-uuid"],
            ],
        )

    @mock.patch("wifi_connect.time.sleep")
    @mock.patch("wifi_connect.run_cmd")
    def test_ssid_detection_does_not_accept_substring_match(self, run_cmd, _sleep):
        run_cmd.side_effect = ["", "", "", ""] + ["authorized-test-guest"] * 15

        self.assertFalse(
            wifi_connect.connect_to_wifi("authorized-test", psk="private-psk")
        )


class NmapNetworkTests(unittest.TestCase):
    @mock.patch("nmap_scan.subprocess.check_output")
    def test_interface_prefix_is_preserved(self, check_output):
        check_output.return_value = (
            "7: wlan1    inet 192.0.2.130/25 brd 192.0.2.255 scope global wlan1\n"
        )

        self.assertEqual(nmap_scan.get_wifi_network("wlan1"), "192.0.2.128/25")

    @mock.patch("nmap_scan.subprocess.run")
    def test_nmap_receives_calculated_network(self, run):
        run.return_value.stdout = "scan"

        self.assertEqual(nmap_scan.run_nmap_scan("192.0.2.128/25"), "scan")
        self.assertEqual(run.call_args.args[0][-1], "192.0.2.128/25")


if __name__ == "__main__":
    unittest.main()
