# Network Observer

A lightweight automated tool for wireless network reconnaissance and WPS-based attacks using [Wifite2](https://github.com/kimocoder/wifite2) on headless devices like Raspberry Pi Zero.

> ⚠️ **Educational Use Only**  
> This project is intended strictly for cybersecurity research, education, and authorized testing of networks you own or have explicit permission to audit. Any misuse is strongly discouraged and entirely your responsibility.

---

## Features

- Passive Wi-Fi scan for nearby access points
- Target filtering based on signal strength
- WPS PIN/PSK attacks using [Wifite2](https://github.com/kimocoder/wifite2) internal logic
- Automatic connection to compromised networks
- Telegram alert with credentials (PSK or WPS PIN)
- Auto-shutdown or persistent mode (depends on ssh connection)
- Systemd-compatible for headless deployment
- SSH session detection to prevent shutdown while connected

---

## Hardware Requirements

- Raspberry Pi Zero 2 W (or similar)
- External Wi-Fi adapter with monitor mode support (for `wlan1`)
- Power bank (for portable field use)
- Optional: small OLED/HDMI screen for local TUI (not implemented yet)

---

## Software Dependencies

Installed via `apt`:

```bash
sudo apt update
sudo apt install -y \
  aircrack-ng \
  wireless-tools \
  iw \
  tcpdump \
  curl \
  jq \
  arp-scan \
  network-manager \
  wifite \
  net-tools
```

## 🔧 Example systemd service

To automatically run `networkObserver` on boot via `systemd`, you can create a service like this:

```ini
[Unit]
Description=Auto-start Network Observer script on boot
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
WorkingDirectory=/home/pi/networkObserver/core
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=TERM=xterm
Environment=COLUMNS=80
Environment=LINES=24
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/python3 /home/pi/networkObserver/core/main.py

# Last-resort ceiling above the default 30-minute application limit.
RuntimeMaxSec=45min
TimeoutStopSec=15s
KillMode=control-group
Restart=no

[Install]
WantedBy=multi-user.target
```

`max_runtime_sec` is enforced inside the Python process as a wall-clock limit,
including a stage blocked on subprocess output. The systemd limit is a final
safety net and should remain higher than the configured application limit so
normal cleanup and the SSH-aware shutdown decision can run.
