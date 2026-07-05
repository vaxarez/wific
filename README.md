# wific

A minimal, dependency-light command-line WiFi connector for Linux. `wific` talks directly to `wpa_supplicant`'s control socket — no NetworkManager, no `iwd`, no GUI — so you can scan and connect to a WiFi network from a bare terminal in one command.

```
+--------------------------------------+
|  wific - Simple WiFi Connector       |
+--------------------------------------+

  Interface: wlan0
  State: up
  Scanning for networks...

  #  SSID                           SIGNAL         SECURITY   BAND
  -- ------                         --------       --------   ----
  1  Home-5G                        [#######---]  78%  WPA2      5G
  2  Neighbor-WiFi                   [####------]  45%  WPA2      2.4G
  3  Cafe-Guest                      [##--------]  20%  Open      2.4G

  Select [1-3, r=rescan, q=quit]:
```

## Features

- **Zero setup** — auto-detects wireless interfaces and starts `wpa_supplicant` if it isn't already running
- **Interactive scan & connect** — lists nearby networks sorted by signal strength, deduplicated by SSID
- **Signal visualization** — dBm converted to a percentage and a colored ASCII signal bar
- **Broad security support** — Open, WEP, WPA/WPA2-PSK, WPA3-SAE, and mixed WPA2/WPA3 networks
- **Automatic DHCP** — brings the interface up and requests an address via `dhcpcd`, `dhclient`, or `udhcpc` (whichever is available)
- **Safe retries** — wrong passwords and timeouts remove the failed network profile instead of leaving broken configs behind
- **Config persistence** — saves successful connections to the `wpa_supplicant` config so they reconnect automatically next time
- **No external libraries** — pure C using only POSIX/Linux system headers

## How it works

`wific` is a thin client for `wpa_supplicant`'s control interface (the same UNIX-socket protocol tools like `wpa_cli` use):

1. Detects wireless interfaces via `/sys/class/net/*/wireless`
2. Starts `wpa_supplicant` (with a generated temp config, if none exists) and connects to its control socket at `/run/wpa_supplicant/<iface>`
3. Issues `SCAN` / `SCAN_RESULTS` and parses the reply into a sorted, deduplicated network list
4. On selection, prompts for a password (hidden input), configures a network profile over the control socket (`SET_NETWORK`, `ENABLE_NETWORK`, `SELECT_NETWORK`), and waits for `CTRL-EVENT-CONNECTED`
5. Brings the interface up and runs a DHCP client to obtain an IP address

## Requirements

- Linux with a wireless interface
- `wpa_supplicant`
- Root privileges
- One DHCP client: `dhcpcd`, `dhclient`, or `udhcpc`
- Optional: `rfkill` (used to unblock WiFi if soft-blocked)

Install `wpa_supplicant` if you don't already have it:

```bash
# Debian / Ubuntu
sudo apt install wpasupplicant

# Arch
sudo pacman -S wpa_supplicant

# Fedora
sudo dnf install wpa_supplicant
```

> **Note:** If NetworkManager or `iwd` is currently managing your interface, `wific` won't be able to bind to it. Release it first, e.g.:
> ```bash
> sudo nmcli device set wlan0 managed no
> ```

## Build

```bash
sudo make install
```

No third-party libraries are required — just a standard C toolchain and Linux headers.

## Usage

```bash
sudo wific [OPTIONS]
```

| Option          | Description                  |
|-----------------|-------------------------------|
| `-h`, `--help`    | Show usage information       |
| `-v`, `--version` | Show version                  |
| `-i IFACE`      | Use a specific interface       |

### Environment variables

| Variable        | Description                                      |
|-----------------|---------------------------------------------------|
| `WIFIC_IFACE`   | Interface to use (overridden by `-i`)             |
| `WIFIC_DRIVER`  | `wpa_supplicant` driver to use (default: `nl80211`) |

### Examples

```bash
sudo wific                 # Auto-detect interface and connect
sudo wific -i wlan0        # Use a specific interface
WIFIC_IFACE=wlan1 sudo wific
```

Once connected, `wific` stays attached to the control socket — press `Ctrl+C` to detach and exit.

## Interactive controls

While a network list is displayed:

- Enter a number to select and connect to that network
- `r` — rescan for networks
- `q` — quit

Enterprise (802.1X/EAP) networks are detected but not currently supported for automatic connection.

## Limitations

- No support for WPA-Enterprise (EAP) networks
- Shows at most 7 networks per scan (strongest signal first), rescan to refresh
- Requires root
- Linux only

## License

No License
