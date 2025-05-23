# Network Scanner

A Python CLI tool to scan the local network using ARP requests and display active devices.

## Features

-   Autodetects the local subnet.
-   Scans for live devices using ARP.
-   Displays IP Address, MAC Address, and Vendor (optional).
-   Results displayed in a clean table format.
-   Optional logging of results to a CSV file.
-   Device Tagging: Assign custom names (tags) to devices based on their MAC address via a JSON configuration file.
-   Diff Mode: Compare the current scan against a previous scan to highlight new, missing, or changed (IP only) devices.
-   Watch Mode: Automatically re-scan the network at a specified interval, clearing the screen and updating the display.
-   Ping Fallback: If ARP scan (which usually requires sudo/admin) fails due to permissions, can optionally fall back to an ICMP ping sweep (provides IP addresses only).

## Requirements

-   Python 3.10+
-   Dependencies listed in `requirements.txt`:
    -   `scapy`
    -   `rich`
    -   `mac-vendor-lookup`
    -   `argparse`

## Installation

1.  Clone the repository or download the files.
2.  Navigate to the `network_scanner` directory.
3.  Activate venv and install the required packages:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    *Note: `scapy` might require additional dependencies or build tools on some systems. Refer to the [Scapy installation guide](https://scapy.readthedocs.io/en/latest/installation.html) for details.*
    *You might need to run the script with `sudo` or as an Administrator for ARP packet sniffing.*

## Usage

```bash
python3 scanner.py [OPTIONS]
```

**Examples:**

-   Scan the network and display results in the terminal:
    ```bash
    sudo python3 scanner.py
    ```

-   Scan the network and save results to a CSV file:
    ```bash
    sudo python3 scanner.py --csv logs/scan_results.csv
    ```

-   Scan a specific subnet:
    ```bash
    sudo python3 scanner.py --subnet 10.0.0.0/24
    ```

-   Scan without vendor lookup (faster):
    ```bash
    sudo python3 scanner.py --no-vendor
    ```

### Options

-   `--subnet SUBNET`: Specify the target subnet (e.g., `192.168.1.0/24`). If not provided, the script will attempt to autodetect it.
-   `--csv FILEPATH`: Path to save the scan results in CSV format (e.g., `logs/scan.csv`). The directory will be created if it doesn't exist.
-   `--no-vendor`: Skip the MAC address vendor lookup to speed up the scan.
-   `--known-devices FILEPATH`: Path to a JSON file for device tagging. MAC addresses are keys, and desired tags are values (e.g., `"00:11:22:33:44:55": "My Router"`). Defaults to `known_devices.json` in the script's directory if the file exists and this option is not provided. If the file is not found or the option is not used, tags will show as "N/A".
-   `--diff`: Enable diff mode. Compares the current scan results with a previous scan stored in the file specified by `--diff-file`.
-   `--diff-file FILEPATH`: Path to the CSV file used for diff comparison and to store the current scan as a baseline for the next diff. Defaults to `network_scanner_last_scan.csv` in the script's directory.
-   `--watch SECONDS`: Enable watch mode to automatically re-scan the network every `SECONDS`. For example, `--watch 5` will scan every 5 seconds. The screen is cleared before each new scan result is displayed. Press `Ctrl+C` to stop watch mode.
-   `--ping-fallback`: If the primary ARP-based scan fails due to a `PermissionError` (i.e., not run with sudo/admin), this flag enables an attempt to perform a basic ICMP ping sweep instead. This fallback will only identify live IP addresses; MAC addresses, vendor information, and device tags will not be available. Diff mode will also be less effective.

## Device Tagging

You can create a JSON file (e.g., `known_devices.json`) to map MAC addresses to custom tags. This helps in easily identifying your devices in the scan results.

**Format of `known_devices.json`:**
```json
{
  "00:1a:2b:3c:4d:5e": "Main Server",
  "aa:bb:cc:dd:ee:ff": "Living Room TV",
  "11:22:33:aa:bb:cc": "Roddy's Mac Mini"
}
```
- MAC addresses should be in lowercase or uppercase; the script normalizes them to lowercase for matching.
- The script will look for `known_devices.json` in the same directory by default if `--known-devices` is not specified. You can provide a custom path using the argument.

## Diff Mode

When `--diff` is enabled, the scanner performs the following:
1.  Conducts a normal network scan to find currently live devices.
2.  Loads device information from a previous scan stored in a CSV file (specified by `--diff-file`, defaulting to `network_scanner_last_scan.csv`).
3.  Compares the current devices with the previous devices based on MAC addresses.
4.  Assigns a status to each device:
    -   `New`: Device is present in the current scan but not in the previous one.
    -   `Missing`: Device was present in the previous scan but not in the current one.
    -   `Changed_IP`: Device (same MAC) is present in both scans but has a different IP address.
    -   `Unchanged`: Device is present in both scans with the same IP address.
5.  Displays the results with the status highlighted (e.g., new devices in green, missing in red).
6.  After the scan and display, if `--diff` was used, the current list of *live* devices (excluding any marked as 'missing' from the previous scan) is saved back to the `--diff-file`, overwriting it. This makes the current scan the baseline for the next time diff mode is used.

**Example of using Diff Mode:**
```bash
# First run (no diff file exists yet, or to establish a baseline)
sudo python3 scanner.py --diff 

# Subsequent runs
sudo python3 scanner.py --diff 
# This will compare against network_scanner_last_scan.csv created/updated by the previous run.

# Using a custom diff file
sudo python3 scanner.py --diff --diff-file my_network_baseline.csv
```

## Watch Mode

When `--watch SECONDS` is enabled, the scanner will:
1. Perform an initial scan (including any diff logic if `--diff` is also active).
2. Display the results.
3. Wait for the specified number of `SECONDS`.
4. Clear the console screen.
5. Repeat from step 1.

This provides a live-updating view of the network. Press `Ctrl+C` to exit watch mode.

**Example of using Watch Mode:**
```bash
# Scan every 10 seconds
sudo python3 scanner.py --watch 10

# Scan every 5 seconds, also using diff mode
sudo python3 scanner.py --watch 5 --diff

# Attempt a scan without sudo, using ping fallback if ARP fails
python3 scanner.py --ping-fallback
```

## How it Works

1.  **Subnet Determination**:
    -   If a subnet is provided via `--subnet`, it's used directly.
    -   Otherwise, the script attempts to find the default network interface's IP address and assumes a `/24` subnet (e.g., if IP is `192.168.1.100`, subnet becomes `192.168.1.0/24`). This is a basic detection and might need adjustment for more complex network configurations.

2.  **ARP Scan**:
    -   An ARP request packet (`who-has`) is crafted for the target subnet.
    -   The `scapy` library is used to send these packets and listen for ARP replies.
    -   Devices that respond are considered live.
    -   **Ping Fallback**: If ARP scan fails due to permissions and `--ping-fallback` is enabled, the script will attempt to send ICMP echo requests to IPs in the subnet. This can identify live IPs but not MAC addresses.

3.  **Data Collection**:
    -   For each live device, its IP address and MAC address are extracted from the ARP reply.
    -   If vendor lookup is enabled (default), the `mac-vendor-lookup` library queries a local database (or an online API if the local DB is outdated/missing) to find the vendor associated with the MAC address's OUI (Organizationally Unique Identifier).
    -   If a `known_devices.json` file is used, the script matches the device's MAC address (case-insensitively) against the keys in the JSON file to assign a custom tag.

4.  **Display and Output**:
    -   The collected information (including custom tags) is displayed in a formatted table using the `rich` library.
    -   If the `--csv` option is used, the results are also written to the specified CSV file.

## Permissions

Sending and receiving ARP packets typically requires raw socket access, which is a privileged operation on most operating systems (Linux, macOS, Windows). Therefore, you usually need to run the script with administrative privileges:

-   **Linux/macOS**: `sudo python3 scanner.py`
-   **Windows**: Run your terminal (Command Prompt, PowerShell) as Administrator, then execute `python scanner.py`.

If you encounter permission errors, this is the most likely cause.

## Future Enhancements (Phase 2 Ideas)

-   **Diff Mode**: Compare current scan results with a previous scan and highlight new or changed devices.
-   **Watch Mode**: Automatically re-scan the network at a specified interval (e.g., `python3 scanner.py --watch 5` for every 5 seconds).
-   **Alerts**: Notify (e.g., sound, log message) if an unknown or unexpected MAC address appears on the network.
-   **Improved Subnet Detection**: More robust methods for detecting the active subnet, potentially handling non-/24 subnets or multiple active interfaces.
-   **Hostname Resolution**: Attempt to resolve hostnames for discovered IP addresses.
