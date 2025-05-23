#!/usr/bin/env python3

import argparse
from rich.table import Table
from rich.console import Console
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup, BaseMacLookup
import ipaddress
import sys
import json
import os
import csv
import time

# Placeholder for utils.py functions
# from utils import get_default_interface_ip, get_subnet_from_ip

def get_default_interface_ip():
    """
    Placeholder function to get default interface IP.
    In a real scenario, this would involve platform-specific calls
    or using a library like netifaces.
    """
    # For demonstration, returning a common default gateway pattern
    # This should be replaced with actual network interface detection
    try:
        # Attempt to get the default route's interface IP
        # This is a simplified approach and might not work on all systems/configurations
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Connect to a known external IP
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        print(f"Error getting default IP: {e}. Defaulting to 192.168.1.100")
        return "192.168.1.100" # Fallback

def get_subnet_from_ip(ip_address):
    """
    Placeholder function to derive subnet from IP.
    Assumes /24 if not specified.
    """
    try:
        ip_obj = ipaddress.ip_interface(f"{ip_address}/24") # Assume /24
        return str(ip_obj.network)
    except ValueError as e:
        print(f"Error deriving subnet: {e}. Defaulting to 192.168.1.0/24")
        return "192.168.1.0/24" # Fallback

def load_known_devices(filepath):
    """Loads known devices from a JSON file."""
    if not filepath or not os.path.exists(filepath):
        # print(f"Info: Known devices file '{filepath}' not found or not specified. No tags will be applied.")
        return {}
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            # Normalize MAC addresses in the loaded data to lowercase for consistent matching
            return {key.lower(): value for key, value in data.items()}
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{filepath}'. Please check its format.")
        return {}
    except Exception as e:
        print(f"Error loading known devices file '{filepath}': {e}")
        return {}

def load_devices_from_csv(filepath):
    """Loads a list of devices from a CSV file."""
    devices = []
    if not os.path.exists(filepath):
        # print(f"Info: Diff file '{filepath}' not found. Assuming no previous scan.")
        return devices
    try:
        with open(filepath, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Ensure all expected keys are present, provide defaults if not
                devices.append({
                    'ip': row.get('IP Address', 'N/A'),
                    'mac': row.get('MAC Address', 'N/A').lower(), # Normalize MAC for comparison
                    'vendor': row.get('Vendor', 'N/A'),
                    'tag': row.get('Tag', 'N/A')
                    # '#' column is ignored as it's just an index
                })
    except Exception as e:
        print(f"Error loading devices from CSV '{filepath}': {e}")
    return devices

def scan_network(subnet, perform_vendor_lookup=True, known_devices_map=None):
    """
    Scans the network for live hosts using ARP requests.
    """
    print(f"Scanning {subnet}...")
    arp_request = ARP(pdst=subnet)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    
    # Send packets and collect responses
    # Timeout is 1 second, verbose is off
    answered, unanswered = srp(packet, timeout=2, verbose=False)
    
    devices = []
    mac_lookup = None
    if perform_vendor_lookup:
        try:
            mac_lookup = MacLookup()
            # mac_lookup.update_vendors() # Update vendor list - can be slow
        except Exception as e:
            print(f"Warning: Could not initialize MAC vendor lookup: {e}. Vendor info will be skipped.")
            perform_vendor_lookup = False

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        vendor = "N/A"
        if perform_vendor_lookup and mac_lookup:
            try:
                vendor = mac_lookup.lookup(mac)
            except Exception: # Using a broad exception as MacLookup can raise various errors
                vendor = "Error"
        
        tag = "N/A"
        if known_devices_map and mac.lower() in known_devices_map:
            tag = known_devices_map[mac.lower()]
            
        devices.append({"ip": ip, "mac": mac, "vendor": vendor, "tag": tag})
        
    return devices

def ping_scan_network(subnet_str):
    """
    Scans the network for live hosts using ICMP pings.
    Returns a list of dicts, each with an 'ip' key.
    MAC, vendor, tag will be N/A.
    """
    print(f"Attempting ICMP Ping scan for {subnet_str} (MAC addresses will not be available)...")
    live_hosts = []
    try:
        # Create a list of all IP addresses in the subnet
        # ipaddress.ip_network(subnet_str, strict=False).hosts() can be very large for /16 etc.
        # For /24, it's 254 hosts. For larger subnets, this could be slow.
        # Consider adding a warning or limit for very large subnets.
        network = ipaddress.ip_network(subnet_str, strict=False)
        if network.num_addresses > 1024: # Arbitrary limit to prevent very long scans
            print(f"Warning: Subnet {subnet_str} is large ({network.num_addresses} addresses). Ping scan might be slow.")

        # Scapy's sr1 with IP/ICMP for individual pings
        # Sending to all hosts in a large subnet one by one can be slow.
        # A more optimized approach might use srp with a list of packets, but error handling is trickier.
        
        # For simplicity, let's try to ping the common ones first or limit the scope.
        # A full ping sweep of a /24 can take a while if many hosts don't respond (due to timeout).
        # Using scapy.layers.inet.IP and scapy.layers.inet.ICMP
        from scapy.layers.inet import IP, ICMP

        for ip_obj in network.hosts():
            ip_dst = str(ip_obj)
            # Timeout of 0.2 seconds for faster scanning, verbose off
            # Scapy ping often requires root for receiving replies on some systems,
            # even if sending doesn't. This might not be a perfect no-sudo solution.
            try:
                ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_dst), timeout=0.1, verbose=False) # ARP ping to populate cache
                if ans: # if ARP ping got a reply, it's up.
                     live_hosts.append({"ip": ip_dst, "mac": "N/A (Ping Scan)", "vendor": "N/A", "tag": "N/A"})
                     continue # Skip ICMP if ARP worked

                # If ARP ping didn't work, try ICMP
                # This part might still need privileges on some systems to get replies
                resp = srp(IP(dst=ip_dst)/ICMP(), timeout=0.2, verbose=False, iface_hint=ip_dst)
                if resp and resp[0]: # Check if any response was received
                    live_hosts.append({"ip": ip_dst, "mac": "N/A (Ping Scan)", "vendor": "N/A", "tag": "N/A"})
            except Exception as e_ping:
                # print(f"Note: No response or error pinging {ip_dst}: {e_ping}")
                pass # Suppress individual ping errors to keep scan going

        if not live_hosts:
             print("No hosts responded to ping.")
        else:
            print(f"Ping scan found {len(live_hosts)} responsive IP(s).")

    except Exception as e:
        print(f"An error occurred during ping scan: {e}")
    return live_hosts

def display_results(devices):
    """
    Displays the scan results in a table.
    """
    if not devices:
        print("No devices found.")
        return
        
    table = Table(title="Live Devices on Network")
    table.add_column("#", style="dim", width=3)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Vendor", style="green")
    table.add_column("Tag", style="yellow")
    table.add_column("Status", style="white") # New column for diff status
    
    for i, device in enumerate(devices, 1):
        status = device.get("status", "")
        style = ""
        if status == "new":
            style = "bold green"
        elif status == "missing":
            style = "bold red"
        elif status == "changed_ip":
            style = "bold yellow"
        
        # For missing devices, IP might be N/A if not found in current scan logic
        # Ensure all fields are present for the row
        ip_display = device.get("ip", "N/A")
        mac_display = device.get("mac", "N/A")
        vendor_display = device.get("vendor", "N/A")
        tag_display = device.get("tag", "N/A")

        table.add_row(
            str(i), 
            ip_display,
            mac_display,
            vendor_display,
            tag_display,
            status.capitalize(), 
            style=style
        )
        
    console = Console()
    console.print(table)

def save_to_csv(devices, filename):
    """
    Saves the scan results to a CSV file.
    """
    if not devices:
        # print("No devices to save for diff baseline or CSV.") # Minor: changed print message
        return
        
    # Ensure directory exists
    dir_name = os.path.dirname(filename)
    if dir_name: # Only create directories if dirname is not empty
        os.makedirs(dir_name, exist_ok=True)

    try:
        with open(filename, "w", newline="") as csvfile:
            # Add "Status" to fieldnames if any device has a status (i.e., diff mode was active)
            # However, to keep CSV consistent, always include it if diff mode is a feature.
            # Or, only include if args.diff was true. For simplicity, always include.
            fieldnames = ["#", "IP Address", "MAC Address", "Vendor", "Tag", "Status"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for i, device in enumerate(devices, 1):
                writer.writerow({
                    "#": str(i),
                    "IP Address": device.get("ip", "N/A"),
                    "MAC Address": device.get("mac", "N/A"),
                    "Vendor": device.get("vendor", "N/A"),
                    "Tag": device.get("tag", "N/A"),
                    "Status": device.get("status", "").capitalize()
                })
        print(f"Results saved to {filename}")
    except IOError as e:
        print(f"Error saving to CSV: {e}")

def run_scan_cycle(args, console):
    """Encapsulates a single scan, diff, display, and save cycle."""
    target_subnet = args.subnet
    if not target_subnet:
        default_ip = get_default_interface_ip()
        if not default_ip:
            print("Error: Could not determine default IP address. Please specify a subnet with --subnet.")
            return False # Indicate failure
        target_subnet = get_subnet_from_ip(default_ip)
        if not target_subnet:
            print("Error: Could not determine subnet. Please specify a subnet with --subnet.")
            return False # Indicate failure
        print(f"Autodetected subnet: {target_subnet}")

    try:
        ipaddress.ip_network(target_subnet, strict=False)
    except ValueError:
        print(f"Error: Invalid subnet format '{target_subnet}'. Example: 192.168.1.0/24")
        return False # Indicate failure

    perform_vendor_lookup = not args.no_vendor
    known_devices_map = load_known_devices(args.known_devices)
    
    try:
        current_devices = scan_network(target_subnet, perform_vendor_lookup, known_devices_map)
    except PermissionError as pe:
        print("ARP Scan Error: Root/Administrator privileges are required to send ARP packets.")
        print("Please try running the script with sudo or as an Administrator.")
        if args.ping_fallback:
            print("Attempting ICMP ping fallback as --ping-fallback is enabled...")
            current_devices = ping_scan_network(target_subnet)
            if not current_devices: # If ping scan also fails or finds nothing
                print("Ping fallback scan also found no devices or failed.")
                return False # Indicate failure to scan
            # Ping scan results won't have MACs, so diff/tagging won't be very effective.
            # Vendor lookup is also not possible without MACs.
            # The display_results and save_to_csv should handle missing fields.
            # For diff mode with ping fallback, it will mostly show all previous (ARP-scanned) devices as 'missing'
            # and all current (ping-scanned) devices as 'new' because MACs won't match.
            # This is a limitation of ping fallback.
            print("Note: Ping scan provides IP addresses only. MAC, Vendor, Tag, and Diff status may be limited.")
        else:
            return False # Indicate failure if no fallback
    except Exception as e:
        print(f"An unexpected error occurred during ARP scanning: {e}")
        return False # Indicate failure
        
    if args.diff:
        # console.print(f"Diff mode enabled. Comparing with '{args.diff_file}'") # Rich console for consistency
        print(f"Diff mode enabled. Comparing with '{args.diff_file}'")
        previous_devices_list = load_devices_from_csv(args.diff_file)
        previous_devices_map = {dev['mac']: dev for dev in previous_devices_list}
        
        for dev in current_devices:
            prev_dev = previous_devices_map.get(dev['mac'].lower())
            if prev_dev:
                dev['status'] = 'unchanged'
                if dev['ip'] != prev_dev['ip']:
                    dev['status'] = 'changed_ip' 
                previous_devices_map.pop(dev['mac'].lower(), None) # Use pop with default
            else:
                dev['status'] = 'new'
        
        for mac, prev_dev_data in previous_devices_map.items():
            missing_dev = prev_dev_data.copy()
            missing_dev['status'] = 'missing'
            missing_dev.setdefault('ip', prev_dev_data.get('ip', 'N/A'))
            missing_dev.setdefault('vendor', prev_dev_data.get('vendor', 'N/A'))
            missing_dev.setdefault('tag', prev_dev_data.get('tag', 'N/A'))
            current_devices.append(missing_dev)

    if args.watch > 0:
        console.clear() # Clear screen for watch mode
    display_results(current_devices) 
    
    if args.csv:
        save_to_csv(current_devices, args.csv)

    if args.diff:
        # console.print(f"Updating diff baseline file: '{args.diff_file}'")
        print(f"Updating diff baseline file: '{args.diff_file}'")
        baseline_devices_to_save = [d for d in current_devices if d.get('status') != 'missing']
        save_to_csv(baseline_devices_to_save, args.diff_file)
    return True # Indicate success

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network scanner using ARP requests.")
    parser.add_argument(
        "--subnet",
        type=str,
        help="Target subnet (e.g., 192.168.1.0/24). Autodetected if not provided."
    )
    parser.add_argument(
        "--csv",
        type=str,
        help="Output CSV file path (e.g., logs/scan.csv)."
    )
    parser.add_argument(
        "--no-vendor",
        action="store_true",
        help="Skip MAC address vendor lookup."
    )
    parser.add_argument(
        "--known-devices",
        type=str,
        default=None, 
        help="Path to a JSON file mapping MAC addresses to device tags (e.g., known_devices.json). MACs should be keys, tags as values."
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Enable diff mode to compare current scan with a previous scan."
    )
    parser.add_argument(
        "--diff-file",
        type=str,
        default="network_scanner_last_scan.csv", 
        help="Path to the CSV file for diff comparison (default: network_scanner_last_scan.csv in the script's directory)."
    )
    parser.add_argument(
        "--watch",
        type=int,
        default=0, 
        help="Enable watch mode to auto-rescan every X seconds. Provide the interval in seconds (e.g., 5)."
    )
    parser.add_argument(
        "--ping-fallback",
        action="store_true",
        help="If ARP scan fails due to permissions, attempt a basic ICMP ping sweep (less info, no MACs)."
    )
    args = parser.parse_args()

    # Pre-emptive check for MacLookup, outside the loop if watch mode is active
    if not args.no_vendor : 
        try:
            # Ensure cache path is relative to script dir if not absolute
            cache_file_name = "mac_vendors_cache.txt"
            script_dir = os.path.dirname(os.path.abspath(__file__))
            BaseMacLookup.cache_path = os.path.join(script_dir, cache_file_name)
            # print(f"DEBUG: MacLookup cache path set to: {BaseMacLookup.cache_path}") # For debugging
            _ = MacLookup()
        except Exception as e:
            print(f"Warning: MAC vendor lookup might fail or is initializing: {e}")
            # print("Consider running with --no-vendor or ensure 'mac_vendors_cache.txt' is accessible/writable in the script's directory.")

    console = Console() 

    if args.watch > 0:
        try:
            while True:
                if not run_scan_cycle(args, console):
                    break # Exit loop on critical error during scan cycle
                print(f"\nWatching... Next scan in {args.watch} seconds. Press Ctrl+C to stop.")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nWatch mode stopped by user.")
        except Exception as e:
            print(f"\nAn unexpected error occurred in watch mode: {e}")
    else:
        run_scan_cycle(args, console)
