#!/usr/bin/env python3
"""
Verify Device Script
Connects to devices and automatically detects their device type for devices.csv
"""

import csv
import getpass
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler


def detect_device_type(show_version, show_inventory):
    """
    Use regex patterns to detect device type from show version and show inventory output
    Returns the appropriate Netmiko device_type string
    """
    combined_output = (show_version + "\n" + show_inventory).lower()
    
    # Cisco IOS patterns
    ios_patterns = [
        r'cisco ios software',
        r'ios\s+\(tm\)',
        r'cisco.*router',
        r'c\d{4}',  # C2960, C3750, etc.
        r'catalyst.*l3',
    ]
    
    # Cisco IOS-XE patterns
    iosxe_patterns = [
        r'cisco ios-xe software',
        r'ios xe',
        r'cat[a-z]*\s*[9][0-9]{3}',  # Cat9k series
        r'isr[0-9]{4}',  # ISR4k series
    ]
    
    # Cisco NX-OS patterns
    nxos_patterns = [
        r'cisco nx-os',
        r'nexus\s*[0-9]{4}',
        r'n[579]k',
        r'cisco nexus',
    ]
    
    # Cisco ASA patterns
    asa_patterns = [
        r'cisco adaptive security appliance',
        r'asa[0-9]{4}',
        r'cisco asa',
    ]
    
    # Cisco WLC patterns
    wlc_patterns = [
        r'cisco controller',
        r'wireless.*controller',
        r'wlc',
    ]
    
    # Arista EOS patterns
    arista_patterns = [
        r'arista',
        r'veos',
        r'eos',
        r'dcs-[0-9]',
    ]
    
    # Juniper patterns
    juniper_patterns = [
        r'junos',
        r'juniper networks',
        r'srx[0-9]{3,4}',
        r'ex[0-9]{4}',
        r'qfx[0-9]{4}',
    ]
    
    # Check patterns in priority order (most specific first)
    if any(re.search(pattern, combined_output) for pattern in iosxe_patterns):
        return "cisco_ios"  # IOS-XE uses same driver as IOS
    
    if any(re.search(pattern, combined_output) for pattern in nxos_patterns):
        return "cisco_nxos"
    
    if any(re.search(pattern, combined_output) for pattern in asa_patterns):
        return "cisco_asa"
    
    if any(re.search(pattern, combined_output) for pattern in wlc_patterns):
        return "cisco_wlc"
    
    if any(re.search(pattern, combined_output) for pattern in arista_patterns):
        return "arista_eos"
    
    if any(re.search(pattern, combined_output) for pattern in juniper_patterns):
        return "juniper_junos"
    
    if any(re.search(pattern, combined_output) for pattern in ios_patterns):
        return "cisco_ios"
    
    # Default fallback
    return "cisco_ios"


def verify_device(hostname, username, password):
    """
    Connect to a device using generic terminal and determine its type from output
    """
    result = {
        'hostname': hostname,
        'deviceType': None,
        'success': False,
        'error': None,
        'show_version': None,
        'show_inventory': None
    }
    
    # Use generic terminal_server (most primitive/universal)
    device_params = {
        'device_type': 'terminal_server',  # Most basic connection type
        'host': hostname,
        'username': username,
        'password': password,
        'timeout': 10,
        'conn_timeout': 10,
        'auth_timeout': 10,
        'banner_timeout': 10,
        'session_log': None,
    }
    
    connection = None
    
    try:
        print(f"Connecting to {hostname} with generic SSH...")
        connection = ConnectHandler(**device_params)
        print(f"  Connected successfully")
        
        # Send enable command (might not work on all devices, but worth trying)
        try:
            connection.enable()
        except:
            pass  # Not all devices need/support enable
        
        # Try to get a clean prompt
        connection.write_channel('\n')
        time.sleep(1)
        connection.clear_buffer()
        
        # Run discovery commands using write_channel and read_channel (primitive)
        print(f"  Running 'show version'...")
        connection.write_channel('show version\n')
        time.sleep(2)  # Wait for output
        show_version = connection.read_channel()
        
        # Clean up the output (remove command echo and prompt)
        show_version = show_version.replace('show version', '').strip()
        result['show_version'] = show_version
        
        # Clear buffer before next command
        connection.clear_buffer()
        
        print(f"  Running 'show inventory'...")
        connection.write_channel('show inventory\n')
        time.sleep(2)  # Wait for output
        show_inventory = connection.read_channel()
        
        show_inventory = show_inventory.replace('show inventory', '').strip()
        result['show_inventory'] = show_inventory
        
        if not show_version or len(show_version) < 50:
            raise Exception("No valid output received from 'show version'")
        
        # Detect device type using regex from actual output
        detected_type = detect_device_type(show_version, show_inventory)
        result['deviceType'] = detected_type
        result['success'] = True
        
        print(f"  ✓ Detected device type: {detected_type}")
        
    except Exception as e:
        result['error'] = str(e)
        print(f"  ✗ Error: {e}")
    
    finally:
        if connection:
            try:
                connection.disconnect()
            except:
                pass
    
    return result


def main():
    print("="*80)
    print("DEVICE TYPE VERIFICATION TOOL")
    print("="*80)
    print("This tool will connect to devices and automatically detect their type.")
    print()
    
    # Get input file
    input_file = input("Enter input CSV with hostnames (or just enter hostnames manually): ").strip()
    
    hostnames = []
    
    if input_file and input_file.endswith('.csv'):
        # Load from CSV
        try:
            with open(input_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'hostname' in row:
                        hostnames.append(row['hostname'])
                    else:
                        # Assume first column is hostname
                        hostnames.append(list(row.values())[0])
            print(f"Loaded {len(hostnames)} hosts from {input_file}")
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return
    else:
        # Manual entry
        print("Enter hostnames (one per line, blank line to finish):")
        while True:
            host = input("  Hostname: ").strip()
            if not host:
                break
            hostnames.append(host)
    
    if not hostnames:
        print("No hostnames provided.")
        return
    
    # Get credentials
    print()
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Verify each device using thread pool
    results = []
    print("\n" + "="*80)
    print("VERIFYING DEVICES")
    print("="*80)
    
    max_workers = min(20, len(hostnames))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(verify_device, hostname, username, password): hostname
            for hostname in hostnames
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print()
    
    # Display summary
    print("="*80)
    print("SUMMARY")
    print("="*80)
    
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print(f"Successful: {len(successful)}/{len(results)}")
    print(f"Failed: {len(failed)}/{len(results)}")
    
    if successful:
        print("\nSuccessful devices:")
        for r in successful:
            print(f"  {r['hostname']:30} -> {r['deviceType']}")
    
    if failed:
        print("\nFailed devices:")
        for r in failed:
            print(f"  {r['hostname']:30} -> {r['error']}")
    
    # Save to devices.csv
    output_file = "devices.csv"
    print(f"\n{'='*80}")
    save = input(f"Save results to {output_file}? (y/n): ").strip().lower()
    
    if save == 'y':
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['hostname', 'deviceType'])
            for r in successful:
                writer.writerow([r['hostname'], r['deviceType']])
        
        print(f"✓ Saved {len(successful)} devices to {output_file}")
        
        if failed:
            print(f"\nNote: {len(failed)} failed devices were not saved.")


if __name__ == "__main__":
    main()

