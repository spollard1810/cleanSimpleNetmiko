#!/usr/bin/env python3
"""Device type verification using primitive SSH connection"""

import csv
import getpass
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler


def detect_device_type(output):
    """Detect device type from show version/inventory output using regex"""
    output = output.lower()
    
    patterns = {
        'cisco_nxos': [r'cisco nx-os', r'nexus\s*[0-9]{4}', r'n[579]k'],
        'cisco_asa': [r'cisco adaptive security appliance', r'asa[0-9]{4}'],
        'cisco_wlc': [r'cisco controller', r'wireless.*controller'],
        'arista_eos': [r'arista', r'veos', r'dcs-[0-9]'],
        'juniper_junos': [r'junos', r'juniper networks', r'srx[0-9]{3,4}', r'ex[0-9]{4}'],
    }
    
    for device_type, regex_list in patterns.items():
        if any(re.search(pattern, output) for pattern in regex_list):
            return device_type
    
    return "cisco_ios"  # Default


def verify_device(hostname, username, password):
    """Connect with generic SSH and detect device type"""
    result = {'hostname': hostname, 'deviceType': None, 'success': False, 'error': None}
    connection = None
    
    try:
        print(f"Connecting to {hostname}...")
        connection = ConnectHandler(
            device_type='terminal_server',
            host=hostname,
            username=username,
            password=password,
            timeout=10,
            conn_timeout=10,
        )
        
        # Get show version output
        connection.write_channel('show version\n')
        time.sleep(2)
        output = connection.read_channel()
        
        if len(output) < 50:
            raise Exception("No valid output received")
        
        result['deviceType'] = detect_device_type(output)
        result['success'] = True
        print(f"  ✓ {result['deviceType']}")
        
    except Exception as e:
        result['error'] = str(e)
        print(f"  ✗ {e}")
    finally:
        if connection:
            connection.disconnect()
    
    return result


def main():
    print("="*80 + "\nDEVICE TYPE VERIFICATION\n" + "="*80)
    
    # Get hostnames
    input_file = input("CSV file or press enter for manual entry: ").strip()
    hostnames = []
    
    if input_file.endswith('.csv'):
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            hostnames = [row.get('hostname', list(row.values())[0]) for row in reader]
        print(f"Loaded {len(hostnames)} hosts")
    else:
        print("Enter hostnames (blank to finish):")
        while (host := input("  ").strip()):
            hostnames.append(host)
    
    if not hostnames:
        return print("No hostnames provided.")
    
    # Get credentials
    username = input("\nUsername: ")
    password = getpass.getpass("Password: ")
    
    # Verify devices in parallel
    print(f"\n{'='*80}\nVERIFYING {len(hostnames)} DEVICES\n{'='*80}")
    
    with ThreadPoolExecutor(max_workers=min(20, len(hostnames))) as executor:
        results = list(executor.map(lambda h: verify_device(h, username, password), hostnames))
    
    # Summary
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print(f"\n{'='*80}\nSUMMARY\n{'='*80}")
    print(f"Successful: {len(successful)}/{len(results)}")
    
    if successful:
        print("\nDetected devices:")
        for r in successful:
            print(f"  {r['hostname']:30} -> {r['deviceType']}")
    
    if failed:
        print(f"\nFailed: {len(failed)}")
        for r in failed:
            print(f"  {r['hostname']:30} -> {r['error'][:50]}")
    
    # Save
    if successful and input(f"\nSave to devices.csv? (y/n): ").lower() == 'y':
        with open('devices.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['hostname', 'deviceType'])
            writer.writerows([[r['hostname'], r['deviceType']] for r in successful])
        print(f"✓ Saved {len(successful)} devices")


if __name__ == "__main__":
    main()
