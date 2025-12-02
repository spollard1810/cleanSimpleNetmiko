import csv
import getpass
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from Core import NetworkDevice


def loadCSV(filename):
    """Load device list from CSV file with hostname and deviceType headers"""
    devices = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append({
                'hostname': row['hostname'],
                'deviceType': row['deviceType']
            })
    return devices


def parse_ip_addresses_to_cidr(output):
    """Parse 'ip address X.X.X.X Y.Y.Y.Y' lines and convert to CIDR with ranges"""
    # Regex to match: ip address 172.16.255.252 255.255.255.255
    pattern = r'ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
    matches = re.findall(pattern, output)
    
    parsed_data = []
    for ip_str, mask_str in matches:
        try:
            # Create network object from IP and netmask
            network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
            
            # Get CIDR notation
            cidr = str(network)
            
            # Get start and end of range
            start_ip = str(network.network_address)
            end_ip = str(network.broadcast_address)
            
            parsed_data.append({
                'cidr': cidr,
                'start': start_ip,
                'end': end_ip
            })
        except Exception as e:
            print(f"Error parsing {ip_str}/{mask_str}: {e}")
    
    return parsed_data


def execute_command_on_device(hostname, device_type, username, password, command):
    """Connect to device, execute command, and return results"""
    device = NetworkDevice(hostname, device_type, username, password)
    result = {
        'hostname': hostname,
        'success': False,
        'output': None,
        'error': None
    }
    
    try:
        print(f"Connecting to {hostname}...")
        device.connect()
        print(f"Connected to {hostname}. Executing command...")
        output = device.sendCommand(command)
        result['success'] = True
        result['output'] = output
        print(f"Command completed on {hostname}")
    except Exception as e:
        result['error'] = str(e)
        print(f"Error on {hostname}: {e}")
    finally:
        device.disconnect()
    
    return result


def main():
    # Load devices from CSV
    csv_file = input("Enter CSV filename (default: devices.csv): ").strip()
    if not csv_file:
        csv_file = "devices.csv"
    
    devices = loadCSV(csv_file)
    print(f"Loaded {len(devices)} devices")
    
    # Get credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Get command to execute
    command = input("Command to execute: ")
    
    # Execute on all devices using thread pool
    max_workers = min(20, len(devices))
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                execute_command_on_device,
                device['hostname'],
                device['deviceType'],
                username,
                password,
                command
            ): device for device in devices
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    
    # Display results
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    
    for result in results:
        print(f"\n{'='*80}")
        print(f"Device: {result['hostname']}")
        print(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
        print(f"{'='*80}")
        
        if result['success']:
            print(result['output'])
        else:
            print(f"Error: {result['error']}")
    
    # Parse IP addresses and output to CSV
    print("\n" + "="*80)
    print("PARSING IP ADDRESSES")
    print("="*80)
    
    all_parsed_ips = []
    for result in results:
        if result['success']:
            parsed = parse_ip_addresses_to_cidr(result['output'])
            for entry in parsed:
                entry['hostname'] = result['hostname']
                all_parsed_ips.append(entry)
    
    # Write to CSV
    if all_parsed_ips:
        output_csv = "ip_addresses.csv"
        with open(output_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Hostname', 'CIDR', 'Start IP', 'End IP'])
            for entry in all_parsed_ips:
                writer.writerow([
                    entry['hostname'],
                    entry['cidr'],
                    entry['start'],
                    entry['end']
                ])
        print(f"\nParsed {len(all_parsed_ips)} IP addresses")
        print(f"Output written to: {output_csv}")
        
        # Display sample
        print("\nSample output:")
        for entry in all_parsed_ips[:5]:
            print(f"{entry['cidr']} {entry['start']} - {entry['end']}")
    else:
        print("No IP addresses found to parse")


if __name__ == "__main__":
    main()

